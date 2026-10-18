"""Native-configured process authoring client. Runtime owns every canonical record.

No Executor, review workflow, result producer, capture or provider is composed.
The command journal retains client intent; catalog cursors are observations only.
"""
from __future__ import annotations

import argparse
import asyncio
from contextlib import closing
from dataclasses import dataclass
from importlib.resources import files
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
from urllib.parse import urlsplit
import uuid

from process_runtime_client import RuntimeClient, RuntimeClientError, resource_for
from process_runtime_client.client import validate_wire

from .journal import APP_ID, Journal
from .model import Rejected, UnknownOutcome, canonical, decode_json, digest, identity
from .runtime import ContractValidator, GeneratedClientAdapter, RuntimeGateway
from .wallet_authority import WalletCallAuthority, _pinned_file

MAX_INPUT_BYTES = 65_536
MARKER = "frank-workspace-cleanup.json"
COMMANDS = {"draft-put":"process.draft.put", "publish":"process.publish"}
ACTIONS = ("check-config", "catalog", "get", "validate", "draft-put", "publish", "resume-command", "check-renewal", "migrate-binding")


class CleanupUnresolved(Rejected):
    pass


def closed(value, fields):
    if type(value) is not dict or set(value) != set(fields):
        raise Rejected("Closed workspace input required")
    return value


def pin(value):
    if type(value) is not str or re.fullmatch("[a-f0-9]{64}", value) is None:
        raise Rejected("Exact lowercase SHA-256 required")
    return value


def path(value):
    if type(value) is not str or not 1 <= len(value) <= 4096 or "\0" in value:
        raise Rejected("Absolute selected path required")
    result = Path(value)
    if not result.is_absolute() or ".." in result.parts:
        raise Rejected("Absolute selected path required")
    return result


def private_directory(selected):
    for item in (selected, *selected.parents):
        info = item.lstat()
        sticky = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.getuid())
                or info.st_mode & 0o022 and not sticky):
            raise Rejected("Workspace paths must be owner controlled")
    leaf = selected.lstat()
    if leaf.st_uid != os.getuid() or leaf.st_mode & 0o077:
        raise Rejected("Workspace directory must be private")


def read_input(selected, expected):
    return decode_json(_pinned_file(path(selected), pin(expected), MAX_INPUT_BYTES))


@dataclass(frozen=True)
class Profile:
    selected: Path
    config_sha256: str
    raw: bytes

    @property
    def value(self):
        return decode_json(self.raw)

    def wallet(self):
        return WalletCallAuthority(**self.value["wallet"])

    def current(self):
        if _pinned_file(self.selected, self.config_sha256, MAX_INPUT_BYTES) != self.raw:
            raise Rejected("Workspace configuration changed")
        self.wallet().check_available()


def load_profile(selected, expected):
    selected, expected = path(selected), pin(expected)
    raw = _pinned_file(selected, expected, MAX_INPUT_BYTES)
    value = closed(decode_json(raw), ("schema", "runtime_endpoint", "journal", "wallet"))
    if value["schema"] != "frank.workspace.v1" or type(value["runtime_endpoint"]) is not str:
        raise Rejected("Workspace configuration required")
    origin = urlsplit(value["runtime_endpoint"])
    if (origin.scheme != "http" or origin.hostname != "127.0.0.1" or origin.username is not None
            or origin.password is not None or origin.query or origin.fragment or origin.path not in ("", "/")
            or origin.port is None or not 1024 <= origin.port <= 65535):
        raise Rejected("Workspace requires an explicit numeric-loopback Runtime origin")
    journal = path(value["journal"])
    private_directory(journal.parent)
    try:
        info = journal.lstat()
    except FileNotFoundError:
        pass
    else:
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_nlink != 1):
            raise Rejected("Workspace journal must be a private regular file")
    wallet = closed(value["wallet"], ("executable", "executable_sha256", "configuration", "configuration_sha256"))
    path(wallet["executable"]); path(wallet["configuration"])
    pin(wallet["executable_sha256"]); pin(wallet["configuration_sha256"])
    if journal in (selected, path(wallet["configuration"]), path(wallet["executable"])):
        raise Rejected("Workspace journal must be separate from selected inputs")
    profile = Profile(selected, expected, raw)
    profile.current()  # Artifact/config inspection only; no process, storage or network.
    return profile


def bind_journal(profile, journal):
    """Bind client acknowledgements to one exact owner-selected composition.

    This is local receipt metadata, never canonical Runtime state or authority.
    A changed endpoint/holder/config cannot adopt old observed acknowledgements.
    """
    with journal.connection() as db:
        db.execute("BEGIN IMMEDIATE")
        tables = [row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        if "workspace_binding" in tables:
            rows = db.execute("SELECT singleton,configuration_sha256 FROM workspace_binding").fetchall()
            if len(rows) != 1 or tuple(rows[0]) != (1, profile.config_sha256):
                raise Rejected("Workspace journal binding selects another configuration")
            return
        for table in tables:
            if table.startswith("sqlite_"):
                continue
            quoted = '"' + table.replace('"', '""') + '"'
            if db.execute("SELECT 1 FROM " + quoted + " LIMIT 1").fetchone() is not None:
                raise Rejected("Nonempty journal has no workspace binding")
        db.execute("CREATE TABLE workspace_binding(singleton INTEGER PRIMARY KEY CHECK(singleton=1),configuration_sha256 TEXT NOT NULL)")
        db.execute("INSERT INTO workspace_binding VALUES (1,?)", (profile.config_sha256,))


def _same_except(previous, current, changing=()):
    if (type(previous) is not dict or type(current) is not dict
            or {k:v for k,v in previous.items() if k not in changing}
            != {k:v for k,v in current.items() if k not in changing}):
        raise Rejected("Workspace renewal changes retained identity or scope")


def _selected(value):
    closed(value, ("path", "sha256"))
    selected, expected = path(value["path"]), pin(value["sha256"])
    return selected, decode_json(_pinned_file(selected, expected, MAX_INPUT_BYTES))


def _renewal_complete(selection):
    selected, receipt = _selected(selection)
    required = {"schema", "plan_sha256", "root", "holder", "native_generation", "native_sha256",
        "command_issuer", "configuration_hashes", "not_before", "not_after", "identity_not_after",
        "journal_capacity", "scope", "activation", "service_started", "runtime_store_initialized",
        "process_created", "run_created"}
    renewal = receipt.get("schema") == "castalia.wallet-workspace-renewal-complete.v1" if type(receipt) is dict else False
    closed(receipt, required | ({"previous_complete"} if renewal else set()))
    if (receipt["schema"] not in {"castalia.wallet-workspace-setup-complete.v1", "castalia.wallet-workspace-renewal-complete.v1"}
            or any(receipt[n] is not False for n in ("activation", "service_started", "runtime_store_initialized", "process_created", "run_created"))
            or type(receipt["native_generation"]) is not int or not 1 <= receipt["native_generation"] <= 9_007_199_254_740_991
            or type(receipt["not_before"]) is not int or type(receipt["not_after"]) is not int
            or not 0 < receipt["not_before"] < receipt["not_after"] <= 9_007_199_254_740_991
            or receipt["not_after"] - receipt["not_before"] > 3600):
        raise Rejected("Bounded inactive workspace renewal receipt required")
    pin(receipt["plan_sha256"]); pin(receipt["native_sha256"])
    root = path(receipt["root"])
    expected = root / "authority"
    if renewal:
        expected = expected / "renewals" / str(receipt["native_generation"])
    if selected != expected / "COMPLETE.json":
        raise Rejected("Workspace receipt must retain its original publication path")
    names = {"wallet-command.json", "command-authority.json", "runtime-policy.json", "runtime-receiver.json"}
    closed(receipt["configuration_hashes"], names)
    configs = {name:decode_json(_pinned_file(selected.parent / "config" / name, pin(hashed), MAX_INPUT_BYTES))
               for name, hashed in receipt["configuration_hashes"].items()}
    return receipt, configs


def _migration_evidence(profile, value):
    """Compare pinned public producer receipts, never custody or authority output.

    These owner-selected metadata facts cannot grant a permission or refresh a
    pending challenge. Native and Runtime still validate every actual request.
    """
    closed(value, ("schema", "previous_configuration", "previous_complete", "renewed_complete"))
    if value["schema"] != "frank.workspace-migration.v1":
        raise Rejected("Explicit workspace owner migration required")
    closed(value["previous_configuration"], ("path", "sha256"))
    previous = load_profile(value["previous_configuration"]["path"], value["previous_configuration"]["sha256"])
    before, after = previous.value, profile.value
    _same_except(before, after, ("wallet",))
    _same_except(before["wallet"], after["wallet"], ("configuration", "configuration_sha256"))
    if previous.config_sha256 == profile.config_sha256:
        raise Rejected("Workspace migration must name a new exact composition")
    old, oc = _renewal_complete(value["previous_complete"])
    new, nc = _renewal_complete(value["renewed_complete"])
    if (new["schema"] != "castalia.wallet-workspace-renewal-complete.v1"
            or new["previous_complete"] != value["previous_complete"]
            or new["native_generation"] != old["native_generation"] + 1
            or new["not_before"] < old["not_before"] or new["not_after"] <= old["not_after"]):
        raise Rejected("Workspace renewal does not extend its exact predecessor")
    _same_except(old, new, ("schema", "plan_sha256", "holder", "native_generation", "native_sha256",
                           "configuration_hashes", "not_before", "not_after", "previous_complete"))
    root = path(old["root"])
    if path(after["journal"]) != root / "data/frank-workspace.db":
        raise Rejected("Workspace journal differs from retained setup root")
    oh, nh = old["holder"], new["holder"]
    holder_fields = ("schema", "store_id", "subject_id", "purpose", "application", "state_revision",
        "key_generation", "key_id", "public_key_hex", "public_key_sha256", "state", "created_at", "key_created_at",
        "published_at", "not_before", "not_after", "revoked_at", "previous_state_sha256", "owner_input_sha256")
    closed(oh, holder_fields); closed(nh, holder_fields)
    _same_except(oh, nh, ("state_revision", "published_at", "previous_state_sha256", "owner_input_sha256"))
    if (oh["schema"] != "castalia.wallet-service-custody-state.v1" or oh["application"] != "runtime"
            or oh["state"] != "active" or oh["revoked_at"] is not None
            or type(oh["state_revision"]) is not int or type(nh["state_revision"]) is not int
            or not 1 <= oh["state_revision"] < nh["state_revision"] <= 9_007_199_254_740_991
            or nh["state_revision"] != oh["state_revision"] + 1
            or nh["previous_state_sha256"] != digest(oh)
            or type(nh["published_at"]) is not int or type(oh["published_at"]) is not int
            or nh["published_at"] < oh["published_at"]
            or type(nh["not_after"]) is not int or nh["not_after"] < new["not_after"]
            or new["identity_not_after"] != nh["not_after"]):
        raise Rejected("Workspace renewal must preserve the original active holder")
    pin(nh["owner_input_sha256"]); pin(oh["owner_input_sha256"])
    pin(oh["public_key_hex"]); pin(oh["public_key_sha256"])
    import hashlib
    if hashlib.sha256(bytes.fromhex(oh["public_key_hex"])).hexdigest() != oh["public_key_sha256"]:
        raise Rejected("Workspace public holder key digest differs")
    native_fields = ("schema", "wallet_root", "wallet_observation_pin", "native_root", "native_generation",
        "native_sha256", "issuer_root", "issuer_node_id", "issuer_key_id", "issuer_public_key_hex",
        "journal_root", "maximum_ttl", "journal_capacity")
    for receipt, configs, master, holder, selection in ((old, oc, before, oh, value["previous_complete"]),
                                                       (new, nc, after, nh, value["renewed_complete"])):
        config_root = path(selection["path"]).parent / "config"
        if (path(master["wallet"]["configuration"]) != config_root / "wallet-command.json"
                or master["wallet"]["configuration_sha256"] != receipt["configuration_hashes"]["wallet-command.json"]):
            raise Rejected("Workspace master differs from its pinned public receipt")
        w, n, p, r = (configs[k] for k in ("wallet-command.json", "command-authority.json", "runtime-policy.json", "runtime-receiver.json"))
        closed(w, ("schema", "application", "native_configuration", "native_configuration_sha256", "wallet_root", "store_binding", "expected_state"))
        closed(n, native_fields)
        closed(w["store_binding"], ("store_id", "subject_id", "application", "purpose", "minimum_revision"))
        closed(w["expected_state"], ("state_revision", "state_sha256"))
        closed(n["wallet_observation_pin"], ("schema", "store_id", "minimum_state_revision", "minimum_key_generation", "expected_wallet_reference_sha256"))
        wp = n["wallet_observation_pin"]
        issuer = closed(receipt["command_issuer"], ("node_id", "key_id", "public_key_hex"))
        if (w["schema"] != "castalia.wallet-service-command.v1" or w["application"] != "runtime"
                or w["wallet_root"] != str(root / "authority/wallet") or n["wallet_root"] != w["wallet_root"]
                or w["native_configuration"] != str(config_root / "command-authority.json")
                or w["native_configuration_sha256"] != receipt["configuration_hashes"]["command-authority.json"]
                or w["store_binding"] != {**{k:holder[k] for k in ("store_id", "subject_id", "application", "purpose")}, "minimum_revision":holder["state_revision"]}
                or w["expected_state"] != {"state_revision":holder["state_revision"], "state_sha256":digest(holder)}
                or n["schema"] != "secs.service-authority-configuration.v1"
                or n["native_root"] != str(root / "authority/native") or n["issuer_root"] != str(root / "authority/command-issuer")
                or n["journal_root"] != str(root / "authority/command-journal")
                or n["native_generation"] != receipt["native_generation"] or n["native_sha256"] != receipt["native_sha256"]
                or (n["issuer_node_id"], n["issuer_key_id"], n["issuer_public_key_hex"]) != (issuer["node_id"], issuer["key_id"], issuer["public_key_hex"])
                or wp["schema"] != "secs.wallet-current-startup-pin.v2" or wp["store_id"] != holder["store_id"]
                or wp["minimum_state_revision"] != holder["state_revision"] or wp["minimum_key_generation"] != holder["key_generation"]):
            raise Rejected("Workspace configs do not bind the retained holder and Native owner")
        pin(wp["expected_wallet_reference_sha256"])
        closed(p, ("schema", "audience", "keys", "descriptors", "permissions", "revoked_subject_keys"))
        closed(r, ("schema", "audience", "native_verifier", "policy_file"))
        if (p["schema"] != "runtime.receiver-policy.v1" or r["schema"] != "runtime.receiver-configuration.v1"
                or r["audience"] != p["audience"] or r["policy_file"] != str(config_root / "runtime-policy.json")
                or type(p["keys"]) is not list or len(p["keys"]) != 1
                or type(p["permissions"]) is not list or len(p["permissions"]) != 5):
            raise Rejected("Workspace receiver config differs from the finite renewal")
        key = p["keys"][0]
        if (type(key) is not dict or key.get("key_id") != issuer["key_id"] or key.get("public_key_hex") != issuer["public_key_hex"]
                or key.get("not_before") != receipt["not_before"] or key.get("not_after") != receipt["not_after"]):
            raise Rejected("Workspace receiver issuer differs from the retained key")
        expected = {("runtime."+name+".v1", resource, match) for name, resource, match in (
            ("process.draft.put", "processes/", "prefix"), ("process.publish", "processes/", "prefix"),
            ("process.get", "processes/", "prefix"), ("version.get", "versions/", "prefix"), ("events.list", "events", "exact"))}
        actual = set()
        for rule in p["permissions"]:
            closed(rule, ("subject_id", "key_id", "operation", "resource", "resource_match", "effect", "active", "not_before_ms", "not_after_ms"))
            if (rule["subject_id"] != holder["subject_id"] or rule["key_id"] != holder["key_id"]
                    or rule["effect"] != "allow" or rule["active"] is not True
                    or rule["not_before_ms"] != receipt["not_before"] * 1000 or rule["not_after_ms"] != receipt["not_after"] * 1000):
                raise Rejected("Workspace permission differs from its original finite scope")
            actual.add((rule["operation"], rule["resource"], rule["resource_match"]))
        if actual != expected:
            raise Rejected("Workspace renewal changes its five operation/resource permissions")
    _same_except(oc["wallet-command.json"], nc["wallet-command.json"], ("native_configuration", "native_configuration_sha256", "store_binding", "expected_state"))
    _same_except(oc["command-authority.json"], nc["command-authority.json"], ("wallet_observation_pin", "native_generation", "native_sha256"))
    _same_except(oc["command-authority.json"]["wallet_observation_pin"], nc["command-authority.json"]["wallet_observation_pin"], ("minimum_state_revision", "expected_wallet_reference_sha256"))
    _same_except(oc["runtime-receiver.json"], nc["runtime-receiver.json"], ("policy_file",))
    _same_except(oc["runtime-policy.json"], nc["runtime-policy.json"], ("keys", "permissions"))
    _same_except(oc["runtime-policy.json"]["keys"][0], nc["runtime-policy.json"]["keys"][0], ("not_before", "not_after"))
    # Ordering is retained too; a reordered grant list is not a window-only change.
    for old_rule, new_rule in zip(oc["runtime-policy.json"]["permissions"], nc["runtime-policy.json"]["permissions"]):
        _same_except(old_rule, new_rule, ("not_before_ms", "not_after_ms"))
    previous.current(); profile.current()
    return previous


def migrate_binding(profile, value, migration_sha256):
    previous = _migration_evidence(profile, value)
    pin(migration_sha256)
    selected = path(profile.value["journal"])
    if not selected.exists():
        raise Rejected("Workspace migration requires an existing bound journal")
    response = {"schema":"frank.workspace-migration-result.v1", "previous_configuration_sha256":previous.config_sha256,
        "configuration_sha256":profile.config_sha256, "migration_sha256":migration_sha256,
        "previous_complete_sha256":value["previous_complete"]["sha256"], "renewed_complete_sha256":value["renewed_complete"]["sha256"],
        "duplicate":False, "commands_preserved":True}
    evidence = canonical(value).decode()
    # Journal.__init__ is deliberately not called: it initializes schema/WAL.
    # Rejected foreign, unbound or malformed stores must retain exact bytes.
    with closing(sqlite3.connect(selected.as_uri()+"?mode=ro", uri=True, timeout=5)) as probe:
        _workspace_binding(probe)
    with closing(sqlite3.connect(selected.as_uri()+"?mode=rw", uri=True, timeout=10)) as db:
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA synchronous=FULL")
        with db:
            db.execute("BEGIN IMMEDIATE")
            current = _workspace_binding(db)
            # Lock acquisition may wait. Re-read all pinned public inputs before
            # the binding commit; no external authority operation occurs here.
            _migration_evidence(profile, value)
            _settled_workspace(db)
            tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if current == profile.config_sha256 and "workspace_migrations" in tables:
                row = db.execute("SELECT * FROM workspace_migrations WHERE migration_sha256=?", (migration_sha256,)).fetchone()
                if row is not None and row["evidence"] == evidence and row["response"] == canonical(response).decode():
                    return {**response, "duplicate":True}
            if current != previous.config_sha256:
                raise Rejected("Workspace migration predecessor no longer matches")
            db.execute("CREATE TABLE IF NOT EXISTS workspace_migrations(migration_sha256 TEXT PRIMARY KEY,previous_configuration_sha256 TEXT NOT NULL,configuration_sha256 TEXT NOT NULL UNIQUE,evidence TEXT NOT NULL,response TEXT NOT NULL)")
            db.execute("INSERT INTO workspace_migrations VALUES (?,?,?,?,?)", (migration_sha256, previous.config_sha256, profile.config_sha256, evidence, canonical(response).decode()))
            db.execute("UPDATE workspace_binding SET configuration_sha256=? WHERE singleton=1 AND configuration_sha256=?", (profile.config_sha256, previous.config_sha256))
    return response


def _workspace_binding(db):
    try:
        if (db.execute("PRAGMA application_id").fetchone()[0] != APP_ID
                or db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='workspace_binding'").fetchone() is None):
            raise Rejected("Workspace migration requires an existing bound Frank journal")
        rows = db.execute("SELECT singleton,configuration_sha256 FROM workspace_binding").fetchall()
        if len(rows) != 1 or rows[0][0] != 1:
            raise Rejected("Workspace binding is malformed")
        return pin(rows[0][1])
    except sqlite3.Error:
        raise Rejected("Workspace binding is malformed") from None


def _settled_workspace(db):
    if (db.execute("SELECT 1 FROM commands WHERE state IS NOT 'observed' OR response IS NULL LIMIT 1").fetchone()
            or db.execute("SELECT 1 FROM deliveries WHERE state IS NULL OR state NOT IN ('committed','failed_committed') LIMIT 1").fetchone()):
        raise Rejected("Workspace has unresolved intents; reconcile before renewal")


def renewal_ready(profile):
    """Read-only pre-native owner preflight; never creates or configures a DB."""
    if marker_present(profile):
        raise CleanupUnresolved("Retained workspace ownership requires inspection")
    selected = path(profile.value["journal"])
    state = "absent"
    if selected.exists():
        db = sqlite3.connect(selected.as_uri() + "?mode=ro", uri=True, timeout=5)
        try:
            db.execute("BEGIN")
            if _workspace_binding(db) != profile.config_sha256:
                raise Rejected("Workspace renewal requires its exact bound composition")
            _settled_workspace(db)
            state = "bound"
        finally:
            db.close()
    # Finish all blocking reads before the final cleanup/artifact observation.
    profile.current()
    if marker_present(profile):
        raise CleanupUnresolved("Retained workspace ownership requires inspection")
    return {"schema":"frank.workspace-renewal-readiness.v1", "configuration_sha256":profile.config_sha256,
            "journal":state, "ready":True, "pending_commands":0, "cleanup_retained":False}


def sync_directory(selected):
    fd = os.open(selected, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def wallet_pending(wallet):
    if wallet is None:
        return False
    lock = getattr(wallet, "_operation", None)
    return bool(getattr(wallet, "_owned", None) is not None
                or getattr(wallet, "_census", None) is not None
                or getattr(wallet, "_loose_fds", ()) or getattr(wallet, "_loose_observers", ())
                or lock is not None and lock.locked())


class Operation:
    """Crash/cleanup observation. Saved identifiers never authorize a signal."""
    def __init__(self, profile, action):
        self.path = path(profile.value["journal"]).parent / MARKER
        private_directory(self.path.parent)
        self.value = {"schema":"frank.workspace.cleanup.v1", "operation_id":uuid.uuid4().hex,
            "profile_sha256":profile.config_sha256, "action":action, "state":"running",
            "unresolved":{"wallet":False, "runtime":False}}
        try:
            self.fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            raise CleanupUnresolved("Retained workspace ownership requires inspection") from None
        self.identity = os.fstat(self.fd)
        try:
            self._write()
            sync_directory(self.path.parent)
        except BaseException:
            os.close(self.fd)
            self.fd = None
            raise CleanupUnresolved("Workspace ownership record could not be retained") from None

    def _same(self):
        info = self.path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
                or info.st_mode & 0o077
                or (info.st_dev, info.st_ino) != (self.identity.st_dev, self.identity.st_ino)):
            raise CleanupUnresolved("Workspace operation owner changed")

    def _write(self):
        raw = canonical(self.value)
        os.lseek(self.fd, 0, os.SEEK_SET)
        os.ftruncate(self.fd, 0)
        while raw:
            count = os.write(self.fd, raw)
            if count <= 0:
                raise OSError("short ownership record write")
            raw = raw[count:]
        os.fsync(self.fd)

    def finish(self, *, wallet=None, runtime=None):
        try:
            self._same()
            current = _pinned_file(self.path, digest(self.value), 4096)
            if current != canonical(self.value):
                raise CleanupUnresolved("Workspace operation record changed")
            states = {"wallet":wallet_pending(wallet), "runtime":bool(getattr(runtime, "pending", False))}
            if any(states.values()):
                self.value.update(state="cleanup_unresolved", unresolved=states)
                self._write()
                sync_directory(self.path.parent)
                raise CleanupUnresolved("Workspace operation cleanup is unresolved")
            self._same()
            os.unlink(self.path)
            sync_directory(self.path.parent)
        except (OSError, Rejected):
            raise CleanupUnresolved("Workspace operation cleanup is unresolved") from None
        finally:
            if self.fd is not None:
                os.close(self.fd)
                self.fd = None


class OwnedRuntimeAdapter(GeneratedClientAdapter):
    """Retain an SDK worker across cancellation, then drain before releasing ownership.

    The local HTTP timeout is five seconds; drain is bounded to ten seconds. An
    unresolved Python worker cannot be killed safely and keeps the marker held.
    """
    def __init__(self, client):
        super().__init__(client)
        self.tasks = set()

    @property
    def pending(self):
        return any(not task.done() for task in self.tasks)

    async def _owned(self, coroutine):
        task = asyncio.create_task(coroutine)
        self.tasks.add(task)
        def finished(done):
            self.tasks.discard(done)
            if not done.cancelled():
                done.exception()  # Retrieve failures even after caller cancellation.
        task.add_done_callback(finished)
        return await asyncio.shield(task)

    async def _execute(self, envelope, authority, guard=None):
        return await self._owned(super()._execute(envelope, authority, guard))

    async def query(self, envelope, *, authority):
        return await self._owned(super().query(envelope, authority=authority))

    async def drain(self):
        pending = [task for task in self.tasks if not task.done()]
        if pending:
            await asyncio.wait(pending, timeout=10)


def validate_draft(value):
    # Runtime's own compiler is the source of DAG/type semantics. It performs no
    # I/O and publication independently recompiles within Runtime's transaction.
    from process_runtime.compiler import compile_draft
    from process_runtime.domain import DomainError
    try:
        compiled = compile_draft(value)
    except DomainError as error:
        return {"schema":"frank.workspace.validation.v1", "valid":False,
                "code":error.code, "detail":str(error)[:1024]}
    return {"schema":"frank.workspace.validation.v1", "valid":True,
            "compilation_hash":compiled.compilation_hash, "compiled":compiled.snapshot.value}


async def catalog(gateway, value):
    closed(value, ("after", "limit", "max_pages"))
    after, limit, pages = (value[n] for n in ("after", "limit", "max_pages"))
    if (type(after) is not int or not 0 <= after <= 9_007_199_254_740_991
            or type(limit) is not int or not 1 <= limit <= 100
            or type(pages) is not int or not 1 <= pages <= 20):
        raise Rejected("Catalog cursor/page bounds exceeded")
    cursor, watermark, found, seen = after, after, set(), set()
    for _ in range(pages):
        page = closed(await gateway.query("events.list", {"after":cursor, "limit":limit}),
                      ("events", "next_cursor", "high_watermark"))
        rows, next_cursor, high = (page[n] for n in ("events", "next_cursor", "high_watermark"))
        if (type(rows) is not list or len(rows) > limit or type(next_cursor) is not int
                or type(high) is not int or not cursor <= next_cursor <= high or high < watermark):
            raise Rejected("Runtime catalog cursor is inconsistent")
        sequence = cursor
        for row in rows:
            try:
                validate_wire(row, "event")
            except (ValueError, RuntimeClientError):
                raise Rejected("Runtime catalog event contract mismatch") from None
            sequence += 1
            if row["sequence"] != sequence or row["event_id"] in seen:
                raise Rejected("Runtime catalog event gap or duplicate")
            seen.add(row["event_id"])
            if row["kind"] in {"process.draft_updated", "process.published"}:
                if not row["resource"].startswith("processes/"):
                    raise Rejected("Runtime process event resource changed")
                process_id = identity(row["resource"][len("processes/"):])
                if row["kind"] == "process.draft_updated":
                    selected = row["data"].get("process_id")
                else:
                    published = row["data"].get("pin")
                    if type(published) is not dict:
                        raise Rejected("Runtime publication event pin is missing")
                    selected = published.get("process_id")
                if selected != process_id:
                    raise Rejected("Runtime process event identity changed")
                found.add(process_id)
        if next_cursor != sequence or not rows and cursor != high:
            raise Rejected("Runtime catalog stream did not make contiguous progress")
        cursor, watermark = next_cursor, high
        if cursor == watermark:
            break
    return {"schema":"frank.workspace.catalog.v1", "process_ids":sorted(found),
            "after":after, "next_cursor":cursor, "high_watermark":watermark,
            "cursor_exhausted":cursor == watermark, "complete":after == 0 and cursor == watermark}


def authoring_command(gateway, action, value):
    gateway.validate(value, "command")
    if value["operation"] != COMMANDS[action] or value["resource"] != resource_for(value):
        raise Rejected("Workspace action does not match its exact command")
    return value


def observed(gateway, command, saved):
    if saved["body"] != canonical(command).decode() or saved["digest"] != digest(command):
        raise Rejected("Retained workspace command changed")
    if saved["state"] != "observed" or saved["response"] is None:
        raise UnknownOutcome("Saved workspace command requires explicit resume")
    response = decode_json(saved["response"])
    gateway.validate(response, "result")
    if any(response[n] != command[n] for n in ("request_id", "operation", "resource")):
        raise Rejected("Retained workspace acknowledgement changed")
    return response


async def dispatch(gateway, action, value, *, guard=None):
    if action == "catalog":
        return await catalog(gateway, value)
    if action == "get":
        closed(value, ("process_id",)); identity(value["process_id"])
        process = await gateway.query("process.get", value)
        closed(process, ("process_id", "version", "revision", "draft", "provenance", "last_ordinal", "active_version"))
        if (process["process_id"] != value["process_id"]
                or any(type(process[n]) is not int or process[n] < minimum
                       for n, minimum in (("version", 1), ("revision", 1), ("last_ordinal", 0)))
                or type(process["draft"]) is not dict
                or process["draft"].get("process_id") != value["process_id"]):
            raise Rejected("Runtime process identity differs from selected ID")
        from process_runtime_client import command_envelope
        command_envelope("process.draft.put", request_id="read-contract", expected_version=process["version"],
            payload={"draft":process["draft"], "provenance":process["provenance"]})
        if process["active_version"] is not None:
            try:
                validate_wire(process["active_version"], "pin")
            except RuntimeClientError:
                raise Rejected("Runtime active process pin is malformed") from None
            if process["active_version"]["process_id"] != value["process_id"]:
                raise Rejected("Runtime active version belongs to another process")
        return {"schema":"frank.workspace.process.v1", "process":process}
    if action in COMMANDS:
        command = authoring_command(gateway, action, value)
        # run() holds this workspace's exclusive operation marker throughout.
        # RuntimeGateway durably records fresh intent before acquiring evidence.
        try:
            previous = gateway.journal.saved_command(command["request_id"])
        except Rejected:
            pass
        else:
            return observed(gateway, command, previous)
        return await gateway.send(command, guard=guard)
    if action == "resume-command":
        closed(value, ("request_id",)); identity(value["request_id"])
        saved = gateway.journal.saved_command(value["request_id"])
        command = decode_json(saved["body"])
        action = next((name for name, operation in COMMANDS.items() if command.get("operation") == operation), None)
        if action is None:
            raise Rejected("Saved command is outside workspace authoring")
        authoring_command(gateway, action, command)
        if saved["state"] == "observed":
            return observed(gateway, command, saved)
        if saved["state"] != "pending" or saved["digest"] != digest(command):
            raise Rejected("Retained workspace intent changed")
        return await gateway.replay(value["request_id"], guard=guard)
    raise Rejected("Unsupported workspace action")


async def _run(args):
    profile = load_profile(args.config, args.config_sha256)
    if args.action == "check-config":
        return {"schema":"frank.workspace.status.v1", "configuration":"valid", "runtime_checked":False,
                "authorization":"checked_per_request", "cleanup_retained":marker_present(profile)}
    if args.action == "check-renewal":
        return renewal_ready(profile)
    value = read_input(args.input, args.input_sha256)
    if args.action == "validate":
        return validate_draft(value)
    operation = Operation(profile, args.action)
    wallet = runtime = None
    try:
        if args.action == "migrate-binding":
            return migrate_binding(profile, value, pin(args.input_sha256))
        wallet = profile.wallet()
        runtime = OwnedRuntimeAdapter(RuntimeClient(profile.value["runtime_endpoint"], timeout=5))
        journal = Journal(profile.value["journal"])
        bind_journal(profile, journal)
        validator = ContractValidator(json.loads(files("process_runtime_client").joinpath("runtime-v1.schema.json").read_text()))
        gateway = RuntimeGateway(runtime, wallet, journal, validator)
        profile.current()
        return await dispatch(gateway, args.action, value, guard=lambda _:profile.current())
    finally:
        prior_error = sys.exc_info()[0] is not None
        failed = False
        if runtime is not None:
            try:
                await runtime.drain()
            except BaseException:
                failed = True
        if wallet is not None:
            try:
                await wallet.aclose()
            except BaseException:
                failed = True
        operation.finish(wallet=wallet, runtime=runtime)
        if failed and not prior_error:
            raise Rejected("Workspace close failed after ownership resolved")


def marker_present(profile):
    try:
        (path(profile.value["journal"]).parent / MARKER).lstat()
    except FileNotFoundError:
        return False
    return True


async def run(args):
    try:
        async with asyncio.timeout(args.wait_seconds):
            return await _run(args)
    except TimeoutError:
        raise UnknownOutcome("Workspace deadline expired; inspect or explicitly resume saved intent") from None


def arguments(argv=None):
    parser = argparse.ArgumentParser(description="Generic native workspace process authoring; no executor or provider")
    parser.add_argument("action", choices=ACTIONS)
    parser.add_argument("--config", required=True)
    parser.add_argument("--config-sha256", required=True)
    parser.add_argument("--input")
    parser.add_argument("--input-sha256")
    parser.add_argument("--wait-seconds", type=float, default=60)
    args = parser.parse_args(argv)
    if args.action not in {"check-config", "check-renewal"} and not (args.input and args.input_sha256):
        parser.error("this action requires --input and --input-sha256")
    if args.action in {"check-config", "check-renewal"} and (args.input or args.input_sha256):
        parser.error("this check accepts no process input")
    if not math.isfinite(args.wait_seconds) or not 0 < args.wait_seconds <= 120:
        parser.error("wait budget must be finite and at most120seconds")
    return parser, args


def main(argv=None):
    parser, args = arguments(argv)
    try:
        result = asyncio.run(run(args))
        output = canonical(result)
    except CleanupUnresolved:
        parser.exit(4, "Workspace cleanup state is retained; native actions are blocked\n")
    except UnknownOutcome:
        parser.exit(3, "Workspace outcome unknown; use exact saved-command reconciliation\n")
    except (Rejected, OSError, ValueError, TypeError, KeyError, RuntimeClientError, sqlite3.Error):
        parser.exit(2, "Workspace configuration, process input or current authority unavailable\n")
    sys.stdout.buffer.write(output + b"\n")


if __name__ == "__main__":
    main()
