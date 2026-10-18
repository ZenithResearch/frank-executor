"""Native-configured process authoring client. Runtime owns every canonical record.

No Executor, review workflow, result producer, capture or provider is composed.
The command journal retains client intent; catalog cursors are observations only.
"""
from __future__ import annotations

import argparse
import asyncio
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

from .journal import Journal
from .model import Rejected, UnknownOutcome, canonical, decode_json, digest, identity
from .runtime import ContractValidator, GeneratedClientAdapter, RuntimeGateway
from .wallet_authority import WalletCallAuthority, _pinned_file

MAX_INPUT_BYTES = 65_536
MARKER = "frank-workspace-cleanup.json"
COMMANDS = {"draft-put":"process.draft.put", "publish":"process.publish"}
ACTIONS = ("check-config", "catalog", "get", "validate", "draft-put", "publish", "resume-command")


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
    value = read_input(args.input, args.input_sha256)
    if args.action == "validate":
        return validate_draft(value)
    operation = Operation(profile, args.action)
    wallet = runtime = None
    try:
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
    if args.action != "check-config" and not (args.input and args.input_sha256):
        parser.error("this action requires --input and --input-sha256")
    if args.action == "check-config" and (args.input or args.input_sha256):
        parser.error("check-config accepts no process input")
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
