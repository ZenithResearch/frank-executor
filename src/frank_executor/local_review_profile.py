"""Closed, owner-selected native local-review composition. No discovery/fallback."""
from __future__ import annotations

from dataclasses import dataclass
from importlib.resources import files
import json
import os
import stat
from pathlib import Path
from urllib.parse import urlsplit

from .model import Rejected, decode_json, identity
from .native_results import FileReceiverPolicy, NativeResultVerifier, NativeSecSHelper
from .native_result_producer import NativeResultProducer, _ResultCommand
from .wallet_authority import WalletCallAuthority, _pinned_file, _hex
from frank_review_adapter.local_capture import (
    LocalReviewPolicy, LocalReviewCapture, OPERATIONS, private_directory,
    source_manifest,
)


DECLARED_CAPABILITIES = OPERATIONS | frozenset({
    "transcribe-review-audio", "annotate-review-transcript",
    "extract-review-observations", "update_review_status",
})

def closed(value, keys):
    if type(value) is not dict or set(value) != set(keys):
        raise Rejected("Unsupported local-review profile shape")
    return value


def pin(value):
    if not _hex(value, 64):
        raise Rejected("Explicit SHA256 required")
    return value


def path(value):
    if type(value) is not str or not Path(value).is_absolute() or str(Path(value)) != value:
        raise Rejected("Absolute local-review path required")
    if ".." in Path(value).parts:
        raise Rejected("Canonical local-review path required")
    return Path(value)


def artifact(value):
    closed(value, ("content_hash", "byte_length", "media_type"))
    pin(value["content_hash"])
    if (type(value["byte_length"]) is not int or not 0 <= value["byte_length"] <= 1048576
            or type(value["media_type"]) is not str or not 1 <= len(value["media_type"]) <= 128):
        raise Rejected("Bounded artifact reference required")


def command_profile(value):
    closed(value, ("executable", "executable_sha256", "configuration", "configuration_sha256"))
    path(value["executable"]); path(value["configuration"])
    pin(value["executable_sha256"]); pin(value["configuration_sha256"])
    return value


@dataclass(frozen=True)
class LocalReviewProfile:
    config_path: Path
    config_sha256: str
    master_bytes: bytes
    composition_bytes: bytes

    @property
    def master(self):
        return decode_json(self.master_bytes)

    @property
    def composition(self):
        return decode_json(self.composition_bytes)

    @property
    def policy(self):
        master, value = self.master, self.composition
        actor = value["actor"]
        return LocalReviewPolicy(actor["actor_id"], actor["integration_id"], actor["route"],
            value["producer_artifact_sha256"], value["normalizer_sha256"],
            master["composition"]["sha256"], master["source_manifest_sha256"])

    def current(self):
        master = self.master
        if (_pinned_file(self.config_path, self.config_sha256, 65536) != self.master_bytes
                or _pinned_file(path(master["composition"]["path"]),
                                master["composition"]["sha256"], 65536) != self.composition_bytes):
            raise Rejected("Local-review composition changed")
        value = self.composition
        private_directory(path(value["journal"]).parent)
        if path(value["journal"]).exists() or path(value["journal"]).is_symlink():
            # Metadata admission only: no SQLite connection or database bytes.
            fd = os.open(path(value["journal"]), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                        or info.st_mode & 0o077 or info.st_nlink != 1):
                    raise Rejected("Owner-private Frank journal required")
            finally:
                os.close(fd)
        source_manifest(path(value["capture_root"]), self.policy)

    def native_sources(self):
        self.current()
        master = self.master
        authority = WalletCallAuthority(**master["wallet"])
        result = _ResultCommand(capture_root=path(self.composition["capture_root"]), **master["result"])
        helper = NativeSecSHelper(master["verifier"]["executable"], master["verifier"]["sha256"])
        verifier = NativeResultVerifier(helper, FileReceiverPolicy(master["verifier"]["policy"]))
        authority.check_available()
        result.check_available()
        actor = self.composition["actor"]
        verifier.require_native_sources(actor_binding=
            (actor["actor_id"], actor["integration_id"], actor["route"]))
        return authority, verifier


def load_profile(config_path, config_sha256):
    selected = path(config_path)
    pin(config_sha256)
    raw = _pinned_file(selected, config_sha256, 65536)
    master = closed(decode_json(raw), ("schema", "composition", "source_manifest_sha256",
                                      "wallet", "result", "verifier"))
    if master["schema"] != "frank.local-review.config.v1":
        raise Rejected("Unsupported local-review profile")
    closed(master["composition"], ("path", "sha256"))
    pin(master["composition"]["sha256"]); pin(master["source_manifest_sha256"])
    body = _pinned_file(path(master["composition"]["path"]), master["composition"]["sha256"], 65536)
    value = closed(decode_json(body), ("schema", "runtime_endpoint", "journal", "capture_root",
        "actor", "run_ids", "producer_artifact_sha256", "normalizer_sha256", "transcript", "snapshots"))
    if value["schema"] != "frank.local-review.composition.v1":
        raise Rejected("Unsupported producer composition")
    if type(value["runtime_endpoint"]) is not str:
        raise Rejected("Explicit Runtime endpoint required")
    endpoint = urlsplit(value["runtime_endpoint"])
    if (endpoint.scheme not in {"http", "https"} or not endpoint.hostname
            or endpoint.username is not None or endpoint.password is not None
            or endpoint.query or endpoint.fragment or endpoint.path not in {"", "/"}):
        raise Rejected("Explicit Runtime endpoint required")
    path(value["journal"]); path(value["capture_root"])
    pin(value["producer_artifact_sha256"]); pin(value["normalizer_sha256"])
    actor = closed(value["actor"], ("actor_id", "integration_id", "route", "capabilities", "resources"))
    for name in ("actor_id", "integration_id", "route"):
        identity(actor[name])
    for key, maximum in (("capabilities", 13), ("resources", 128)):
        rows = actor[key]
        if (type(rows) is not list or len(rows) > maximum
                or any(type(v) is not str or not 1 <= len(v) <= 4096 for v in rows)
                or len(set(rows)) != len(rows)):
            raise Rejected("Bounded unique actor declarations required")
    if not actor["capabilities"] or not set(actor["capabilities"]) <= DECLARED_CAPABILITIES:
        raise Rejected("Only fixed local-review operations are supported")
    runs = value["run_ids"]
    if type(runs) is not list or not 1 <= len(runs) <= 64:
        raise Rejected("Finite selected run IDs required")
    for run in runs:
        identity(run)
    if len(set(runs)) != len(runs):
        raise Rejected("Duplicate selected run")
    transcript = closed(value["transcript"], ("audio_sha256", "artifact"))
    pin(transcript["audio_sha256"]); artifact(transcript["artifact"])
    snapshots = value["snapshots"]
    if type(snapshots) is not dict or len(snapshots) > 64:
        raise Rejected("Bounded selected snapshots required")
    for subject, rows in snapshots.items():
        identity(subject)
        if type(rows) is not list or len(rows) > 128:
            raise Rejected("Bounded selected snapshots required")
        for row in rows:
            closed(row, ("path", "artifact"))
            if type(row["path"]) is not str or not 1 <= len(row["path"]) <= 4096:
                raise Rejected("Logical source identity required")
            artifact(row["artifact"])
    command_profile(master["wallet"]); command_profile(master["result"])
    helper = closed(master["verifier"], ("executable", "sha256", "policy"))
    path(helper["executable"]); path(helper["policy"]); pin(helper["sha256"])
    journal_path = path(value["journal"])
    fixed_files = {selected, path(master["composition"]["path"]), path(helper["executable"]), path(helper["policy"])}
    for name in ("wallet", "result"):
        fixed_files.update(path(master[name][field]) for field in ("executable", "configuration"))
    if journal_path in fixed_files or journal_path.is_relative_to(path(value["capture_root"])):
        raise Rejected("Frank journal overlaps immutable selected inputs")
    profile = LocalReviewProfile(selected, config_sha256, raw, body)
    profile.current()
    return profile


def compose(profile):
    """Open Frank-owned stores only for an explicit execution action."""
    from process_runtime_client import RuntimeClient
    from .executor import Executor
    from .journal import Journal
    from .registry import Registry
    from .runtime import RuntimeGateway, GeneratedClientAdapter, ContractValidator
    from frank_review_adapter.adapter import ReviewAdapter
    from frank_review_adapter.local_ports import (RuntimeArtifacts, RuntimeClaims,
        RuntimeSnapshotSources, SuppliedTranscript, DurableSimulatedIntents)
    from frank_review_adapter.ports import ReviewPorts
    authority, verifier = profile.native_sources()
    value, master = profile.composition, profile.master
    actor = value["actor"]
    journal_path = path(value["journal"])
    try:
        fd = os.open(journal_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        pass
    else:
        os.close(fd)
    profile.current()
    journal = Journal(journal_path)
    schema = json.loads(files("process_runtime_client").joinpath("runtime-v1.schema.json").read_text())
    gateway = RuntimeGateway(GeneratedClientAdapter(RuntimeClient(value["runtime_endpoint"])),
                             authority, journal, ContractValidator(schema))
    artifacts = RuntimeArtifacts(gateway)
    claims = RuntimeClaims(gateway, journal, actor_id=actor["actor_id"],
                           integration_id=actor["integration_id"], route=actor["route"])
    capture = LocalReviewCapture(journal, value["capture_root"], profile.policy)
    producer = NativeResultProducer(capture=capture, claims=claims, verifier=verifier, **master["result"])
    sources = RuntimeSnapshotSources(artifacts, value["snapshots"])
    transcript = SuppliedTranscript(artifacts, audio_sha256=value["transcript"]["audio_sha256"],
                                    transcript_artifact=value["transcript"]["artifact"])
    ports = ReviewPorts(artifacts, transcript, sources, sources, DurableSimulatedIntents(journal), claims, producer)
    adapter = ReviewAdapter.local_native(actor["integration_id"], {"effects":"disabled", "route":actor["route"]},
        ports=ports, capture=capture, producer=producer, environment="production")
    registry = Registry({"schema":"frank.integrations.v1", "actors":[actor], "integrations":[{
        "id":actor["integration_id"], "plugin":"local-review", "enabled":True, "config":{}}]},
        {"local-review":lambda *_:adapter})
    executor = Executor(gateway, registry, journal, verifier, environment="production")
    return executor, adapter
