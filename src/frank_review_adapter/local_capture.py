"""Trusted local-review observations, durable reservation and exact publication.

This writer is injected by local execution composition. Persisted JSON is not an
execution capability and a digest does not prove that selected software ran.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, fields
import hashlib
import os
from pathlib import Path
import re
import stat
import uuid

from frank_executor.model import Binding, Rejected, canonical, decode_json, digest, identity, validate_result
from frank_executor.native_results import payload_for
from frank_executor.connector_capture import CapturePending
from .ports import ReviewPorts

HASH = re.compile(r"[a-f0-9]{64}\Z")
OPERATIONS = frozenset("review." + n for n in (
    "load_review", "transcribe", "resolve_components", "annotate", "extract",
    "bind_source", "write_review", "write_status", "daily_note"))
KINDS = frozenset({"artifact-read", "artifact-write", "provider-response", "source-snapshot-read",
                   "component-snapshot-read", "claim-check", "simulated-intent"})
FAILURES = frozenset({"artifact_integrity_mismatch", "artifact_write_integrity_mismatch", "artifact_unavailable",
    "daily_note_simulation_unconfirmed", "malformed_artifact", "malformed_component_evidence",
    "malformed_review_events", "malformed_source_evidence", "malformed_transcription",
    "malformed_transcription_timing", "malformed_packet", "packet_input_mismatch", "review_packet_degraded",
    "status_intent_required", "status_simulation_unconfirmed", "unresolved_event_timing"})
MAX_BLOB = 1024 * 1024
MAX_TRACE = 4 * 1024 * 1024
MAX_METADATA = 16384
MAX_STORE = 512 * 1024 * 1024
MAX_HISTORY = 4
# Charge future capture, duplicated transaction/publication bytes and four proof
# envelopes before computing. This is a quota reservation, not OS preallocation.
RESERVATION_BYTES = 24 * 1024 * 1024


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def metadata(value):
    raw = canonical(value)
    if len(raw) > MAX_METADATA:
        raise Rejected("Local-review metadata exceeds bound")
    return raw


def private_directory(path):
    path = Path(path)
    if not path.is_absolute():
        raise Rejected("Local-review root must be absolute")
    for current in (path, *path.parents):
        st = current.lstat()
        sticky = st.st_uid == 0 and bool(st.st_mode & stat.S_ISVTX)
        if (not stat.S_ISDIR(st.st_mode) or st.st_uid not in (0, os.getuid())
                or (st.st_mode & 0o022 and not sticky)):
            raise Rejected("Unsafe local-review root")
    st = path.lstat()
    if st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise Rejected("Owner-private local-review root required")
    return st.st_dev, st.st_ino


def read_private(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or before.st_nlink != 1 or before.st_mode & 0o077 or before.st_size > maximum):
            raise Rejected("Unsafe local-review file")
        with os.fdopen(fd, "rb", closefd=False) as source:
            raw = source.read(maximum + 1)
        after = os.fstat(fd)
        stable = lambda s: (s.st_dev,s.st_ino,s.st_size,s.st_mode,s.st_uid,s.st_nlink,s.st_mtime_ns,s.st_ctime_ns)
        if len(raw) != before.st_size or len(raw) > maximum or stable(before) != stable(after):
            raise Rejected("Local-review file changed")
        return raw
    finally:
        os.close(fd)


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def exact_file(path, raw):
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        if read_private(path, len(raw)) != raw:
            raise Rejected("Immutable local-review bytes changed")
        return
    try:
        with os.fdopen(fd, "wb", closefd=False) as out:
            out.write(raw)
            out.flush()
            os.fsync(fd)
    finally:
        os.close(fd)


@dataclass(frozen=True)
class LocalReviewPolicy:
    actor_id: str
    integration_id: str
    route: str
    producer_artifact_sha256: str
    normalizer_sha256: str
    configuration_sha256: str
    source_manifest_sha256: str

    def __post_init__(self):
        for name in ("actor_id", "integration_id", "route"):
            identity(getattr(self, name))
        for field in fields(self):
            if field.name.endswith("sha256") and (type(getattr(self,field.name)) is not str or not HASH.fullmatch(getattr(self, field.name))):
                raise Rejected("Explicit producer-composition pins required")

    def bytes(self):
        return metadata({f.name: getattr(self, f.name) for f in fields(self)})


def source_manifest(root, policy):
    """Read the same selected manifest without constructing a journal/capture."""
    root = Path(root)
    private_directory(root)
    private_directory(root / "blobs")
    raw = read_private(root / "source-manifest.json", MAX_METADATA)
    value = decode_json(raw)
    keys = {"schema", "producer_artifact_sha256", "normalizer_sha256", "configuration_sha256", "entries"}
    if (sha(raw) != policy.source_manifest_sha256 or type(value) is not dict
            or set(value) != keys or value["schema"] != "frank.local-review.source-manifest.v1"
            or any(value[n] != getattr(policy, n) for n in keys - {"schema", "entries"})
            or type(value["entries"]) is not list or not 3 <= len(value["entries"]) <= 128):
        raise Rejected("Selected source manifest changed")
    seen = set()
    for item in value["entries"]:
        if (type(item) is not dict or set(item) != {"sha256", "byte_length"}
                or type(item["sha256"]) is not str or not HASH.fullmatch(item["sha256"]) or item["sha256"] in seen
                or type(item["byte_length"]) is not int or not 0 <= item["byte_length"] <= MAX_BLOB):
            raise Rejected("Invalid selected source entry")
        seen.add(item["sha256"])
        body = read_private((root / "blobs") / item["sha256"], item["byte_length"])
        if len(body) != item["byte_length"] or sha(body) != item["sha256"]:
            raise Rejected("Selected source bytes changed")
    if not {policy.producer_artifact_sha256, policy.normalizer_sha256,
            policy.configuration_sha256}.issubset(seen):
        raise Rejected("Selected composition blobs absent")
    return raw


class LocalReviewCapture:
    def __init__(self, journal, root, policy):
        from frank_executor.journal import Journal
        if type(journal) is not Journal or type(policy) is not LocalReviewPolicy:
            raise Rejected("Trusted local-review journal and policy required")
        self.journal, self.root, self.policy = journal, Path(root), policy
        self._root_identity, self._policy = private_directory(self.root), policy.bytes()
        info = Path(journal.path).lstat()
        self._journal_identity = info.st_dev, info.st_ino
        self._journal_parent = private_directory(Path(journal.path).parent)
        self.blobs = self.root / "blobs"
        self.blobs.mkdir(mode=0o700, exist_ok=True)
        private_directory(self.blobs)
        # Native uses this same cooperative lock. Publication never replaces it.
        exact_file(self.root / "capture.lock", b"")
        with self._connection() as db:
            db.execute("CREATE TABLE IF NOT EXISTS local_review_capture (effect TEXT PRIMARY KEY,capture_id TEXT UNIQUE NOT NULL,work BLOB NOT NULL,policy BLOB NOT NULL,reservation BLOB NOT NULL,state TEXT NOT NULL,payload BLOB,receipt BLOB)")
            db.execute("CREATE TABLE IF NOT EXISTS local_review_exchange (capture_id TEXT NOT NULL,selector_sha256 TEXT NOT NULL,selector BLOB NOT NULL,mode TEXT NOT NULL,envelope BLOB,PRIMARY KEY(capture_id,selector_sha256))")
        self._source_manifest()

    def _current(self):
        if private_directory(self.root) != self._root_identity or self.policy.bytes() != self._policy:
            raise Rejected("Selected local-review root or profile changed")
        info = Path(self.journal.path).lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077
                or info.st_nlink != 1 or (info.st_dev,info.st_ino) != self._journal_identity
                or private_directory(Path(self.journal.path).parent) != self._journal_parent):
            raise Rejected("Unsafe selected Frank journal")

    def _capacity(self):
        total, entries = 0, 0
        for directory, dirs, files in os.walk(self.root, followlinks=False):
            entries += len(dirs) + len(files)
            if entries > 8192:
                raise Rejected("Local-review storage entry capacity exhausted")
            for name in dirs:
                private_directory(Path(directory) / name)
            for name in files:
                info = (Path(directory) / name).lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise Rejected("Unexpected capture storage entry")
                total += info.st_size
        for suffix in ("", "-wal", "-shm"):
            path = Path(self.journal.path + suffix)
            if path.exists():
                info = path.lstat()
                if not stat.S_ISREG(info.st_mode):
                    raise Rejected("Unexpected journal storage entry")
                total += info.st_size
        if total > MAX_STORE:
            raise Rejected("Local-review storage capacity exhausted")

    @contextmanager
    def _connection(self):
        self._current()
        self._capacity()
        with self.journal.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            self._capacity()
            yield db
            self._capacity()
        self._current()
        self._capacity()

    def _source_manifest(self):
        return source_manifest(self.root, self.policy)

    def _work(self, work):
        Binding.read(work["binding"])
        if (work.get("schema") != "frank.work.v1" or work.get("operation") not in OPERATIONS
                or any(work.get(n) != getattr(self.policy, n) for n in ("actor_id", "integration_id", "route"))):
            raise Rejected("Work outside selected local-review scope")
        identity(work["effect_id"])
        raw = canonical(work)
        key = digest({n: work[n] for n in ("binding", "actor_id", "integration_id", "route", "effect_id")})
        return key, raw

    def reserve(self, work):
        key, raw = self._work(work)
        reservation = metadata({"schema":"frank.local-review.reservation.v1", "reservation_id":"review-"+key,
                                "work_sha256":sha(raw), "configuration_sha256":self.policy.configuration_sha256})
        capture_id = sha(reservation)
        self._source_manifest()
        with self._connection() as db:
            prior = db.execute("SELECT * FROM local_review_capture WHERE effect=?", (key,)).fetchone()
            if prior:
                if bytes(prior["work"]) != raw or bytes(prior["policy"]) != self._policy or bytes(prior["reservation"]) != reservation:
                    raise Rejected("Local-review effect reused with changed work")
                return capture_id, False
            count = db.execute("SELECT count(*) FROM local_review_capture").fetchone()[0]
            if count >= 128 or (count + 1) * RESERVATION_BYTES > MAX_STORE:
                raise Rejected("Local-review reservation capacity exhausted")
            db.execute("INSERT INTO local_review_capture VALUES (?,?,?,?,?,'reserved',NULL,NULL)",
                       (key,capture_id,raw,self._policy,reservation))
        return capture_id, True

    def retained(self, work):
        key, raw = self._work(work)
        with self._connection() as db:
            row = db.execute("SELECT * FROM local_review_capture WHERE effect=?", (key,)).fetchone()
            if row is None:
                return None
            if bytes(row["work"]) != raw or bytes(row["policy"]) != self._policy:
                raise Rejected("Retained local-review work changed")
            row = dict(row)
        if row["state"] != "completed":
            raise CapturePending("Local-review computation is unresolved; do not rerun provider")
        payload, receipt = decode_json(bytes(row["payload"])), decode_json(bytes(row["receipt"]))
        result = payload["result"]
        expected = {"schema","reservation_id","work_sha256","payload_sha256","unsigned_result_sha256",
                    "producer_artifact_sha256","normalizer_sha256","configuration_sha256","source_manifest_sha256",
                    "operation","outcome","completion_kind","observations"}
        if (type(receipt) is not dict or set(receipt) != expected or metadata(receipt) != bytes(row["receipt"])
                or receipt["schema"] != "frank.local-review.capture.v1" or receipt["reservation_id"] != "review-"+key
                or receipt["operation"] != work["operation"] or receipt["outcome"] != result["outcome"]
                or any(receipt[n] != getattr(self.policy,n) for n in expected if n.endswith("sha256") and hasattr(self.policy,n))
                or "proof" in result or result["provider_reference"] != "local-review:review-"+key):
            raise Rejected("Retained local-review receipt changed")
        reservation = {"schema":"frank.local-review.reservation.v1","reservation_id":"review-"+key,
                       "work_sha256":sha(raw),"configuration_sha256":self.policy.configuration_sha256}
        if (sha(bytes(row["reservation"])) != row["capture_id"]
                or metadata(reservation) != bytes(row["reservation"])
                or payload_for(result, work) != bytes(row["payload"])
                or receipt["payload_sha256"] != sha(bytes(row["payload"]))
                or receipt["unsigned_result_sha256"] != digest(result)
                or receipt["work_sha256"] != sha(raw)):
            raise Rejected("Retained local-review computation changed")
        self._observations(receipt["observations"],raw)
        self._source_manifest()
        row.update(result=result, receipt_value=receipt)
        return row

    def complete(self, work, result, completion_kind, recorder):
        key, raw = self._work(work)
        validate_result(result, work)
        payload = payload_for(result, work)
        if "proof" in result or result["outcome"] not in {"succeeded", "failed"}:
            raise Rejected("Capture requires original terminal computation")
        if ((result["outcome"] == "succeeded" and completion_kind != "computed")
                or (result["outcome"] == "failed" and completion_kind not in FAILURES)
                or result["provider_reference"] != "local-review:review-"+key):
            raise Rejected("Unsupported local-review completion")
        if recorder.owner is not self or recorder.work != raw or not recorder.observations or recorder.observations[-1]["kind"] != "claim-check":
            raise Rejected("Actual final claim observation required")
        self._observations(recorder.observations,raw)
        with self._connection() as db:
            row = db.execute("SELECT * FROM local_review_capture WHERE effect=?", (key,)).fetchone()
            if row is None or bytes(row["work"]) != raw or row["state"] != "reserved":
                raise Rejected("Original computation reservation required")
            receipt = metadata({"schema":"frank.local-review.capture.v1", "reservation_id":"review-"+key,
                "work_sha256":sha(raw), "payload_sha256":sha(payload), "unsigned_result_sha256":digest(result),
                **{n:getattr(self.policy,n) for n in ("producer_artifact_sha256","normalizer_sha256","configuration_sha256","source_manifest_sha256")},
                "operation":work["operation"],"outcome":result["outcome"],"completion_kind":identity(completion_kind),
                "observations":recorder.observations})
            db.execute("UPDATE local_review_capture SET state='completed',payload=?,receipt=? WHERE effect=?", (payload,receipt,key))
        return self.publish(work)

    def _observations(self, observations, work):
        if type(observations) is not list or not 1 <= len(observations) <= 128:
            raise Rejected("Actual port observations required")
        for item in observations:
            if (type(item) is not dict or set(item) != {"kind","input_sha256","output_sha256","byte_length","reference"}
                    or type(item["kind"]) is not str or item["kind"] not in KINDS
                    or type(item["byte_length"]) is not int or not 0 <= item["byte_length"] <= MAX_BLOB
                    or type(item["reference"]) is not str or not HASH.fullmatch(item["reference"])):
                raise Rejected("Malformed local-review observation")
            if item["reference"] != (item["output_sha256"] or item["input_sha256"]):
                raise Rejected("Observation reference changed")
            for name in ("input_sha256","output_sha256"):
                pin = item[name]
                if pin is None:
                    continue
                if type(pin) is not str or not HASH.fullmatch(pin):
                    raise Rejected("Malformed observation digest")
                body = read_private(self.blobs / pin,MAX_BLOB)
                if sha(body) != pin or (pin == item["reference"] and len(body) != item["byte_length"]):
                    raise Rejected("Observation bytes changed")
        last = observations[-1]
        if last["kind"] != "claim-check" or last["input_sha256"] != sha(work) or last["output_sha256"] is None:
            raise Rejected("Current claim observation required")

    def publish(self, work):
        import fcntl
        row = self.retained(work)
        if row is None:
            raise CapturePending("No retained local-review computation")
        self._source_manifest()
        lock = os.open(self.root / "capture.lock", os.O_RDWR | os.O_NOFOLLOW)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            before = os.fstat(lock)
            current = (self.root / "capture.lock").lstat()
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid != os.getuid()
                    or before.st_mode & 0o077 or (before.st_dev,before.st_ino)!=(current.st_dev,current.st_ino)):
                raise Rejected("Capture publication lock changed")
            final = self.root / row["capture_id"]
            values = {"work.json":bytes(row["work"]),"reservation.json":bytes(row["reservation"]),
                      "payload.json":bytes(row["payload"]),"receipt.json":bytes(row["receipt"])}
            if final.exists():
                private_directory(final)
                if set(p.name for p in final.iterdir()) != set(values):
                    raise Rejected("Published capture inventory changed")
                for name, raw in values.items():
                    if read_private(final / name, len(raw)) != raw:
                        raise Rejected("Published capture changed")
            else:
                pending = self.root / ("pending-"+uuid.uuid4().hex)
                pending.mkdir(mode=0o700)
                for name, raw in values.items():
                    exact_file(pending / name,raw)
                sync_directory(pending)
                os.rename(pending,final)
                sync_directory(self.root)
            self._current()
            entry = (self.root / "capture.lock").lstat()
            if (entry.st_dev,entry.st_ino)!=(before.st_dev,before.st_ino):
                raise Rejected("Capture publication lock replaced")
            self._capacity()
        finally:
            os.close(lock)
        return row

    def exchange(self, work, mode=None, renewal_of=None):
        row = self.publish(work)
        with self._connection() as db:
            rows = db.execute("SELECT * FROM local_review_exchange WHERE capture_id=? ORDER BY rowid", (row["capture_id"],)).fetchall()
            if mode is None:
                return dict(rows[-1]) if rows else None
            if mode not in {"attest","renew"} or (mode == "attest") != (renewal_of is None):
                raise Rejected("Explicit result exchange required")
            if (mode == "attest" and rows) or (mode == "renew" and (not rows or rows[-1]["envelope"] is None or sha(bytes(rows[-1]["envelope"])) != renewal_of)):
                raise CapturePending("Resume the exact retained result selector")
            if len(rows) >= MAX_HISTORY:
                raise Rejected("Result history capacity exhausted")
            selector = metadata({"schema":"frank.result-capture-selector.v1","capture_id":row["capture_id"],"renewal_of":renewal_of})
            db.execute("INSERT INTO local_review_exchange VALUES (?,?,?,?,NULL)", (row["capture_id"],sha(selector),selector,mode))
            return {"capture_id":row["capture_id"],"selector_sha256":sha(selector),"selector":selector,"mode":mode,"envelope":None}

    def exchange_completed(self, work, exchange, envelope):
        if len(envelope) > 700_000:
            raise Rejected("Result envelope exceeds bound")
        row = self.retained(work)
        with self._connection() as db:
            old = db.execute("SELECT * FROM local_review_exchange WHERE capture_id=? AND selector_sha256=?", (row["capture_id"],exchange["selector_sha256"])).fetchone()
            if old is None or bytes(old["selector"]) != bytes(exchange["selector"]) or (old["envelope"] is not None and bytes(old["envelope"]) != envelope):
                raise Rejected("Result exchange output changed")
            db.execute("UPDATE local_review_exchange SET envelope=? WHERE capture_id=? AND selector_sha256=?", (envelope,row["capture_id"],exchange["selector_sha256"]))


class ObservationRecorder:
    def __init__(self, capture, work):
        self.owner, self.work = capture, canonical(work)
        self.observations, self.bytes = [], 0

    def add(self, kind, input_raw, output_raw):
        if kind not in KINDS or len(self.observations) >= 128:
            raise Rejected("Local-review observation bound")
        pins = []
        for raw in (input_raw, output_raw):
            if raw is None:
                pins.append(None)
                continue
            if type(raw) is not bytes or len(raw) > MAX_BLOB:
                raise Rejected("Local-review evidence blob exceeds bound")
            self.bytes += len(raw)
            if self.bytes > MAX_TRACE:
                raise Rejected("Local-review trace exceeds bound")
            pin = sha(raw)
            exact_file(self.owner.blobs / pin, raw)
            pins.append(pin)
        if pins == [None,None]:
            raise Rejected("Observation requires actual bytes")
        reference = pins[1] or pins[0]
        length = len(output_raw if output_raw is not None else input_raw)
        observation = {"kind":kind,"input_sha256":pins[0],"output_sha256":pins[1],"byte_length":length,"reference":reference}
        metadata({"observations":[*self.observations,observation]})
        self.observations.append(observation)
        sync_directory(self.owner.blobs)

    def wrap(self, ports):
        recorder = self
        class Port:
            effects_disabled = True
            def __init__(self, delegate, methods):
                self.delegate, self.methods = delegate, methods
            def __getattr__(self, name):
                kind = self.methods[name]
                async def call(*args):
                    input_raw = (args[0] if name in {"write","transcribe"} else canonical(args[0]) if name == "check" else canonical(list(args)))
                    output = await getattr(self.delegate,name)(*args)
                    output_raw = output if isinstance(output,bytes) else canonical(output)
                    import asyncio
                    await asyncio.to_thread(recorder.add,kind,input_raw,output_raw)
                    return decode_json(canonical(output)) if not isinstance(output,bytes) else bytes(output)
                return call
        return ReviewPorts(Port(ports.artifacts,{"read":"artifact-read","write":"artifact-write"}),
            Port(ports.stt,{"transcribe":"provider-response"}),Port(ports.components,{"resolve":"component-snapshot-read"}),
            Port(ports.sources,{"inspect":"source-snapshot-read"}),Port(ports.intents,{"record":"simulated-intent"}),
            Port(ports.claims,{"check":"claim-check"}),ports.results)
