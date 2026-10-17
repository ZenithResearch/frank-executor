"""Frank-owned verification and immutable admission. No signing or key custody.

A native signature authenticates a qualified issuer's assertion; this port does
not rerun original caller evidence. The installed issuer and result producer must
qualify separately. This library deliberately remains production-unqualified.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, field
import hashlib
import json
import math
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import time
from typing import Callable

from .model import Binding, Rejected, canonical, decode_json, digest, identity, validate_result

AUDIENCE = "frank://result-receiver"
OPERATION = "frank.result.attest.v1"
MAX_PAYLOAD = 262144
MAX_OUTPUT = 131072
CTX_FIELDS = frozenset(
    (
        "schema_version",
        "context_id",
        "packet_hash",
        "session_id",
        "nonce",
        "opcode",
        "operation",
        "resource",
        "subject",
        "audience",
        "evidence_summary",
        "proof_metadata",
        "capability_result",
        "credential_result",
        "issued_at",
        "expires_at",
        "descriptor_fingerprint",
        "replay_scope",
        "handler_id",
    )
)


def _reject():
    return Rejected("Native result authority rejected")


def _hex(value, length=None):
    return (
        type(value) is str
        and bool(value)
        and len(value) % 2 == 0
        and re.fullmatch("[a-f0-9]+", value) is not None
        and (length is None or len(value) == length)
    )


def _now(value):
    if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
        raise _reject()
    return value


def _window(start, end):
    return type(start) is int and type(end) is int and 0 <= start < end


def _bytes(value, size):
    if (
        type(value) is not list
        or len(value) != size
        or any(type(x) is not int or not 0 <= x <= 255 for x in value)
    ):
        raise _reject()
    return bytes(value)


def unsigned_result(result):
    if type(result) is not dict:
        raise _reject()
    return {k: v for k, v in result.items() if k != "proof"}


def payload_for(result, work):
    fields = {
        "schema",
        "binding",
        "actor_id",
        "integration_id",
        "route",
        "effect_id",
        "operation",
        "scope",
        "inputs",
        "output_types",
    }
    if type(work) is not dict or set(work) != fields or work["schema"] != "frank.work.v1":
        raise _reject()
    Binding.read(work["binding"])
    for key in ("actor_id", "integration_id", "route", "effect_id", "operation"):
        identity(work[key])
    if (
        type(work["scope"]) is not str
        or not 1 <= len(work["scope"]) <= 4096
        or type(work["inputs"]) is not dict
        or type(work["output_types"]) is not dict
    ):
        raise _reject()
    validate_result(result, work)
    if result["outcome"] not in {"succeeded", "failed"}:
        raise _reject()
    data = canonical(
        {
            "schema": "frank.native-result-payload.v1",
            "work_sha256": digest(work),
            "result": unsigned_result(result),
        }
    )
    if len(data) > MAX_PAYLOAD:
        raise _reject()
    return data


def resource_for(work):
    b = Binding.read(work["binding"])
    return f"runs/{b.run_id}/steps/{b.step_id}/attempts/{b.attempt_id}/effects/{identity(work['effect_id'])}"


@dataclass(frozen=True)
class VerifierKey:
    key_id: str
    public_key_hex: str
    status: str = "active"
    production_authority: bool = True
    not_before: int | None = None
    not_after: int | None = None
    revoked_at: int | None = None

    def __post_init__(self):
        identity(self.key_id)
        if (
            not _hex(self.public_key_hex, 64)
            or self.status not in {"active", "revoked", "expired"}
            or type(self.production_authority) is not bool
        ):
            raise _reject()
        for x in (self.not_before, self.not_after, self.revoked_at):
            if x is not None and (type(x) is not int or x < 0):
                raise _reject()
        if (
            self.not_before is not None
            and self.not_after is not None
            and self.not_before >= self.not_after
        ):
            raise _reject()


@dataclass(frozen=True)
class Descriptor:
    opcode: int
    fingerprint: str
    handler_id: str

    def __post_init__(self):
        if (
            type(self.opcode) is not int
            or not 64 <= self.opcode <= 255
            or not _hex(self.fingerprint, 64)
        ):
            raise _reject()
        identity(self.handler_id)


@dataclass(frozen=True)
class SubjectBinding:
    subject_id: str
    key_id: str
    actor_id: str
    integration_id: str
    route: str

    def __post_init__(self):
        for x in (self.subject_id, self.key_id, self.actor_id, self.integration_id, self.route):
            identity(x)


@dataclass(frozen=True)
class PermissionRule:
    subject_id: str
    resource: str
    effect: str
    not_before_ms: int
    not_after_ms: int
    resource_match: str = "exact"
    key_id: str | None = None
    active: bool = True

    def __post_init__(self):
        identity(self.subject_id)
        if self.key_id is not None:
            identity(self.key_id)
        if (
            type(self.resource) is not str
            or not 1 <= len(self.resource) <= 4096
            or "*" in self.resource
            or any(ord(c) < 32 for c in self.resource)
            or self.effect not in {"allow", "deny"}
            or self.resource_match not in {"exact", "prefix"}
            or (self.resource_match == "prefix" and not self.resource.endswith("/"))
            or not _window(self.not_before_ms, self.not_after_ms)
            or type(self.active) is not bool
        ):
            raise _reject()


@dataclass(frozen=True)
class ReceiverPolicy:
    keys: tuple[VerifierKey, ...]
    descriptor: Descriptor
    subjects: tuple[SubjectBinding, ...]
    rules: tuple[PermissionRule, ...]
    revoked_subject_keys: frozenset[tuple[str, str]] = frozenset()

    def __post_init__(self):
        for values, kind, limit in (
            (self.keys, VerifierKey, 32),
            (self.subjects, SubjectBinding, 1024),
            (self.rules, PermissionRule, 4096),
        ):
            if (
                type(values) is not tuple
                or len(values) > limit
                or not all(isinstance(x, kind) for x in values)
            ):
                raise _reject()
        if (
            not self.keys
            or not self.subjects
            or not isinstance(self.descriptor, Descriptor)
            or len({k.key_id for k in self.keys}) != len(self.keys)
            or len(set(self.subjects)) != len(self.subjects)
            or type(self.revoked_subject_keys) is not frozenset
            or len(self.revoked_subject_keys) > 4096
        ):
            raise _reject()
        for pair in self.revoked_subject_keys:
            if type(pair) is not tuple or len(pair) != 2:
                raise _reject()
            for x in pair:
                identity(x)

    def snapshot(self):
        return {
            "schema": "frank.result-receiver-policy.v1",
            "audience": AUDIENCE,
            "operation": OPERATION,
            "keys": [asdict(x) for x in self.keys],
            "descriptor": asdict(self.descriptor),
            "subjects": [asdict(x) for x in self.subjects],
            "rules": [asdict(x) for x in self.rules],
            "revoked_subject_keys": [list(x) for x in sorted(self.revoked_subject_keys)],
        }

    def require(self, c, signer_id, work, now):
        now = _now(now)
        if type(c) is not dict or set(c) != CTX_FIELDS:
            raise _reject()
        if (
            type(c["schema_version"]) is not int
            or c["schema_version"] != 4
            or c["audience"] != AUDIENCE
            or c["operation"] != OPERATION
            or c["resource"] != resource_for(work)
            or type(c["opcode"]) is not int
            or c["opcode"] != self.descriptor.opcode
            or c["descriptor_fingerprint"] != self.descriptor.fingerprint
            or c["handler_id"] != self.descriptor.handler_id
            or c["replay_scope"] != "session:opcode:nonce"
            or not _window(c["issued_at"], c["expires_at"])
            or not c["issued_at"] <= now < c["expires_at"]
            or c["expires_at"] - c["issued_at"] > 60
        ):
            raise _reject()
        identity(c["context_id"])
        _bytes(c["packet_hash"], 32)
        _bytes(c["session_id"], 16)
        _bytes(c["nonce"], 12)
        if type(c["subject"]) is not dict or set(c["subject"]) != {"subject_id", "key_id"}:
            raise _reject()
        subject, key = c["subject"]["subject_id"], c["subject"]["key_id"]
        identity(subject)
        identity(key)
        if (subject, key) in self.revoked_subject_keys or not any(
            (b.subject_id, b.key_id, b.actor_id, b.integration_id, b.route)
            == (subject, key, work["actor_id"], work["integration_id"], work["route"])
            for b in self.subjects
        ):
            raise _reject()
        for name in ("capability_result", "credential_result"):
            if type(c[name]) is not str or not 1 <= len(c[name]) <= 4096:
                raise _reject()
        if (
            type(c["evidence_summary"]) is not list
            or len(c["evidence_summary"]) > 128
            or any(type(x) is not str or len(x) > 4096 for x in c["evidence_summary"])
        ):
            raise _reject()
        signer = next((k for k in self.keys if k.key_id == signer_id), None)
        if (
            signer is None
            or signer.status != "active"
            or not signer.production_authority
            or (signer.not_before is not None and now < signer.not_before)
            or (signer.not_after is not None and now >= signer.not_after)
            or (signer.revoked_at is not None and now >= signer.revoked_at)
        ):
            raise _reject()
        matching = [
            r
            for r in self.rules
            if r.active
            and r.subject_id == subject
            and (r.key_id is None or r.key_id == key)
            and r.not_before_ms <= now * 1000 < r.not_after_ms
            and (
                r.resource == c["resource"]
                if r.resource_match == "exact"
                else c["resource"].startswith(r.resource)
            )
        ]
        if not any(r.effect == "allow" for r in matching) or any(
            r.effect == "deny" for r in matching
        ):
            raise _reject()
        return signer


class NativeSecSHelper:
    """Bounded pinned verifier process; exposes no signing/key interface."""

    def __init__(self, executable, sha256, *, timeout=5):
        self.executable = Path(executable)
        self.sha256 = sha256
        self.timeout = timeout
        if (
            not self.executable.is_absolute()
            or not _hex(sha256, 64)
            or type(timeout) not in (int, float)
            or not math.isfinite(timeout)
            or not 0.05 <= timeout <= 5
        ):
            raise _reject()

    def check_available(self):
        try:
            for p in (self.executable, *self.executable.parents):
                info = p.lstat()
                if stat.S_ISLNK(info.st_mode):
                    raise _reject()
                if p != self.executable:
                    sticky = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
                    if (
                        not stat.S_ISDIR(info.st_mode)
                        or info.st_uid not in (0, os.getuid())
                        or (info.st_mode & 0o022 and not sticky)
                    ):
                        raise _reject()
            fd = os.open(self.executable, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                info = os.fstat(fd)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid not in (0, os.getuid())
                    or info.st_mode & 0o022
                    or not info.st_mode & 0o111
                    or info.st_nlink != 1
                    or not 0 < info.st_size <= 67108864
                ):
                    raise _reject()
                with os.fdopen(fd, "rb", closefd=False) as f:
                    actual = hashlib.file_digest(f, "sha256").hexdigest()
                if actual != self.sha256:
                    raise _reject()
            finally:
                os.close(fd)
        except (OSError, ValueError):
            raise _reject() from None

    @property
    def artifact_binding(self):
        return (str(self.executable), self.sha256, self.timeout)

    def verify(self, value):
        self.check_available()
        process = None
        streams = []
        try:
            data = json.dumps(
                value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
            ).encode()
            if len(data) > 9 * 1024 * 1024:
                raise _reject()
            process = subprocess.Popen(
                [str(self.executable)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={},
                bufsize=0,
            )
            streams = [process.stdin, process.stdout, process.stderr]
            selector = selectors.DefaultSelector()
            deadline = time.monotonic() + self.timeout
            sent = 0
            output = bytearray()
            errors = bytearray()
            with selector:
                for stream, events in (
                    (process.stdin, selectors.EVENT_WRITE),
                    (process.stdout, selectors.EVENT_READ),
                    (process.stderr, selectors.EVENT_READ),
                ):
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, events)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise _reject()
                    for event, _ in selector.select(min(remaining, 0.05)):
                        stream = event.fileobj
                        if stream is process.stdin:
                            sent += os.write(stream.fileno(), data[sent : sent + 8192])
                            if sent == len(data):
                                selector.unregister(stream)
                                stream.close()
                        else:
                            block = os.read(stream.fileno(), 8192)
                            if not block:
                                selector.unregister(stream)
                                stream.close()
                                continue
                            target = output if stream is process.stdout else errors
                            target.extend(block)
                            if len(output) > MAX_OUTPUT or len(errors) > 4096:
                                raise _reject()
                remaining = deadline - time.monotonic()
                if remaining <= 0 or process.wait(timeout=remaining) != 0 or errors:
                    raise _reject()
            self.check_available()
            value = decode_json(bytes(output))
            if (
                type(value) is not dict
                or set(value) != {"schema", "context", "signer_key_id", "authenticator_kind"}
                or value["schema"] != "process-runtime.secs-check-output.v1"
            ):
                raise _reject()
            return value
        except (OSError, ValueError, TypeError, subprocess.SubprocessError):
            raise _reject() from None
        finally:
            if process is not None:
                if process.poll() is None:
                    process.kill()
                process.wait()
            for stream in streams:
                if not stream.closed:
                    stream.close()


@dataclass(frozen=True)
class NativeResultAdmission:
    identity: str
    work_sha256: str
    replay_key: tuple[str, str, int, str]
    replay_digest: str
    policy_sha256: str
    proof_json: str = field(repr=False)
    context_json: str = field(repr=False)
    signer_key_id: str
    _policy: ReceiverPolicy = field(repr=False, compare=False)
    _load_policy: Callable = field(repr=False, compare=False)
    _helper: object = field(repr=False, compare=False)
    _clock: Callable = field(repr=False, compare=False)
    _artifact_binding: object = field(default=None, repr=False, compare=False)

    @property
    def proof(self):
        return decode_json(self.proof_json)

    def current_time(self):
        """Trusted Unix clock sample; no helper or policy I/O."""
        try:
            return _now(self._clock())
        except Exception:
            raise _reject() from None

    def revalidate_window(self, result, work, now):
        """Final page-window pass after full I/O validation in the writer lock.

        This checks the already loaded immutable policy at a shared admission
        instant. It never substitutes for revalidate() or native verification.
        """
        try:
            payload_for(result, work)
            if (
                digest(work) != self.work_sha256
                or digest(unsigned_result(result)) != self.identity
                or canonical(result.get("proof")).decode() != self.proof_json
            ):
                raise _reject()
            self._policy.require(
                decode_json(self.context_json), self.signer_key_id, work, _now(now)
            )
        except Exception:
            raise _reject() from None

    def revalidate(self, result, work):
        try:
            payload_for(result, work)
            if (
                digest(work) != self.work_sha256
                or digest(unsigned_result(result)) != self.identity
                or canonical(result.get("proof")).decode() != self.proof_json
            ):
                raise _reject()
            if (
                self._load_policy() != self._policy
                or getattr(self._helper, "artifact_binding", None) != self._artifact_binding
            ):
                raise _reject()
            self._helper.check_available()
            if self._load_policy() != self._policy:
                raise _reject()
            # Read time after the last potentially blocking policy/artifact load.
            self._policy.require(
                decode_json(self.context_json), self.signer_key_id, work, _now(self._clock())
            )
        except Exception:
            raise _reject() from None


class NativeResultVerifier:
    mode = "native_unqualified"

    def __init__(self, native_helper, load_policy, *, clock=time.time):
        self.helper, self.load_policy, self.clock = native_helper, load_policy, clock

    async def verify(self, result, work):
        # Hashing/process I/O never blocks the executor heartbeat event loop.
        return await asyncio.to_thread(
            self._verify, decode_json(canonical(result)), decode_json(canonical(work))
        )

    def _verify(self, result, work):
        try:
            payload = payload_for(result, work)
            proof = result.get("proof")
            if (
                type(proof) is not dict
                or set(proof) != {"schema", "packet_hex", "signed_context_hex"}
                or proof["schema"] != "frank.secs-result-envelope.v1"
            ):
                raise _reject()
            if (
                not _hex(proof["packet_hex"])
                or len(proof["packet_hex"]) > 2097152
                or not _hex(proof["signed_context_hex"])
                or len(proof["signed_context_hex"]) > 131072
            ):
                raise _reject()
            artifact_binding = getattr(self.helper, "artifact_binding", None)
            policy = self.load_policy()
            if not isinstance(policy, ReceiverPolicy):
                raise _reject()
            output = self.helper.verify(
                {
                    "schema": "process-runtime.secs-check-input.v1",
                    "packet_hex": proof["packet_hex"],
                    "signed_context_hex": proof["signed_context_hex"],
                    "request_hex": payload.hex(),
                    "audience": AUDIENCE,
                    "now_seconds": int(_now(self.clock())),
                    "keys": [asdict(k) for k in policy.keys],
                }
            )
            if (
                type(output) is not dict
                or set(output) != {"schema", "context", "signer_key_id", "authenticator_kind"}
                or output["schema"] != "process-runtime.secs-check-output.v1"
                or output["authenticator_kind"] != "ed25519_node_and_verifier"
            ):
                raise _reject()
            c = output["context"]
            signer = policy.require(c, output["signer_key_id"], work, _now(self.clock()))
            if (
                _bytes(c["packet_hash"], 32)
                != hashlib.sha256(bytes.fromhex(proof["packet_hex"])).digest()
            ):
                raise _reject()
            if self.load_policy() != policy:
                raise _reject()
            body_digest = digest(unsigned_result(result))
            work_digest = digest(work)
            proof_json = canonical(proof).decode()
            context_json = canonical(c).decode()
            subject = c["subject"]
            replay = (
                subject["subject_id"],
                _bytes(c["session_id"], 16).hex(),
                c["opcode"],
                _bytes(c["nonce"], 12).hex(),
            )
            replay_digest = digest(
                {
                    "schema": "frank.native-result-replay.v1",
                    "work_sha256": work_digest,
                    "result_sha256": body_digest,
                    "proof_sha256": digest(proof),
                    "packet_sha256": hashlib.sha256(bytes.fromhex(proof["packet_hex"])).hexdigest(),
                    "context_sha256": hashlib.sha256(
                        bytes.fromhex(proof["signed_context_hex"])
                    ).hexdigest(),
                    "subject_id": subject["subject_id"],
                    "holder_key_id": subject["key_id"],
                    "verifier_key_id": signer.key_id,
                    "verifier_public_key_sha256": hashlib.sha256(
                        bytes.fromhex(signer.public_key_hex)
                    ).hexdigest(),
                }
            )
            token = NativeResultAdmission(
                body_digest,
                work_digest,
                replay,
                replay_digest,
                digest(policy.snapshot()),
                proof_json,
                context_json,
                signer.key_id,
                policy,
                self.load_policy,
                self.helper,
                self.clock,
                artifact_binding,
            )
            token.revalidate(result, work)
            return token
        except Exception:
            raise _reject() from None


class FileReceiverPolicy:
    """Reload closed public pins/policy from private owner-controlled configuration."""

    def __init__(self, path):
        self.path = Path(path)
        if not self.path.is_absolute():
            raise _reject()

    def __call__(self):
        fd = None
        try:
            for path in (self.path, *self.path.parents):
                info = path.lstat()
                if stat.S_ISLNK(info.st_mode):
                    raise _reject()
                if path != self.path:
                    sticky = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
                    if (
                        not stat.S_ISDIR(info.st_mode)
                        or info.st_uid not in (0, os.getuid())
                        or (info.st_mode & 0o022 and not sticky)
                    ):
                        raise _reject()
            info = self.path.parent.lstat()
            if info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise _reject()
            fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_mode & 0o077
                or info.st_nlink != 1
                or not 0 < info.st_size <= 1048576
            ):
                raise _reject()
            with os.fdopen(fd, "rb", closefd=False) as source:
                value = decode_json(source.read(1048577))
            fields = {
                "schema",
                "audience",
                "operation",
                "keys",
                "descriptor",
                "subjects",
                "rules",
                "revoked_subject_keys",
            }
            if (
                type(value) is not dict
                or set(value) != fields
                or value["schema"] != "frank.result-receiver-policy.v1"
                or value["audience"] != AUDIENCE
                or value["operation"] != OPERATION
            ):
                raise _reject()
            for name, maximum in (
                ("keys", 32),
                ("subjects", 1024),
                ("rules", 4096),
                ("revoked_subject_keys", 4096),
            ):
                if type(value[name]) is not list or len(value[name]) > maximum:
                    raise _reject()
            if any(type(p) is not list or len(p) != 2 for p in value["revoked_subject_keys"]):
                raise _reject()
            revoked = frozenset(tuple(p) for p in value["revoked_subject_keys"])
            if len(revoked) != len(value["revoked_subject_keys"]):
                raise _reject()
            return ReceiverPolicy(
                tuple(VerifierKey(**x) for x in value["keys"]),
                Descriptor(**value["descriptor"]),
                tuple(SubjectBinding(**x) for x in value["subjects"]),
                tuple(PermissionRule(**x) for x in value["rules"]),
                revoked,
            )
        except Exception:
            raise _reject() from None
        finally:
            if fd is not None:
                os.close(fd)
