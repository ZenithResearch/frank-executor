"""Unsigned connector observations. No issuer, proof minting or terminal admission.

Only trusted execution composition supplies this route-scoped dependency to a
built-in connector. Persisted JSON is evidence, never a restored trusted token.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
import sqlite3

from .model import Rejected, canonical, decode_json, digest, identity, validate_result
from .native_results import payload_for, resource_for

MAX_METADATA_BYTES = 16_384
MAX_REFERENCE_BYTES = 4_096
MAX_MATRIX_ROOMS = 100
MAX_MATRIX_EVENTS = 1_000
MAX_PAGE_RESULTS = 100
MAX_RESULT_HISTORY = 4
MAX_RESULT_ENVELOPE = 700_000
_HASH = re.compile(r"[a-f0-9]{64}\Z")


class CapturePending(Rejected):
    """Unsigned evidence is retained; no terminal result or cursor may escape."""


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _reference(value):
    if type(value) is not str or not value:
        raise Rejected("Connector reference exceeds bound")
    try:
        raw = value.encode()
    except UnicodeError:
        raise Rejected("Invalid connector reference") from None
    if len(raw) > MAX_REFERENCE_BYTES:
        raise Rejected("Connector reference exceeds bound")
    return value


def _metadata(value):
    raw = canonical(value)
    if len(raw) > MAX_METADATA_BYTES:
        raise Rejected("Connector metadata exceeds bound")
    return raw


@dataclass(frozen=True)
class ConnectorPolicy:
    """Host-selected observation scope; these pins confer no signing authority."""

    kind: str
    integration_id: str
    actor_id: str
    route: str
    configuration_sha256: str
    artifact_sha256: str
    normalization_sha256: str

    def __post_init__(self):
        if type(self.kind) is not str or self.kind not in {"matrix", "hermes"}:
            raise Rejected("Unknown capture connector")
        for value in (self.integration_id, self.actor_id, self.route):
            identity(value)
        for value in (self.configuration_sha256, self.artifact_sha256, self.normalization_sha256):
            if type(value) is not str or _HASH.fullmatch(value) is None:
                raise Rejected("Explicit connector artifact/configuration pins required")

    def bytes(self):
        return _metadata({"kind": self.kind, "integration_id": self.integration_id,
                          "actor_id": self.actor_id, "route": self.route,
                          "configuration_sha256": self.configuration_sha256,
                          "artifact_sha256": self.artifact_sha256,
                          "normalization_sha256": self.normalization_sha256})


@dataclass(frozen=True)
class _PreparedCapture:
    owner: object
    effect_key: str
    work_bytes: bytes
    result_bytes: bytes
    provenance_bytes: bytes
    original_bytes: bytes


class ConnectorCapture:
    """Execution-only host capability for one actor/integration/route.

    This does not accept a native issuer dependency. Its only terminal-facing
    behavior is CapturePending. Future issuer/renewal work needs separate review.
    """

    def __init__(self, journal, policy):
        from .journal import Journal

        if type(journal) is not Journal or type(policy) is not ConnectorPolicy:
            raise Rejected("Trusted journal and connector policy required")
        self.journal, self.policy = journal, policy
        self._owner = object()
        self._policy_bytes = policy.bytes()

    def bind(self, kind, integration_id, configuration):
        self._unchanged_policy()
        if (kind != self.policy.kind or integration_id != self.policy.integration_id
                or digest(configuration) != self.policy.configuration_sha256):
            raise Rejected("Connector configuration changed")
        _metadata(configuration)

    def selected(self, route):
        return route == self.policy.route

    def _unchanged_policy(self):
        if type(self.policy) is not ConnectorPolicy or self.policy.bytes() != self._policy_bytes:
            raise Rejected("Connector capture policy changed")

    def _scope(self, work):
        self._unchanged_policy()
        if any(work.get(name) != getattr(self.policy, name)
               for name in ("integration_id", "actor_id", "route")):
            raise Rejected("Capture is outside configured connector scope")

    def _delivery(self, db, result):
        if type(result) is not dict:
            raise Rejected("Capture requires a correlated object")
        integration_id = identity(result.get("integration_id"))
        effect_id = identity(result.get("effect_id"))
        rows = db.execute(
            "SELECT * FROM deliveries WHERE json_extract(work,'$.integration_id')=? AND json_extract(work,'$.effect_id')=?",
            (integration_id, effect_id),
        ).fetchall()
        if len(rows) != 1:
            raise Rejected("Capture requires one retained delivery")
        row = rows[0]
        work = decode_json(row["work"])
        if digest(work) != row["digest"]:
            raise Rejected("Retained capture work changed")
        self._scope(work)
        return row, work

    def _prepare(self, result, provenance, original):
        # Freeze every source-owned value before the adapter's next await.
        result_bytes, original_bytes = canonical(result), canonical(original)
        provenance_bytes = _metadata(provenance)
        result = json.loads(result_bytes)
        with self.journal.connection() as db:
            row, work = self._delivery(db, result)
            validate_result(result, work)
            work_bytes = canonical(work)
        if "proof" in result:
            self._reject_proved(row["effect_key"], work_bytes, result_bytes,
                                provenance_bytes, original_bytes)
            raise Rejected("Unsigned capture route received proved ingress")
        if result["outcome"] not in {"succeeded", "failed"}:
            return None
        payload_for(result, work)
        return _PreparedCapture(self._owner, row["effect_key"], work_bytes,
                                result_bytes, provenance_bytes, original_bytes)

    def _reject_proved(self, key, work, body, provenance, original):
        values = (key, _sha(work), self._policy_bytes.decode(), body.decode(),
                  provenance.decode(), original.decode())
        with self.journal.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row, current = self._delivery(db, json.loads(body))
            if row["effect_key"] != key or canonical(current) != work:
                raise Rejected("Rejected ingress work changed")
            prior = db.execute("SELECT * FROM connector_rejected_ingress WHERE effect_key=?", (key,)).fetchone()
            if prior and tuple(prior) != values:
                raise Rejected("Rejected ingress evidence is immutable")
            if not prior:
                db.execute("INSERT INTO connector_rejected_ingress VALUES (?,?,?,?,?,?)", values)

    def prepare_matrix(self, result, *, room, event, read_path):
        if self.policy.kind != "matrix" or read_path not in {"sync", "event"}:
            raise Rejected("Invalid Matrix capture path")
        provenance = {"kind": "matrix", "read_path": read_path,
                      "room_id": _reference(room), "sender_id": _reference(event["sender"]),
                      "raw_event_id": _reference(event["event_id"]),
                      "original_sha256": digest(event), "plain_room_policy": "require-absent-encryption-v1"}
        return self._prepare(result, provenance, event)

    def reserve_hermes(self, work, prompt):
        if self.policy.kind != "hermes" or type(prompt) is not str:
            raise Rejected("Invalid Hermes dispatch")
        work_bytes = canonical(work)
        # The bounded prompt is generated from the retained work by this connector.
        if len(prompt.encode()) > 1024 * 1024 + 512:
            raise Rejected("Hermes prompt exceeds bound")
        with self.journal.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row, retained = self._delivery(db, work)
            if canonical(retained) != work_bytes:
                raise Rejected("Hermes dispatch differs from retained work")
            values = (row["effect_key"], _sha(work_bytes), self._policy_bytes.decode(), _sha(prompt.encode()))
            prior = db.execute("SELECT * FROM connector_dispatch WHERE effect_key=?", (row["effect_key"],)).fetchone()
            if prior:
                if tuple(prior) != values:
                    raise Rejected("Hermes dispatch reservation changed")
                return False
            if row["state"] != "unknown" or row["result"] is not None:
                raise Rejected("Hermes dispatch requires retained unknown delivery")
            db.execute("INSERT INTO connector_dispatch VALUES (?,?,?,?)", values)
        return True

    def retain_hermes_response(self, work, prompt, final_response):
        """Retain the exact provider response before any derived Runtime writes.

        The response is owner-private recovery evidence. It is not an admitted
        result and cannot become terminal until normal capture and native result
        verification complete.
        """
        if self.policy.kind != "hermes" or type(prompt) is not str or type(final_response) is not str:
            raise Rejected("Invalid Hermes response")
        if len(final_response.encode()) > 1024 * 1024:
            raise Rejected("Hermes result exceeds bound")
        work_bytes = canonical(work)
        with self.journal.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row, retained = self._delivery(db, work)
            if canonical(retained) != work_bytes:
                raise Rejected("Hermes response differs from retained work")
            marker = db.execute(
                "SELECT * FROM connector_dispatch WHERE effect_key=?", (row["effect_key"],)
            ).fetchone()
            values = (
                row["effect_key"],
                _sha(work_bytes),
                self._policy_bytes.decode(),
                _sha(prompt.encode()),
                final_response,
                _sha(final_response.encode()),
            )
            if (
                marker is None
                or marker["work_sha256"] != values[1]
                or marker["policy"] != values[2]
                or marker["prompt_sha256"] != values[3]
            ):
                raise Rejected("Hermes response has no matching durable dispatch")
            prior = db.execute(
                "SELECT * FROM connector_responses WHERE effect_key=?", (row["effect_key"],)
            ).fetchone()
            if prior:
                if tuple(prior) != values:
                    raise Rejected("Hermes response is immutable")
                return False
            db.execute("INSERT INTO connector_responses VALUES (?,?,?,?,?,?)", values)
        return True

    def hermes_response(self, work, prompt):
        if self.policy.kind != "hermes" or type(prompt) is not str:
            raise Rejected("Invalid Hermes response lookup")
        work_bytes = canonical(work)
        with self.journal.connection() as db:
            row, retained = self._delivery(db, work)
            if canonical(retained) != work_bytes:
                raise Rejected("Hermes response differs from retained work")
            marker = db.execute(
                "SELECT * FROM connector_dispatch WHERE effect_key=?", (row["effect_key"],)
            ).fetchone()
            response = db.execute(
                "SELECT * FROM connector_responses WHERE effect_key=?", (row["effect_key"],)
            ).fetchone()
            if response is None:
                return None
            if (
                marker is None
                or response["work_sha256"] != _sha(work_bytes)
                or response["policy"] != self._policy_bytes.decode()
                or response["prompt_sha256"] != _sha(prompt.encode())
                or marker["work_sha256"] != response["work_sha256"]
                or marker["policy"] != response["policy"]
                or marker["prompt_sha256"] != response["prompt_sha256"]
                or response["response_sha256"] != _sha(response["final_response"].encode())
            ):
                raise Rejected("Retained Hermes response changed")
            return response["final_response"]

    def prepare_hermes(self, result, *, prompt, final_response):
        if self.policy.kind != "hermes" or type(final_response) is not str:
            raise Rejected("Invalid Hermes capture")
        original = {"final_response": final_response}
        provenance = {"kind": "hermes", "session_id": _reference(result["effect_id"]),
                      "task_id": _reference(result["effect_id"]),
                      "prompt_sha256": _sha(prompt.encode()),
                      "final_response_sha256": _sha(final_response.encode()),
                      "outputs_sha256": digest(result["outputs"]),
                      "interruption": "returned-final-response"}
        return self._prepare(result, provenance, original)

    def commit(self, prepared):
        self._unchanged_policy()
        prepared = tuple(prepared)
        if not prepared or len(prepared) > MAX_PAGE_RESULTS:
            raise Rejected("Invalid connector capture batch")
        with self.journal.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            for item in prepared:
                if type(item) is not _PreparedCapture or item.owner is not self._owner:
                    raise Rejected("Capture requires connector-owned preparation")
                result, work = json.loads(item.result_bytes), json.loads(item.work_bytes)
                row, current = self._delivery(db, result)
                if row["effect_key"] != item.effect_key or canonical(current) != item.work_bytes:
                    raise Rejected("Prepared capture work changed")
                validate_result(result, work)
                payload = payload_for(result, work)
                if "proof" in result:
                    raise Rejected("Capture cannot contain proof")
                values = (item.effect_key, _sha(item.work_bytes), self._policy_bytes.decode(),
                          item.result_bytes.decode(), _sha(item.result_bytes), _sha(payload),
                          resource_for(work), item.provenance_bytes.decode(), _sha(item.provenance_bytes),
                          item.original_bytes.decode(), _sha(item.original_bytes),
                          result["integration_id"], result["event_id"])
                prior = db.execute("SELECT * FROM connector_captures WHERE effect_key=?", (item.effect_key,)).fetchone()
                if prior:
                    if tuple(prior) != values:
                        raise Rejected("Connector capture is immutable")
                    continue
                if row["state"] not in {"unknown", "acknowledged"}:
                    raise Rejected("Capture cannot upgrade terminal or legacy evidence")
                if self.policy.kind == "hermes":
                    marker = db.execute("SELECT * FROM connector_dispatch WHERE effect_key=?", (item.effect_key,)).fetchone()
                    provenance = json.loads(item.provenance_bytes)
                    if (marker is None or marker["work_sha256"] != values[1]
                            or marker["policy"] != values[2]
                            or marker["prompt_sha256"] != provenance["prompt_sha256"]):
                        raise Rejected("Hermes capture has no matching durable dispatch")
                try:
                    db.execute("INSERT INTO connector_captures VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", values)
                except sqlite3.IntegrityError:
                    raise Rejected("Connector event belongs to another delivery") from None
        return tuple(item.effect_key for item in prepared)

    def retained(self, work):
        """Read original eligible provenance; never derive eligibility from admission.

        This returns unsigned internal evidence only, not IntegrationAdapter output
        or a proof. No issuer or renewal operation is implemented in this slice.
        """
        work_bytes = canonical(work)
        with self.journal.connection() as db:
            row, current = self._delivery(db, work)
            if canonical(current) != work_bytes:
                raise Rejected("Retained capture work changed")
            capture = db.execute("SELECT * FROM connector_captures WHERE effect_key=?", (row["effect_key"],)).fetchone()
            if capture is None:
                return None
            result = decode_json(capture["body"])
            payload = payload_for(result, current)
            if (capture["work_sha256"] != _sha(work_bytes)
                    or capture["policy"] != self._policy_bytes.decode()
                    or capture["body_sha256"] != digest(result)
                    or capture["payload_sha256"] != _sha(payload)
                    or capture["resource"] != resource_for(current)
                    or "proof" in result):
                raise Rejected("Retained connector evidence changed")
            provenance, original = decode_json(capture["provenance"]), decode_json(capture["original"])
            if (type(provenance) is not dict or type(original) is not dict
                    or _sha(_metadata(provenance)) != capture["provenance_sha256"]
                    or digest(original) != capture["original_sha256"]
                    or capture["integration_id"] != result["integration_id"]
                    or capture["event_id"] != result["event_id"]):
                raise Rejected("Retained connector provenance changed")
            if self.policy.kind == "matrix":
                if provenance.get("original_sha256") != digest(original):
                    raise Rejected("Retained Matrix ingress changed")
            else:
                marker = db.execute("SELECT * FROM connector_dispatch WHERE effect_key=?", (row["effect_key"],)).fetchone()
                response = db.execute("SELECT * FROM connector_responses WHERE effect_key=?", (row["effect_key"],)).fetchone()
                if (marker is None or marker["policy"] != capture["policy"]
                        or marker["work_sha256"] != capture["work_sha256"]
                        or marker["prompt_sha256"] != provenance.get("prompt_sha256")
                        or type(original.get("final_response")) is not str
                        or provenance.get("final_response_sha256") != _sha(original["final_response"].encode())
                        or provenance.get("outputs_sha256") != digest(result["outputs"])):
                    raise Rejected("Retained Hermes provenance changed")
                # Historical captures already retain the exact response in
                # `original`. New captures also require the pre-materialization
                # recovery row without invalidating that existing evidence.
                if response is not None and (
                    response["policy"] != capture["policy"]
                    or response["work_sha256"] != capture["work_sha256"]
                    or response["prompt_sha256"] != marker["prompt_sha256"]
                    or response["final_response"] != original["final_response"]
                    or response["response_sha256"] != provenance["final_response_sha256"]
                ):
                    raise Rejected("Retained Hermes response changed")
            return {"effect_key": row["effect_key"], "state": "unsigned-capture-pending",
                    "body": result, "work": current, "provenance": provenance,
                    "payload": payload, "resource": capture["resource"],
                    "policy_sha256": _sha(self._policy_bytes),
                    "body_sha256": capture["body_sha256"],
                    "provenance_sha256": capture["provenance_sha256"],
                    "original_sha256": capture["original_sha256"]}

    def exchange(self, work, mode=None, renewal_of=None):
        """Select one immutable native attestation exchange for a retained capture.

        Persisting this selector does not grant authority. The native producer must
        independently reopen the selected journal and validate every referenced
        capture byte before issuing an envelope.
        """
        retained = self.retained(work)
        if retained is None:
            raise CapturePending("No retained connector result")
        key = retained["effect_key"]
        with self.journal.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute(
                "SELECT * FROM connector_result_exchange WHERE effect_key=? ORDER BY id",
                (key,),
            ).fetchall()
            if mode is None:
                return dict(rows[-1]) if rows else None
            if mode not in {"attest", "renew"} or (mode == "attest") != (renewal_of is None):
                raise Rejected("Invalid connector result exchange")
            if mode == "attest":
                if rows:
                    raise CapturePending("Use explicit retained-result resume or renewal")
            else:
                if (
                    not rows
                    or rows[-1]["envelope"] is None
                    or _sha(bytes(rows[-1]["envelope"])) != renewal_of
                ):
                    raise CapturePending("Renewal requires the retained completed tip")
            if len(rows) >= MAX_RESULT_HISTORY:
                raise Rejected("Connector result proof history capacity exhausted")
            selector = canonical({
                "schema": "frank.connector-result-selector.v1",
                "effect_key": key,
                "work_sha256": digest(retained["work"]),
                "body_sha256": retained["body_sha256"],
                "payload_sha256": _sha(retained["payload"]),
                "resource": retained["resource"],
                "policy_sha256": retained["policy_sha256"],
                "provenance_sha256": retained["provenance_sha256"],
                "original_sha256": retained["original_sha256"],
                "integration_id": retained["body"]["integration_id"],
                "event_id": retained["body"]["event_id"],
                "renewal_of": renewal_of,
            })
            selector_sha = _sha(selector)
            db.execute(
                "INSERT INTO connector_result_exchange"
                "(effect_key,selector_sha256,selector,mode,renewal_of,envelope) "
                "VALUES (?,?,?,?,?,NULL)",
                (key, selector_sha, selector, mode, renewal_of),
            )
            return dict(db.execute(
                "SELECT * FROM connector_result_exchange WHERE effect_key=? AND selector_sha256=?",
                (key, selector_sha),
            ).fetchone())

    def exchange_completed(self, work, exchange, envelope):
        retained = self.retained(work)
        if retained is None or type(exchange) is not dict:
            raise CapturePending("No retained connector result exchange")
        if type(envelope) is not bytes or not 0 < len(envelope) <= MAX_RESULT_ENVELOPE:
            raise Rejected("Connector result envelope exceeds bound")
        key = retained["effect_key"]
        with self.journal.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM connector_result_exchange WHERE effect_key=? AND selector_sha256=?",
                (key, exchange.get("selector_sha256")),
            ).fetchone()
            if row is None or bytes(row["selector"]) != bytes(exchange.get("selector", b"")):
                raise Rejected("Connector result exchange changed")
            if row["envelope"] is not None:
                if bytes(row["envelope"]) != envelope:
                    raise Rejected("Connector result envelope changed")
                return
            db.execute(
                "UPDATE connector_result_exchange SET envelope=? WHERE id=?",
                (envelope, row["id"]),
            )
