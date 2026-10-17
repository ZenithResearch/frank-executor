"""Frank-owned delivery evidence only. Never open the runtime database here."""

from __future__ import annotations
import json
import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from .model import Rejected, canonical, digest, validate_result

APP_ID = 0x46524E4B


class Journal:
    def __init__(self, path):
        self.path = str(path)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        if Path(path).exists():
            # Check identity read-only before configuring WAL or touching a foreign store.
            probe = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True)
            try:
                app = probe.execute("PRAGMA application_id").fetchone()[0]
                tables = probe.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
                if app != APP_ID and (app != 0 or tables):
                    raise Rejected("Database belongs to another component")
            finally:
                probe.close()
        with self.connection() as db:
            app = db.execute("PRAGMA application_id").fetchone()[0]
            tables = db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            if app != APP_ID and (app != 0 or tables):
                raise Rejected("Database belongs to another component")
            db.execute(f"PRAGMA application_id={APP_ID}")
            db.execute("BEGIN IMMEDIATE")
            statements = """
            CREATE TABLE IF NOT EXISTS commands(request_id TEXT PRIMARY KEY,body TEXT NOT NULL,digest TEXT NOT NULL,state TEXT NOT NULL,response TEXT);
            CREATE TABLE IF NOT EXISTS deliveries(effect_key TEXT PRIMARY KEY,work TEXT NOT NULL,digest TEXT NOT NULL,state TEXT NOT NULL,result TEXT);
            CREATE TABLE IF NOT EXISTS events(integration_id TEXT NOT NULL,event_id TEXT NOT NULL,digest TEXT NOT NULL,PRIMARY KEY(integration_id,event_id));
            CREATE TABLE IF NOT EXISTS cursors(integration_id TEXT PRIMARY KEY,cursor TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS native_result_identity(effect_key TEXT PRIMARY KEY,identity TEXT NOT NULL,work_sha256 TEXT NOT NULL,integration_id TEXT NOT NULL,event_id TEXT NOT NULL,unsigned_result TEXT NOT NULL,UNIQUE(integration_id,event_id));
            CREATE TABLE IF NOT EXISTS native_result_proofs(id INTEGER PRIMARY KEY AUTOINCREMENT,effect_key TEXT NOT NULL,identity TEXT NOT NULL,work_sha256 TEXT NOT NULL,proof_sha256 TEXT NOT NULL,proof TEXT NOT NULL,replay_digest TEXT NOT NULL,UNIQUE(effect_key,proof_sha256,replay_digest));
            CREATE TABLE IF NOT EXISTS native_result_replay(subject TEXT NOT NULL,session TEXT NOT NULL,opcode INTEGER NOT NULL,nonce TEXT NOT NULL,binding_digest TEXT NOT NULL,effect_key TEXT NOT NULL,identity TEXT NOT NULL,work_sha256 TEXT NOT NULL,proof_sha256 TEXT NOT NULL,replay_digest TEXT NOT NULL,PRIMARY KEY(subject,session,opcode,nonce));
            CREATE TABLE IF NOT EXISTS native_result_dispatch(id INTEGER PRIMARY KEY AUTOINCREMENT,effect_key TEXT NOT NULL,identity TEXT NOT NULL,command_request_id TEXT NOT NULL,command_digest TEXT NOT NULL,proof_sha256 TEXT NOT NULL,replay_digest TEXT NOT NULL,policy_sha256 TEXT,admitted_at_ms INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS connector_dispatch(effect_key TEXT PRIMARY KEY,work_sha256 TEXT NOT NULL,policy TEXT NOT NULL,prompt_sha256 TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS connector_captures(effect_key TEXT PRIMARY KEY,work_sha256 TEXT NOT NULL,policy TEXT NOT NULL,body TEXT NOT NULL,body_sha256 TEXT NOT NULL,payload_sha256 TEXT NOT NULL,resource TEXT NOT NULL,provenance TEXT NOT NULL,provenance_sha256 TEXT NOT NULL,original TEXT NOT NULL,original_sha256 TEXT NOT NULL,integration_id TEXT NOT NULL,event_id TEXT NOT NULL,UNIQUE(integration_id,event_id));
            CREATE TABLE IF NOT EXISTS connector_rejected_ingress(effect_key TEXT PRIMARY KEY,work_sha256 TEXT NOT NULL,policy TEXT NOT NULL,body TEXT NOT NULL,provenance TEXT NOT NULL,original TEXT NOT NULL);
            """
            for statement in statements.split(";"):
                if statement.strip():
                    db.execute(statement)
        os.chmod(path, 0o600)

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        try:
            with db:
                yield db
        finally:
            db.close()

    def command(self, envelope):
        body = canonical(envelope).decode()
        hashed = digest(envelope)
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM commands WHERE request_id=?", (envelope["request_id"],)
            ).fetchone()
            if row and row["digest"] != hashed:
                raise Rejected("Command key reused with different bytes")
            if row:
                return dict(row)
            db.execute(
                "INSERT INTO commands VALUES (?,?,?,'pending',NULL)",
                (envelope["request_id"], body, hashed),
            )
        return {"body": body, "state": "pending", "response": None}

    def command_result(self, request_id, response):
        with self.connection() as db:
            db.execute(
                "UPDATE commands SET state='observed',response=? WHERE request_id=?",
                (canonical(response).decode(), request_id),
            )

    def saved_command(self, request_id):
        with self.connection() as db:
            row = db.execute("SELECT * FROM commands WHERE request_id=?", (request_id,)).fetchone()
            if not row:
                raise Rejected("Unknown command request")
            return dict(row)

    def delivery(self, key, work):
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM deliveries WHERE effect_key=?", (key,)).fetchone()
            if row and row["digest"] != digest(work):
                raise Rejected("Effect key reused with different intent")
            if not row:
                db.execute(
                    "INSERT INTO deliveries VALUES (?,?,?,'intent',NULL)",
                    (key, canonical(work).decode(), digest(work)),
                )
        return self.get(key)

    def get(self, key):
        with self.connection() as db:
            row = db.execute("SELECT * FROM deliveries WHERE effect_key=?", (key,)).fetchone()
            if not row:
                raise Rejected("Unknown effect")
            work = json.loads(row["work"])
            if digest(work) != row["digest"]:
                raise Rejected("Retained delivery digest mismatch")
            result = json.loads(row["result"]) if row["result"] else None
            native = db.execute(
                "SELECT * FROM native_result_identity WHERE effect_key=?", (key,)
            ).fetchone()
            if native:
                if (
                    result is None
                    or self._unsigned_digest(result) != native["identity"]
                    or row["digest"] != native["work_sha256"]
                ):
                    raise Rejected("Retained native result identity mismatch")
                proof = db.execute(
                    "SELECT proof FROM native_result_proofs WHERE effect_key=? ORDER BY id DESC LIMIT 1",
                    (key,),
                ).fetchone()
                if proof is None:
                    raise Rejected("Native result has no retained proof")
                result = {**result, "proof": json.loads(proof["proof"])}
            return {**dict(row), "work": work, "result": result}

    def begin_dispatch(self, key):
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            return (
                db.execute(
                    "UPDATE deliveries SET state='unknown' WHERE effect_key=? AND state='intent'",
                    (key,),
                ).rowcount
                == 1
            )

    def seen_event(self, result):
        with self.connection() as db:
            row = db.execute(
                "SELECT digest FROM events WHERE integration_id=? AND event_id=?",
                (result["integration_id"], result["event_id"]),
            ).fetchone()
            if row and row["digest"] != digest(result):
                raise Rejected("Replayed event changed its content")
            return row is not None

    def observation(self, key, result, *, admission=None):
        result = json.loads(canonical(result))
        if admission is not None:
            with self.connection() as db:
                db.execute("BEGIN IMMEDIATE")
                return self._native_admit(db, key, result, admission, initial=True)
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute(
                "SELECT 1 FROM native_result_identity WHERE effect_key=?", (key,)
            ).fetchone():
                raise Rejected("Native result requires trusted admission")
            return self._legacy_observation(db, key, result)

    def _legacy_observation(self, db, key, result):
        row = db.execute(
            "SELECT * FROM events WHERE integration_id=? AND event_id=?",
            (result["integration_id"], result["event_id"]),
        ).fetchone()
        if row:
            if row["digest"] != digest(result):
                raise Rejected("Replayed event changed its content")
            return False
        delivery = db.execute("SELECT state FROM deliveries WHERE effect_key=?", (key,)).fetchone()
        if not delivery or delivery["state"] not in {"unknown", "acknowledged"}:
            raise Rejected("Effect outcome is immutable")
        db.execute(
            "INSERT INTO events VALUES (?,?,?)",
            (result["integration_id"], result["event_id"], digest(result)),
        )
        db.execute(
            "UPDATE deliveries SET state=?,result=? WHERE effect_key=?",
            (result["outcome"], canonical(result).decode(), key),
        )
        return True

    def committed(self, key):
        with self.connection() as db:
            if (
                db.execute(
                    "UPDATE deliveries SET state='committed' WHERE effect_key=? AND state='succeeded'",
                    (key,),
                ).rowcount
                != 1
            ):
                raise Rejected("Only observed successful effects can commit")

    def failed_committed(self, key):
        with self.connection() as db:
            if (
                db.execute(
                    "UPDATE deliveries SET state='failed_committed' WHERE effect_key=? AND state='failed'",
                    (key,),
                ).rowcount
                != 1
            ):
                raise Rejected("Only verified failed effects can finish failure reconciliation")

    def unresolved(self):
        with self.connection() as db:
            return [
                dict(row)
                for row in db.execute(
                    "SELECT effect_key,state FROM deliveries WHERE state NOT IN ('committed','failed_committed') ORDER BY effect_key"
                )
            ]

    def cursor(self, integration_id, new=None, *, admissions=()):
        admissions = tuple(
            (key, json.loads(canonical(result)), admission) for key, result, admission in admissions
        )
        with self.connection() as db:
            if new is not None:
                db.execute("BEGIN IMMEDIATE")
                checked = []
                for key, result, admission in admissions:
                    self._native_admit(db, key, result, admission, initial=False)
                    retained = db.execute(
                        "SELECT work FROM deliveries WHERE effect_key=?", (key,)
                    ).fetchone()
                    checked.append((result, json.loads(retained["work"]), admission))
                if checked:
                    # Later policy/helper I/O can outlive an earlier proof. Finish all
                    # blocking validation before the shared, no-I/O page admission pass.
                    now = max(admission.current_time() for _, _, admission in checked)
                    for result, work, admission in checked:
                        admission.revalidate_window(result, work, now)
                db.execute(
                    "INSERT INTO cursors VALUES (?,?) ON CONFLICT(integration_id) DO UPDATE SET cursor=excluded.cursor",
                    (integration_id, new),
                )
            row = db.execute(
                "SELECT cursor FROM cursors WHERE integration_id=?", (integration_id,)
            ).fetchone()
            return row["cursor"] if row else None

    def pending_commands(self):
        with self.connection() as db:
            return [
                {
                    "request_id": row["request_id"],
                    "operation": json.loads(row["body"])["operation"],
                    "state": row["state"],
                }
                for row in db.execute(
                    "SELECT request_id,body,state FROM commands WHERE state!='observed' ORDER BY rowid"
                )
            ]

    def for_result(self, result):
        with self.connection() as db:
            rows = db.execute(
                "SELECT effect_key FROM deliveries WHERE json_extract(work,'$.integration_id')=? AND json_extract(work,'$.effect_id')=?",
                (result.get("integration_id"), result.get("effect_id")),
            ).fetchall()
            if len(rows) != 1:
                raise Rejected("Result has no unique retained delivery")
            return self.get(rows[0]["effect_key"])

    @staticmethod
    def _unsigned_digest(result):
        return digest({key: value for key, value in result.items() if key != "proof"})

    def is_native(self, key):
        with self.connection() as db:
            return (
                db.execute(
                    "SELECT 1 FROM native_result_identity WHERE effect_key=?", (key,)
                ).fetchone()
                is not None
            )

    def result_digest(self, key, result):
        with self.connection() as db:
            row = db.execute(
                "SELECT * FROM native_result_identity WHERE effect_key=?", (key,)
            ).fetchone()
            if row is None:
                return digest(result)
            if (
                self._unsigned_digest(result) != row["identity"]
                or result.get("integration_id") != row["integration_id"]
                or result.get("event_id") != row["event_id"]
            ):
                raise Rejected("Native result body changed")
            return row["identity"]

    def reauthorize(self, key, result, admission, command=None):
        # Freeze before lock acquisition; the verifier token is an internal immutable object.
        result = json.loads(canonical(result))
        command = json.loads(canonical(command)) if command is not None else None
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            return self._native_admit(db, key, result, admission, initial=False, command=command)

    def _native_admit(self, db, key, result, admission, *, initial, command=None):
        from .native_results import NativeResultAdmission

        if type(admission) is not NativeResultAdmission:
            raise Rejected("Native result requires a trusted verifier admission")
        delivery = db.execute("SELECT * FROM deliveries WHERE effect_key=?", (key,)).fetchone()
        if delivery is None:
            raise Rejected("Unknown effect")
        work = json.loads(delivery["work"])
        if digest(work) != delivery["digest"]:
            raise Rejected("Retained delivery digest mismatch")
        validate_result(result, work)
        if result["outcome"] not in {"succeeded", "failed"}:
            raise Rejected("Native admission requires a terminal result")
        unsigned = {name: value for name, value in result.items() if name != "proof"}
        identity = digest(unsigned)
        work_digest = digest(work)
        proof = admission.proof
        if (
            admission.identity != identity
            or admission.work_sha256 != work_digest
            or canonical(proof) != canonical(result.get("proof"))
        ):
            raise Rejected("Native admission binding mismatch")
        native = db.execute(
            "SELECT * FROM native_result_identity WHERE effect_key=?", (key,)
        ).fetchone()
        event = db.execute(
            "SELECT * FROM events WHERE integration_id=? AND event_id=?",
            (result["integration_id"], result["event_id"]),
        ).fetchone()
        if native:
            if any(
                native[field] != value
                for field, value in {
                    "identity": identity,
                    "work_sha256": work_digest,
                    "integration_id": result["integration_id"],
                    "event_id": result["event_id"],
                    "unsigned_result": canonical(unsigned).decode(),
                }.items()
            ):
                raise Rejected("Native result identity is immutable")
            retained = json.loads(delivery["result"]) if delivery["result"] else None
            if (
                retained is None
                or self._unsigned_digest(retained) != identity
                or event is None
                or event["digest"] != digest(retained)
            ):
                raise Rejected("Native retained result/event evidence mismatch")
            valid_states = (
                {"succeeded", "committed"}
                if result["outcome"] == "succeeded"
                else {"failed", "failed_committed"}
            )
            if delivery["state"] not in valid_states:
                raise Rejected("Native terminal state mismatch")
        else:
            if not initial:
                raise Rejected("Reauthorization cannot upgrade legacy evidence")
            if event is not None or delivery["state"] not in {"unknown", "acknowledged"}:
                raise Rejected("Native admission cannot replace legacy or terminal evidence")
            if db.execute(
                "SELECT 1 FROM native_result_identity WHERE integration_id=? AND event_id=?",
                (result["integration_id"], result["event_id"]),
            ).fetchone():
                raise Rejected("Native transport event belongs to another effect")
        # This runs after BEGIN IMMEDIATE, including any writer wait.
        admission.revalidate(result, work)
        replay = admission.replay_key
        if (
            not isinstance(replay, tuple)
            or len(replay) != 4
            or not isinstance(replay[0], str)
            or not replay[0]
            or not isinstance(replay[1], str)
            or len(replay[1]) != 32
            or type(replay[2]) is not int
            or not isinstance(replay[3], str)
            or len(replay[3]) != 24
        ):
            raise Rejected("Native replay binding is malformed")
        proof_digest = digest(proof)
        replay_digest = admission.replay_digest
        binding_digest = digest(
            {
                "effect_key": key,
                "identity": identity,
                "work_sha256": work_digest,
                "proof_sha256": proof_digest,
                "replay_digest": replay_digest,
                "replay_key": list(replay),
            }
        )
        previous = db.execute(
            "SELECT binding_digest FROM native_result_replay WHERE subject=? AND session=? AND opcode=? AND nonce=?",
            replay,
        ).fetchone()
        if previous and previous["binding_digest"] != binding_digest:
            raise Rejected("Native replay key changed its binding")
        if command is not None:
            self._validate_native_command(db, command, work, result, identity)
        if not previous:
            db.execute(
                "INSERT INTO native_result_replay VALUES (?,?,?,?,?,?,?,?,?,?)",
                (*replay, binding_digest, key, identity, work_digest, proof_digest, replay_digest),
            )
        if native is None:
            db.execute(
                "INSERT INTO native_result_identity VALUES (?,?,?,?,?,?)",
                (
                    key,
                    identity,
                    work_digest,
                    result["integration_id"],
                    result["event_id"],
                    canonical(unsigned).decode(),
                ),
            )
        db.execute(
            "INSERT OR IGNORE INTO native_result_proofs(effect_key,identity,work_sha256,proof_sha256,proof,replay_digest) VALUES (?,?,?,?,?,?)",
            (key, identity, work_digest, proof_digest, canonical(proof).decode(), replay_digest),
        )
        if native is None:
            db.execute(
                "INSERT INTO events VALUES (?,?,?)",
                (result["integration_id"], result["event_id"], digest(result)),
            )
            db.execute(
                "UPDATE deliveries SET state=?,result=? WHERE effect_key=?",
                (result["outcome"], canonical(result).decode(), key),
            )
        if command is not None:
            db.execute(
                "INSERT INTO native_result_dispatch(effect_key,identity,command_request_id,command_digest,proof_sha256,replay_digest,policy_sha256,admitted_at_ms) VALUES (?,?,?,?,?,?,?,?)",
                (
                    key,
                    identity,
                    command["request_id"],
                    digest(command),
                    proof_digest,
                    replay_digest,
                    admission.policy_sha256,
                    time.time_ns() // 1_000_000,
                ),
            )
        # Keep the commit authorization current even if local evidence writes were delayed.
        admission.revalidate(result, work)
        return native is None

    @staticmethod
    def _validate_native_command(db, command, work, result, identity):
        saved = db.execute(
            "SELECT * FROM commands WHERE request_id=?", (command.get("request_id"),)
        ).fetchone()
        if (
            saved is None
            or saved["digest"] != digest(command)
            or saved["body"] != canonical(command).decode()
        ):
            raise Rejected("Native dispatch requires the exact retained command")
        payload = command.get("payload", {})
        if any(payload.get(key) != value for key, value in work["binding"].items()):
            raise Rejected("Native command belongs to another attempt")
        operation = command.get("operation")
        if operation == "executor.complete":
            valid = result["outcome"] == "succeeded" and canonical(
                payload.get("outputs")
            ) == canonical(result["outputs"])
        elif operation == "executor.fail":
            valid = result["outcome"] == "failed"
        elif operation == "executor.effect.observe":
            valid = all(
                payload.get(key) == value
                for key, value in {
                    "effect_id": work["effect_id"],
                    "provider_reference": result["provider_reference"],
                    "outcome": result["outcome"],
                    "observation_digest": identity,
                }.items()
            )
        else:
            valid = False
        if not valid:
            raise Rejected("Native command does not match admitted result")

    def command_requires_admission(self, command):
        if command.get("operation") not in {
            "executor.complete",
            "executor.fail",
            "executor.effect.observe",
        }:
            return False
        payload = command.get("payload", {})
        with self.connection() as db:
            rows = db.execute(
                "SELECT d.work FROM native_result_identity n JOIN deliveries d ON d.effect_key=n.effect_key"
            ).fetchall()
            for row in rows:
                work = json.loads(row["work"])
                if all(payload.get(key) == value for key, value in work["binding"].items()):
                    if (
                        command["operation"] != "executor.effect.observe"
                        or payload.get("effect_id") == work["effect_id"]
                    ):
                        return True
        return False
