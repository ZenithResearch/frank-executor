from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

import pytest

import frank_executor.brand_approval_cli as approval
from frank_executor.model import Rejected


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def decision_value(approved=True):
    return {
        "schema": "frank.brand-approval-decision.v1",
        "run_id": "handoff-" + "a" * 48,
        "claim": {"run_id": "handoff-" + "a" * 48, "step_id": "human-approval",
                  "attempt_id": "attempt-1", "fence": 1, "step_version": 3,
                  "input_digest": "b" * 64},
        "approved": approved,
        "approval_record": {"content_utf8": "# Approved\n", "media_type": "text/markdown"} if approved else None,
        "reason": "Owner reviewed the exact retained direction.",
        "artifact_request_id": "approval-artifact-1",
        "terminal_request_id": "approval-terminal-1",
    }


def test_decision_is_exact_and_rejection_has_no_approval_artifact(tmp_path, monkeypatch):
    monkeypatch.setattr(approval, "_pinned_file", lambda path, expected, maximum: path.read_bytes())
    selected = tmp_path / "decision.json"
    selected.write_bytes(canonical(decision_value()))
    value = approval.decision(str(selected), sha(selected.read_bytes()), "handoff-" + "a" * 48)
    assert value["claim"]["input_digest"] == "b" * 64
    changed = decision_value(False)
    changed["approval_record"] = {"content_utf8": "wrong", "media_type": "text/markdown"}
    selected.write_bytes(canonical(changed))
    with pytest.raises(Rejected):
        approval.decision(str(selected), sha(selected.read_bytes()), "handoff-" + "a" * 48)


def test_approve_commits_artifact_before_exact_terminal_command(monkeypatch):
    run_id = "handoff-" + "a" * 48
    class Authority:
        async def aclose(self): pass
    monkeypatch.setattr(approval, "load_config", lambda *_: ({"runtime_endpoint": "http://127.0.0.1:8292", "run_id": run_id}, Authority()))
    monkeypatch.setattr(approval, "decision", lambda *_: decision_value())
    monkeypatch.setattr("process_runtime_client.RuntimeClient", lambda _: object())
    async def query(_client, _authority, operation, payload):
        assert operation == "attempt.get"
        return {"run_id": run_id, "step_id": "human-approval", "attempt_id": "attempt-1",
                "fence": 1, "input_digest": "b" * 64, "step_version": 3}
    calls = []
    async def call(_client, _authority, operation, payload, expected_version, request_id):
        calls.append((operation, payload, expected_version, request_id))
        return {"schema": "runtime.result.v1", "operation": operation, "result": {}}
    monkeypatch.setattr(approval, "query", query)
    monkeypatch.setattr(approval, "call", call)
    result = __import__("asyncio").run(approval.run(SimpleNamespace(
        action="decide", config="x", config_sha256="a" * 64,
        decision="d", decision_sha256="c" * 64, request_id=None)))
    assert [row[0] for row in calls] == ["artifact.put", "executor.complete"]
    assert calls[0][3] == "approval-artifact-1"
    assert calls[1][2:] == (3, "approval-terminal-1")
    assert calls[1][1]["outputs"]["approved"] is True
    assert result["decision_sha256"] == "c" * 64


def test_claim_filters_to_exact_run_and_human_step(monkeypatch):
    run_id = "handoff-" + "a" * 48
    class Authority:
        async def aclose(self): pass
    monkeypatch.setattr(approval, "load_config", lambda *_: ({"runtime_endpoint": "http://127.0.0.1:8292", "run_id": run_id}, Authority()))
    monkeypatch.setattr("process_runtime_client.RuntimeClient", lambda _: object())
    async def query(*_):
        return {"work": [
            {"run_id": "other", "step_id": "human-approval", "version": 1},
            {"run_id": run_id, "step_id": "human-approval", "version": 2},
        ], "next_cursor": None}
    async def call(_client, _authority, operation, payload, expected_version, request_id):
        assert operation == "executor.claim" and expected_version == 2 and request_id == "claim-1"
        return {"result": {"run_id": run_id, "step_id": "human-approval", "attempt_id": "attempt-1",
                           "fence": 1, "step_version": 3, "lease_expires_at_ms": 1000,
                           "input_digest": "b" * 64, "inputs": {"reviewed_strategy": {"content_hash": "c" * 64,
                           "byte_length": 1, "media_type": "text/markdown"}}}}
    monkeypatch.setattr(approval, "query", query)
    monkeypatch.setattr(approval, "call", call)
    result = __import__("asyncio").run(approval.run(SimpleNamespace(
        action="claim", config="x", config_sha256="a" * 64,
        request_id="claim-1", decision=None, decision_sha256=None)))
    assert result["schema"] == "frank.brand-approval-claim.v1"
    assert result["run_id"] == run_id


def test_command_result_must_correlate_to_exact_request(monkeypatch):
    class Authority:
        async def evidence(self, _body): return b"proof"

    class Client:
        def execute(self, envelope, *, evidence):
            assert evidence == b"proof"
            return {"schema": "runtime.result.v1", "request_id": "another-request",
                    "operation": envelope["operation"], "resource": envelope["resource"],
                    "duplicate": False, "version": 1, "result": {}}

    with pytest.raises(Rejected, match="correlation"):
        __import__("asyncio").run(approval.call(
            Client(), Authority(), "actor.register",
            {"actor_id": approval.ACTOR_ID, "capabilities": approval.CAPABILITIES,
             "resources": approval.RESOURCES}, None, "register-reviewer"))
