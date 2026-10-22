"""Unsigned capture candidate tests. Authored for later validation; no signer."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import threading
from types import SimpleNamespace

import httpx
import pytest

from frank_executor.authority import DenyAuthority, LocalDevResults
from frank_executor.connector_capture import ConnectorCapture, ConnectorPolicy, CapturePending
from frank_executor.executor import Executor
from frank_executor.integrations.hermes import HermesAdapter
from frank_executor.integrations.matrix import MatrixAdapter
from frank_executor.journal import Journal
from frank_executor.model import Rejected, UnknownOutcome, canonical, digest
from frank_executor.native_results import payload_for, resource_for
from frank_executor.output_materializer import RuntimeOutputMaterializer
from conftest import Adapter, arun, child_environment, python_child
from test_adapters import MATRIX, Hermes
from test_contract_journal import packet


HERMES = {"model": "fixture/model", "toolsets": [], "routes": ["local"], "max_iterations": 2}
UNCHANGED_TABLES = ("commands", "events", "cursors", "native_result_identity",
                    "native_result_proofs", "native_result_replay", "native_result_dispatch")


def policy(kind, config):
    # Artifact/configuration pins describe this unsigned test connector only.
    return ConnectorPolicy(kind, "fixture", "worker", "local", digest(config), "a" * 64, "b" * 64)


def setup_capture(tmp_path, kind="matrix", *, key="delivery", work=None):
    journal = Journal(tmp_path / "frank.db")
    work = packet() if work is None else work
    journal.delivery(key, work)
    assert journal.begin_dispatch(key)
    capture = ConnectorCapture(journal, policy(kind, MATRIX if kind == "matrix" else HERMES))
    return journal, capture, work


def event_for(work, *, event_id="$actual", outcome="succeeded"):
    result = Adapter().result(work)
    result.update(outcome=outcome, outputs=result["outputs"] if outcome == "succeeded" else {})
    return {"type": "m.room.message", "sender": MATRIX["routes"]["local"]["sender_id"],
            "event_id": event_id, "content": {"org.zenith.frank.v1": result}}


def page_for(*events):
    return {"next_batch": "next", "rooms": {"join": {
        MATRIX["routes"]["local"]["room_id"]: {"timeline": {"events": list(events)}}}}}


def matrix(capture, page, *, encrypted=False, after_plain=None):
    requests = []

    def handler(request):
        requests.append(request)
        if request.url.path.endswith("whoami"):
            return httpx.Response(200, json={"user_id": MATRIX["account_id"]})
        if request.url.path.endswith("m.room.encryption"):
            if after_plain:
                after_plain()
            return httpx.Response(200, json={"algorithm": "encrypted"}) if encrypted else httpx.Response(404, json={})
        if "/event/" in request.url.path:
            return httpx.Response(200, json=page)
        assert request.url.path.endswith("/sync")
        return httpx.Response(200, json=page)

    adapter = MatrixAdapter("fixture", deepcopy(MATRIX),
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        secret_resolver=lambda _: "fixture-token", connector_capture=capture)
    # Plain-room checks during receive/reconcile must not rely on connect-time state.
    adapter.ready, adapter.token = True, "fixture-token"
    return adapter, requests


def table_counts(journal):
    with sqlite3.connect(journal.path) as db:
        return {name: db.execute("SELECT count(*) FROM " + name).fetchone()[0]
                for name in (*UNCHANGED_TABLES, "connector_dispatch", "connector_captures", "connector_rejected_ingress")}


def assert_no_terminal(journal):
    counts = table_counts(journal)
    assert all(counts[name] == 0 for name in UNCHANGED_TABLES)
    assert journal.get("delivery")["state"] == "unknown"
    assert journal.get("delivery")["result"] is None


@pytest.mark.parametrize("outcome", ["succeeded", "failed"])
def test_matrix_freezes_complete_normalized_body_and_holds_cursor(tmp_path, outcome):
    journal, capture, work = setup_capture(tmp_path)
    event = event_for(work, outcome=outcome)
    event["content"]["org.zenith.frank.v1"].update(event_id="body-alias", provider_reference="body-reference")
    adapter, calls = matrix(capture, page_for(event))
    expected = adapter.normalize(MATRIX["routes"]["local"]["room_id"], event)
    with pytest.raises(CapturePending):
        arun(adapter.receive("before"))
    retained = capture.retained(work)
    assert retained["body"] == expected
    assert retained["payload"] == payload_for(expected, work)
    assert retained["resource"] == resource_for(work)
    assert retained["body"]["provider_reference"] == "$actual"
    assert retained["body"]["event_id"] != "body-alias"
    assert len(calls) == 2 and calls[0].url.params["since"] == "before"
    assert table_counts(journal)["connector_captures"] == 1
    assert_no_terminal(journal)


@pytest.mark.parametrize("malformation", ["cursor", "cursor-bytes", "later-gap", "events-type", "content-type", "limited-type", "too-many", "too-many-raw", "too-many-rooms"])
def test_whole_matrix_page_rejects_before_any_eligible_capture(tmp_path, malformation):
    journal, capture, work = setup_capture(tmp_path)
    page = page_for(event_for(work))
    joined = page["rooms"]["join"]
    timeline = next(iter(joined.values()))["timeline"]
    if malformation == "cursor":
        page["next_batch"] = None
    elif malformation == "cursor-bytes":
        page["next_batch"] = "é" * 2049
    elif malformation == "later-gap":
        joined["!later:example.test"] = {"timeline": {"limited": True}}
    elif malformation == "events-type":
        timeline["events"] = {}
    elif malformation == "content-type":
        timeline["events"].append({"content": []})
    elif malformation == "limited-type":
        timeline["limited"] = 0
    elif malformation == "too-many":
        timeline["events"] *= 101
    elif malformation == "too-many-raw":
        timeline["events"] = [{}] * 1001
    else:
        joined.update({f"!room{i}:example.test": {} for i in range(100)})
    adapter, calls = matrix(capture, page)
    with pytest.raises(Rejected):
        arun(adapter.receive(None))
    assert len(calls) == 1
    assert table_counts(journal)["connector_captures"] == 0
    assert_no_terminal(journal)


def test_plain_room_change_prevents_receive_and_reconcile_capture(tmp_path):
    journal, capture, work = setup_capture(tmp_path)
    event = event_for(work)
    for data, method, args in [(page_for(event), "receive", (None,)), (event, "reconcile", (work, "$actual"))]:
        adapter, calls = matrix(capture, data, encrypted=True)
        with pytest.raises(Rejected, match="crypto adapter"):
            arun(getattr(adapter, method)(*args))
        assert any(call.url.path.endswith("m.room.encryption") for call in calls)
        assert table_counts(journal)["connector_captures"] == 0
    assert_no_terminal(journal)


def test_matrix_work_and_body_freeze_before_room_check_await(tmp_path):
    journal, capture, work = setup_capture(tmp_path)
    event = event_for(work)
    page = page_for(event)

    def mutate_transport_objects():
        event["content"]["org.zenith.frank.v1"]["outputs"]["answer"] = 999
        work["inputs"]["number"] = 999

    expected = deepcopy(work)
    adapter, _ = matrix(capture, page, after_plain=mutate_transport_objects)
    with pytest.raises(CapturePending):
        arun(adapter.receive(None))
    retained = capture.retained(expected)
    assert retained["work"]["inputs"] == {"number": 7}
    assert retained["body"]["outputs"] == {"answer": 14}
    assert_no_terminal(journal)


def test_policy_mutation_during_plain_check_denies_capture(tmp_path):
    journal, capture, work = setup_capture(tmp_path)
    def change():
        capture.policy = replace(capture.policy, artifact_sha256="c" * 64)
    adapter, _ = matrix(capture, page_for(event_for(work)), after_plain=change)
    with pytest.raises(Rejected, match="policy changed"):
        arun(adapter.receive(None))
    assert table_counts(journal)["connector_captures"] == 0
    assert_no_terminal(journal)


def test_unexpected_proof_retains_rejected_ingress_without_eligible_capture(tmp_path):
    journal, capture, work = setup_capture(tmp_path)
    event = event_for(work)
    event["content"]["org.zenith.frank.v1"]["proof"] = {"unexpected": "untrusted-evidence"}
    adapter, _ = matrix(capture, page_for(event))
    for _ in range(2):
        with pytest.raises(Rejected, match="proved ingress"):
            arun(adapter.receive(None))
    counts = table_counts(journal)
    assert counts["connector_rejected_ingress"] == 1 and counts["connector_captures"] == 0
    with sqlite3.connect(journal.path) as db:
        original = json.loads(db.execute("SELECT original FROM connector_rejected_ingress").fetchone()[0])
    assert original == event
    assert capture.retained(work) is None
    assert_no_terminal(journal)


def test_changed_unexpected_proof_never_replaces_first_ingress(tmp_path):
    journal, capture, work = setup_capture(tmp_path)
    event = event_for(work)
    event["content"]["org.zenith.frank.v1"]["proof"] = {"unexpected": "first"}
    adapter, _ = matrix(capture, page_for(event))
    with pytest.raises(Rejected, match="proved ingress"):
        arun(adapter.receive(None))
    with sqlite3.connect(journal.path) as db:
        before = db.execute("SELECT * FROM connector_rejected_ingress").fetchall()
    event["content"]["org.zenith.frank.v1"]["proof"]["unexpected"] = "changed"
    adapter, _ = matrix(capture, page_for(event))
    with pytest.raises(Rejected, match="immutable"):
        arun(adapter.receive(None))
    with sqlite3.connect(journal.path) as db:
        assert db.execute("SELECT * FROM connector_rejected_ingress").fetchall() == before
    assert capture.retained(work) is None
    assert_no_terminal(journal)


def test_verify_only_proof_route_does_not_fall_back_to_capture(tmp_path):
    journal, capture, work = setup_capture(tmp_path)
    event = event_for(work)
    event["content"]["org.zenith.frank.v1"]["proof"] = {"invalid": "existing-proof"}
    adapter, _ = matrix(None, page_for(event))
    seen = []
    class RejectingVerifier:
        mode = "unavailable"
        async def verify(self, result, retained_work):
            seen.append(result)
            raise Rejected("independent verifier denied")
    class Gateway:
        authority = DenyAuthority()
        async def query(self, *args):
            raise AssertionError("No Runtime call on verification failure")
        async def execute(self, *args):
            raise AssertionError("No Runtime call on verification failure")
    executor = Executor(Gateway(), SimpleNamespace(adapters={"fixture": adapter}), journal,
                        RejectingVerifier(), environment="test")
    with pytest.raises(Rejected, match="verifier denied"):
        arun(executor.receive("fixture"))
    assert len(seen) == 1 and "proof" in seen[0]
    assert capture.retained(work) is None
    assert_no_terminal(journal)


def test_capture_cannot_leak_to_local_dev_verifier_or_runtime(tmp_path):
    journal, capture, work = setup_capture(tmp_path)
    adapter, _ = matrix(capture, page_for(event_for(work)))
    class Gateway:
        authority = DenyAuthority()
        async def query(self, *args):
            raise AssertionError("Capture must not query Runtime")
        async def execute(self, *args):
            raise AssertionError("Capture must not mutate Runtime")
    class Results(LocalDevResults):
        async def verify(self, *args):
            raise AssertionError("Unsigned capture must not reach local-dev admission")
    executor = Executor(Gateway(), SimpleNamespace(adapters={"fixture": adapter}), journal,
                        Results(environment="test", enabled=True), environment="test")
    with pytest.raises(CapturePending):
        arun(executor.receive("fixture"))
    assert capture.retained(work) is not None
    assert_no_terminal(journal)


def prepared(capture, work, *, event_id="$actual"):
    event = event_for(work, event_id=event_id)
    # Same connector-owned final normalization as the transport adapter.
    normalized = {**event["content"]["org.zenith.frank.v1"],
                  "event_id": "event-" + digest(event_id)[:48], "provider_reference": event_id}
    return capture.prepare_matrix(normalized, room=MATRIX["routes"]["local"]["room_id"],
                                  event=event, read_path="sync")


def test_exact_capture_race_restart_conflict_and_original_provenance(tmp_path):
    journal, capture, work = setup_capture(tmp_path)
    def writer(_):
        own = ConnectorCapture(Journal(journal.path), policy("matrix", MATRIX))
        own.commit((prepared(own, work),))
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(writer, range(4)))
    restarted = ConnectorCapture(Journal(journal.path), policy("matrix", MATRIX))
    assert restarted.retained(work)["payload"] == capture.retained(work)["payload"]
    with pytest.raises(Rejected, match="immutable"):
        restarted.commit((prepared(restarted, work, event_id="$changed"),))
    assert table_counts(journal)["connector_captures"] == 1
    assert_no_terminal(journal)


def test_capture_batch_collision_rolls_back_all_records(tmp_path):
    journal, capture, work = setup_capture(tmp_path)
    other = deepcopy(work)
    other["effect_id"] = "effect-2"
    other["binding"]["attempt_id"] = "attempt-2"
    journal.delivery("other", other)
    journal.begin_dispatch("other")
    with pytest.raises(Rejected, match="another delivery"):
        capture.commit((prepared(capture, work), prepared(capture, other)))
    assert table_counts(journal)["connector_captures"] == 0
    assert_no_terminal(journal)


def test_duplicate_retained_delivery_and_changed_original_provenance_deny(tmp_path):
    journal, capture, work = setup_capture(tmp_path)
    first = prepared(capture, work)
    capture.commit((first,))
    event = event_for(work)
    event["unsigned"] = {"age": 1}
    normalized = {**event["content"]["org.zenith.frank.v1"],
                  "event_id": "event-" + digest("$actual")[:48], "provider_reference": "$actual"}
    changed = capture.prepare_matrix(normalized, room=MATRIX["routes"]["local"]["room_id"],
                                     event=event, read_path="sync")
    with pytest.raises(Rejected, match="immutable"):
        capture.commit((changed,))
    journal.delivery("duplicate", work)
    journal.begin_dispatch("duplicate")
    with pytest.raises(Rejected, match="one retained delivery"):
        prepared(capture, work)
    assert table_counts(journal)["connector_captures"] == 1
    assert_no_terminal(journal)


def test_additive_migration_preserves_historical_row_bytes(tmp_path):
    journal, _, work = setup_capture(tmp_path)
    result = Adapter().result(work)
    journal.observation("delivery", result)
    journal.command({"request_id": "historical-command", "payload": {"number": 7}})
    journal.cursor("fixture", "historical-cursor")
    historical = ("deliveries", *UNCHANGED_TABLES)
    with sqlite3.connect(journal.path) as db:
        before = {name: db.execute("SELECT * FROM " + name + " ORDER BY rowid").fetchall()
                  for name in historical}
        for name in ("connector_dispatch", "connector_captures", "connector_rejected_ingress"):
            db.execute("DROP TABLE " + name)
    Journal(journal.path)
    with sqlite3.connect(journal.path) as db:
        after = {name: db.execute("SELECT * FROM " + name + " ORDER BY rowid").fetchall()
                 for name in historical}
    assert after == before
    assert table_counts(journal)["connector_captures"] == 0


@pytest.mark.parametrize("change", ["work", "provenance", "original", "body"])
def test_retained_capture_checks_digest_and_provenance(tmp_path, change):
    journal, capture, work = setup_capture(tmp_path)
    capture.commit((prepared(capture, work),))
    with sqlite3.connect(journal.path) as db:
        if change == "work":
            changed = deepcopy(work)
            changed["inputs"]["number"] = 8
            db.execute("UPDATE deliveries SET work=?", (canonical(changed).decode(),))
        else:
            db.execute("UPDATE connector_captures SET " + change + "='{}'")
    with pytest.raises(Rejected):
        capture.retained(work)


def test_legacy_terminal_has_no_connector_renewal_eligibility(tmp_path):
    journal, capture, work = setup_capture(tmp_path)
    result = Adapter().result(work)
    journal.observation("delivery", result)
    before = journal.get("delivery")
    assert capture.retained(work) is None
    with pytest.raises(Rejected, match="cannot upgrade"):
        capture.commit((prepared(capture, work),))
    assert journal.get("delivery") == before
    assert table_counts(journal)["connector_captures"] == 0


@pytest.mark.parametrize("field", ["binding", "actor_id", "integration_id", "route", "effect_id"])
def test_changed_correlation_never_creates_capture(tmp_path, field):
    journal, capture, work = setup_capture(tmp_path)
    event = event_for(work)
    result = event["content"]["org.zenith.frank.v1"]
    if field == "binding":
        result["binding"]["fence"] += 1
    else:
        result[field] = "other"
    adapter, _ = matrix(capture, page_for(event))
    with pytest.raises(Rejected):
        arun(adapter.receive(None))
    assert table_counts(journal)["connector_captures"] == 0


def test_hermes_reservation_wins_once_across_instances_and_restart(tmp_path):
    journal, capture, work = setup_capture(tmp_path, "hermes")
    calls = []
    lock = threading.Lock()
    class Counted(Hermes):
        def __init__(self, **kwargs):
            with lock:
                calls.append("factory")
            super().__init__(**kwargs)
        def run_conversation(self, *args, **kwargs):
            with lock:
                calls.append("run")
            return super().run_conversation(*args, **kwargs)
    def writer(_):
        own = ConnectorCapture(Journal(journal.path), policy("hermes", HERMES))
        adapter = HermesAdapter("fixture", deepcopy(HERMES), agent_factory=Counted, connector_capture=own)
        arun(adapter.connect())
        with pytest.raises(CapturePending):
            arun(adapter.send(work))
        assert adapter.results == {}
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(writer, range(2)))
    writer(3)
    assert calls == ["factory", "run"]
    retained = capture.retained(work)
    assert retained["body"]["outputs"] == {"answer": 14}
    assert retained["payload"] == payload_for(retained["body"], work)
    assert table_counts(journal)["connector_dispatch"] == 1
    assert_no_terminal(journal)


@pytest.mark.parametrize("phase", ["factory", "after-capture"])
def test_hermes_real_process_crash_retains_no_resend_marker(tmp_path, phase):
    journal, capture, work = setup_capture(tmp_path, "hermes")
    code = '''
import asyncio,json,os,sys
from frank_executor.connector_capture import ConnectorCapture,ConnectorPolicy
from frank_executor.integrations.hermes import HermesAdapter
from frank_executor.journal import Journal
from frank_executor.model import digest
config=json.loads(sys.argv[2]);work=json.loads(sys.argv[3]);phase=sys.argv[4]
capture=ConnectorCapture(Journal(sys.argv[1]),ConnectorPolicy('hermes','fixture','worker','local',digest(config),'a'*64,'b'*64))
if phase=='after-capture':
    original=capture.commit
    def commit(values):
        original(values)
        os._exit(72)
    capture.commit=commit
class Agent:
    def __init__(self,**kwargs):
        if phase=='factory':os._exit(71)
    def run_conversation(self,*args,**kwargs):return {'final_response':'{"answer":14}'}
    def interrupt(self,*args):pass
async def main():
    adapter=HermesAdapter('fixture',config,agent_factory=Agent,connector_capture=capture)
    await adapter.connect()
    await adapter.send(work)
asyncio.run(main())
'''
    result = subprocess.run(python_child(["-c", code, journal.path, json.dumps(HERMES), json.dumps(work), phase]),
                            env=child_environment(), cwd=Path(__file__).resolve().parents[1], timeout=30)
    assert result.returncode == (71 if phase == "factory" else 72)
    def forbidden_factory(**kwargs):
        raise AssertionError("Restart must never instantiate an agent")
    reopened = ConnectorCapture(Journal(journal.path), policy("hermes", HERMES))
    adapter = HermesAdapter("fixture", deepcopy(HERMES), agent_factory=forbidden_factory, connector_capture=reopened)
    arun(adapter.connect())
    with pytest.raises(CapturePending):
        arun(adapter.send(work))
    if phase == "after-capture":
        assert reopened.retained(work)["body"]["outputs"] == {"answer": 14}
        with pytest.raises(CapturePending):
            arun(adapter.reconcile(work, "effect-1"))
    else:
        assert reopened.retained(work) is None
        assert arun(adapter.reconcile(work, "effect-1")) is None
    assert_no_terminal(journal)


def test_native_payload_bound_preserved_without_output_coercion(tmp_path):
    journal, capture, work = setup_capture(tmp_path)
    event = event_for(work)
    event["content"]["org.zenith.frank.v1"]["outputs"] = {"answer": "x" * 262144}
    adapter, _ = matrix(capture, page_for(event))
    with pytest.raises(Rejected):
        arun(adapter.receive(None))
    assert table_counts(journal)["connector_captures"] == 0
    assert_no_terminal(journal)


@pytest.mark.parametrize("outcome", ["acknowledged", "unknown"])
def test_nonterminal_matrix_observation_is_never_capture_eligible(tmp_path, outcome):
    journal, capture, work = setup_capture(tmp_path)
    adapter, _ = matrix(capture, page_for(event_for(work, outcome=outcome)))
    results, cursor = arun(adapter.receive(None))
    assert cursor == "next" and results[0]["outcome"] == outcome
    assert capture.retained(work) is None
    assert_no_terminal(journal)


def test_hermes_malformed_return_leaves_marker_without_capture(tmp_path):
    journal, capture, work = setup_capture(tmp_path, "hermes")
    class Invalid(Hermes):
        def run_conversation(self, *args, **kwargs):
            return {"final_response": "not json"}
    adapter = HermesAdapter("fixture", deepcopy(HERMES), agent_factory=Invalid, connector_capture=capture)
    arun(adapter.connect())
    with pytest.raises(Rejected, match="outcome unavailable"):
        arun(adapter.send(work))
    assert table_counts(journal)["connector_dispatch"] == 1
    assert capture.retained(work) is None
    restarted = HermesAdapter("fixture", deepcopy(HERMES), agent_factory=lambda **kw: pytest.fail("must not rerun"), connector_capture=capture)
    arun(restarted.connect())
    with pytest.raises(CapturePending):
        arun(restarted.send(work))
    assert_no_terminal(journal)


def test_hermes_response_survives_artifact_unknown_outcome_without_redispatch(tmp_path):
    work = packet()
    work["output_types"] = {"document": {"kind": "artifact"}}
    journal, capture, work = setup_capture(tmp_path, "hermes", work=work)

    class Document(Hermes):
        def run_conversation(self, *args, **kwargs):
            return {
                "final_response": json.dumps({
                    "document": {
                        "content_utf8": "# Durable output\n",
                        "media_type": "text/markdown",
                    }
                })
            }

    calls = []

    class UnknownWriter:
        async def write(self, content, media_type, *, request_id=None):
            calls.append((content, media_type, request_id, "unknown"))
            raise UnknownOutcome("artifact result lost")

    adapter = HermesAdapter(
        "fixture",
        deepcopy(HERMES),
        agent_factory=Document,
        connector_capture=capture,
        output_materializer=RuntimeOutputMaterializer(UnknownWriter()),
    )
    arun(adapter.connect())
    with pytest.raises(UnknownOutcome):
        arun(adapter.send(work))
    assert capture.retained(work) is None
    prompt = adapter._prompt(work)
    assert capture.hermes_response(work, prompt) is not None

    class RecoveredWriter:
        async def write(self, content, media_type, *, request_id=None):
            calls.append((content, media_type, request_id, "recovered"))
            return {
                "content_hash": hashlib.sha256(content).hexdigest(),
                "byte_length": len(content),
                "media_type": media_type,
            }

    def forbidden_factory(**kwargs):
        raise AssertionError("reconcile must not redispatch Hermes")

    reopened = ConnectorCapture(Journal(journal.path), policy("hermes", HERMES))
    restarted = HermesAdapter(
        "fixture",
        deepcopy(HERMES),
        agent_factory=forbidden_factory,
        connector_capture=reopened,
        output_materializer=RuntimeOutputMaterializer(RecoveredWriter()),
    )
    arun(restarted.connect())
    with pytest.raises(CapturePending):
        arun(restarted.reconcile(work, work["effect_id"]))
    retained = reopened.retained(work)
    assert retained["body"]["outputs"]["document"] == {
        "content_hash": hashlib.sha256(b"# Durable output\n").hexdigest(),
        "byte_length": 17,
        "media_type": "text/markdown",
    }
    assert calls[0][2] == calls[1][2]


def test_historical_hermes_capture_without_response_row_remains_readable(tmp_path):
    journal, capture, work = setup_capture(tmp_path, "hermes")
    adapter = HermesAdapter(
        "fixture", deepcopy(HERMES), agent_factory=Hermes, connector_capture=capture
    )
    arun(adapter.connect())
    with pytest.raises(CapturePending):
        arun(adapter.send(work))
    with journal.connection() as db:
        db.execute("DELETE FROM connector_responses")
    retained = ConnectorCapture(Journal(journal.path), policy("hermes", HERMES)).retained(work)
    assert retained["body"]["outputs"] == {"answer": 14}


def test_hermes_cancelled_await_retains_marker_and_interrupts_without_capture(tmp_path):
    journal, capture, work = setup_capture(tmp_path, "hermes")
    entered, release = threading.Event(), threading.Event()
    made = []
    class Waiting(Hermes):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            made.append(self)
        def run_conversation(self, *args, **kwargs):
            entered.set()
            if not release.wait(3):
                raise AssertionError("fixture release timed out")
            return super().run_conversation(*args, **kwargs)
    async def cancel():
        adapter = HermesAdapter("fixture", deepcopy(HERMES), agent_factory=Waiting, connector_capture=capture)
        await adapter.connect()
        task = asyncio.create_task(adapter.send(work))
        try:
            assert await asyncio.to_thread(entered.wait, 3)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        finally:
            release.set()
    arun(cancel())
    assert len(made) == 1 and made[0].interruptions
    assert table_counts(journal)["connector_dispatch"] == 1
    assert capture.retained(work) is None
    assert_no_terminal(journal)


def test_capture_metadata_bounds_and_non_host_dependencies_deny(tmp_path):
    journal, capture, work = setup_capture(tmp_path)
    with pytest.raises(Rejected):
        ConnectorCapture(journal, {"kind": "matrix"})
    with pytest.raises(Rejected):
        MatrixAdapter("fixture", deepcopy(MATRIX), client=None, secret_resolver=None,
                      connector_capture={"enabled": True})
    with pytest.raises(Rejected):
        capture.commit(({"effect_key": "delivery", "eligible": True},))
    item = event_for(work)
    result = item["content"]["org.zenith.frank.v1"]
    with pytest.raises(Rejected):
        capture.prepare_matrix(result, room="x" * 4097, event=item, read_path="sync")
    assert table_counts(journal)["connector_captures"] == 0
    assert_no_terminal(journal)


def test_check_config_and_health_do_not_open_capture_store(tmp_path, monkeypatch):
    from frank_executor import cli
    config = {"schema": "frank.config.v1", "environment": "production",
              "runtime_endpoint": "http://127.0.0.1:1", "journal": str(tmp_path / "must-not-exist.db"),
              "allow_local_dev_untrusted": False,
              "integrations": {"schema": "frank.integrations.v1", "integrations": [], "actors": []}}
    path = tmp_path / "config.json"
    path.write_text(json.dumps(config))
    monkeypatch.setattr(cli, "Journal", lambda *args: pytest.fail("health/config must not construct Journal"))
    for action in ("check-config", "health"):
        result = arun(cli.run(SimpleNamespace(config=str(path), action=action)))
        assert result["configuration"] == "valid"
    assert not Path(config["journal"]).exists()
