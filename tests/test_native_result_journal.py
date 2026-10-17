"""Durable native admission/dispatch, legacy compatibility and pinned-helper recovery."""

from __future__ import annotations
import asyncio
import sqlite3
import threading
import pytest
from frank_executor.journal import Journal
from frank_executor.model import Rejected
from frank_executor.runtime import GeneratedClientAdapter
from conftest import arun


def test_additive_native_tables_exist_without_rewriting_legacy(tmp_path):
    path = tmp_path / "frank.db"
    Journal(path)
    with sqlite3.connect(path) as db:
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {
        "native_result_identity",
        "native_result_proofs",
        "native_result_replay",
        "native_result_dispatch",
    } <= tables


def test_guard_executes_in_worker_immediately_before_sdk():
    events = []
    main_thread = threading.get_ident()

    class SDK:
        def execute(self, envelope, *, evidence):
            events.append(("execute", threading.get_ident()))
            return {"ok": True}

    def guard(envelope):
        events.append(("guard", threading.get_ident()))

    result = arun(
        GeneratedClientAdapter(SDK()).command_guarded(
            {"request_id": "one"}, authority=b"proof", guard=guard
        )
    )
    assert result == {"ok": True}
    assert [name for name, _ in events] == ["guard", "execute"]
    assert events[0][1] == events[1][1] != main_thread


def test_guard_rejection_in_worker_never_calls_sdk():
    calls = []

    class SDK:
        def execute(self, *args, **kwargs):
            calls.append(1)

    def reject(_):
        raise Rejected("expired")

    with pytest.raises(Rejected, match="expired"):
        arun(
            GeneratedClientAdapter(SDK()).command_guarded(
                {"request_id": "one"}, authority=b"proof", guard=reject
            )
        )
    assert calls == []


from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import replace
from frank_executor.model import canonical, digest, UnknownOutcome
from frank_executor.native_results import NativeResultVerifier
from native_result_support import SyntheticHelper, policy, work_result


def native(
    work=None, result=None, *, state=None, nonce=2, proof_byte=None, expires=1060, issued=1000
):
    if work is None:
        work, result = work_result()
    result = deepcopy(result)
    proof_byte = nonce if proof_byte is None else proof_byte
    result["proof"] = {
        "schema": "frank.secs-result-envelope.v1",
        "packet_hex": f"{proof_byte:02x}",
        "signed_context_hex": f"{proof_byte:02x}",
    }
    binding = work["binding"]
    resource = f"runs/{binding['run_id']}/steps/{binding['step_id']}/attempts/{binding['attempt_id']}/effects/{work['effect_id']}"
    base = policy()
    configured = replace(
        base,
        subjects=(
            replace(
                base.subjects[0],
                actor_id=work["actor_id"],
                integration_id=work["integration_id"],
                route=work["route"],
            ),
        ),
        rules=(replace(base.rules[0], resource=resource),),
    )
    state = state or {"policy": configured, "now": 1001.0}
    helper = SyntheticHelper(work, result)
    helper.context.update(
        resource=resource, nonce=[nonce] * 12, expires_at=expires, issued_at=issued
    )
    verifier = NativeResultVerifier(helper, lambda: state["policy"], clock=lambda: state["now"])
    token = arun(verifier.verify(result, work))
    return token, verifier, helper, state, deepcopy(work), result


def prepared(tmp_path):
    token, verifier, helper, state, work, result = native()
    journal = Journal(tmp_path / "journal.db")
    journal.delivery("effect", work)
    journal.begin_dispatch("effect")
    return journal, token, verifier, helper, state, work, result


def rows(journal, table):
    with sqlite3.connect(journal.path) as db:
        return db.execute("SELECT * FROM " + table + " ORDER BY rowid").fetchall()


def test_native_exact_replay_concurrent_and_after_restart(tmp_path):
    journal, token, _, _, _, work, result = prepared(tmp_path)
    connections = [Journal(journal.path) for _ in range(8)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        answers = list(
            pool.map(
                lambda target: target.observation("effect", result, admission=token), connections
            )
        )
    assert answers.count(True) == 1 and answers.count(False) == 7
    restarted = Journal(journal.path)
    assert restarted.observation("effect", result, admission=token) is False
    assert (
        len(rows(journal, "native_result_identity"))
        == len(rows(journal, "native_result_proofs"))
        == len(rows(journal, "native_result_replay"))
        == 1
    )
    assert restarted.result_digest("effect", result) == digest(
        {k: v for k, v in result.items() if k != "proof"}
    )


def test_nonce_collision_or_changed_identity_denies_without_consuming_new_rows(tmp_path):
    journal, token, _, _, state, work, result = prepared(tmp_path)
    journal.observation("effect", result, admission=token)
    first = rows(journal, "native_result_replay")
    changed, _, _, _, _, renewed = native(work, result, state=state, nonce=2, proof_byte=4)
    with pytest.raises(Rejected, match="replay"):
        journal.reauthorize("effect", renewed, changed)
    for field, value in [
        ("event_id", "other-event"),
        ("provider_reference", "other-provider"),
        ("outputs", {"answer": 99}),
    ]:
        altered = deepcopy(result)
        altered[field] = value
        new_token, _, _, _, _, altered = native(work, altered, state=state, nonce=3)
        with pytest.raises(Rejected, match="immutable"):
            journal.reauthorize("effect", altered, new_token)
    assert (
        rows(journal, "native_result_replay") == first
        and len(rows(journal, "native_result_proofs")) == 1
    )


def test_native_proof_renewal_preserves_first_bytes_event_hash_and_commands(tmp_path):
    journal, token, _, _, state, work, result = prepared(tmp_path)
    journal.observation("effect", result, admission=token)
    from process_runtime_client import command_envelope

    command = command_envelope(
        "executor.complete",
        request_id="effect-complete",
        expected_version=7,
        payload={**work["binding"], "outputs": result["outputs"]},
    )
    journal.command(command)
    first_delivery = rows(journal, "deliveries")
    first_events = rows(journal, "events")
    first_commands = rows(journal, "commands")
    renewed_token, _, _, _, _, renewed = native(work, result, state=state, nonce=3)
    assert journal.reauthorize("effect", renewed, renewed_token) is False
    assert journal.get("effect")["result"]["proof"] == renewed["proof"]
    assert (
        rows(journal, "deliveries") == first_delivery
        and rows(journal, "events") == first_events
        and rows(journal, "commands") == first_commands
    )
    assert (
        journal.result_digest("effect", renewed) == token.identity
        and len(rows(journal, "native_result_proofs")) == 2
    )
    journal.reauthorize("effect", renewed, renewed_token, command)
    dispatch = rows(journal, "native_result_dispatch")
    assert len(dispatch) == 1
    assert dispatch[0][4] == digest(command) and dispatch[0][7] == renewed_token.policy_sha256


def test_native_observation_rollback_does_not_burn_nonce(tmp_path):
    journal, token, _, _, _, _, result = prepared(tmp_path)
    with sqlite3.connect(journal.path) as db:
        db.execute(
            "CREATE TRIGGER break_identity BEFORE INSERT ON native_result_identity BEGIN SELECT RAISE(ABORT,'injected failure after replay'); END"
        )
    with pytest.raises(sqlite3.IntegrityError):
        journal.observation("effect", result, admission=token)
    assert (
        rows(journal, "native_result_replay")
        == rows(journal, "native_result_proofs")
        == rows(journal, "native_result_identity")
        == rows(journal, "events")
        == []
    )
    assert journal.get("effect")["state"] == "unknown"
    with sqlite3.connect(journal.path) as db:
        db.execute("DROP TRIGGER break_identity")
    assert journal.observation("effect", result, admission=token)


def test_writer_delay_expiry_rolls_back_all_native_admission(tmp_path):
    journal, token, _, _, state, _, result = prepared(tmp_path)
    blocker = sqlite3.connect(journal.path)
    blocker.execute("BEGIN IMMEDIATE")
    started = threading.Event()

    def admit():
        started.set()
        return journal.observation("effect", result, admission=token)

    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(admit)
            assert started.wait(2)
            state["now"] = 1060
            blocker.commit()
            with pytest.raises(Rejected):
                future.result(3)
    finally:
        blocker.close()
    assert (
        rows(journal, "native_result_replay") == [] and journal.get("effect")["state"] == "unknown"
    )


def test_legacy_proof_event_and_commands_survive_additive_reopen_and_cannot_upgrade(tmp_path):
    journal, token, _, _, _, work, result = prepared(tmp_path)
    result["proof"] = {"legacy": "opaque-proof"}
    assert journal.observation("effect", result)
    from process_runtime_client import command_envelope

    for op, extra in [
        (
            "executor.effect.observe",
            {
                "effect_id": work["effect_id"],
                "provider_reference": result["provider_reference"],
                "outcome": "succeeded",
                "observation_digest": digest(result),
            },
        ),
        ("executor.complete", {"outputs": result["outputs"]}),
        ("executor.fail", {"reason": "fixture", "retryable": False}),
    ]:
        journal.command(
            command_envelope(
                op, request_id=op, expected_version=9, payload={**work["binding"], **extra}
            )
        )
    before = {table: rows(journal, table) for table in ["deliveries", "events", "commands"]}
    reopened = Journal(journal.path)
    assert reopened.result_digest("effect", result) == digest(result)
    assert all(rows(reopened, table) == snapshot for table, snapshot in before.items())
    token, _, _, _, _, native_result = native(work, result)
    with pytest.raises(Rejected):
        reopened.reauthorize("effect", native_result, token)
    with pytest.raises(Rejected):
        reopened.observation("effect", native_result, admission=token)
    assert rows(reopened, "native_result_identity") == []


def test_native_cannot_downgrade_to_legacy_or_caller_lookalike(tmp_path):
    journal, token, _, _, _, _, result = prepared(tmp_path)
    with pytest.raises(Rejected):
        journal.observation("effect", result, admission={"identity": token.identity})
    assert journal.observation("effect", result, admission=token)
    with pytest.raises(Rejected):
        journal.observation("effect", result)
    with pytest.raises(Rejected):
        journal.reauthorize("effect", result, None)


def test_expired_duplicate_cursor_denial_preserves_confirmed_history(tmp_path):
    journal, token, _, _, state, _, result = prepared(tmp_path)
    journal.observation("effect", result, admission=token)
    journal.committed("effect")
    before = rows(journal, "deliveries")
    state["now"] = 1060
    with pytest.raises(Rejected):
        journal.cursor("fixture", "after", admissions=[("effect", result, token)])
    assert journal.cursor("fixture") is None and rows(journal, "deliveries") == before


def prepare_executor(harness, outcome="succeeded", expires=1060):
    executor, adapter, journal, work, actor, _ = harness
    attempt = arun(executor.claim(actor, work))
    adapter.outcome = "acknowledged"
    saved = arun(executor.dispatch(attempt, operation="compute", scope="answer"))
    terminal = adapter.result(saved["work"], outcome)
    token, verifier, helper, state, _, result = native(saved["work"], terminal, expires=expires)
    executor.result_verifier = verifier
    arun(executor.observe(attempt, saved["effect_key"], result))
    return (
        executor,
        adapter,
        journal,
        attempt,
        saved["effect_key"],
        token,
        verifier,
        helper,
        state,
        result,
    )


def test_native_observe_identity_stable_under_renewal_and_unchecked_replay_denied(harness):
    executor, _, journal, attempt, key, token, _, _, state, result = prepare_executor(harness)
    request_id = key + "-" + token.identity[:24]
    before = journal.saved_command(request_id)
    renewed, verifier, _, _, _, result = native(
        journal.get(key)["work"], result, state=state, nonce=3
    )
    executor.result_verifier = verifier
    arun(executor.observe(attempt, key, result))
    assert (
        journal.saved_command(request_id) == before
        and journal.get(key)["result"]["proof"] == renewed.proof
    )
    with pytest.raises(Rejected, match="current result admission"):
        arun(executor.gateway.replay(request_id))


@pytest.mark.parametrize("change", ["expire", "revoke"])
def test_native_terminal_waiting_for_attempt_lock_revalidates(harness, change):
    executor, _, journal, attempt, key, _, verifier, _, state, result = prepare_executor(harness)
    entered = asyncio.Event()

    class WaitingVerifier:
        mode = "native_unqualified"

        async def verify(self, *args):
            value = await verifier.verify(*args)
            entered.set()
            return value

    executor.result_verifier = WaitingVerifier()
    calls = []
    original = executor.gateway.client.command_guarded

    async def tracked(*args, **kwargs):
        calls.append(1)
        return await original(*args, **kwargs)

    executor.gateway.client.command_guarded = tracked

    async def run():
        await attempt.lock.acquire()
        pending = asyncio.create_task(executor.complete(attempt, key))
        await entered.wait()
        if change == "expire":
            state["now"] = 1060
        else:
            state["policy"] = replace(
                state["policy"],
                revoked_subject_keys=frozenset({("synthetic-subject", "synthetic-holder")}),
            )
        attempt.lock.release()
        with pytest.raises(Rejected):
            await pending

    arun(run())
    assert calls == [] and journal.get(key)["state"] == "succeeded"


def test_native_authority_wait_and_worker_delay_each_revalidate(harness, monkeypatch):
    executor, _, journal, attempt, key, _, _, _, state, _ = prepare_executor(harness)
    original = executor.gateway.authority.evidence
    calls = []
    execute = executor.gateway.client.client.execute

    def sdk(*args, **kwargs):
        calls.append(1)
        return execute(*args, **kwargs)

    executor.gateway.client.client.execute = sdk

    async def delayed_authority(envelope):
        evidence = await original(envelope)
        state["now"] = 1060
        return evidence

    executor.gateway.authority.evidence = delayed_authority
    with pytest.raises(Rejected):
        arun(executor.complete(attempt, key))
    assert calls == []
    # Repeat from retained immutable evidence with a fresh current Attempt view.
    state["now"] = 1001
    executor.gateway.authority.evidence = original
    attempt = arun(executor.recover(attempt.binding, attempt.actor_id))
    to_thread = asyncio.to_thread

    async def queued(function, *args, **kwargs):
        if getattr(function, "__name__", "") == "dispatch":
            state["now"] = 1060
        return await to_thread(function, *args, **kwargs)

    monkeypatch.setattr(asyncio, "to_thread", queued)
    with pytest.raises(Rejected):
        arun(executor.complete(attempt, key))
    assert calls == [] and journal.get(key)["state"] == "succeeded"


def test_native_terminal_transport_without_guard_is_denied(harness):
    executor, _, _, attempt, key, _, _, _, _, _ = prepare_executor(harness)
    original = executor.gateway.client
    calls = []

    class LegacyOnly:
        async def command(self, *args, **kwargs):
            calls.append(1)
            return await original.command(*args, **kwargs)

        async def query(self, *args, **kwargs):
            return await original.query(*args, **kwargs)

    executor.gateway.client = LegacyOnly()
    with pytest.raises(Rejected, match="guarded dispatch"):
        arun(executor.complete(attempt, key))
    assert calls == []


@pytest.mark.parametrize("outcome", ["succeeded", "failed"])
def test_native_uncertain_terminal_replay_requires_current_proof_and_renewal(harness, outcome):
    executor, adapter, journal, attempt, key, _, _, _, state, result = prepare_executor(
        harness, outcome, expires=1002
    )
    original = executor.gateway.client.client.execute
    operation = "executor.complete" if outcome == "succeeded" else "executor.fail"

    def lost(envelope, **kwargs):
        response = original(envelope, **kwargs)
        if envelope["operation"] == operation:
            raise TimeoutError("response lost")
        return response

    executor.gateway.client.client.execute = lost
    finish = executor.complete if outcome == "succeeded" else executor.fail_delivery
    with pytest.raises(UnknownOutcome):
        arun(finish(attempt, key))
    suffix = "-complete" if outcome == "succeeded" else "-fail"
    before = journal.saved_command(key + suffix)
    calls = []

    def tracked(*args, **kwargs):
        calls.append(1)
        return original(*args, **kwargs)

    executor.gateway.client.client.execute = tracked
    state["now"] = 1002
    reconcile = (
        executor.reconcile_completion if outcome == "succeeded" else executor.reconcile_failure
    )
    with pytest.raises(Rejected):
        arun(reconcile(key))
    assert calls == [] and journal.get(key)["state"] == outcome
    token, verifier, _, _, _, renewed = native(
        journal.get(key)["work"], result, state=state, nonce=3, issued=1002, expires=1062
    )
    executor.result_verifier = verifier
    adapter.events = [renewed]
    arun(executor.receive("fixture"))
    after = journal.saved_command(key + suffix)
    assert after["body"] == before["body"] and after["digest"] == before["digest"]
    assert journal.get(key)["state"] == (
        "committed" if outcome == "succeeded" else "failed_committed"
    )
    assert len(adapter.sent) == 1 and journal.cursor("fixture") == "next-cursor"


def test_native_committed_receive_revalidates_and_renews_before_cursor(harness):
    executor, adapter, journal, attempt, key, _, _, _, state, result = prepare_executor(
        harness, expires=1002
    )
    arun(executor.complete(attempt, key))
    before = rows(journal, "deliveries")
    state["now"] = 1002
    adapter.events = [result]
    with pytest.raises(Rejected):
        arun(executor.receive("fixture"))
    assert journal.cursor("fixture") is None and rows(journal, "deliveries") == before
    _, verifier, _, _, _, renewed = native(
        journal.get(key)["work"], result, state=state, nonce=3, issued=1002, expires=1062
    )
    executor.result_verifier = verifier
    adapter.events = [renewed]
    assert arun(executor.receive("fixture")) == []
    assert journal.cursor("fixture") == "next-cursor" and rows(journal, "deliveries") == before


def test_mutated_caller_result_during_verification_cannot_change_executed_outputs(harness):
    executor, adapter, journal, work, actor, _ = harness
    attempt = arun(executor.claim(actor, work))
    adapter.outcome = "acknowledged"
    saved = arun(executor.dispatch(attempt, operation="compute", scope="answer"))
    key = saved["effect_key"]
    _, verifier, _, _, _, result = native(saved["work"], adapter.result(saved["work"], "succeeded"))

    class MutatingVerifier:
        mode = "native_unqualified"

        async def verify(self, *args):
            token = await verifier.verify(*args)
            result["outputs"]["answer"] = 999
            return token

    executor.result_verifier = MutatingVerifier()
    arun(executor.observe(attempt, key, result))
    assert journal.get(key)["result"]["outputs"] == {"answer": 14}
    arun(executor.complete(attempt, key))
    assert journal.get(key)["state"] == "committed"


def test_native_verifier_none_return_cannot_fall_back_to_legacy(harness):
    executor, adapter, journal, work, actor, _ = harness
    attempt = arun(executor.claim(actor, work))
    adapter.outcome = "acknowledged"
    saved = arun(executor.dispatch(attempt, operation="compute", scope="answer"))

    class Broken:
        mode = "native_unqualified"

        async def verify(self, *args):
            return None

    executor.result_verifier = Broken()
    with pytest.raises(Rejected, match="trusted admission"):
        arun(
            executor.observe(
                attempt, saved["effect_key"], adapter.result(saved["work"], "succeeded")
            )
        )
    assert journal.get(saved["effect_key"])["state"] == "acknowledged"


@pytest.mark.parametrize("before_commit", [False, True])
def test_native_process_crash_durability_and_rollback(tmp_path, before_commit):
    import subprocess
    from pathlib import Path
    from conftest import python_child, child_environment

    journal, token, _, _, _, work, result = prepared(tmp_path)
    if before_commit:
        with sqlite3.connect(journal.path) as db:
            db.execute(
                "CREATE TRIGGER crash_admission AFTER INSERT ON native_result_identity BEGIN SELECT crash(); END"
            )
    code = """import os,sys
sys.path.insert(0,sys.argv[2])
from contextlib import contextmanager
from frank_executor.journal import Journal
from test_native_result_journal import native
original=Journal.connection
@contextmanager
def connection(self):
    with original(self) as db:
        db.create_function('crash',0,lambda:os._exit(32))
        yield db
Journal.connection=connection
journal=Journal(sys.argv[1]);token,_,_,_,work,result=native()
journal.observation('effect',result,admission=token)
os._exit(31)
"""
    child = subprocess.run(
        python_child(["-c", code, journal.path, str(Path(__file__).parent)]),
        env=child_environment(),
        capture_output=True,
        text=True,
        timeout=90,
    )
    assert child.returncode == (32 if before_commit else 31), child.stderr
    reopened = Journal(journal.path)
    if before_commit:
        assert (
            rows(reopened, "native_result_replay")
            == rows(reopened, "native_result_identity")
            == rows(reopened, "native_result_proofs")
            == []
        )
        assert reopened.get("effect")["state"] == "unknown"
        with sqlite3.connect(journal.path) as db:
            db.execute("DROP TRIGGER crash_admission")
        assert reopened.observation("effect", result, admission=token)
    else:
        assert reopened.get("effect")["state"] == "succeeded"
        assert reopened.observation("effect", result, admission=token) is False
    assert len(rows(reopened, "native_result_replay")) == 1


def test_native_command_binding_rejects_other_body_and_does_not_admit_renewal(tmp_path):
    from process_runtime_client import command_envelope

    journal, token, _, _, state, work, result = prepared(tmp_path)
    journal.observation("effect", result, admission=token)
    renewed, _, _, _, _, new_result = native(work, result, state=state, nonce=3)
    bad = command_envelope(
        "executor.complete",
        request_id="wrong-outputs",
        expected_version=9,
        payload={**work["binding"], "outputs": {"answer": 999}},
    )
    journal.command(bad)
    with pytest.raises(Rejected, match="does not match"):
        journal.reauthorize("effect", new_result, renewed, bad)
    assert (
        len(rows(journal, "native_result_replay"))
        == len(rows(journal, "native_result_proofs"))
        == 1
    )
    assert rows(journal, "native_result_dispatch") == []


def test_native_same_nonce_cannot_move_to_another_effect(tmp_path):
    journal, token, _, _, _, work, result = prepared(tmp_path)
    journal.observation("effect", result, admission=token)
    second = deepcopy(work)
    second["effect_id"] = "effect-two"
    changed = deepcopy(result)
    changed["effect_id"] = "effect-two"
    changed["event_id"] = "event-two"
    second_token, _, _, _, _, changed = native(second, changed)
    journal.delivery("second", second)
    journal.begin_dispatch("second")
    with pytest.raises(Rejected, match="replay"):
        journal.observation("second", changed, admission=second_token)
    assert (
        journal.get("second")["state"] == "unknown"
        and len(rows(journal, "native_result_identity")) == 1
    )


def test_true_legacy_schema_additive_migration_preserves_bytes(tmp_path):
    from frank_executor.journal import APP_ID

    path = tmp_path / "legacy.db"
    work, result = work_result()
    result["proof"] = {"old-profile": "opaque"}
    command = {
        "request_id": "existing",
        "schema": "fixture",
        "payload": {"integer": 1, "float": 1.0},
    }
    with sqlite3.connect(path) as db:
        db.execute(f"PRAGMA application_id={APP_ID}")
        db.executescript("""
CREATE TABLE commands(request_id TEXT PRIMARY KEY,body TEXT NOT NULL,digest TEXT NOT NULL,state TEXT NOT NULL,response TEXT);
CREATE TABLE deliveries(effect_key TEXT PRIMARY KEY,work TEXT NOT NULL,digest TEXT NOT NULL,state TEXT NOT NULL,result TEXT);
CREATE TABLE events(integration_id TEXT NOT NULL,event_id TEXT NOT NULL,digest TEXT NOT NULL,PRIMARY KEY(integration_id,event_id));
CREATE TABLE cursors(integration_id TEXT PRIMARY KEY,cursor TEXT NOT NULL);
""")
        db.execute(
            "INSERT INTO deliveries VALUES (?,?,?,?,?)",
            (
                "effect",
                canonical(work).decode(),
                digest(work),
                "succeeded",
                canonical(result).decode(),
            ),
        )
        db.execute(
            "INSERT INTO events VALUES (?,?,?)",
            (result["integration_id"], result["event_id"], digest(result)),
        )
        db.execute(
            "INSERT INTO commands VALUES (?,?,?,?,?)",
            ("existing", canonical(command).decode(), digest(command), "pending", None),
        )
        before = {
            table: db.execute("SELECT * FROM " + table).fetchall()
            for table in ("deliveries", "events", "commands")
        }
    journal = Journal(path)
    assert all(rows(journal, table) == value for table, value in before.items())
    assert journal.result_digest("effect", result) == digest(result) and not journal.is_native(
        "effect"
    )


def test_native_renewal_preserves_numeric_canonical_distinction(tmp_path):
    journal, token, _, _, state, work, result = prepared(tmp_path)
    journal.observation("effect", result, admission=token)
    changed = deepcopy(result)
    changed["outputs"]["answer"] = 14.0
    renewed, _, _, _, _, changed = native(work, changed, state=state, nonce=3)
    with pytest.raises(Rejected, match="immutable"):
        journal.reauthorize("effect", changed, renewed)
    assert journal.get("effect")["result"]["outputs"]["answer"] == 14


def test_native_page_rechecks_authority_after_runtime_completion_before_cursor(harness):
    executor, adapter, journal, attempt, key, _, _, _, state, result = prepare_executor(harness)
    complete = executor.complete

    async def expires_after_complete(*args):
        value = await complete(*args)
        state["now"] = 1060
        return value

    executor.complete = expires_after_complete
    adapter.events = [result]
    with pytest.raises(Rejected):
        arun(executor.receive("fixture"))
    assert journal.get(key)["state"] == "committed" and journal.cursor("fixture") is None


def test_terminal_native_result_replay_revalidates_even_after_response_observed(harness):
    executor, _, journal, attempt, key, token, _, _, state, result = prepare_executor(harness)
    request_id = key + "-" + token.identity[:24]
    assert journal.saved_command(request_id)["state"] == "observed"
    state["now"] = 1060
    with pytest.raises(Rejected):
        arun(executor.gateway.replay(request_id, guard=executor._guard(key, result, token)))
    assert journal.saved_command(request_id)["state"] == "observed"


def test_actual_pinned_native_helper_admission_restart_and_nonce_renewal(tmp_path):
    import hashlib
    import shutil
    from frank_executor.native_results import NativeSecSHelper
    from test_native_result_compat import fixture, native_verifier, SOURCE, HELPER_SHA256

    assert SOURCE.is_file(), "Pinned native helper is required; this test cannot be skipped"
    binary = tmp_path / "native-verifier"
    shutil.copyfile(SOURCE, binary)
    binary.chmod(0o700)
    expected_hash = HELPER_SHA256
    assert hashlib.sha256(binary.read_bytes()).hexdigest() == expected_hash
    helper = NativeSecSHelper(binary, expected_hash)
    case = fixture("success")
    verifier, state = native_verifier(helper, case)
    token = arun(verifier.verify(case["result"], case["work"]))
    journal = Journal(tmp_path / "actual-native.db")
    journal.delivery("native-effect", case["work"])
    journal.begin_dispatch("native-effect")
    assert journal.observation("native-effect", case["result"], admission=token)
    before = rows(journal, "deliveries")
    events = rows(journal, "events")
    journal = Journal(journal.path)
    assert journal.observation("native-effect", case["result"], admission=token) is False
    renewal = fixture("renewed")
    state["now"] = renewal["now_seconds"]
    renewed = arun(verifier.verify(renewal["result"], renewal["work"]))
    assert renewed.identity == token.identity and renewed.replay_key != token.replay_key
    journal.reauthorize("native-effect", renewal["result"], renewed)
    assert rows(journal, "deliveries") == before and rows(journal, "events") == events
    assert (
        len(rows(journal, "native_result_proofs"))
        == len(rows(journal, "native_result_replay"))
        == 2
    )
    assert journal.get("native-effect")["result"]["proof"] == renewal["result"]["proof"]
    state["now"] = 2000
    with pytest.raises(Rejected):
        journal.reauthorize("native-effect", renewal["result"], renewed)
    assert rows(journal, "deliveries") == before


@pytest.mark.parametrize("advance_first_clock", [True, False])
def test_native_page_final_shared_time_rejects_earlier_expiry_atomically(
    tmp_path, advance_first_clock
):
    journal, token1, _, _, state1, work1, result1 = prepared(tmp_path)
    journal.observation("effect", result1, admission=token1)
    work2, result2 = deepcopy(work1), deepcopy(result1)
    work2["effect_id"] = result2["effect_id"] = "second-effect"
    result2["event_id"] = "second-event"
    token2, _, _, state2, work2, result2 = native(work2, result2, nonce=3)
    journal.delivery("effect2", work2)
    journal.begin_dispatch("effect2")
    journal.observation("effect2", result2, admission=token2)
    journal.cursor("fixture", "page-before")
    # Both proofs are fresh nonce renewals so a failed page must roll back their
    # proof and replay writes as well as retain the earlier cursor and first bytes.
    renewed1, _, _, _, _, result1 = native(
        work1, result1, state=state1, nonce=4, expires=1002
    )
    renewed2, _, helper2, _, _, result2 = native(work2, result2, state=state2, nonce=5)
    tables = ["native_result_proofs", "native_result_replay", "deliveries", "events", "cursors"]
    before = {table: rows(journal, table) for table in tables}
    original_check = helper2.check_available

    def delayed_second_check():
        original_check()
        state2["now"] = 1002
        if advance_first_clock:
            state1["now"] = 1002

    helper2.check_available = delayed_second_check
    admissions = (("effect", result1, renewed1), ("effect2", result2, renewed2))
    with pytest.raises(Rejected):
        journal.cursor("fixture", "page-after", admissions=admissions)
    assert {table: rows(journal, table) for table in tables} == before
    # The same nonce pair is usable after the synthetic delay is removed: failed
    # batch admission did not burn either nonce or alter stored result evidence.
    helper2.check_available = original_check
    state1["now"] = state2["now"] = 1001
    assert journal.cursor("fixture", "page-after", admissions=admissions) == "page-after"
    assert len(rows(journal, "native_result_proofs")) == 4
    assert len(rows(journal, "native_result_replay")) == 4
    assert rows(journal, "deliveries") == before["deliveries"]
    assert rows(journal, "events") == before["events"]
