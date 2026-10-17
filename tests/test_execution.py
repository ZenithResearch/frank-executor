from __future__ import annotations
import asyncio
from copy import deepcopy
import pytest
from frank_executor.authority import (
    DenyAuthority,
    DenyResults,
    check_authority,
    LocalDevAuthority,
    LocalDevResults,
)
from frank_executor.journal import Journal
from frank_executor.model import Binding, Rejected, UnknownOutcome, effect_key
from frank_executor.runtime import RuntimeFailure
from conftest import arun


def claim(harness, lease_ms=120000):
    executor, _, _, work, actor, _ = harness
    return arun(executor.claim(actor, work, lease_ms=lease_ms))


def test_public_provider_claim_effect_complete_and_immutable_snapshot(harness):
    executor, adapter, journal, work, actor, client = harness
    attempt = claim(harness)
    inputs = attempt.inputs
    inputs["number"] = 999
    assert attempt.inputs == {"number": 7}
    outcome = arun(executor.run(attempt, operation="compute", scope="answer", wait_seconds=10))
    assert outcome["state"] == "committed" and len(adapter.sent) == 1
    run = client.query(
        {
            "schema": "runtime.query.v1",
            "operation": "run.get",
            "payload": {"run_id": work["run_id"]},
        }
    )["data"]
    assert run["state"] == "succeeded"
    assert journal.unresolved() == []
    assert arun(executor.work(actor))["work"] == []


def test_acknowledgement_never_completes_and_delayed_result_completes(harness):
    executor, adapter, journal, _, _, _ = harness
    attempt = claim(harness)
    adapter.outcome = "acknowledged"
    saved = arun(executor.dispatch(attempt, operation="compute", scope="answer"))
    with pytest.raises(Rejected, match="successful"):
        arun(executor.complete(attempt, saved["effect_key"]))
    assert saved["state"] == "acknowledged"
    adapter.events = [adapter.result(adapter.sent[0], "succeeded")]
    result = arun(
        executor.run(attempt, operation="compute", scope="answer", resume=True, wait_seconds=10)
    )
    assert result["state"] == "committed" and len(adapter.sent) == 1
    assert journal.cursor("fixture") == "next-cursor"
    adapter.events = [adapter.result(adapter.sent[0], "succeeded")]
    assert arun(executor.receive("fixture")) == []


@pytest.mark.parametrize(
    "failure",
    [TimeoutError("before send or after send is unknowable"), ConnectionError("lost ack")],
)
def test_unknown_provider_never_resends_across_restart(harness, failure):
    executor, adapter, journal, _, actor, _ = harness
    attempt = claim(harness)
    adapter.failure = failure
    with pytest.raises(UnknownOutcome):
        arun(executor.dispatch(attempt, operation="compute", scope="answer"))
    key = effect_key(attempt.binding, "compute", "answer")
    restarted = Journal(journal.path)
    executor.journal = restarted
    executor.gateway.journal = restarted
    recovered = arun(executor.recover(attempt.binding, actor))
    assert (
        arun(executor.dispatch(recovered, operation="compute", scope="answer"))["state"]
        == "unknown"
    )
    assert (
        arun(executor.reconcile(recovered, key))["action"]
        == "native operator reconciliation required"
    )
    assert len(adapter.sent) == 1
    assert restarted.get(key)["state"] == "unknown"


@pytest.mark.parametrize(
    "field,value",
    [
        ("actor_id", "other"),
        ("integration_id", "other"),
        ("route", "other"),
        ("effect_id", "other"),
    ],
)
def test_unrelated_results_cannot_change_evidence_or_runtime(harness, field, value):
    executor, adapter, journal, _, _, _ = harness
    attempt = claim(harness)
    adapter.outcome = "acknowledged"
    saved = arun(executor.dispatch(attempt, operation="compute", scope="answer"))
    result = adapter.result(adapter.sent[0], "succeeded")
    result[field] = value
    with pytest.raises(Rejected, match="correlation"):
        arun(executor.observe(attempt, saved["effect_key"], result))
    assert journal.get(saved["effect_key"])["state"] == "acknowledged"


def test_expired_and_wrong_fence_rejected_before_external_effect(harness):
    executor, adapter, _, _, actor, _ = harness
    attempt = claim(harness)
    with pytest.raises(Rejected, match="correlation"):
        arun(
            executor.recover(
                Binding(
                    attempt.binding.run_id,
                    attempt.binding.step_id,
                    attempt.binding.attempt_id,
                    attempt.binding.fence + 1,
                ),
                actor,
            )
        )
    executor.clock = lambda: attempt.lease_expires_at_ms
    with pytest.raises(Rejected, match="lease"):
        arun(executor.dispatch(attempt, operation="compute", scope="answer"))
    assert adapter.sent == []


def test_heartbeat_release_and_retry_are_distinct_runtime_attempts(harness):
    executor, adapter, _, work, actor, _ = harness
    first = claim(harness)
    version = first.step_version
    arun(executor.heartbeat(first, lease_ms=180000))
    assert first.step_version > version
    arun(executor.release(first, "Yield without effects"))
    fresh = next(
        item for item in arun(executor.work(actor))["work"] if item["run_id"] == work["run_id"]
    )
    second = arun(executor.claim(actor, fresh))
    assert (
        second.binding.attempt_id != first.binding.attempt_id
        and second.binding.fence > first.binding.fence
    )
    with pytest.raises(Rejected):
        arun(executor.heartbeat(first))
    arun(executor.fail(second, "Known computation failure"))
    assert adapter.sent == []


def test_runtime_claim_has_one_winner_for_concurrent_franks(harness):
    executor, adapter, _, work, actor, _ = harness

    async def race():
        return await asyncio.gather(
            *(executor.claim(actor, work) for _ in range(8)), return_exceptions=True
        )

    outcomes = arun(race())
    assert sum(not isinstance(item, Exception) for item in outcomes) == 1
    assert all(
        not isinstance(item, Exception) or isinstance(item, RuntimeFailure) for item in outcomes
    )
    assert adapter.sent == []


def test_lost_runtime_completion_replays_exact_saved_command_after_restart(harness):
    executor, adapter, journal, _, _, client = harness
    attempt = claim(harness)
    saved = arun(executor.dispatch(attempt, operation="compute", scope="answer"))
    original = executor.gateway.client.command

    async def lose(envelope, **kwargs):
        response = await original(envelope, **kwargs)
        if envelope["operation"] == "executor.complete":
            raise TimeoutError("response lost after commit")
        return response

    executor.gateway.client.command = lose
    with pytest.raises(UnknownOutcome):
        arun(executor.complete(attempt, saved["effect_key"]))
    assert journal.get(saved["effect_key"])["state"] == "succeeded"
    executor.gateway.client.command = original
    executor.journal = Journal(journal.path)
    executor.gateway.journal = executor.journal
    receipt = arun(executor.reconcile_completion(saved["effect_key"]))
    assert receipt["duplicate"] is True
    assert executor.journal.get(saved["effect_key"])["state"] == "committed"
    assert len(adapter.sent) == 1


def test_duplicate_changed_provider_event_rejected(harness):
    executor, adapter, journal, _, _, _ = harness
    attempt = claim(harness)
    adapter.outcome = "acknowledged"
    saved = arun(executor.dispatch(attempt, operation="compute", scope="answer"))
    result = deepcopy(saved["result"])
    result["provider_reference"] = "changed"
    with pytest.raises(Rejected, match="changed"):
        arun(executor.observe(attempt, saved["effect_key"], result))
    assert journal.get(saved["effect_key"])["result"] == saved["result"]


def test_result_recorded_before_runtime_observe_crash_recovers(harness):
    executor, adapter, journal, _, actor, _ = harness
    attempt = claim(harness)
    adapter.outcome = "acknowledged"
    saved = arun(executor.dispatch(attempt, operation="compute", scope="answer"))
    result = adapter.result(adapter.sent[0], "succeeded")
    assert journal.observation(saved["effect_key"], result)
    recovered = arun(executor.recover(attempt.binding, actor))
    arun(executor.observe(recovered, saved["effect_key"], result))
    arun(executor.complete(recovered, saved["effect_key"]))
    assert journal.get(saved["effect_key"])["state"] == "committed"


def test_supervision_cancels_delivery_on_heartbeat_loss(harness):
    executor, adapter, journal, _, _, _ = harness
    attempt = claim(harness)
    sent = asyncio.Event()

    async def blocked(work):
        adapter.sent.append(work)
        sent.set()
        await asyncio.Event().wait()

    adapter.send = blocked

    async def lost(attempt, **kwargs):
        await sent.wait()
        attempt.active = False
        raise RuntimeFailure("stale_fence")

    executor.heartbeat = lost
    with pytest.raises(RuntimeFailure):
        arun(executor.run(attempt, operation="compute", scope="answer", lease_ms=3, wait_seconds=2))
    assert len(adapter.sent) == 1
    assert journal.get(effect_key(attempt.binding, "compute", "answer"))["state"] == "unknown"
    assert attempt.active is False and len(adapter.cancelled) == 1


def test_wait_timeout_retains_ack_and_cancels_advisory(harness):
    executor, adapter, journal, _, _, _ = harness
    attempt = claim(harness)
    adapter.outcome = "acknowledged"
    with pytest.raises(UnknownOutcome, match="wait expired"):
        arun(
            executor.run(
                attempt, operation="compute", scope="answer", wait_seconds=0.15, poll_seconds=0.02
            )
        )
    assert journal.get(effect_key(attempt.binding, "compute", "answer"))["state"] == "acknowledged"
    assert len(adapter.cancelled) == 1 and len(adapter.sent) == 1


@pytest.mark.parametrize(
    "reason",
    [
        "revoked",
        "expired",
        "replay",
        "wrong audience",
        "wrong operation",
        "wrong resource",
        "Matrix provenance only",
    ],
)
def test_unavailable_native_authority_denies_before_network(harness, reason):
    executor, adapter, journal, work, actor, _ = harness

    class RejectAuthority:
        mode = "secs_verified"

        async def evidence(self, envelope):
            raise Rejected(reason)

    executor.gateway.authority = RejectAuthority()
    with pytest.raises(Rejected, match=reason):
        arun(executor.claim(actor, work))
    assert adapter.sent == []
    # These test the injected port boundary, not cryptographic/native verifier qualification.


@pytest.mark.parametrize(
    "port", [DenyAuthority(), LocalDevAuthority(lambda _: b"x", environment="test", enabled=True)]
)
def test_production_rejects_unqualified_ports(port):
    with pytest.raises(Rejected):
        check_authority("production", port, DenyResults())
    with pytest.raises(Rejected):
        LocalDevResults(environment="production", enabled=True)


def test_runtime_rejects_bool_as_integer_output_without_completion(harness):
    executor, adapter, journal, _, _, _ = harness
    attempt = claim(harness)
    original = adapter.result

    def wrong(work, outcome=None):
        result = original(work, outcome)
        result["outputs"]["answer"] = True
        return result

    adapter.result = wrong
    saved = arun(executor.dispatch(attempt, operation="compute", scope="answer"))
    with pytest.raises(RuntimeFailure):
        arun(executor.complete(attempt, saved["effect_key"]))
    assert journal.get(saved["effect_key"])["state"] == "succeeded" and not attempt.active
    assert len(adapter.sent) == 1


def test_version_skew_response_does_not_become_observed(harness):
    executor, adapter, journal, work, actor, _ = harness

    async def skew(envelope, **kwargs):
        return {"schema": "runtime.result.v99", "request_id": envelope["request_id"]}

    executor.gateway.client.command = skew
    with pytest.raises(Rejected, match="contract"):
        arun(executor.claim(actor, work, request_id="skew-test"))
    assert journal.saved_command("skew-test")["state"] == "pending"
    assert adapter.sent == []


def test_native_result_rejection_prevents_terminal_observation(harness):
    executor, adapter, journal, _, _, _ = harness
    attempt = claim(harness)
    adapter.outcome = "acknowledged"
    saved = arun(executor.dispatch(attempt, operation="compute", scope="answer"))
    executor.result_verifier = DenyResults()
    with pytest.raises(Rejected, match="not qualified"):
        arun(
            executor.observe(
                attempt, saved["effect_key"], adapter.result(adapter.sent[0], "succeeded")
            )
        )
    assert journal.get(saved["effect_key"])["state"] == "acknowledged"


def test_delayed_dispatch_response_cannot_send_after_lease_expiry(harness):
    executor, adapter, journal, _, _, _ = harness
    attempt = claim(harness)
    original = executor.gateway.client.command

    async def delayed(envelope, **kwargs):
        response = await original(envelope, **kwargs)
        if envelope["operation"] == "executor.effect.dispatch":
            executor.clock = lambda: attempt.lease_expires_at_ms
        return response

    executor.gateway.client.command = delayed
    with pytest.raises(Rejected, match="live lease"):
        arun(executor.dispatch(attempt, operation="compute", scope="answer"))
    assert adapter.sent == []
    assert journal.get(effect_key(attempt.binding, "compute", "answer"))["state"] == "unknown"


def failed_delivery(harness):
    executor, adapter, _, _, _, _ = harness
    attempt = claim(harness)
    adapter.outcome = "acknowledged"
    saved = arun(executor.dispatch(attempt, operation="compute", scope="answer"))
    failure = adapter.result(adapter.sent[0], "failed")
    return saved["effect_key"], failure


def test_duplicate_failed_event_is_terminal_and_cursor_can_advance(harness):
    executor, adapter, journal, _, _, _ = harness
    key, failure = failed_delivery(harness)
    adapter.events = [failure]
    arun(executor.receive("fixture"))
    assert journal.get(key)["state"] == "failed_committed"
    adapter.events = [failure]
    assert arun(executor.receive("fixture")) == []
    assert journal.cursor("fixture") == "next-cursor" and journal.unresolved() == []
    changed = deepcopy(failure)
    changed["provider_reference"] = "changed"
    adapter.events = [changed]
    with pytest.raises(Rejected, match="changed"):
        arun(executor.receive("fixture"))


def test_failed_runtime_response_loss_reconciles_without_recovering_retired_attempt(harness):
    executor, adapter, journal, _, _, _ = harness
    key, failure = failed_delivery(harness)
    original = executor.gateway.client.command

    async def lost(envelope, **kwargs):
        response = await original(envelope, **kwargs)
        if envelope["operation"] == "executor.fail":
            raise TimeoutError("response lost after failure commit")
        return response

    executor.gateway.client.command = lost
    adapter.events = [failure]
    with pytest.raises(UnknownOutcome):
        arun(executor.receive("fixture"))
    assert journal.get(key)["state"] == "failed" and journal.cursor("fixture") is None
    executor.gateway.client.command = original
    executor.journal = Journal(journal.path)
    executor.gateway.journal = executor.journal
    adapter.events = [failure]
    arun(executor.receive("fixture"))
    assert executor.journal.get(key)["state"] == "failed_committed"
    assert executor.journal.cursor("fixture") == "next-cursor" and len(adapter.sent) == 1


def test_failure_committed_before_cursor_checkpoint_survives_restart(harness):
    executor, adapter, journal, _, _, _ = harness
    key, failure = failed_delivery(harness)
    cursor = journal.cursor

    def crash(integration_id, new=None):
        if new is not None:
            raise OSError("simulated crash before cursor commit")
        return cursor(integration_id)

    journal.cursor = crash
    adapter.events = [failure]
    with pytest.raises(OSError):
        arun(executor.receive("fixture"))
    restarted = Journal(journal.path)
    executor.journal = restarted
    executor.gateway.journal = restarted
    assert restarted.get(key)["state"] == "failed_committed" and restarted.cursor("fixture") is None
    adapter.events = [failure]
    arun(executor.receive("fixture"))
    assert restarted.cursor("fixture") == "next-cursor" and len(adapter.sent) == 1


def test_replayed_page_accepts_retained_ack_before_terminal_result(harness):
    executor, adapter, journal, _, _, _ = harness
    attempt = claim(harness)
    adapter.outcome = "acknowledged"
    saved = arun(executor.dispatch(attempt, operation="compute", scope="answer"))
    success = adapter.result(adapter.sent[0], "succeeded")
    adapter.events = [success]
    arun(executor.receive("fixture"))
    adapter.events = [saved["result"], success]
    assert arun(executor.receive("fixture")) == []
    assert journal.cursor("fixture") == "next-cursor" and len(adapter.sent) == 1


def test_receive_reconciles_lost_success_response_before_cursor_checkpoint(harness):
    executor, adapter, journal, _, _, _ = harness
    attempt = claim(harness)
    adapter.outcome = "acknowledged"
    saved = arun(executor.dispatch(attempt, operation="compute", scope="answer"))
    success = adapter.result(adapter.sent[0], "succeeded")
    original = executor.gateway.client.command

    async def lost(envelope, **kwargs):
        response = await original(envelope, **kwargs)
        if envelope["operation"] == "executor.complete":
            raise TimeoutError("completion response lost")
        return response

    executor.gateway.client.command = lost
    adapter.events = [success]
    with pytest.raises(UnknownOutcome):
        arun(executor.receive("fixture"))
    assert (
        journal.get(saved["effect_key"])["state"] == "succeeded"
        and journal.cursor("fixture") is None
    )
    executor.gateway.client.command = original
    adapter.events = [success]
    arun(executor.receive("fixture"))
    assert (
        journal.get(saved["effect_key"])["state"] == "committed"
        and journal.cursor("fixture") == "next-cursor"
    )
