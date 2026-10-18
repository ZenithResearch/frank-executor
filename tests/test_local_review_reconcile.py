"""Ordinary Executor recovery; synthetic authority is only a unit seam."""
import asyncio
from dataclasses import replace

import pytest

from frank_executor.authority import DenyAuthority
from frank_executor.executor import ClaimedAttempt, Executor
from frank_executor.journal import Journal
from frank_executor.model import Binding, Rejected, UnknownOutcome, canonical, effect_key
from frank_executor.native_result_producer import NativeResultProducer
from frank_executor.native_results import payload_for
from frank_executor.registry import Registry
from frank_review_adapter.adapter import ReviewAdapter
from frank_review_adapter.local_capture import LocalReviewCapture
from frank_review_adapter.ports import ReviewFailure
from process_runtime_client import command_envelope
from test_local_review_capture import result_for
from test_local_review_ports import adapter_fixture
from test_native_result_producer import PROOF


class DispatchGateway:
    """Retain exact commands and invoke actual native admission guards.

    This finite unit seam replaces the Runtime receiver, not the Executor,
    adapter, capture, result producer, verifier or journal.
    """
    authority = DenyAuthority()

    def __init__(self, journal):
        self.journal = journal
        self.commands = []

    async def execute(self, operation, payload, expected_version, *, request_id=None, guard=None):
        command = command_envelope(operation, request_id=request_id,
                                   expected_version=expected_version, payload=payload)
        self.journal.command(command)
        if guard is not None:
            guard(command)
        self.commands.append(command)
        result = {"effect_id":"effect-1"} if operation == "executor.effect.intent" else {}
        return {"version":expected_version + 1, "result":result}


def registry(adapter):
    return Registry({"schema":"frank.integrations.v1",
        "integrations":[{"id":"fixture","plugin":"review","enabled":True,"config":{}}],
        "actors":[{"actor_id":"worker","integration_id":"fixture","route":"local",
                   "capabilities":["review.bind_source"],"resources":[]}]},
        {"review":lambda *_:adapter})


def test_executor_recovers_missing_reference_from_exact_capture_without_recomputing(tmp_path):
    adapter, capture, work, producer, claims, sources, ports, calls = adapter_fixture(tmp_path)
    work["inputs"]["observations"] = [{"observation_id":"o","selectors":["button.x"],
        "component":"button.x","match_type":"unresolved"}]
    sources.failure = ReviewFailure("malformed_source_evidence")
    producer.verifier.helper.request_hex = payload_for(result_for(work, {}, "failed"), work).hex()
    original_transport = producer.transport.request
    selectors = []

    async def lose_first_output(mode, selector):
        selectors.append((mode, selector))
        result = await original_transport(mode, selector)
        if mode == "attest":
            raise Rejected("unit discards completed Native output")
        return result

    producer.transport.request = lose_first_output

    async def case():
        initial_registry = registry(adapter)
        await initial_registry.connect()
        gateway = DispatchGateway(capture.journal)
        executor = Executor(gateway, initial_registry, capture.journal, producer.verifier,
                            environment="test", clock=lambda:1_001_000)
        binding = Binding.read(work["binding"])
        attempt = ClaimedAttempt(binding, work["actor_id"], 1, 1_100_000,
            canonical(work["inputs"]).decode(), canonical(work["output_types"]).decode(), "{}")
        key = effect_key(binding, work["operation"], work["scope"])
        with pytest.raises(UnknownOutcome, match="outcome unknown"):
            await executor.dispatch(attempt, operation=work["operation"], scope=work["scope"])
        assert capture.journal.get(key)["result"] is None
        assert capture.journal.get(key)["state"] == "unknown"
        original = capture.retained(work)
        assert original["result"]["outcome"] == "failed" and sources.calls == 1
        pending = capture.exchange(work)
        assert pending["envelope"] is None and pending["mode"] == "attest"
        await initial_registry.close()

        # Reopen the durable journal/capture and compose ordinary dependencies.
        journal = Journal(capture.journal.path)
        reopened_capture = LocalReviewCapture(journal, capture.root, capture.policy)
        resumed = NativeResultProducer(capture=reopened_capture, claims=claims, verifier=producer.verifier,
            executable=tmp_path / "never-executed-unit-program", executable_sha256="a"*64,
            configuration=tmp_path / "never-read-unit-config", configuration_sha256="b"*64)
        resumed.transport.request = lose_first_output
        resumed.transport.check_available = lambda:None
        reopened = ReviewAdapter.local_native("fixture", {"effects":"disabled","route":"local"},
            ports=replace(ports, results=resumed), capture=reopened_capture, producer=resumed,
            environment="test")
        reopened_registry = registry(reopened)
        await reopened_registry.connect()
        try:
            # A supplied conflicting reference still denies before any resume.
            with pytest.raises(Rejected, match="reference mismatch"):
                await reopened.reconcile(work, "local-review:wrong")
            assert calls == ["attest"] and sources.calls == 1
            recovering = Executor(DispatchGateway(journal), reopened_registry, journal,
                                  resumed.verifier, environment="test", clock=lambda:1_001_000)
            recovered = await recovering.reconcile(attempt, key)
            assert recovered["state"] == "failed"
            assert recovered["result"] == {**original["result"], "proof":PROOF}
            assert calls == ["attest", "resume"] and sources.calls == 1
            assert selectors[0][1] == selectors[1][1] == bytes(pending["selector"])
            current = reopened_capture.retained(work)
            assert all(current[name] == original[name] for name in ("capture_id","payload","receipt","result"))
            assert [c["operation"] for c in recovering.gateway.commands] == ["executor.effect.observe"]
            with journal.connection() as db:
                assert db.execute("SELECT count(*) FROM native_result_identity").fetchone()[0] == 1
        finally:
            await reopened_registry.close()
    asyncio.run(case())


def test_absent_capture_cannot_recover_a_missing_reference(tmp_path):
    adapter, capture, work, producer, claims, sources, ports, calls = adapter_fixture(tmp_path)
    async def case():
        await adapter.connect()
        try:
            assert await adapter.reconcile(work, None) is None
            assert sources.calls == 0 and calls == []
        finally:
            await adapter.close()
    asyncio.run(case())
