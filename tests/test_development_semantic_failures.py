"""Computed development failures; upstream corruption is explicit test-only data."""
from __future__ import annotations

import asyncio
from importlib.resources import files
import json
from pathlib import Path
import uuid

import pytest

from frank_executor.authority import LocalDevAuthority, LocalDevResults
from frank_executor.executor import Executor
from frank_executor.journal import Journal
from frank_executor.model import digest, effect_key
from frank_executor.registry import Registry
from frank_executor.runtime import ContractValidator, GeneratedClientAdapter, RuntimeFailure, RuntimeGateway
from frank_review_adapter.development import DevelopmentAdapter
from frank_review_adapter.fixture_ports import (
    FrozenSTT, MemoryArtifacts, SimulatedIntents, SnapshotSources, SyntheticClaims, SyntheticResults,
)
from frank_review_adapter.ports import ReviewPorts
from frank_review_adapter.verification import PublicArtifacts, PublicClaims, publish
from process_runtime_client import LocalDevAuthority as SDKAuthority, RuntimeClient


FIXTURES = Path(__file__).parent / "fixtures/independent-review"
DEVELOPMENT = json.loads((FIXTURES / "development-sop-v1.json").read_text())
SPECS = {step["step_id"]: step for step in DEVELOPMENT["steps"]}
BEFORE = "def add(a, b):\n    return a - b\n"
GOOD = "def add(a, b):\n    return a + b\n"
FAILURES = [
    ("unit-tests", BEFORE, "development_unit_tests_failed"),
    ("contract-tests", "def renamed(a, b):\n    return a + b\n", "development_contract_tests_failed"),
]


def ports_for(artifacts=None, claims=None):
    sources = SnapshotSources({})
    return ReviewPorts(artifacts or MemoryArtifacts(), FrozenSTT(b"", {}), sources, sources,
                       SimulatedIntents(), claims or SyntheticClaims(), SyntheticResults())


async def patch_artifact(artifacts, after):
    return await artifacts.write(json.dumps({"before": BEFORE, "after": after, "path": "calc.py"},
                                           sort_keys=True).encode(), "application/json")


async def send_synthetic(adapter, ports, operation, inputs, step_id):
    packet = {"schema": "frank.work.v1", "binding": {"run_id": "synthetic-development",
              "step_id": step_id, "attempt_id": "synthetic-attempt", "fence": 1},
              "actor_id": "worker", "integration_id": adapter.integration_id, "route": "local",
              "effect_id": "development-failure", "operation": operation, "scope": "test",
              "inputs": inputs, "output_types": SPECS[step_id]["outputs"]}
    ports.claims.confirm(packet)
    return await adapter.send(packet)


@pytest.mark.parametrize("step_id,after,code", FAILURES)
def test_computed_false_development_check_fails_without_success_artifact(step_id, after, code):
    async def run():
        ports = ports_for()
        adapter = DevelopmentAdapter("development-fixture", {"effects": "disabled", "route": "local"},
                                     ports=ports, environment="test")
        patch = await patch_artifact(ports.artifacts, after)
        retained = dict(ports.artifacts.contents)
        await adapter.connect()
        try:
            result = await send_synthetic(adapter, ports, "development." + step_id, {"patch": patch}, step_id)
            assert result["outcome"] == "failed" and result["outputs"] == {}
            assert adapter.decisions[-1]["code"] == code
            assert ports.artifacts.contents == retained and ports.intents.intents == []
        finally:
            await adapter.close()
    asyncio.run(run())


def test_explicit_automated_review_rejection_fails_without_success_artifact():
    async def run():
        ports = ports_for()
        adapter = DevelopmentAdapter("development-fixture", {"effects": "disabled", "route": "local"},
                                     ports=ports, environment="test")
        patch = await patch_artifact(ports.artifacts, GOOD)
        unit = await ports.artifacts.write(b'{"passed":false}', "application/json")
        contract = await ports.artifacts.write(b'{"passed":true}', "application/json")
        retained = dict(ports.artifacts.contents)
        await adapter.connect()
        try:
            result = await send_synthetic(adapter, ports, "development.review", {
                "patch": patch, "unit_passed": False, "unit_report": unit,
                "contract_passed": True, "contract_report": contract}, "review")
            assert result["outcome"] == "failed" and result["outputs"] == {}
            assert adapter.decisions[-1]["code"] == "development_review_not_approved"
            assert ports.artifacts.contents == retained and ports.intents.intents == []
        finally:
            await adapter.close()
    asyncio.run(run())


@pytest.mark.parametrize("failed_step,after,code", FAILURES)
def test_public_runtime_development_failure_retains_sibling_and_blocks_join(provider, tmp_path, failed_step, after, code):
    async def run():
        endpoint = provider[0]
        signer = SDKAuthority(environment="test")
        client = RuntimeClient(endpoint, authority=signer)
        pin = await asyncio.to_thread(publish, client, DEVELOPMENT)
        artifacts = PublicArtifacts(client)
        ports = ports_for(artifacts, PublicClaims(client, SPECS, pin))
        adapter = DevelopmentAdapter("development-fixture", {"effects": "disabled", "route": "local"},
                                     ports=ports, environment="test")
        actor_id = "development-fault-worker-" + uuid.uuid4().hex
        registry = Registry({"schema": "frank.integrations.v1", "integrations": [
            {"id": adapter.integration_id, "plugin": "development.test-only", "enabled": True, "config": {}}],
            "actors": [{"actor_id": actor_id, "integration_id": adapter.integration_id, "route": "local",
                "capabilities": sorted({cap for step in SPECS.values() for cap in step["capabilities"]}),
                "resources": sorted({resource for step in SPECS.values() for resource in step["resources"]})}]},
            {"development.test-only": lambda *_: adapter})
        journal = Journal(tmp_path / "development-fault-frank.db")
        schema = json.loads(files("process_runtime_client").joinpath("runtime-v1.schema.json").read_text())
        gateway = RuntimeGateway(GeneratedClientAdapter(RuntimeClient(endpoint)),
            LocalDevAuthority(lambda raw: signer(json.loads(raw)), environment="test", enabled=True),
            journal, ContractValidator(schema))
        executor = Executor(gateway, registry, journal, LocalDevResults(environment="test", enabled=True), environment="test")
        run_id = "development-fault-" + uuid.uuid4().hex
        snapshot = await artifacts.write(json.dumps({"calc.py": BEFORE}).encode(), "application/json")
        scope = "test-only-faulty-upstream-patch"

        async def ready():
            page = await executor.work(actor_id, limit=100)
            return {work["step_id"]: work for work in page["work"] if work["run_id"] == run_id}

        await registry.connect()
        try:
            await executor.register(actor_id)
            await gateway.execute("run.create", {"run_id": run_id, "pin": pin, "inputs": {
                "change_request": "Make add(a, b) return a + b.", "repository_snapshot": snapshot}}, None)
            upstream = await ready()
            assert set(upstream) == {"scope"}
            attempt = await executor.claim(actor_id, upstream["scope"])
            await executor.run(attempt, operation="development.scope", scope=scope, wait_seconds=30)

            upstream = await ready()
            assert set(upstream) == {"implement"}
            attempt = await executor.claim(actor_id, upstream["implement"])
            # Fault injection only: commit an intentionally wrong, hashed upstream patch via
            # the public test runtime. No production hook or expected handler output is used.
            faulty_patch = await patch_artifact(artifacts, after)
            await gateway.execute("executor.complete", {**attempt.binding.json(),
                                  "outputs": {"patch": faulty_patch}}, attempt.step_version)

            branches = await ready()
            assert set(branches) == {"unit-tests", "contract-tests"}
            attempts = {}
            for step_id, work in branches.items():
                actors, _ = registry.match(SPECS[step_id]["capabilities"], SPECS[step_id]["resources"])
                assert actor_id in {actor.actor_id for actor in actors}
                attempts[step_id] = await executor.claim(actor_id, work)
            # Compute both claimed branches before committing failure, then retain the
            # successful sibling after it. Only public work.list decided readiness.
            keys = {}
            for step_id, attempt in attempts.items():
                operation = SPECS[step_id]["capabilities"][0]
                await executor.dispatch(attempt, operation=operation, scope=scope)
                keys[step_id] = effect_key(attempt.binding, operation, scope)
            failed = attempts[failed_step]
            sibling_step = ({"unit-tests", "contract-tests"} - {failed_step}).pop()
            sibling = attempts[sibling_step]
            assert journal.get(keys[failed_step])["result"]["outputs"] == {}
            assert journal.get(keys[failed_step])["state"] == "failed"
            failure = await executor.fail_delivery(failed, keys[failed_step])
            success = await executor.complete(sibling, keys[sibling_step])
            failed_receipt = await gateway.query("receipt.get", {"receipt_id": failure["receipt_id"]})
            sibling_receipt = await gateway.query("receipt.get", {"receipt_id": success["receipt_id"]})
            for attempt, receipt, outcome in ((failed, failed_receipt, "failed"), (sibling, sibling_receipt, "succeeded")):
                assert all(receipt[field] == value for field, value in attempt.binding.json().items())
                assert receipt["actor_id"] == actor_id and receipt["pin"] == pin
                assert receipt["input_digest"] == digest(attempt.inputs) and receipt["outcome"] == outcome
            assert failed_receipt["output_digest"] is None
            with pytest.raises(RuntimeFailure) as missing:
                await gateway.query("output.get", {key: value for key, value in failed.binding.json().items() if key != "fence"})
            assert missing.value.code == "not_found"
            output = await gateway.query("output.get", {key: value for key, value in sibling.binding.json().items() if key != "fence"})
            assert output["output_digest"] == sibling_receipt["output_digest"]
            assert output["output_digest"] == digest(journal.get(keys[sibling_step])["result"]["outputs"])
            state = await gateway.query("run.get", {"run_id": run_id})
            states = {step["step_id"]: step["state"] for step in state["steps"]}
            assert state["state"] == "failed"
            assert states[failed_step] == "failed" and states[sibling_step] == "succeeded"
            assert states["review"] == states["package"] == "waiting"
            assert await ready() == {}
            assert ports.intents.intents == [] and ports.stt.calls == 0
            assert all(getattr(port, "effects_disabled", False) for port in (
                ports.artifacts, ports.stt, ports.components, ports.sources, ports.intents, ports.claims, ports.results))
            assert any(row["code"] == code and row["outcome"] == "failed" for row in adapter.decisions)
        finally:
            await registry.close()
    asyncio.run(run())
