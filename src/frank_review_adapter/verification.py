"""Public-contract, effect-disabled fixture driver for independent handlers."""
from __future__ import annotations

import asyncio
import base64
from copy import deepcopy
import hashlib
from importlib.resources import files
import json
from pathlib import Path
import time
import uuid

from frank_executor.authority import LocalDevAuthority, LocalDevResults
from frank_executor.executor import Executor
from frank_executor.journal import Journal
from frank_executor.model import Rejected, digest, effect_key
from frank_executor.registry import Registry
from frank_executor.runtime import ContractValidator, GeneratedClientAdapter, RuntimeFailure, RuntimeGateway
from process_runtime.compiler import compile_draft, validate_values
from process_runtime_client import LocalDevAuthority as SDKAuthority, RuntimeClient, RuntimeClientError, command_envelope

from .adapter import ReviewAdapter
from .development import DevelopmentAdapter
from .fixture_ports import MemoryArtifacts, FrozenSTT, SnapshotSources, SimulatedIntents, SyntheticResults
from .ports import ReviewPorts
from .comparison import validate_computed_report


class PublicArtifacts(MemoryArtifacts):
    def __init__(self, client):
        super().__init__()
        self.client, self.refs = client, {}

    async def read(self, reference):
        response = await asyncio.to_thread(self.client.query, {"schema": "runtime.query.v1", "operation": "artifact.get",
                           "payload": {"content_hash": reference["content_hash"]}})
        record = response["data"]
        if record["artifact"] != reference:
            raise Rejected("Public artifact metadata mismatch")
        content = base64.b64decode(record["content_base64"], validate=True)
        self.contents[reference["content_hash"]] = content
        self.refs[reference["content_hash"]] = deepcopy(reference)
        return content

    async def write(self, content, media_type):
        ref = await super().write(content, media_type)
        await asyncio.to_thread(self.client.execute, command_envelope("artifact.put", request_id=uuid.uuid4().hex,
                 expected_version=None, payload={"artifact": ref, "content_base64": base64.b64encode(content).decode()}))
        self.refs[ref["content_hash"]] = deepcopy(ref)
        return ref


class PublicClaims:
    effects_disabled = True

    def __init__(self, client, specs, pin):
        self.client, self.specs, self.pin = client, specs, pin

    async def check(self, work):
        binding = work["binding"]
        response = await asyncio.to_thread(self.client.query, {"schema": "runtime.query.v1", "operation": "attempt.get",
                     "payload": {key: binding[key] for key in ("run_id", "step_id", "attempt_id")}})
        claim = response["data"]
        if (any(claim.get(key) != value for key, value in binding.items()) or claim["actor_id"] != work["actor_id"]
                or claim["state"] != "active" or claim["current"] is not True
                or claim["lease_expires_at_ms"] <= time.time_ns() // 1_000_000
                or claim["pin"] != self.pin or claim["input_digest"] != digest(work["inputs"])
                or claim["inputs"] != work["inputs"] or claim["output_types"] != work["output_types"]
                or work["operation"] not in self.specs[binding["step_id"]]["capabilities"]):
            raise Rejected("Public runtime claim does not authorize this fixture work")
        validate_values(work["inputs"], claim["input_types"])


def command(client, operation, payload, version=None):
    return client.execute(command_envelope(operation, request_id=uuid.uuid4().hex, expected_version=version, payload=payload))["result"]


def query(client, operation, payload):
    return client.query({"schema": "runtime.query.v1", "operation": operation, "payload": payload})["data"]


def publish(client, draft):
    version_id = "independent-version-" + digest(draft)[:32]
    try:
        prior = query(client, "version.get", {"process_version": version_id})
        return prior["pin"]
    except RuntimeClientError as exc:
        if exc.code != "not_found":
            raise
    response = client.execute(command_envelope("process.draft.put", request_id=uuid.uuid4().hex, expected_version=None, payload={"draft": draft, "provenance": {
        "source_id": "independent-frozen-input", "media_type": "application/json", "content_hash": digest(draft),
        "parser": "explicit-json-v1", "uncertainties": []}}))
    revision = response["result"]["revision"]
    return command(client, "process.publish", {"process_id": draft["process_id"], "draft_revision": revision, "version_id": version_id}, response["version"])["pin"]


async def execute_case(endpoint, draft, inputs, source, directory, *, scenario, development=False):
    """Only runtime work.list/claim decide readiness; this driver cannot invent it."""
    signer = SDKAuthority(environment="test")
    client = RuntimeClient(endpoint, authority=signer)
    pin = await asyncio.to_thread(publish, client, draft)
    published_version = await asyncio.to_thread(query, client, "version.get", {"process_version": pin["process_version"]})
    if published_version["pin"] != pin or digest(published_version["compiled"]) != pin["compilation_hash"]:
        raise Rejected("Public published version does not match the execution pin")
    if pin["compilation_hash"] != compile_draft(draft).compilation_hash:
        raise Rejected("Published resource compilation mismatch")
    specs = {step["step_id"]: step for step in draft["steps"]}
    artifacts = PublicArtifacts(client)
    stt = FrozenSTT(source.get("audio_utf8", "").encode(), source.get("stt_response", {}))
    sources = SnapshotSources(source.get("source_snapshot", {}))
    intents = SimulatedIntents()
    ports = ReviewPorts(artifacts, stt, sources, sources, intents, PublicClaims(client, specs, pin), SyntheticResults())
    adapter_type = DevelopmentAdapter if development else ReviewAdapter
    adapter = adapter_type("independent-review", {"effects": "disabled", "route": "local"}, ports=ports, environment="test")
    capabilities = sorted({cap for step in specs.values() for cap in step["capabilities"]})
    resources = sorted({resource for step in specs.values() for resource in step["resources"]})
    actor_id = "independent-worker-" + uuid.uuid4().hex
    registry = Registry({"schema": "frank.integrations.v1", "integrations": [{"id": adapter.integration_id, "plugin": "frank.review.effect-disabled.v1", "enabled": True, "config": {}}],
        "actors": [{"actor_id": actor_id, "integration_id": adapter.integration_id, "route": "local", "capabilities": capabilities, "resources": resources}]},
        {"frank.review.effect-disabled.v1": lambda *_: adapter})
    journal = Journal(Path(directory) / (scenario + "-frank.db"))
    schema = json.loads(files("process_runtime_client").joinpath("runtime-v1.schema.json").read_text())
    gateway = RuntimeGateway(GeneratedClientAdapter(RuntimeClient(endpoint)),
        LocalDevAuthority(lambda raw: signer(json.loads(raw)), environment="test", enabled=True), journal, ContractValidator(schema))
    executor = Executor(gateway, registry, journal, LocalDevResults(environment="test", enabled=True), environment="test")
    if development:
        root_inputs = {"change_request": "Make add(a, b) return a + b.", "repository_snapshot": await artifacts.write(b'{"calc.py":"def add(a, b):\\n    return a - b\\n"}', "application/json")}
    else:
        root_inputs = {key: inputs[key] for key in draft["inputs"] if key not in {"audio_asset", "events_asset"}}
        root_inputs["audio_asset"] = await artifacts.write(source["audio_utf8"].encode(), "text/plain")
        root_inputs["events_asset"] = await artifacts.write(json.dumps(source["events"], sort_keys=True, separators=(",", ":")).encode(), "application/json")
    run_id = "independent-" + scenario + "-" + uuid.uuid4().hex
    await registry.connect()
    await executor.register(actor_id)
    await asyncio.to_thread(command, client, "run.create", {"run_id": run_id, "pin": pin, "inputs": root_inputs})
    records, batches = [], []
    try:
        for _ in range(len(specs) + 1):
            page = await executor.work(actor_id, limit=100)
            ready = [work for work in page["work"] if work["run_id"] == run_id]
            batches.append(sorted(work["step_id"] for work in ready))
            if not ready:
                break
            claimed = []
            for work in ready:
                actors, _ = registry.match(specs[work["step_id"]]["capabilities"], specs[work["step_id"]]["resources"])
                if actor_id not in {actor.actor_id for actor in actors}:
                    raise Rejected("No capability-selected actor for fixture work")
                claimed.append(await executor.claim(actor_id, work))
            for attempt in claimed:
                operation = next(cap for cap in specs[attempt.binding.step_id]["capabilities"] if cap in adapter.handlers.operations)
                await executor.run(attempt, operation=operation, scope=scenario, wait_seconds=30)
                key = effect_key(attempt.binding, operation, scenario)
                saved = journal.get(key)
                suffix = "-complete" if saved["state"] == "committed" else "-fail"
                response = json.loads(journal.saved_command(key + suffix)["response"])
                receipt = await gateway.query("receipt.get", {"receipt_id": response["result"]["receipt_id"]})
                if receipt["pin"] != pin or receipt["input_digest"] != digest(attempt.inputs) or receipt["fence"] != attempt.binding.fence:
                    raise Rejected("Independent receipt binding mismatch")
                outputs = saved["result"]["outputs"]
                output_payload = {key: value for key, value in attempt.binding.json().items() if key != "fence"}
                terminal_attempt = await gateway.query("attempt.get", output_payload)
                commit, output_code = None, "ok"
                try:
                    commit = await gateway.query("output.get", output_payload)
                except RuntimeFailure as exc:
                    if saved["state"] == "committed" or exc.code != "not_found":
                        raise
                    output_code = exc.code
                if saved["state"] == "committed":
                    if commit["output_digest"] != digest(outputs) or receipt["output_digest"] != commit["output_digest"]:
                        raise Rejected("Independent output/receipt mismatch")
                records.append({"step_id": attempt.binding.step_id, "operation": operation, "binding": attempt.binding.json(),
                                "outcome": saved["result"]["outcome"], "outputs": outputs, "input_digest": digest(attempt.inputs),
                                "receipt": receipt, "receipt_digest": digest(receipt), "delivery_state": saved["state"],
                                "actor_id": attempt.actor_id, "inputs": attempt.inputs, "attempt": terminal_attempt,
                                "output_commit": commit, "output_query": {"operation": "output.get", "payload": output_payload, "code": output_code}})
        else:
            raise Rejected("Independent fixture driver exceeded process bound")
    finally:
        await registry.close()
    run = await asyncio.to_thread(query, client, "run.get", {"run_id": run_id})
    report = {"scenario": scenario, "process_id": draft["process_id"], "run_id": run_id, "pin": pin, "run_state": run["state"],
            "observation_schema": "review.computed-observations.v1", "published_version": published_version, "actor_id": actor_id,
            "runnable_batches": batches, "step_states": {step["step_id"]: step["state"] for step in run["steps"]},
            "steps": records, "decisions": adapter.decisions, "simulated_intents": intents.intents, "stt_calls": stt.calls,
            "root_inputs": root_inputs, "authority_mode": "local_dev_untrusted", "external_send_count": 0,
            "artifacts": {key: {"reference": artifacts.refs[key], "content_base64": base64.b64encode(value).decode()} for key, value in artifacts.contents.items()}}
    if validate_computed_report(report):
        raise Rejected("Independent computed public report is incomplete or inconsistent")
    report["report_validation"] = {"schema": "review.report-validation.v1", "public_bindings_complete": True,
                                   "profile": "one non-retrying Attempt per step", "golden_outputs_compared": False}
    return report
