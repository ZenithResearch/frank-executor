"""Connector-result orchestration with synthetic native responses only."""

import asyncio
from copy import deepcopy
import json
from pathlib import Path

import pytest

from frank_executor.connector_capture import CapturePending
from frank_executor.connector_result_producer import ConnectorResultProducer
from frank_executor.integrations.hermes import HermesAdapter
from frank_executor.model import Rejected, canonical, digest
from frank_executor.native_results import NativeResultVerifier
from jsonschema import Draft202012Validator, ValidationError
from native_result_support import SyntheticHelper, policy as receiver_policy
from test_adapters import Hermes
from test_connector_capture import HERMES, setup_capture


PROOF = {
    "schema": "frank.secs-result-envelope.v1",
    "packet_hex": "00",
    "signed_context_hex": "00",
}


class Claims:
    def __init__(self):
        self.current = True
        self.calls = 0

    async def check(self, work):
        self.calls += 1
        if not self.current:
            raise Rejected("retired connector claim")
        return {"current": True, "work_sha256": digest(work)}


def expected_result(work):
    outputs = {"answer": 14}
    return {
        "schema": "frank.result.v1",
        "event_id": "hermes-" + digest({"effect_id": work["effect_id"], "outputs": outputs})[:48],
        **{
            key: work[key]
            for key in ("binding", "actor_id", "integration_id", "route", "effect_id")
        },
        "provider_reference": work["effect_id"],
        "outcome": "succeeded",
        "outputs": outputs,
    }


def producer_for(tmp_path, capture, work):
    result = expected_result(work)
    helper = SyntheticHelper(work, {**result, "proof": PROOF})
    verifier = NativeResultVerifier(helper, receiver_policy, clock=lambda: 1001.0)
    claims = Claims()
    producer = ConnectorResultProducer(
        capture=capture,
        claims=claims,
        verifier=verifier,
        executable=tmp_path / "never-executed-native-connector-helper",
        executable_sha256="a" * 64,
        configuration=tmp_path / "never-read-native-connector-config",
        configuration_sha256="b" * 64,
        authority_configuration=tmp_path / "never-read-result-authority-config",
        authority_configuration_sha256="c" * 64,
    )
    calls = []
    outputs = {}

    async def request(mode, selector):
        calls.append((mode, selector))
        if mode == "resume":
            if selector not in outputs:
                raise Rejected("missing synthetic native output")
            return outputs[selector]
        outputs[selector] = canonical(PROOF)
        return outputs[selector]

    producer.transport.request = request
    return producer, claims, calls, outputs


def capture_hermes(capture, work):
    adapter = HermesAdapter(
        "fixture", deepcopy(HERMES), agent_factory=Hermes, connector_capture=capture
    )
    asyncio.run(adapter.connect())
    with pytest.raises(CapturePending):
        asyncio.run(adapter.send(work))
    return capture.retained(work)


def test_connector_result_binder_adds_only_independently_admitted_proof(tmp_path):
    _, capture, work = setup_capture(tmp_path, "hermes")
    retained = capture_hermes(capture, work)
    producer, claims, calls, _ = producer_for(tmp_path, capture, work)
    bound = asyncio.run(producer.bind(work))
    assert {key: value for key, value in bound.items() if key != "proof"} == retained["body"]
    assert bound["proof"] == PROOF
    assert calls[0][0] == "attest"
    assert claims.calls >= 3


def test_lost_connector_attestation_requires_exact_resume_without_resend(tmp_path):
    _, capture, work = setup_capture(tmp_path, "hermes")
    capture_hermes(capture, work)
    producer, _, calls, _ = producer_for(tmp_path, capture, work)
    real = producer.transport.request

    async def lost(mode, selector):
        await real(mode, selector)
        raise Rejected("synthetic reply lost")

    producer.transport.request = lost
    with pytest.raises(Rejected):
        asyncio.run(producer.bind(work))
    pending = capture.exchange(work)
    assert pending["mode"] == "attest" and pending["envelope"] is None
    with pytest.raises(CapturePending):
        asyncio.run(producer.bind(work))
    producer.transport.request = real
    resumed = asyncio.run(producer.resume(work))
    assert resumed["proof"] == PROOF
    assert [mode for mode, _ in calls] == ["attest", "resume"]
    assert calls[0][1] == calls[1][1] == bytes(pending["selector"])


def test_hermes_returns_only_native_admitted_connector_result(tmp_path):
    _, capture, work = setup_capture(tmp_path, "hermes")
    producer, _, calls, _ = producer_for(tmp_path, capture, work)
    adapter = HermesAdapter(
        "fixture",
        deepcopy(HERMES),
        agent_factory=Hermes,
        connector_capture=capture,
        connector_producer=producer,
    )
    asyncio.run(adapter.connect())
    result = asyncio.run(adapter.send(work))
    assert result == {**expected_result(work), "proof": PROOF}
    assert [mode for mode, _ in calls] == ["attest"]
    assert capture.retained(work)["body"] == expected_result(work)


def test_retired_claim_never_exports_connector_result(tmp_path):
    _, capture, work = setup_capture(tmp_path, "hermes")
    capture_hermes(capture, work)
    producer, claims, calls, _ = producer_for(tmp_path, capture, work)
    claims.current = False
    with pytest.raises(Rejected, match="retired"):
        asyncio.run(producer.bind(work))
    assert calls == []


def test_connector_selector_and_native_config_share_one_closed_schema(tmp_path):
    _, capture, work = setup_capture(tmp_path, "hermes")
    capture_hermes(capture, work)
    exchange = capture.exchange(work, "attest", None)
    schema_path = (
        Path(__file__).resolve().parents[1]
        / "contracts/connector-result-selector-v1.schema.json"
    )
    schema = json.loads(schema_path.read_text())
    validator = Draft202012Validator(schema)
    selector = json.loads(bytes(exchange["selector"]))
    validator.validate(selector)
    validator.validate({
        "schema": "frank.connector-result-producer.v1",
        "journal": capture.journal.path,
        "connector_policy_sha256": selector["policy_sha256"],
        "authority_configuration": str(tmp_path / "result-authority.json"),
        "authority_configuration_sha256": "c" * 64,
    })
    with pytest.raises(ValidationError):
        validator.validate({
            "schema": "frank.connector-result-producer.v1",
            "journal": capture.journal.path,
            "connector_policy_sha256": selector["policy_sha256"],
        })
    with pytest.raises(ValidationError):
        validator.validate({**selector, "trusted": True})
