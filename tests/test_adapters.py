from copy import deepcopy
import json
import httpx
import pytest
from frank_executor.integrations.matrix import MatrixAdapter
from frank_executor.integrations.hermes import HermesAdapter
from frank_executor.model import Rejected, validate_result
from conftest import arun, Adapter
from test_contract_journal import packet

MATRIX = {
    "homeserver": "https://matrix.example.test",
    "account_id": "@frank:example.test",
    "token_ref": "secret:env:MATRIX_TOKEN",
    "routes": {"local": {"room_id": "!work:example.test", "sender_id": "@worker:example.test"}},
}


def matrix(handler):
    return MatrixAdapter(
        "fixture",
        deepcopy(MATRIX),
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        secret_resolver=lambda _: "super-secret",
    )


def test_matrix_uses_runtime_effect_transaction_and_ack_is_not_result():
    seen = []

    def handler(request):
        if request.url.path.endswith("m.room.encryption"):
            return httpx.Response(404, json={"errcode": "M_NOT_FOUND"})
        seen.append(request)
        assert request.headers["authorization"] == "Bearer super-secret"
        if request.url.path.endswith("/account/whoami"):
            return httpx.Response(200, json={"user_id": MATRIX["account_id"]})
        assert request.method == "PUT" and request.url.path.endswith(
            "/send/m.room.message/effect-1"
        )
        assert json.loads(request.content)["org.zenith.frank.v1"] == packet()
        return httpx.Response(200, json={"event_id": "$ack"})

    adapter = matrix(handler)
    arun(adapter.connect())
    result = arun(adapter.send(packet()))
    validate_result(result, packet())
    assert result["outcome"] == "acknowledged" and result["outputs"] == {}
    arun(adapter.close())
    assert adapter.token is None
    arun(adapter.connect())
    assert len(seen) == 3
    assert arun(adapter.cancel(packet())) is False


@pytest.mark.parametrize(
    "field,value", [("room", "!other:example.test"), ("sender", "@other:example.test")]
)
def test_matrix_rejects_unrelated_route(field, value):
    adapter = matrix(lambda _: httpx.Response(200, json={}))
    result = Adapter().result(packet())
    room = MATRIX["routes"]["local"]["room_id"]
    event = {
        "type": "m.room.message",
        "sender": MATRIX["routes"]["local"]["sender_id"],
        "event_id": "$result",
        "content": {"org.zenith.frank.v1": result},
    }
    if field == "room":
        room = value
    else:
        event[field] = value
    with pytest.raises(Rejected, match="unrelated"):
        adapter.normalize(room, event)


def test_matrix_replay_identity_uses_actual_event_and_gap_does_not_advance():
    result = Adapter().result(packet())
    result["event_id"] = "forged"
    event = {
        "type": "m.room.message",
        "sender": "@worker:example.test",
        "event_id": "$actual",
        "content": {"org.zenith.frank.v1": result},
    }

    def handler(request):
        if request.url.path.endswith("m.room.encryption"):
            return httpx.Response(404, json={"errcode": "M_NOT_FOUND"})
        if request.url.path.endswith("whoami"):
            return httpx.Response(200, json={"user_id": MATRIX["account_id"]})
        assert request.url.params["since"] == "cursor-before"
        return httpx.Response(
            200,
            json={
                "next_batch": "cursor-after",
                "rooms": {
                    "join": {
                        "!work:example.test": {"timeline": {"limited": True, "events": [event]}}
                    }
                },
            },
        )

    adapter = matrix(handler)
    arun(adapter.connect())
    normalized = adapter.normalize("!work:example.test", event)
    assert normalized["event_id"] != "forged" and normalized["provider_reference"] == "$actual"
    assert normalized == adapter.normalize("!work:example.test", event)
    with pytest.raises(Rejected, match="gap"):
        arun(adapter.receive("cursor-before"))


@pytest.mark.parametrize("status", [301, 401, 429, 500])
def test_matrix_provider_errors_redact_transport_body(status):
    adapter = matrix(lambda request: httpx.Response(status, json={"error": "super-secret"}))
    with pytest.raises(Rejected) as error:
        arun(adapter.connect())
    assert "super-secret" not in str(error.value)


def test_matrix_account_mismatch_never_reports_ready():
    adapter = matrix(lambda request: httpx.Response(200, json={"user_id": "@other:example.test"}))
    with pytest.raises(Rejected, match="another account"):
        arun(adapter.connect())
    assert not arun(adapter.health())["ready"]


class Hermes:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.calls = []
        self.interruptions = []

    def run_conversation(self, prompt, *, task_id):
        self.calls.append((prompt, task_id))
        return {"final_response": '{"answer":14}'}

    def interrupt(self, reason):
        self.interruptions.append(reason)


def hermes(factory=Hermes):
    return HermesAdapter(
        "fixture",
        {
            "model": "provider/model",
            "toolsets": ["terminal"],
            "routes": ["local"],
            "max_iterations": 2,
        },
        agent_factory=factory,
    )


def test_hermes_exact_inspected_sdk_surface_and_no_repeat():
    adapter = hermes()
    arun(adapter.connect())
    result = arun(adapter.send(packet()))
    validate_result(result, packet())
    agent = adapter.agents["effect-1"]
    assert (
        agent.kwargs["session_id"] == "effect-1"
        and agent.kwargs["skip_context_files"]
        and agent.kwargs["skip_memory"]
    )
    assert agent.kwargs["enabled_toolsets"] == ["terminal"]
    assert agent.calls[0][1] == "effect-1"
    with pytest.raises(Rejected, match="already dispatched"):
        arun(adapter.send(packet()))
    assert arun(adapter.reconcile(packet(), "effect-1")) == result
    restarted = hermes()
    arun(restarted.connect())
    assert arun(restarted.reconcile(packet(), "effect-1")) is None
    assert arun(adapter.cancel(packet())) and agent.interruptions


def test_hermes_malformed_output_is_unknown_and_does_not_leak():
    class Bad(Hermes):
        def run_conversation(self, *args, **kwargs):
            return {"final_response": "secret unparseable"}

    adapter = hermes(Bad)
    arun(adapter.connect())
    with pytest.raises(Rejected) as error:
        arun(adapter.send(packet()))
    assert "secret" not in str(error.value)
    with pytest.raises(Rejected, match="already dispatched"):
        arun(adapter.send(packet()))


def test_hermes_sdk_unavailable_keeps_health_closed():
    def factory(**kwargs):
        raise AssertionError("should never instantiate")

    def check():
        raise Rejected("SDK unavailable")

    factory.check_available = check
    adapter = hermes(factory)
    with pytest.raises(Rejected):
        arun(adapter.connect())
    assert not arun(adapter.health())["ready"]


def test_matrix_encrypted_room_fails_before_plaintext_send():
    calls = []

    def handler(request):
        calls.append(request.method)
        if request.url.path.endswith("whoami"):
            return httpx.Response(200, json={"user_id": MATRIX["account_id"]})
        return httpx.Response(200, json={"algorithm": "m.megolm.v1.aes-sha2"})

    adapter = matrix(handler)
    with pytest.raises(Rejected, match="crypto adapter"):
        arun(adapter.connect())
    assert calls == ["GET", "GET"] and adapter.token is None
