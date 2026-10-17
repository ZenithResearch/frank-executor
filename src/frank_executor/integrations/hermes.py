"""Adapter to the inspected Hermes AIAgent interface, not a new agent protocol."""

from __future__ import annotations
import asyncio
from ..model import Rejected, canonical, digest, decode_json
from ..connector_capture import ConnectorCapture, CapturePending


class HermesAdapter:
    contract_version = "frank.integration.v1"
    provider_idempotent = False

    def __init__(self, integration_id, config, *, agent_factory, connector_capture=None):
        if set(config) != {"model", "toolsets", "routes", "max_iterations"}:
            raise Rejected("Malformed Hermes configuration")
        if not isinstance(config["toolsets"], list) or any(
            not isinstance(x, str) for x in config["toolsets"]
        ):
            raise Rejected("Hermes toolsets must be explicit")
        if not isinstance(config["routes"], list) or not config["routes"]:
            raise Rejected("Hermes routes must be explicit")
        if type(config["max_iterations"]) is not int or not 1 <= config["max_iterations"] <= 100:
            raise Rejected("Invalid Hermes iteration budget")
        self.integration_id, self.config, self.factory = integration_id, config, agent_factory
        self.ready = False
        self.agents = {}
        self.results = {}
        self.connector_capture = connector_capture
        if connector_capture is not None:
            if type(connector_capture) is not ConnectorCapture:
                raise Rejected("Trusted connector capture required")
            connector_capture.bind("hermes", integration_id, config)
            if connector_capture.policy.route not in config["routes"]:
                raise Rejected("Capture route is not configured")
            self.config = decode_json(canonical(config))

    async def connect(self):
        if not callable(self.factory):
            raise Rejected("Hermes SDK factory is unavailable")
        check = getattr(self.factory, "check_available", None)
        if check is not None:
            check()
        self.ready = True

    async def close(self):
        for agent in self.agents.values():
            agent.interrupt("Frank adapter closing")
        self.ready = False

    async def capabilities(self):
        return frozenset({"send", "receive", "health", "cancel", "reconcile"})

    async def health(self):
        return {
            "integration_id": self.integration_id,
            "ready": self.ready,
            "code": "ready" if self.ready else "disconnected",
        }

    async def send(self, work):
        if not self.ready or work["route"] not in self.config["routes"]:
            raise Rejected("Hermes route is unavailable")
        capture = self.connector_capture
        capture = capture if capture is not None and capture.selected(work["route"]) else None
        if capture is not None:
            capture.bind("hermes", self.integration_id, self.config)
            work = decode_json(canonical(work))
        identifier = work["effect_id"]
        if identifier in self.agents:
            raise Rejected("Hermes session already dispatched; reconcile it")
        prompt = (
            "Execute only this claimed work packet. Return one JSON object containing exactly the declared output names. Do not schedule, claim, retry, or complete runtime work.\n"
            + canonical(work).decode()
        ) if capture is not None else None
        if capture is not None and not capture.reserve_hermes(work, prompt):
            raise CapturePending("Hermes dispatch is already reserved; never send again")
        agent = self.factory(
            model=self.config["model"],
            enabled_toolsets=list(self.config["toolsets"]),
            max_iterations=self.config["max_iterations"],
            session_id=identifier,
            quiet_mode=True,
            skip_context_files=True,
            skip_memory=True,
        )
        self.agents[identifier] = agent
        if prompt is None:
            prompt = (
                "Execute only this claimed work packet. Return one JSON object containing exactly the declared output names. Do not schedule, claim, retry, or complete runtime work.\n"
                + canonical(work).decode()
            )
        try:
            raw = await asyncio.to_thread(agent.run_conversation, prompt, task_id=identifier)
            text = raw["final_response"]
            if not isinstance(text, str) or len(text.encode()) > 1024 * 1024:
                raise Rejected("Hermes result exceeds bound")
            outputs = decode_json(text)
            if not isinstance(outputs, dict):
                raise Rejected("Hermes must return an output object")
        except asyncio.CancelledError:
            agent.interrupt("Frank delivery cancelled; effect remains unknown")
            raise
        except Exception:
            raise Rejected("Hermes outcome unavailable; reconcile the session") from None
        result = {
            "schema": "frank.result.v1",
            "event_id": "hermes-" + digest({"effect_id": identifier, "outputs": outputs})[:48],
            **{
                key: work[key]
                for key in ("binding", "actor_id", "integration_id", "route", "effect_id")
            },
            "provider_reference": identifier,
            "outcome": "succeeded",
            "outputs": outputs,
        }
        if capture is not None:
            capture.bind("hermes", self.integration_id, self.config)
            item = capture.prepare_hermes(result, prompt=prompt, final_response=text)
            capture.commit((item,))
            raise CapturePending("Unsigned Hermes capture retained; issuer unavailable")
        self.results[identifier] = result
        return result

    async def receive(self, cursor):
        return [], cursor

    async def cancel(self, work):
        agent = self.agents.get(work["effect_id"])
        if not agent:
            return False
        agent.interrupt("Frank cancellation requested; runtime decides terminal state")
        return True

    async def reconcile(self, work, provider_reference):
        # After host restart the durable Frank journal/native session must be inspected;
        # the SDK does not expose an authoritative resume-by-id result query here.
        capture = self.connector_capture
        if capture is not None and capture.selected(work["route"]):
            capture.bind("hermes", self.integration_id, self.config)
            if capture.retained(work) is not None:
                raise CapturePending("Unsigned Hermes capture retained; issuer unavailable")
            return None
        return self.results.get(work["effect_id"])
