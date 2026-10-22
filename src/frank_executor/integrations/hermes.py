"""Adapter to the inspected Hermes AIAgent interface, not a new agent protocol."""

from __future__ import annotations
import asyncio
from ..model import Rejected, canonical, digest, decode_json
from ..connector_capture import ConnectorCapture, CapturePending


class HermesAdapter:
    contract_version = "frank.integration.v1"
    provider_idempotent = False

    def __init__(self, integration_id, config, *, agent_factory, connector_capture=None,
                 connector_producer=None, output_materializer=None):
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
        self.connector_producer = connector_producer
        self.output_materializer = output_materializer
        if connector_capture is not None:
            if type(connector_capture) is not ConnectorCapture:
                raise Rejected("Trusted connector capture required")
            connector_capture.bind("hermes", integration_id, config)
            if connector_capture.policy.route not in config["routes"]:
                raise Rejected("Capture route is not configured")
            self.config = decode_json(canonical(config))
        if connector_producer is not None:
            from ..connector_result_producer import ConnectorResultProducer
            if (
                connector_capture is None
                or type(connector_producer) is not ConnectorResultProducer
                or connector_producer.capture is not connector_capture
            ):
                raise Rejected("Matching native connector result producer required")
        if output_materializer is not None:
            from ..output_materializer import RuntimeOutputMaterializer
            if connector_capture is None or type(output_materializer) is not RuntimeOutputMaterializer:
                raise Rejected("Live output materializer requires matching connector capture")

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
        if self.connector_producer is not None:
            await self.connector_producer.aclose()

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
        prompt = self._prompt(work) if capture is not None else None
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
            prompt = self._prompt(work)
        try:
            raw = await asyncio.to_thread(agent.run_conversation, prompt, task_id=identifier)
            text = raw["final_response"]
        except asyncio.CancelledError:
            agent.interrupt("Frank delivery cancelled; effect remains unknown")
            raise
        except Exception:
            raise Rejected("Hermes outcome unavailable; reconcile the session") from None
        if not isinstance(text, str) or len(text.encode()) > 1024 * 1024:
            raise Rejected("Hermes result exceeds bound")
        if capture is not None:
            capture.retain_hermes_response(work, prompt, text)
        return await self._finish(work, prompt, text, capture)

    def _prompt(self, work):
        suffix = ""
        if self.output_materializer is not None:
            suffix = self.output_materializer.prompt_contract(work)
        return (
            "Execute only this claimed work packet. Return one JSON object containing exactly the declared output names. "
            "Do not schedule, claim, retry, or complete runtime work."
            + suffix
            + "\n"
            + canonical(work).decode()
        )

    async def _finish(self, work, prompt, text, capture):
        try:
            outputs = decode_json(text)
        except Rejected:
            raise Rejected("Hermes outcome unavailable; reconcile the session") from None
        if not isinstance(outputs, dict):
            raise Rejected("Hermes must return an output object")
        if self.output_materializer is not None:
            outputs = await self.output_materializer.materialize(work, outputs)
        result = {
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
        if capture is not None:
            capture.bind("hermes", self.integration_id, self.config)
            item = capture.prepare_hermes(result, prompt=prompt, final_response=text)
            capture.commit((item,))
            if self.connector_producer is None:
                raise CapturePending("Unsigned Hermes capture retained; issuer unavailable")
            return await self.connector_producer.bind(work)
        self.results[work["effect_id"]] = result
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
                if self.connector_producer is None:
                    raise CapturePending("Unsigned Hermes capture retained; issuer unavailable")
                return await self.connector_producer.reconcile(work)
            prompt = self._prompt(work)
            response = capture.hermes_response(work, prompt)
            if response is not None:
                return await self._finish(work, prompt, response, capture)
            return None
        return self.results.get(work["effect_id"])
