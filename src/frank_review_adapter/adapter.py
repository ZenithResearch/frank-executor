from __future__ import annotations

from dataclasses import fields

from frank_executor.model import Binding, Rejected, canonical, digest, identity, validate_result
from process_runtime.compiler import validate_values

from .handlers import Handlers
from .ports import ReviewFailure, ReviewPorts


class ReviewAdapter:
    contract_version = "frank.integration.v1"
    provider_idempotent = False

    def __init__(self, integration_id: str, config: dict, *, ports: ReviewPorts, environment="production"):
        if environment not in {"test", "development"}:
            raise Rejected("Review adapter native command/result authority is unsupported")
        if not isinstance(config, dict) or set(config) != {"effects", "route"} or config["effects"] != "disabled":
            raise Rejected("Review adapter requires explicit effect-disabled configuration")
        if not isinstance(ports, ReviewPorts):
            raise Rejected("Explicit review ports are required")
        for field in fields(ports):
            port = getattr(ports, field.name)
            if port is None or getattr(port, "effects_disabled", False) is not True:
                raise Rejected("Review ports must be explicit and effect-disabled")
        self.integration_id = identity(integration_id)
        self.route, self.ports = identity(config["route"]), ports
        self.handlers = Handlers(ports)
        self.ready = False
        self.results, self.decisions = {}, []

    async def connect(self):
        self.ready = True

    async def close(self):
        self.ready = False

    async def capabilities(self):
        return frozenset({"send", "receive", "health", "cancel", "reconcile"})

    async def health(self):
        return {"integration_id": self.integration_id, "ready": self.ready,
                "authority": "local_dev_untrusted", "external_effects": "disabled",
                "handler_capabilities": sorted(self.handlers.operations)}

    async def send(self, work):
        required = {"schema", "binding", "actor_id", "integration_id", "route", "effect_id",
                    "operation", "scope", "inputs", "output_types"}
        if (not self.ready or not isinstance(work, dict) or set(work) != required
                or work["schema"] != "frank.work.v1" or work["integration_id"] != self.integration_id
                or work["route"] != self.route or work["operation"] not in self.handlers.operations):
            raise Rejected("Unsupported review work")
        Binding.read(work["binding"])
        canonical(work)
        await self.ports.claims.check(work)
        key = identity(work["effect_id"])
        if key in self.results:
            retained = self.results[key]
            if retained["work_digest"] != digest(work):
                raise Rejected("Review effect identity reused with changed work")
            return retained["result"]
        code, outputs, outcome = "computed", {}, "succeeded"
        try:
            outputs = await self.handlers.execute(work)
            validate_values(outputs, work["output_types"])
        except ReviewFailure as exc:
            code, outcome = exc.code, "failed"
            outputs = {}
        result = {"schema": "frank.result.v1", "event_id": "review-" + digest({"effect": key, "outcome": outcome, "outputs": outputs})[:48],
                  **{field: work[field] for field in ("binding", "actor_id", "integration_id", "route", "effect_id")},
                  "provider_reference": "simulated:" + key, "outcome": outcome, "outputs": outputs}
        bound = await self.ports.results.bind(result, work)
        validate_result(bound, work)
        if digest({k: v for k, v in bound.items() if k != "proof"}) != digest(result):
            raise Rejected("Result port changed the computed review result")
        self.results[key] = {"work_digest": digest(work), "result": bound}
        self.decisions.append({"binding": work["binding"], "operation": work["operation"], "code": code,
                               "outcome": outcome, "input_digest": digest(work["inputs"]), "result_digest": digest(bound),
                               "authority": "local_dev_untrusted", "external_effects": "disabled"})
        return bound

    async def receive(self, cursor):
        return [], cursor

    async def cancel(self, work):
        return False

    async def reconcile(self, work, provider_reference):
        retained = self.results.get(work["effect_id"])
        if retained and retained["work_digest"] != digest(work):
            raise Rejected("Review reconciliation correlation mismatch")
        return retained["result"] if retained else None


def configured_review_factory(*, ports, environment="production"):
    """Register as an extra factory; no core dispatcher changes are needed."""
    return lambda identifier, config: ReviewAdapter(identifier, config, ports=ports, environment=environment)
