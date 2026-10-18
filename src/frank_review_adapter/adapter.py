from __future__ import annotations

import asyncio

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
        self._configure(integration_id, config, ports)

    def _configure(self, integration_id, config, ports):
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
        self._local_capture = self._local_producer = None
        self._local_environment = None

    async def connect(self):
        if self._local_producer is not None:
            await asyncio.to_thread(self._local_producer.transport.check_available)
        self.ready = True

    async def close(self):
        self.ready = False
        if self._local_producer is not None:
            await self._local_producer.aclose()

    async def capabilities(self):
        return frozenset({"send", "receive", "health", "cancel", "reconcile"})

    async def health(self):
        return {"integration_id": self.integration_id, "ready": self.ready,
                "authority": ("native" if self._local_environment == "production" else "native_unqualified") if self._local_capture is not None else "local_dev_untrusted", "external_effects": "disabled",
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
        if self._local_capture is not None:
            return await self._send_local(work)
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
        if self._local_capture is not None:
            from frank_executor.model import decode_json
            work = decode_json(canonical(work))
            retained = await asyncio.to_thread(self._local_capture.retained, work)
            if retained is None:
                return None
            if provider_reference is not None and provider_reference != retained["result"]["provider_reference"]:
                raise Rejected("Local-review reconciliation reference mismatch")
            return await self._local_producer.reconcile(work)
        retained = self.results.get(work["effect_id"])
        if retained and retained["work_digest"] != digest(work):
            raise Rejected("Review reconciliation correlation mismatch")
        return retained["result"] if retained else None


    @classmethod
    def local_native(cls, integration_id, config, *, ports, capture, producer, environment="production"):
        """Explicit trusted composition; generic/default construction stays denied."""
        from .local_capture import LocalReviewCapture
        from frank_executor.native_result_producer import NativeResultProducer
        if (not isinstance(config,dict) or not isinstance(ports,ReviewPorts)
                or type(capture) is not LocalReviewCapture or type(producer) is not NativeResultProducer
                or producer.capture is not capture or ports.results is not producer
                or producer.claims is not ports.claims
                or capture.policy.integration_id != integration_id or capture.policy.route != config.get("route")):
            raise Rejected("Matching trusted local-review dependencies required")
        if environment == "production":
            from frank_executor.authority import check_authority
            from .local_ports import (RuntimeArtifacts, RuntimeClaims, RuntimeSnapshotSources,
                                      SuppliedTranscript, DurableSimulatedIntents)
            if (cls is not ReviewAdapter or type(ports.artifacts) is not RuntimeArtifacts
                    or type(ports.claims) is not RuntimeClaims
                    or type(ports.sources) is not RuntimeSnapshotSources
                    or ports.components is not ports.sources
                    or type(ports.stt) is not SuppliedTranscript
                    or type(ports.intents) is not DurableSimulatedIntents
                    or ports.artifacts.gateway is not ports.claims.gateway
                    or ports.sources.artifacts is not ports.artifacts
                    or ports.stt.artifacts is not ports.artifacts
                    or ports.intents.journal is not capture.journal
                    or ports.claims.journal is not capture.journal):
                raise Rejected("Review adapter native command/result authority requires concrete ports")
            check_authority(environment, ports.claims.gateway.authority, producer.verifier)
            adapter = cls.__new__(cls)
            adapter._configure(integration_id,config,ports)
        else:
            adapter = cls(integration_id,config,ports=ports,environment=environment)
        adapter._local_capture,adapter._local_producer = capture,producer
        adapter._local_environment = environment
        return adapter

    async def _send_local(self, work):
        from frank_executor.model import decode_json
        from .local_capture import ObservationRecorder, FAILURES
        work = decode_json(canonical(work))
        _, fresh = await asyncio.to_thread(self._local_capture.reserve,work)
        if not fresh:
            # A reserved-only row is unknown. A completed row may republish its
            # exact files and recover authority, never execute a handler again.
            await asyncio.to_thread(self._local_capture.retained,work)
            return await self._local_producer.reconcile(work)
        recorder = ObservationRecorder(self._local_capture,work)
        ports = recorder.wrap(self.ports)
        await ports.claims.check(work)
        code, outputs, outcome = "computed", {}, "succeeded"
        try:
            outputs = await Handlers(ports).execute(work)
            validate_values(outputs,work["output_types"])
        except ReviewFailure as exc:
            if exc.code not in FAILURES:
                raise
            code,outcome,outputs = exc.code,"failed",{}
        key = digest({n:work[n] for n in ("binding","actor_id","integration_id","route","effect_id")})
        result = {"schema":"frank.result.v1",
            "event_id":"review-"+digest({"effect":work["effect_id"],"outcome":outcome,"outputs":outputs})[:48],
            **{n:work[n] for n in ("binding","actor_id","integration_id","route","effect_id")},
            "provider_reference":"local-review:review-"+key,"outcome":outcome,"outputs":outputs}
        validate_result(result,work)
        await ports.claims.check(work)
        await asyncio.to_thread(self._local_capture.complete,work,result,code,recorder)
        bound = await self._local_producer.bind(result,work)
        validate_result(bound,work)
        if digest({k:v for k,v in bound.items() if k != "proof"}) != digest(result):
            raise Rejected("Native result port changed computed body")
        self.decisions.append({"binding":work["binding"],"operation":work["operation"],"code":code,
            "outcome":outcome,"input_digest":digest(work["inputs"]),"result_digest":digest(bound),
            "authority":"native" if self._local_environment == "production" else "native_unqualified",
            "external_effects":"disabled"})
        return bound

    async def renew_result(self, work, provider_reference):
        if self._local_capture is None:
            raise Rejected("No native local-review composition")
        from frank_executor.model import decode_json
        work = decode_json(canonical(work))
        retained = await asyncio.to_thread(self._local_capture.retained,work)
        if retained is None or retained["result"]["provider_reference"] != provider_reference:
            raise Rejected("Original local-review computation required")
        return await self._local_producer.renew(work)


def configured_review_factory(*, ports, environment="production"):
    """Register as an extra factory; no core dispatcher changes are needed."""
    return lambda identifier, config: ReviewAdapter(identifier, config, ports=ports, environment=environment)
