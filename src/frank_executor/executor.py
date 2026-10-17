from __future__ import annotations
import asyncio
import time
import json
from dataclasses import dataclass, field
from .authority import check_authority
from .model import (
    Binding,
    Rejected,
    UnknownOutcome,
    canonical,
    digest,
    effect_key,
    effect_name,
    validate_result,
    work_packet,
)


@dataclass
class ClaimedAttempt:
    binding: Binding
    actor_id: str
    step_version: int
    lease_expires_at_ms: int
    inputs_json: str
    output_types_json: str
    pin_json: str
    active: bool = True
    lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)

    @property
    def inputs(self):
        return json.loads(self.inputs_json)

    @property
    def output_types(self):
        return json.loads(self.output_types_json)

    @property
    def pin(self):
        return json.loads(self.pin_json)


class Executor:
    def __init__(
        self, gateway, registry, journal, result_verifier, *, environment="production", clock=None
    ):
        check_authority(environment, gateway.authority, result_verifier)
        self.gateway, self.registry, self.journal, self.result_verifier = (
            gateway,
            registry,
            journal,
            result_verifier,
        )
        self.clock = clock or (lambda: time.time_ns() // 1_000_000)

    async def register(self, actor_id):
        actor = self.registry.actors[actor_id]
        return await self.gateway.execute(
            "actor.register",
            {
                "actor_id": actor_id,
                "capabilities": list(actor.capabilities),
                "resources": list(actor.resources),
            },
            None,
        )

    async def work(self, actor_id, *, limit=20, after=None):
        payload = {"actor_id": actor_id, "limit": limit}
        if after:
            payload["after"] = after
        return await self.gateway.query("work.list", payload)

    async def claim(self, actor_id, work, *, lease_ms=120000, request_id=None):
        if actor_id not in self.registry.actors:
            raise Rejected("Actor is not configured")
        result = await self.gateway.execute(
            "executor.claim",
            {
                "run_id": work["run_id"],
                "step_id": work["step_id"],
                "actor_id": actor_id,
                "lease_ms": lease_ms,
            },
            work["version"],
            request_id=request_id,
        )
        data = result["result"]
        binding = Binding(*(data[key] for key in ("run_id", "step_id", "attempt_id", "fence")))
        if (
            binding.run_id != work["run_id"]
            or binding.step_id != work["step_id"]
            or data["actor_id"] != actor_id
        ):
            raise Rejected("Claim correlation mismatch")
        if (
            data["input_digest"] != digest(data["inputs"])
            or result["version"] != data["step_version"]
        ):
            raise Rejected("Claim snapshot mismatch")
        return ClaimedAttempt(
            binding,
            actor_id,
            data["step_version"],
            data["lease_expires_at_ms"],
            canonical(data["inputs"]).decode(),
            canonical(data["output_types"]).decode(),
            canonical(data["pin"]).decode(),
        )

    async def recover(self, binding, actor_id):
        data = await self.gateway.query(
            "attempt.get", {key: value for key, value in binding.json().items() if key != "fence"}
        )
        if (
            any(data.get(key) != value for key, value in binding.json().items())
            or data.get("actor_id") != actor_id
        ):
            raise Rejected("Recovered attempt correlation mismatch")
        if (
            data.get("current") is not True
            or data.get("state") != "active"
            or self.clock() >= data["lease_expires_at_ms"]
        ):
            raise Rejected("Runtime reports a retired or expired attempt")
        if data["input_digest"] != digest(data["inputs"]):
            raise Rejected("Recovered input digest mismatch")
        return ClaimedAttempt(
            binding,
            actor_id,
            data["step_version"],
            data["lease_expires_at_ms"],
            canonical(data["inputs"]).decode(),
            canonical(data["output_types"]).decode(),
            canonical(data["pin"]).decode(),
        )

    async def _verify_result(self, key, result, work):
        # Never let caller or verifier mutation across an await select terminal payload bytes.
        result_bytes = canonical(result)
        work_bytes = canonical(work)
        admission = await self.result_verifier.verify(
            json.loads(result_bytes), json.loads(work_bytes)
        )
        if admission is None:
            if self.result_verifier.mode == "native_unqualified" or self.journal.is_native(key):
                raise Rejected("Native verification did not return trusted admission")
        else:
            from .native_results import NativeResultAdmission

            if type(admission) is not NativeResultAdmission:
                raise Rejected("Result verifier returned an untrusted admission")
        return json.loads(result_bytes), admission

    def _guard(self, key, result, admission):
        if admission is None:
            return None
        result_bytes = canonical(result)

        def guard(command):
            self.journal.reauthorize(key, json.loads(result_bytes), admission, command=command)

        return guard

    async def _verify_retained(self, key, saved):
        result, admission = await self._verify_result(key, saved["result"], saved["work"])
        if admission is not None:
            self.journal.reauthorize(key, result, admission)
        return result, admission

    async def reconcile_completion(self, key):
        saved = self.journal.get(key)
        if saved["state"] not in {"succeeded", "committed"}:
            raise Rejected("No successful result to reconcile")
        result, admission = await self._verify_retained(key, saved)
        if saved["state"] == "committed":
            return saved
        if saved["state"] != "succeeded":
            raise Rejected("No successful result to reconcile")
        # A retry uses exact saved command bytes, re-establishes authority, and lets
        # the runtime decide whether the first completion already committed.
        response = await self.gateway.replay(
            key + "-complete",
            **({"guard": self._guard(key, result, admission)} if admission is not None else {}),
        )
        binding = saved["work"]["binding"]
        output = await self.gateway.query(
            "output.get", {k: binding[k] for k in ("run_id", "step_id", "attempt_id")}
        )
        if output.get("fence") != binding["fence"] or output.get("output_digest") != digest(
            saved["result"]["outputs"]
        ):
            raise Rejected("Committed runtime output differs from local evidence")
        self.journal.committed(key)
        return response

    def _live(self, attempt):
        if not attempt.active or self.clock() >= attempt.lease_expires_at_ms:
            raise Rejected("Attempt has no live lease")

    async def _command(self, attempt, operation, extra, *, request_id=None, guard=None):
        async with attempt.lock:
            self._live(attempt)
            try:
                result = await self.gateway.execute(
                    operation,
                    {**attempt.binding.json(), **extra},
                    attempt.step_version,
                    request_id=request_id,
                    **({"guard": guard} if guard is not None else {}),
                )
            except Exception:
                # Reconcile exact retained command before continuing with a possibly stale version.
                attempt.active = False
                raise
            attempt.step_version = result["version"]
            return result["result"]

    async def heartbeat(self, attempt, *, lease_ms=120000):
        data = await self._command(attempt, "executor.heartbeat", {"lease_ms": lease_ms})
        attempt.lease_expires_at_ms = data["lease_expires_at_ms"]

    async def heartbeat_loop(self, attempt, *, lease_ms=120000):
        while attempt.active:
            await asyncio.sleep(lease_ms / 3000)
            await self.heartbeat(attempt, lease_ms=lease_ms)

    async def release(self, attempt, reason):
        result = await self._command(attempt, "executor.release", {"reason": reason})
        attempt.active = False
        return result

    async def fail(self, attempt, reason, *, retryable=False, request_id=None, guard=None):
        result = await self._command(
            attempt,
            "executor.fail",
            {"reason": reason, "retryable": retryable},
            request_id=request_id,
            guard=guard,
        )
        attempt.active = False
        return result

    async def fail_delivery(self, attempt, key, reason="Integration reported a verified failure"):
        saved = self.journal.get(key)
        if (
            saved["state"] != "failed"
            or saved["work"]["binding"] != attempt.binding.json()
            or saved["work"]["actor_id"] != attempt.actor_id
        ):
            raise Rejected("Failure requires matching verified effect evidence")
        result, admission = await self._verify_retained(key, saved)
        response = await self.fail(
            attempt, reason, request_id=key + "-fail", guard=self._guard(key, result, admission)
        )
        self.journal.failed_committed(key)
        return response

    async def reconcile_failure(self, key):
        saved = self.journal.get(key)
        if saved["state"] not in {"failed", "failed_committed"}:
            raise Rejected("No failed result to reconcile")
        result, admission = await self._verify_retained(key, saved)
        if saved["state"] == "failed_committed":
            return saved
        if saved["state"] != "failed":
            raise Rejected("No failed result to reconcile")
        response = await self.gateway.replay(
            key + "-fail",
            **({"guard": self._guard(key, result, admission)} if admission is not None else {}),
        )
        binding = saved["work"]["binding"]
        terminal = await self.gateway.query(
            "attempt.get", {k: binding[k] for k in ("run_id", "step_id", "attempt_id")}
        )
        if (
            any(terminal.get(k) != v for k, v in binding.items())
            or terminal.get("actor_id") != saved["work"]["actor_id"]
            or terminal.get("state") != "failed"
        ):
            raise Rejected("Runtime failure does not match retained evidence")
        self.journal.failed_committed(key)
        return response

    async def dispatch(self, attempt, *, operation, scope):
        self._live(attempt)
        actor = self.registry.actors[attempt.actor_id]
        adapter = self.registry.adapter(actor)
        key = effect_key(attempt.binding, operation, scope)
        intent = {
            "binding": attempt.binding.json(),
            "actor_id": actor.actor_id,
            "integration_id": actor.integration_id,
            "route": actor.route,
            "operation": operation,
            "scope": scope,
            "inputs": attempt.inputs,
            "output_types": attempt.output_types,
        }
        # Stable request key makes a crash before local delivery insertion reconcilable.
        saved = None
        try:
            saved = self.journal.get(key)
        except Rejected:
            pass
        if saved:
            if saved["state"] == "intent":
                raise UnknownOutcome(
                    "Retained effect intent requires explicit reconciliation before dispatch"
                )
            if self.journal.is_native(key) and saved["result"] is not None:
                await self._verify_retained(key, saved)
            return saved
        data = await self._command(
            attempt,
            "executor.effect.intent",
            {
                "effect_name": effect_name(operation, scope),
                "integration": actor.integration_id,
                "request_digest": digest(intent),
                "provider_idempotent": adapter.provider_idempotent,
            },
            request_id=key + "-intent",
        )
        work = work_packet(
            attempt.binding,
            actor,
            effect_id=data["effect_id"],
            operation=operation,
            scope=scope,
            inputs=attempt.inputs,
            output_types=attempt.output_types,
        )
        self.journal.delivery(key, work)
        await self._command(
            attempt,
            "executor.effect.dispatch",
            {"effect_id": data["effect_id"]},
            request_id=key + "-dispatch",
        )
        if not self.journal.begin_dispatch(key):
            raise UnknownOutcome("Effect already dispatched")
        self._live(attempt)
        try:
            result = await adapter.send(work)
        except Exception as exc:
            raise UnknownOutcome(
                "External delivery outcome unknown; reconcile without another send"
            ) from exc
        await self.observe(attempt, key, result)
        return self.journal.get(key)

    async def observe(self, attempt, key, result):
        result = json.loads(canonical(result))
        self._live(attempt)
        saved = self.journal.get(key)
        work = saved["work"]
        if work["binding"] != attempt.binding.json() or work["actor_id"] != attempt.actor_id:
            raise Rejected("Effect belongs to another attempt")
        validate_result(result, work)
        admission = None
        if result["outcome"] in {"succeeded", "failed"}:
            result, admission = await self._verify_result(key, result, work)
        # Native renewal preserves first result/event bytes and stable observation identity.
        observed = self.journal.observation(
            key, result, **({"admission": admission} if admission is not None else {})
        )
        result_digest = self.journal.result_digest(key, result)
        guard = self._guard(key, result, admission)
        if not observed:
            # A crash may have retained the result before the runtime saw it.
            request_id = key + "-" + result_digest[:24]
            try:
                retained = self.journal.saved_command(request_id)
            except Rejected:
                retained = None
            if retained is not None and retained["state"] != "observed":
                await self.gateway.replay(
                    request_id, **({"guard": guard} if guard is not None else {})
                )
                refreshed = await self.recover(attempt.binding, attempt.actor_id)
                attempt.step_version = refreshed.step_version
                attempt.lease_expires_at_ms = refreshed.lease_expires_at_ms
            if retained is not None:
                return self.journal.get(key)
        try:
            await self._command(
                attempt,
                "executor.effect.observe",
                {
                    "effect_id": work["effect_id"],
                    "provider_reference": result["provider_reference"],
                    "outcome": result["outcome"],
                    "observation_digest": result_digest,
                },
                request_id=key + "-" + result_digest[:24],
                guard=guard,
            )
        except Exception:
            raise
        return self.journal.get(key)

    async def complete(self, attempt, key):
        saved = self.journal.get(key)
        if (
            saved["state"] != "succeeded"
            or saved["work"]["binding"] != attempt.binding.json()
            or saved["work"]["actor_id"] != attempt.actor_id
        ):
            raise Rejected("Completion requires matching successful effect evidence")
        result, admission = await self._verify_retained(key, saved)
        # Runtime atomically validates types, effects and the output commit before completion.
        receipt = await self._command(
            attempt,
            "executor.complete",
            {"outputs": result["outputs"]},
            request_id=key + "-complete",
            guard=self._guard(key, result, admission),
        )
        self.journal.committed(key)
        attempt.active = False
        return receipt

    async def reconcile(self, attempt, key):
        self._live(attempt)
        saved = self.journal.get(key)
        work = saved["work"]
        if work["binding"] != attempt.binding.json():
            raise Rejected("Effect belongs to another attempt")
        adapter = self.registry.adapter(self.registry.actors[attempt.actor_id])
        result = await adapter.reconcile(work, (saved["result"] or {}).get("provider_reference"))
        if result is None:
            if self.journal.is_native(key) and saved["result"] is not None:
                await self._verify_retained(key, saved)
            return {"state": saved["state"], "action": "native operator reconciliation required"}
        return await self.observe(attempt, key, result)

    async def receive(self, integration_id, *, attempts=None):
        """Persist and currently authorize native pages before advancing their cursor."""
        attempts = attempts or {}
        adapter = self.registry.adapters[integration_id]
        results, cursor = await adapter.receive(self.journal.cursor(integration_id))
        results = [json.loads(canonical(result)) for result in results]
        receipts = []
        admissions = []
        for result in results:
            saved = self.journal.for_result(result)
            key = saved["effect_key"]
            validate_result(result, saved["work"])
            # Historical legacy acknowledgements retain their exact full-result identity.
            if (
                result["outcome"] not in {"succeeded", "failed"}
                and saved["result"] is not None
                and digest(result) != digest(saved["result"])
                and self.journal.seen_event(result)
            ):
                continue
            admission = None
            if result["outcome"] in {"succeeded", "failed"}:
                result, admission = await self._verify_result(key, result, saved["work"])
                if admission is not None:
                    self.journal.observation(key, result, admission=admission)
                    admissions.append((key, json.loads(canonical(result)), admission))
                    saved = self.journal.get(key)
            expected = (
                self.journal.result_digest(key, saved["result"])
                if saved["result"] is not None
                else None
            )
            incoming = self.journal.result_digest(key, result)
            if saved["state"] in {"committed", "failed_committed"}:
                if incoming != expected:
                    raise Rejected("Terminal effect result changed")
                continue
            if saved["state"] in {"succeeded", "failed"}:
                if incoming != expected:
                    raise Rejected("Terminal effect result changed")
                suffix = "-complete" if saved["state"] == "succeeded" else "-fail"
                try:
                    retained = self.journal.saved_command(key + suffix)
                except Rejected:
                    retained = None
                if retained is not None:
                    if suffix == "-complete":
                        receipts.append(await self.reconcile_completion(key))
                    else:
                        await self.reconcile_failure(key)
                    continue
            binding = Binding.read(saved["work"]["binding"])
            attempt = attempts.get(binding.attempt_id)
            if attempt is None:
                attempt = await self.recover(binding, saved["work"]["actor_id"])
            await self.observe(attempt, key, result)
            if result["outcome"] == "succeeded":
                receipts.append(await self.complete(attempt, key))
            elif result["outcome"] == "failed":
                await self.fail_delivery(attempt, key)
        if cursor is not None:
            self.journal.cursor(
                integration_id, cursor, **({"admissions": admissions} if admissions else {})
            )
        return receipts

    async def run(
        self,
        attempt,
        *,
        operation,
        scope,
        lease_ms=120000,
        wait_seconds=60,
        poll_seconds=1,
        resume=False,
    ):
        """Supervise one claimed attempt for a bounded time; runtime owns all readiness."""
        if wait_seconds <= 0 or poll_seconds <= 0:
            raise Rejected("Invalid execution wait budget")
        actor = self.registry.actors[attempt.actor_id]
        adapter = self.registry.adapter(actor)
        key = effect_key(attempt.binding, operation, scope)

        async def deliver():
            if resume:
                saved = self.journal.get(key)
                if saved["state"] in {"intent", "unknown"}:
                    await self.reconcile(attempt, key)
                elif saved["result"] is not None:
                    await self.observe(attempt, key, saved["result"])
            else:
                await self.dispatch(attempt, operation=operation, scope=scope)
            while attempt.active:
                saved = self.journal.get(key)
                if saved["state"] == "succeeded":
                    await self.complete(attempt, key)
                    break
                if saved["state"] == "failed":
                    await self.fail_delivery(attempt, saved["effect_key"])
                    break
                if saved["state"] in {"committed", "failed_committed"}:
                    break
                if saved["state"] in {"intent", "unknown"}:
                    return {
                        "effect_key": key,
                        "state": saved["state"],
                        "action": "reconcile before any further dispatch",
                    }
                await self.receive(
                    actor.integration_id, attempts={attempt.binding.attempt_id: attempt}
                )
                if attempt.active:
                    await asyncio.sleep(poll_seconds)
            return {"effect_key": key, "state": self.journal.get(key)["state"]}

        delivery = asyncio.create_task(deliver())
        heartbeat = asyncio.create_task(self.heartbeat_loop(attempt, lease_ms=lease_ms))
        try:
            done, _ = await asyncio.wait(
                {delivery, heartbeat}, timeout=wait_seconds, return_when=asyncio.FIRST_COMPLETED
            )
            if not done:
                raise UnknownOutcome(
                    "Execution wait expired; retained delivery requires reconciliation"
                )
            if delivery in done:
                return await delivery
            await heartbeat
            raise UnknownOutcome("Lease supervision stopped before delivery completed")
        finally:
            for task in (delivery, heartbeat):
                if not task.done():
                    task.cancel()
            await asyncio.gather(delivery, heartbeat, return_exceptions=True)
            attempt.active = False
            try:
                saved = self.journal.get(key)
            except Rejected:
                saved = None
            if saved is not None and saved["state"] not in {"committed", "failed_committed"}:
                try:
                    await asyncio.wait_for(adapter.cancel(saved["work"]), timeout=5)
                except Exception:
                    pass
                # Cancellation is advisory; the runtime lease and journal remain authoritative.
