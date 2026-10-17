"""Public SDK adapter. Runtime schemas may be loaded without runtime imports."""

from __future__ import annotations
import asyncio
import json
import uuid
from .model import Rejected, UnknownOutcome, canonical


class GeneratedClientAdapter:
    def __init__(self, client):
        self.client = client

    async def command(self, envelope, *, authority):
        return await self._execute(envelope, authority)

    async def command_guarded(self, envelope, *, authority, guard):
        return await self._execute(envelope, authority, guard)

    async def _execute(self, envelope, authority, guard=None):
        body = canonical(envelope)

        def dispatch():
            frozen = json.loads(body)
            if guard is not None:
                guard(frozen)
            # Last local authority point is in this worker, immediately before SDK dispatch.
            return self.client.execute(frozen, evidence=authority)

        try:
            return await asyncio.to_thread(dispatch)
        except Exception as exc:
            from process_runtime_client import RuntimeClientError

            if not isinstance(exc, RuntimeClientError):
                raise
            if exc.uncertain:
                raise UnknownOutcome(
                    f"Runtime outcome unknown; reconcile request {envelope['request_id']}"
                ) from None
            raise RuntimeFailure(exc.code, exc.retryable) from None

    async def query(self, envelope, *, authority):
        try:
            return await asyncio.to_thread(self.client.query, envelope, evidence=authority)
        except Exception as exc:
            from process_runtime_client import RuntimeClientError

            if not isinstance(exc, RuntimeClientError):
                raise
            raise RuntimeFailure(exc.code, exc.retryable) from None


class ContractValidator:
    def __init__(self, bundle):
        from jsonschema import Draft202012Validator, validators

        strict = validators.extend(
            Draft202012Validator,
            type_checker=Draft202012Validator.TYPE_CHECKER.redefine(
                "integer", lambda checker, value: type(value) is int
            ),
        )
        self.validators = {
            kind: strict({**bundle, "$ref": f"#/$defs/{kind}"})
            for kind in ("command", "query", "result", "query_result", "error")
        }

    def __call__(self, envelope, kind):
        canonical(envelope)
        if list(self.validators[kind].iter_errors(envelope)):
            raise Rejected(f"Runtime {kind} contract mismatch")


class RuntimeFailure(Rejected):
    def __init__(self, code, retryable=False):
        super().__init__(f"Runtime rejected command: {code}")
        self.code, self.retryable = code, retryable


class RuntimeGateway:
    def __init__(self, client, authority, journal, validator):
        self.client, self.authority, self.journal, self.validate = (
            client,
            authority,
            journal,
            validator,
        )

    async def execute(self, operation, payload, expected_version, *, request_id=None, guard=None):
        from process_runtime_client import command_envelope

        envelope = command_envelope(
            operation,
            request_id=request_id or uuid.uuid4().hex,
            expected_version=expected_version,
            payload=payload,
        )
        return await self.send(envelope, guard=guard)

    async def send(self, envelope, *, guard=None):
        envelope = json.loads(canonical(envelope))
        self.validate(envelope, "command")
        self.journal.command(envelope)
        if guard is None and self.journal.command_requires_admission(envelope):
            raise Rejected("Native terminal dispatch requires current result admission")
        guarded = getattr(self.client, "command_guarded", None)
        if guard is not None and not callable(guarded):
            raise Rejected("Native terminal transport does not support guarded dispatch")
        # Obtain fresh authority even for an exact runtime retry. Never cache credentials.
        evidence = await self.authority.evidence(canonical(envelope))
        try:
            if guard is None:
                if self.journal.command_requires_admission(envelope):
                    raise Rejected("Native terminal dispatch requires current result admission")
                response = await self.client.command(envelope, authority=evidence)
            else:
                guard(envelope)
                response = await guarded(envelope, authority=evidence, guard=guard)
        except (TimeoutError, ConnectionError) as exc:
            raise UnknownOutcome(
                f"Runtime outcome unknown; reconcile request {envelope['request_id']}"
            ) from exc
        if response.get("schema") == "runtime.error.v1":
            self.validate(response, "error")
            raise RuntimeFailure(response["code"], response["retryable"])
        self.validate(response, "result")
        if any(
            response[field] != envelope[field] for field in ("request_id", "operation", "resource")
        ):
            raise Rejected("Runtime result correlation mismatch")
        self.journal.command_result(envelope["request_id"], response)
        return response

    async def replay(self, request_id, *, guard=None):
        return await self.send(
            json.loads(self.journal.saved_command(request_id)["body"]), guard=guard
        )

    async def query(self, operation, payload):
        envelope = {"schema": "runtime.query.v1", "operation": operation, "payload": payload}
        self.validate(envelope, "query")
        evidence = await self.authority.evidence(canonical(envelope))
        response = await self.client.query(envelope, authority=evidence)
        if response.get("schema") == "runtime.error.v1":
            self.validate(response, "error")
            raise RuntimeFailure(response["code"], response["retryable"])
        self.validate(response, "query_result")
        if response["operation"] != operation:
            raise Rejected("Runtime query correlation mismatch")
        return response["data"]
