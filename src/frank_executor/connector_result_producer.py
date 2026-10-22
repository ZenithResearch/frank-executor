"""Native result production from immutable Matrix or Hermes observations."""

from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path

from .connector_capture import CapturePending, ConnectorCapture
from .model import Rejected, canonical, decode_json, validate_result
from .native_result_producer import decode_result_envelope
from .native_results import NativeResultAdmission, payload_for
from .wallet_authority import _PinnedCommand


class _ConnectorResultCommand(_PinnedCommand):
    def __init__(
        self,
        *,
        journal,
        connector_policy_sha256,
        authority_configuration,
        authority_configuration_sha256,
        **profile,
    ):
        self._journal = str(Path(journal))
        self._policy_sha256 = connector_policy_sha256
        self._authority_configuration = str(Path(authority_configuration))
        self._authority_configuration_sha256 = authority_configuration_sha256
        super().__init__(**profile)

    def _check_profile(self):
        raw = super()._check_profile()
        value = decode_json(raw)
        if (
            type(value) is not dict
            or set(value)
            != {
                "schema",
                "journal",
                "connector_policy_sha256",
                "authority_configuration",
                "authority_configuration_sha256",
            }
            or value["schema"] != "frank.connector-result-producer.v1"
            or value["journal"] != self._journal
            or value["connector_policy_sha256"] != self._policy_sha256
            or value["authority_configuration"] != self._authority_configuration
            or value["authority_configuration_sha256"]
            != self._authority_configuration_sha256
        ):
            raise Rejected("Native configuration selects another connector capture")
        return raw

    def _decode_output(self, raw):
        decode_result_envelope(raw)

    async def request(self, mode, selector):
        if mode not in {"attest", "resume", "renew"}:
            raise Rejected("Unsupported result exchange")
        try:
            return await self._worker(self._invoke, mode, selector)
        except Rejected:
            raise Rejected("Native connector result producer unavailable") from None


class ConnectorResultProducer:
    """Attest one retained connector observation through an installed native issuer."""

    def __init__(
        self,
        *,
        capture,
        claims,
        verifier,
        executable,
        executable_sha256,
        configuration,
        configuration_sha256,
        authority_configuration,
        authority_configuration_sha256,
        timeout=5,
    ):
        if type(capture) is not ConnectorCapture or not callable(getattr(claims, "check", None)):
            raise Rejected("Trusted connector capture and current claim port required")
        self.capture, self.claims, self.verifier = capture, claims, verifier
        retained_policy = hashlib.sha256(capture.policy.bytes()).hexdigest()
        self.transport = _ConnectorResultCommand(
            executable=executable,
            executable_sha256=executable_sha256,
            configuration=configuration,
            configuration_sha256=configuration_sha256,
            timeout=timeout,
            journal=capture.journal.path,
            connector_policy_sha256=retained_policy,
            authority_configuration=authority_configuration,
            authority_configuration_sha256=authority_configuration_sha256,
        )

    async def _original(self, work):
        work = decode_json(canonical(work))
        retained = await asyncio.to_thread(self.capture.retained, work)
        if retained is None:
            raise CapturePending("No retained connector result")
        result = retained["body"]
        payload_for(result, work)
        return work, retained, result

    async def bind(self, work):
        work, retained, result = await self._original(work)
        await self.claims.check(work)
        existing = await asyncio.to_thread(self.capture.exchange, work)
        if existing is not None:
            raise CapturePending("Use explicit retained-result resume or renewal")
        exchange = await asyncio.to_thread(self.capture.exchange, work, "attest", None)
        return await self._perform(work, retained, result, exchange, "attest")

    async def resume(self, work):
        work, retained, result = await self._original(work)
        await self.claims.check(work)
        exchange = await asyncio.to_thread(self.capture.exchange, work)
        if exchange is None:
            raise CapturePending("No retained result selector; resume never creates")
        return await self._perform(work, retained, result, exchange, "resume")

    async def renew(self, work):
        work, retained, result = await self._original(work)
        await self.claims.check(work)
        previous = await asyncio.to_thread(self.capture.exchange, work)
        if previous is None or previous["envelope"] is None:
            raise CapturePending(
                "Renewal requires a completed original tip; resume pending exchange"
            )
        renewal_of = hashlib.sha256(bytes(previous["envelope"])).hexdigest()
        exchange = await asyncio.to_thread(self.capture.exchange, work, "renew", renewal_of)
        return await self._perform(work, retained, result, exchange, "renew")

    async def reconcile(self, work):
        work, retained, result = await self._original(work)
        exchange = await asyncio.to_thread(self.capture.exchange, work)
        if exchange is None:
            return await self.bind(work)
        return await self._perform(work, retained, result, exchange, "resume")

    async def _perform(self, work, retained, result, exchange, mode):
        await self.claims.check(work)
        output = await self.transport.request(mode, bytes(exchange["selector"]))
        proof = decode_result_envelope(output)
        await asyncio.to_thread(self.capture.exchange_completed, work, exchange, output)
        proved = {**decode_json(canonical(result)), "proof": proof}
        validate_result(proved, work)
        admission = await self.verifier.verify(proved, work)
        if type(admission) is not NativeResultAdmission:
            raise Rejected("Independent native result admission required")
        admission.revalidate(proved, work)
        await self.claims.check(work)
        admission.revalidate(proved, work)
        return proved

    async def aclose(self):
        await self.transport.aclose()
