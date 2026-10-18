"""Fixed capture-selector transport; no signer, result construction or key port.

The dedicated closed local-review entrypoint composes concrete pinned native
sources after separate installed qualification. The default CLI stays denied;
unsigned input never becomes trusted result evidence.
"""
from __future__ import annotations

import asyncio
from .model import Rejected, canonical, decode_json, validate_result
from .native_results import NativeResultAdmission, payload_for
from .connector_capture import CapturePending
from .wallet_authority import _PinnedCommand, _hex

MAX_RESULT_ENVELOPE = 700_000  # 256-KiB payload + 16-KiB proof + 64-KiB context, hex framed.


def decode_result_envelope(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_RESULT_ENVELOPE:
        raise Rejected("Native result envelope exceeds bound")
    value = decode_json(raw)
    if (type(value) is not dict or set(value) != {"schema","packet_hex","signed_context_hex"}
            or value["schema"] != "frank.secs-result-envelope.v1"):
        raise Rejected("Invalid native result envelope")
    for name, limit in (("packet_hex",2*(262144+16384+69)),("signed_context_hex",131072)):
        field = value[name]
        if type(field) is not str or not 0 < len(field) <= limit or len(field)%2 or not _hex(field,len(field)):
            raise Rejected("Invalid native result envelope")
    return value


class _ResultCommand(_PinnedCommand):
    def __init__(self, *, capture_root, **profile):
        self._capture_root = str(capture_root)
        super().__init__(**profile)

    def _check_profile(self):
        raw = super()._check_profile()
        value = decode_json(raw)
        if type(value) is not dict or value.get("capture_root") != self._capture_root:
            raise Rejected("Native configuration selects another capture root")

    def _decode_output(self, raw):
        decode_result_envelope(raw)

    async def request(self, mode, selector):
        if mode not in {"attest","resume","renew"}:
            raise Rejected("Unsupported result exchange")
        try:
            return await self._worker(self._invoke,mode,selector)
        except Rejected:
            raise Rejected("Native result producer unavailable") from None


class NativeResultProducer:
    """Host-injected ResultPort over the original trusted local capture writer.

    Only composition selects these artifact/configuration/policy dependencies.
    No config-file reconstruction, mode mutation or persisted token activates it.
    """
    effects_disabled = True

    def __init__(self, *, capture, claims, verifier, executable, executable_sha256,
                 configuration, configuration_sha256, timeout=5):
        from frank_review_adapter.local_capture import LocalReviewCapture
        if type(capture) is not LocalReviewCapture or getattr(claims,"effects_disabled",False) is not True:
            raise Rejected("Trusted capture and current claim port required")
        self.capture, self.claims, self.verifier = capture, claims, verifier
        self.transport = _ResultCommand(executable=executable,executable_sha256=executable_sha256,
            configuration=configuration,configuration_sha256=configuration_sha256,timeout=timeout,capture_root=capture.root)

    async def _original(self, work, result=None):
        work = decode_json(canonical(work))
        retained = await asyncio.to_thread(self.capture.publish,work)
        if result is not None and canonical(result) != canonical(retained["result"]):
            raise Rejected("Result differs from original computation capture")
        payload_for(retained["result"],work)
        return work, retained

    async def bind(self, result, work):
        # Freeze both caller-owned inputs before the first await.
        frozen_result, frozen_work = decode_json(canonical(result)), decode_json(canonical(work))
        work, retained = await self._original(frozen_work,frozen_result)
        await self.claims.check(work)
        existing = await asyncio.to_thread(self.capture.exchange,work)
        if existing is not None:
            raise CapturePending("Use explicit retained-result resume or renewal")
        exchange = await asyncio.to_thread(self.capture.exchange,work,"attest",None)
        return await self._perform(work,retained,exchange,"attest")

    async def resume(self, work):
        work, retained = await self._original(work)
        await self.claims.check(work)
        exchange = await asyncio.to_thread(self.capture.exchange,work)
        if exchange is None:
            raise CapturePending("No retained result selector; resume never creates")
        return await self._perform(work,retained,exchange,"resume")

    async def renew(self, work):
        work, retained = await self._original(work)
        await self.claims.check(work)
        previous = await asyncio.to_thread(self.capture.exchange,work)
        if previous is None or previous["envelope"] is None:
            raise CapturePending("Renewal requires a completed original tip; resume pending exchange")
        from hashlib import sha256
        exchange = await asyncio.to_thread(self.capture.exchange,work,"renew",sha256(bytes(previous["envelope"])).hexdigest())
        return await self._perform(work,retained,exchange,"renew")

    async def reconcile(self, work):
        work, retained = await self._original(work)
        exchange = await asyncio.to_thread(self.capture.exchange,work)
        if exchange is None:
            # Durable capture existed before any Native invocation. This is its
            # first attestation, selected by local state, never denial fallback.
            return await self.bind(retained["result"],work)
        return await self.resume(work)

    async def _perform(self, work, retained, exchange, mode):
        # A pending selector is durable before launch. Any unknown output keeps
        # that exact selector; subsequent recovery can only use explicit resume.
        await self.claims.check(work)
        output = await self.transport.request(mode,bytes(exchange["selector"]))
        proof = decode_result_envelope(output)
        # These bytes remain untrusted provenance-free transport output until
        # the independent verifier below succeeds. Retaining them also permits
        # explicit renewal of an actually received expired original tip; Native
        # independently checks the exact parent and capture before renewing.
        await asyncio.to_thread(self.capture.exchange_completed,work,exchange,output)
        result = {**decode_json(canonical(retained["result"])),"proof":proof}
        validate_result(result,work)
        admission = await self.verifier.verify(result,work)
        if type(admission) is not NativeResultAdmission:
            raise Rejected("Independent native result admission required")
        admission.revalidate(result,work)
        # Current Runtime claim and current result policy follow all transport /
        # store waits. The immutable original capture receipt is never rewritten.
        await self.claims.check(work)
        admission.revalidate(result,work)
        return result

    async def aclose(self):
        await self.transport.aclose()
