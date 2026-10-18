"""Result-port orchestration tests with explicitly synthetic Native responses.

The helper does not sign: actual Native binary/helper composition is a later
ordinary integration control and cannot be credited by these unit fixtures.
"""
import asyncio
from copy import deepcopy
import hashlib

import pytest
from frank_executor.model import Rejected, canonical, digest
from frank_executor.connector_capture import CapturePending
from frank_executor.native_result_producer import NativeResultProducer, _ResultCommand, decode_result_envelope
from frank_executor.native_results import NativeResultVerifier
from test_local_review_capture import setup_capture, completed, result_for
from native_result_support import SyntheticHelper, policy

PROOF = {"schema":"frank.secs-result-envelope.v1","packet_hex":"00","signed_context_hex":"00"}


class Claims:
    effects_disabled = True
    def __init__(self): self.current,self.calls = True,0
    async def check(self,work):
        self.calls += 1
        if not self.current: raise Rejected("retired unit claim")
        return {"current":True,"work_sha256":digest(work)}


def setup_producer(tmp_path):
    capture,work = setup_capture(tmp_path)
    result = completed(capture,work)
    helper = SyntheticHelper(work,{**result,"proof":PROOF})
    state = {"now":1001.0,"policy":policy()}
    verifier = NativeResultVerifier(helper,lambda:state["policy"],clock=lambda:state["now"])
    claims = Claims()
    producer = NativeResultProducer(capture=capture,claims=claims,verifier=verifier,
        executable=tmp_path / "never-executed-unit-program",executable_sha256="a"*64,
        configuration=tmp_path / "never-read-unit-config",configuration_sha256="b"*64)
    calls,outputs = [],{}
    async def request(mode,selector):
        calls.append((mode,selector))
        if mode == "resume":
            if selector not in outputs: raise Rejected("missing unit Native output")
            return outputs[selector]
        proof = deepcopy(PROOF)
        if mode == "renew":
            proof["packet_hex"],proof["signed_context_hex"] = "01","01"
            helper.context.update(issued_at=int(state["now"]),expires_at=int(state["now"])+60,session_id=[3]*16,nonce=[4]*12,
                packet_hash=list(hashlib.sha256(b"\x01").digest()))
        outputs[selector] = canonical(proof)
        return outputs[selector]
    producer.transport.request = request
    return producer,work,result,claims,helper,state,calls,outputs


def test_binder_adds_only_independently_admitted_proof(tmp_path):
    producer,work,result,claims,helper,state,calls,outputs = setup_producer(tmp_path)
    bound = asyncio.run(producer.bind(result,work))
    assert {k:v for k,v in bound.items() if k != "proof"} == result
    assert bound["proof"] == PROOF and calls[0][0] == "attest"
    assert claims.calls >= 3
    assert producer.verifier.mode == "native_unqualified"


def test_wrong_computed_body_fails_before_native_invocation(tmp_path):
    producer,work,result,claims,helper,state,calls,outputs = setup_producer(tmp_path)
    changed = deepcopy(result);changed["event_id"] = "different"
    with pytest.raises(Rejected,match="differs"):
        asyncio.run(producer.bind(changed,work))
    assert calls == []


def test_lost_attest_output_requires_exact_explicit_no_create_resume(tmp_path):
    producer,work,result,claims,helper,state,calls,outputs = setup_producer(tmp_path)
    real = producer.transport.request
    async def lost(mode,selector):
        await real(mode,selector)
        raise Rejected("unit output lost after durable Native result")
    producer.transport.request = lost
    with pytest.raises(Rejected): asyncio.run(producer.bind(result,work))
    original = producer.capture.exchange(work)
    assert original["envelope"] is None and original["mode"] == "attest"
    producer.transport.request = real
    with pytest.raises(CapturePending): asyncio.run(producer.bind(result,work))
    assert len(calls) == 1
    bound = asyncio.run(producer.resume(work))
    assert bound["proof"] == PROOF
    assert [m for m,s in calls] == ["attest","resume"]
    assert calls[0][1] == calls[1][1] == bytes(original["selector"])


def test_resume_missing_selector_never_creates(tmp_path):
    producer,work,result,claims,helper,state,calls,outputs = setup_producer(tmp_path)
    with pytest.raises(CapturePending,match="never creates"):
        asyncio.run(producer.resume(work))
    assert calls == []


def test_expired_proof_explicit_renewal_changes_only_proof_not_computation(tmp_path):
    producer,work,result,claims,helper,state,calls,outputs = setup_producer(tmp_path)
    first = asyncio.run(producer.bind(result,work))
    original = producer.capture.retained(work)
    state["now"] = 1061.0
    with pytest.raises(Rejected): asyncio.run(producer.resume(work))
    assert calls[-1][0] == "resume"
    renewed = asyncio.run(producer.renew(work))
    assert renewed["proof"] != first["proof"]
    assert {k:v for k,v in renewed.items() if k != "proof"} == result
    assert producer.capture.retained(work)["payload"] == original["payload"]
    assert producer.capture.retained(work)["receipt"] == original["receipt"]
    assert [m for m,s in calls] == ["attest","resume","renew"]


def test_lost_renewal_resumes_saved_parent_edge_without_second_renew(tmp_path):
    producer,work,result,claims,helper,state,calls,outputs = setup_producer(tmp_path)
    asyncio.run(producer.bind(result,work))
    real = producer.transport.request
    async def lost(mode,selector):
        output = await real(mode,selector)
        if mode == "renew": raise Rejected("unit renewal reply lost")
        return output
    producer.transport.request = lost
    with pytest.raises(Rejected): asyncio.run(producer.renew(work))
    pending = producer.capture.exchange(work)
    assert pending["mode"] == "renew" and pending["envelope"] is None
    with pytest.raises(CapturePending): asyncio.run(producer.renew(work))
    producer.transport.request = real
    resumed = asyncio.run(producer.resume(work))
    assert resumed["proof"]["packet_hex"] == "01"
    assert [m for m,s in calls] == ["attest","renew","resume"]
    assert calls[-1][1] == calls[-2][1] == bytes(pending["selector"])


@pytest.mark.parametrize("stage",["before","after"])
def test_retired_claim_blocks_attestation_or_export(tmp_path,stage):
    producer,work,result,claims,helper,state,calls,outputs = setup_producer(tmp_path)
    if stage == "before": claims.current = False
    else:
        real = producer.transport.request
        async def retire(mode,selector):
            value = await real(mode,selector)
            claims.current = False
            return value
        producer.transport.request = retire
    with pytest.raises(Rejected,match="retired"):
        asyncio.run(producer.bind(result,work))
    assert len(calls) == (0 if stage == "before" else 1)


def test_independent_verifier_failure_never_returns_unsigned_or_trusted_result(tmp_path):
    producer,work,result,claims,helper,state,calls,outputs = setup_producer(tmp_path)
    helper.context["resource"] = "runs/foreign/steps/step/attempts/attempt/effects/effect-1"
    with pytest.raises(Rejected): asyncio.run(producer.bind(result,work))
    assert producer.capture.exchange(work)["envelope"] == canonical(PROOF)  # untrusted transport bytes only
    assert producer.capture.retained(work)["result"] == result


def test_result_history_is_finite_and_retains_original(tmp_path):
    producer,work,result,claims,helper,state,calls,outputs = setup_producer(tmp_path)
    asyncio.run(producer.bind(result,work))
    # Store-only bounded-history control. Each retained exact parent edge has a
    # distinct closed envelope; it does not pretend to be cryptographic evidence.
    for index in range(3):
        previous = producer.capture.exchange(work)
        row = producer.capture.exchange(work,"renew",hashlib.sha256(bytes(previous["envelope"])).hexdigest())
        proof = {**PROOF,"packet_hex":f"{index+1:02x}"}
        producer.capture.exchange_completed(work,row,canonical(proof))
    with pytest.raises(Rejected,match="capacity"):
        previous = producer.capture.exchange(work)
        producer.capture.exchange(work,"renew",hashlib.sha256(bytes(previous["envelope"])).hexdigest())
    assert producer.capture.retained(work)["result"] == result


@pytest.mark.parametrize("raw",[b"{}",b'{"schema":"frank.secs-result-envelope.v1","packet_hex":"AA","signed_context_hex":"00"}',
    b'{"schema":"frank.secs-result-envelope.v1","packet_hex":"00","packet_hex":"01","signed_context_hex":"00"}',
    b'{"schema":"runtime.secs-envelope.v1","packet_hex":"00","signed_context_hex":"00"}'])
def test_result_decoder_is_closed_and_distinct_from_wallet_wire(raw):
    with pytest.raises(Rejected): decode_result_envelope(raw)


def test_shared_owned_transport_uses_fixed_result_mode_and_pinned_config(tmp_path):
    # Ordinary fake-process framing control, not a Native signature/custody test.
    from test_wallet_authority import setup
    wallet,executable,configuration = setup(tmp_path,"sys.stdout.write("+repr(canonical(PROOF).decode())+")\n")
    executable.write_text(executable.read_text().replace('("issue","query","resume")','("attest","resume","renew")'))
    configuration.write_bytes(canonical({"capture_root":str(tmp_path)}))
    p = wallet._profile
    transport = _ResultCommand(executable=p.executable,executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
        configuration=p.configuration,configuration_sha256=hashlib.sha256(configuration.read_bytes()).hexdigest(),timeout=2,capture_root=tmp_path)
    selector = canonical({"schema":"frank.result-capture-selector.v1","capture_id":"a"*64,"renewal_of":None})
    try:
        assert asyncio.run(transport.request("attest",selector)) == canonical(PROOF)
        assert transport._owned is None and transport._census is None
        with pytest.raises(Rejected): asyncio.run(transport.request("issue",selector))
    finally:
        asyncio.run(transport.aclose())
