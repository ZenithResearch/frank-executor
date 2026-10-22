"""Public-client and trusted-adapter unit controls, no live provider claims."""
import asyncio
import base64
from copy import deepcopy
import hashlib
import time

import pytest
from frank_executor.model import Rejected, canonical, digest
from frank_executor.journal import Journal
from frank_executor.native_results import NativeResultVerifier
from frank_executor.native_result_producer import NativeResultProducer
from frank_executor.connector_capture import CapturePending
from frank_review_adapter.adapter import ReviewAdapter
from frank_review_adapter.local_capture import ObservationRecorder
from frank_review_adapter.local_ports import RuntimeArtifacts, RuntimeClaims, RuntimeSnapshotSources, SuppliedTranscript, DurableSimulatedIntents
from frank_review_adapter.ports import ReviewPorts, ReviewFailure
from test_local_review_capture import setup_capture, result_for
from test_native_result_producer import Claims, PROOF
from native_result_support import SyntheticHelper, policy


class UnitSources:
    effects_disabled = True
    def __init__(self): self.calls = 0; self.failure = None
    async def inspect(self,*args):
        self.calls += 1
        if self.failure: raise self.failure
        return []


def adapter_fixture(tmp_path):
    capture,work = setup_capture(tmp_path)
    claims = Claims()
    result = result_for(work,{"codebase_context":[]})
    helper = SyntheticHelper(work,{**result,"proof":PROOF})
    verifier = NativeResultVerifier(helper,policy,clock=lambda:1001)
    producer = NativeResultProducer(capture=capture,claims=claims,verifier=verifier,
        executable=tmp_path / "never-executed-unit-program",executable_sha256="a"*64,
        configuration=tmp_path / "never-read-unit-config",configuration_sha256="b"*64)
    calls=[]
    async def request(mode,selector): calls.append(mode);return canonical(PROOF)
    producer.transport.request=request
    producer.transport.check_available=lambda:None  # Explicit orchestration unit seam, not artifact qualification.
    sources=UnitSources()
    ports=ReviewPorts(sources,sources,sources,sources,sources,claims,producer)
    adapter=ReviewAdapter.local_native("fixture",{"effects":"disabled","route":"local"},ports=ports,
        capture=capture,producer=producer,environment="test")
    return adapter,capture,work,producer,claims,sources,ports,calls


def test_local_adapter_reopens_capture_and_never_reruns_handler(tmp_path):
    adapter,capture,work,producer,claims,sources,ports,calls = adapter_fixture(tmp_path)
    async def case():
        await adapter.connect()
        first = await adapter.send(work)
        assert first["provider_reference"].startswith("local-review:")
        row = capture.retained(work)
        assert [o["kind"] for o in row["receipt_value"]["observations"]] == ["claim-check","claim-check"]
        # Empty pure transformation has no invented provider observation.
        assert row["receipt_value"]["completion_kind"] == "computed"
        reopened=ReviewAdapter.local_native("fixture",{"effects":"disabled","route":"local"},ports=ports,
            capture=capture,producer=producer,environment="test")
        await reopened.connect()
        assert await reopened.send(work) == first
        assert await reopened.reconcile(work,first["provider_reference"]) == first
        assert calls == ["attest","resume","resume"] and sources.calls == 0
        assert (await reopened.health())["authority"] == "native_unqualified"
    asyncio.run(case())


def test_unknown_handler_exception_leaves_durable_unknown_not_terminal(tmp_path):
    adapter,capture,work,producer,claims,sources,ports,calls = adapter_fixture(tmp_path)
    work["inputs"]["observations"]=[{"observation_id":"o","selectors":["button.x"],"component":"button.x","match_type":"unresolved"}]
    sources.failure=RuntimeError("unit provider outcome unknown")
    async def case():
        await adapter.connect()
        with pytest.raises(RuntimeError): await adapter.send(work)
        with pytest.raises(CapturePending): await adapter.send(work)
        assert sources.calls == 1 and calls == []
    asyncio.run(case())


def test_cancellation_after_reservation_cannot_recompute(tmp_path):
    adapter,capture,work,producer,claims,sources,ports,calls = adapter_fixture(tmp_path)
    work["inputs"]["observations"]=[{"observation_id":"o","selectors":["button.x"],"component":"button.x","match_type":"unresolved"}]
    sources.failure=asyncio.CancelledError()
    async def case():
        await adapter.connect()
        with pytest.raises(asyncio.CancelledError): await adapter.send(work)
        with pytest.raises(CapturePending): await adapter.send(work)
        assert sources.calls == 1 and calls == []
    asyncio.run(case())


def test_actual_known_handler_failure_captures_empty_failed_result(tmp_path):
    from frank_executor.native_results import payload_for
    adapter,capture,work,producer,claims,sources,ports,calls = adapter_fixture(tmp_path)
    work["inputs"]["observations"]=[{"observation_id":"o","selectors":["button.x"],"component":"button.x","match_type":"unresolved"}]
    sources.failure=ReviewFailure("malformed_source_evidence")
    producer.verifier.helper.request_hex=payload_for(result_for(work,{},"failed"),work).hex()
    async def case():
        await adapter.connect()
        result=await adapter.send(work)
        assert result["outcome"]=="failed" and result["outputs"]=={}
        receipt=capture.retained(work)["receipt_value"]
        assert receipt["completion_kind"]=="malformed_source_evidence"
        assert receipt["observations"][-1]["kind"]=="claim-check" and sources.calls==1
        assert await adapter.reconcile(work,result["provider_reference"])==result
        assert sources.calls==1 and calls==["attest","resume"]
    asyncio.run(case())


def test_default_production_composition_stays_closed(tmp_path):
    adapter,capture,work,producer,claims,sources,ports,calls = adapter_fixture(tmp_path)
    with pytest.raises(Rejected,match="native command/result"):
        ReviewAdapter.local_native("fixture",{"effects":"disabled","route":"local"},ports=ports,capture=capture,producer=producer)
    assert calls == []


class UnitGateway:
    def __init__(self): self.reads=[];self.writes=[];self.data={}
    async def query(self,op,payload): self.reads.append((op,deepcopy(payload)));return deepcopy(self.data[op])
    async def execute(self,op,payload,expected_version,**kwargs):
        self.writes.append((op,deepcopy(payload),expected_version,kwargs))
        return {"result":{"artifact":payload["artifact"]}}


def test_artifact_port_uses_public_wire_and_checks_actual_content():
    gateway=UnitGateway();port=RuntimeArtifacts(gateway)
    raw=b"real unit artifact bytes";ref={"content_hash":hashlib.sha256(raw).hexdigest(),"byte_length":len(raw),"media_type":"text/plain"}
    gateway.data["artifact.get"]={"artifact":ref,"content_base64":base64.b64encode(raw).decode()}
    async def case():
        assert await port.read(ref)==raw
        assert await port.write(raw,"text/plain")==ref
        assert gateway.reads==[("artifact.get",{"content_hash":ref["content_hash"]})]
        assert gateway.writes[0][0]=="artifact.put" and gateway.writes[0][2] is None
        gateway.data["artifact.get"]["content_base64"]=base64.b64encode(b"tampered").decode()
        with pytest.raises(ReviewFailure,match="integrity"): await port.read(ref)
    asyncio.run(case())


def test_artifact_port_replays_deterministic_request_after_unknown_outcome():
    class Saved:
        def __init__(self): self.ids=set()
        def saved_command(self,request_id):
            if request_id not in self.ids: raise Rejected("Unknown command request")
            return {"request_id":request_id}
    class ReplayGateway(UnitGateway):
        def __init__(self): super().__init__();self.journal=Saved();self.replays=[]
        async def execute(self,op,payload,expected_version,**kwargs):
            self.journal.ids.add(kwargs["request_id"])
            return await super().execute(op,payload,expected_version,**kwargs)
        async def replay(self,request_id):
            self.replays.append(request_id)
            payload=self.writes[0][1]
            return {"result":{"artifact":payload["artifact"]}}
    gateway=ReplayGateway();port=RuntimeArtifacts(gateway);raw=b"same bytes"
    async def case():
        first=await port.write(raw,"text/plain",request_id="artifact-fixed")
        second=await port.write(raw,"text/plain",request_id="artifact-fixed")
        assert first==second and gateway.replays==["artifact-fixed"]
        assert len(gateway.writes)==1
    asyncio.run(case())


def claim_fixture(tmp_path, capabilities=None):
    from process_runtime.compiler import compile_draft
    capture,work=setup_capture(tmp_path)
    journal=capture.journal
    journal.delivery("delivery-unit",work)
    assert journal.begin_dispatch("delivery-unit")
    gateway=UnitGateway()
    input_types={"observations":{"kind":"array","items":{"kind":"string"}},"subject_id":{"kind":"string"}}
    draft={"schema":"process.draft.v1","process_id":"p","inputs":input_types,
        "steps":[{"step_id":"step","depends_on":[],"capabilities":[work["operation"]] if capabilities is None else capabilities,
            "resources":[],"inputs":input_types,"outputs":work["output_types"],"max_attempts":1,
            "bindings":{n:{"source":"run_input","name":n} for n in input_types}}]}
    compiled=compile_draft(draft).snapshot.value
    pin={"process_id":"p","process_version":"v","compilation_hash":digest(compiled)}
    gateway.data["attempt.get"]={**work["binding"],"actor_id":work["actor_id"],"state":"active","current":True,
        "lease_expires_at_ms":time.time_ns()//1_000_000+60000,"inputs":work["inputs"],"input_digest":digest(work["inputs"]),
        "input_types":input_types,"output_types":work["output_types"],"pin":pin}
    gateway.data["run.get"]={"run_id":"run","state":"running","version":1,"pin":pin}
    gateway.data["version.get"]={"pin":pin,"compiled":compiled}
    claims=RuntimeClaims(gateway,journal,actor_id="worker",integration_id="fixture",route="local")
    return claims,gateway,work


def test_claims_require_exact_frank_dispatch_and_current_runtime_state(tmp_path):
    claims,gateway,work=claim_fixture(tmp_path)
    observed=asyncio.run(claims.check(work))
    assert observed["work_sha256"]==digest(work)
    assert [op for op,p in gateway.reads]==["attempt.get","run.get","version.get"]
    changed=deepcopy(work);changed["operation"]="review.extract"
    with pytest.raises(Rejected,match="dispatched"): asyncio.run(claims.check(changed))


@pytest.mark.parametrize("mutation",["fence","actor","inputs","outputs","retired","expired","cancelled","pin"])
def test_current_runtime_claim_substitutions_deny(tmp_path,mutation):
    claims,gateway,work=claim_fixture(tmp_path)
    attempt=gateway.data["attempt.get"]
    if mutation=="fence":attempt["fence"]+=1
    elif mutation=="actor":attempt["actor_id"]="foreign"
    elif mutation=="inputs":attempt["inputs"]={}
    elif mutation=="outputs":attempt["output_types"]={}
    elif mutation=="retired":attempt["current"]=False
    elif mutation=="expired":attempt["lease_expires_at_ms"]=0
    elif mutation=="cancelled":gateway.data["run.get"]["state"]="cancelled"
    else:gateway.data["run.get"]["pin"]={}
    with pytest.raises(Rejected):asyncio.run(claims.check(work))


def test_durable_simulated_intents_never_claim_external_delivery(tmp_path):
    journal=Journal(tmp_path / "frank.sqlite")
    port=DurableSimulatedIntents(journal)
    binding={"run_id":"run","step_id":"step","attempt_id":"attempt","fence":1}
    first=asyncio.run(port.record(binding,"review.status",{"decision":"processed"}))
    assert first["simulation"] is first["recorded"] is True
    reopened=DurableSimulatedIntents(Journal(journal.path))
    assert asyncio.run(reopened.record(binding,"review.status",{"decision":"processed"}))==first
    with pytest.raises(Rejected):asyncio.run(reopened.record(binding,"review.status",{"decision":"changed"}))


def test_supplied_transcript_requires_selected_real_audio_and_honest_provenance():
    gateway=UnitGateway();artifacts=RuntimeArtifacts(gateway)
    audio=b"unit bytes, not a real audio qualification";audio_sha=hashlib.sha256(audio).hexdigest()
    supplied={"schema":"frank.supplied-audio-transcript.v1","audio_sha256":audio_sha,"transcript":"Supplied unit evidence.","words":[],"audio_offset_ms":0}
    raw=canonical(supplied);ref={"content_hash":hashlib.sha256(raw).hexdigest(),"byte_length":len(raw),"media_type":"application/json"}
    gateway.data["artifact.get"]={"artifact":ref,"content_base64":base64.b64encode(raw).decode()}
    port=SuppliedTranscript(artifacts,audio_sha256=audio_sha,transcript_artifact=ref)
    result=asyncio.run(port.transcribe(audio,{"content_hash":audio_sha}))
    assert result["words"]==[] and result["provenance"]["kind"]=="supplied-transcript-for-audio"
    with pytest.raises(Rejected):asyncio.run(port.transcribe(b"different",{"content_hash":audio_sha}))


def test_repeated_artifact_content_uses_distinct_actual_gateway_command_intents(tmp_path):
    # Real Gateway/SDK framing/Frank Journal, stateful Native-issue seam only.
    # A completed command ID cannot be issued anew; explicit Gateway.replay is
    # separate from these two legitimate artifact-write invocations.
    from frank_executor.runtime import RuntimeGateway, GeneratedClientAdapter, ContractValidator
    from process_runtime_client.client import SCHEMA
    class CompletedAuthority:
        def __init__(self): self.issued=set();self.requests=[]
        async def evidence(self,raw):
            request=__import__("json").loads(raw)
            assert canonical(request)==raw
            if request["request_id"] in self.issued:
                raise Rejected("unit Native issue rejects retained Completed request")
            self.issued.add(request["request_id"]);self.requests.append(request)
            return b"unit-outbound-authority-not-a-signature"
        async def resume_evidence(self,raw):
            raise AssertionError("new artifact invocation must not silently select saved-command recovery")
    class PublicCommandClient:
        def __init__(self): self.requests=[]
        def execute(self,request,evidence):
            assert evidence==b"unit-outbound-authority-not-a-signature"
            self.requests.append(deepcopy(request))
            return {"schema":"runtime.result.v1","request_id":request["request_id"],"operation":request["operation"],
                "duplicate":False,"resource":request["resource"],"version":1,"result":{"artifact":request["payload"]["artifact"]}}
    authority,client=CompletedAuthority(),PublicCommandClient()
    journal=Journal(tmp_path / "frank.sqlite")
    gateway=RuntimeGateway(GeneratedClientAdapter(client),authority,journal,ContractValidator(SCHEMA))
    artifacts=RuntimeArtifacts(gateway)
    raw=b"identical legitimate content from two actual handler writes"
    async def case():
        first=await artifacts.write(raw,"text/plain")
        second=await artifacts.write(raw,"text/plain")
        assert first==second=={"content_hash":hashlib.sha256(raw).hexdigest(),"byte_length":len(raw),"media_type":"text/plain"}
    asyncio.run(case())
    assert len(authority.requests)==len(client.requests)==2
    first,second=client.requests
    assert first["request_id"]!=second["request_id"]
    assert first["payload"]==second["payload"] and first["resource"]==second["resource"]
    assert {**first,"request_id":second["request_id"]}==second
    assert journal.pending_commands()==[]
    assert all(journal.saved_command(r["request_id"])["state"]=="observed" for r in client.requests)


@pytest.mark.parametrize("authorized",[True,False])
def test_current_claim_requires_selected_operation_in_the_actual_published_step(tmp_path,authorized):
    # Both worlds use a genuinely compiled, hash-bound published step and a
    # matching Frank dispatch/Runtime Attempt/run. Only capability membership
    # (and its consequential compilation hash) differs; no stale-pin shortcut.
    claims,gateway,work=claim_fixture(tmp_path,capabilities=["review.bind_source"] if authorized else ["review.extract"])
    published=gateway.data["version.get"]
    assert published["pin"]==gateway.data["attempt.get"]["pin"]==gateway.data["run.get"]["pin"]
    assert digest(published["compiled"])==published["pin"]["compilation_hash"]
    if authorized:
        observed=asyncio.run(claims.check(work))
        assert observed["work_sha256"]==digest(work)
    else:
        with pytest.raises(Rejected,match="published"):
            asyncio.run(claims.check(work))


@pytest.mark.parametrize("mutation",["pin","hash","missing-step","duplicate-step"])
def test_current_claim_rejects_unbound_or_ambiguous_published_step(tmp_path,mutation):
    claims,gateway,work=claim_fixture(tmp_path)
    published=gateway.data["version.get"]
    if mutation=="pin":
        published["pin"]={**published["pin"],"process_version":"foreign-version"}
    elif mutation=="hash":
        published["compiled"]["steps"][0]["capabilities"]=["review.extract"]
    else:
        compiled=published["compiled"]
        if mutation=="missing-step": compiled["steps"][0]["step_id"]="foreign-step"
        else: compiled["steps"].append(deepcopy(compiled["steps"][0]))
        pin={**published["pin"],"compilation_hash":digest(compiled)}
        published["pin"]=pin
        gateway.data["attempt.get"]["pin"]=deepcopy(pin)
        gateway.data["run.get"]["pin"]=deepcopy(pin)
    with pytest.raises(Rejected,match="published"):
        asyncio.run(claims.check(work))
