"""Public-contract workflow orchestration controls; no Native/provider execution."""
import asyncio
import base64
from importlib.resources import files
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from frank_executor.journal import Journal
from frank_executor.model import Rejected, UnknownOutcome, canonical, digest
from frank_executor.runtime import ContractValidator
from frank_review_adapter.ports import ReviewFailure
from frank_executor.local_review_profile import load_profile
from frank_executor.local_review_workflow import (load_workflow, initialize, next_step, saved_command,
    inspect_workflow, export_workflow, recovery_selection)
from test_local_review_profile import fixture, sha, write


def selected(tmp_path):
    bodies = [b"actual selected audio bytes",b"[]",b"selected supplied transcript bytes"]
    refs = [{"content_hash":sha(raw),"byte_length":len(raw),"media_type":media}
            for raw,media in zip(bodies,["audio/wav","application/json","application/json"])]
    def change(value):
        value["transcript"] = {"audio_sha256":refs[0]["content_hash"],"artifact":refs[2]}
    master,_,_ = fixture(tmp_path,change)
    profile = load_profile(str(master),sha(master.read_bytes()))
    sources = Path(__file__).parent / "fixtures/independent-review"
    process = {"process_version":"local-review-test-v1"}
    for key,suffix in (("draft","json"),("compiled","compiled.json")):
        target = tmp_path / (key+".json")
        raw = (sources / ("personal-review-v1."+suffix)).read_bytes()
        write(target,raw);process[key] = {"path":str(target),"sha256":sha(raw)}
    artifacts = []
    for i,(raw,ref) in enumerate(zip(bodies,refs)):
        p = tmp_path / ("input-"+str(i));write(p,raw);artifacts.append({"path":str(p),"artifact":ref})
    exports = tmp_path / "exports";exports.mkdir(mode=0o700)
    value = {"schema":"frank.local-review.workflow.v1","profile_sha256":profile.config_sha256,
        "run_id":"run","process":process,"inputs":{"audio_asset":refs[0],"events_asset":refs[1],
        "duration_ms":1000,"review_id":"review","reviewed_at":"2026-10-17","subject_id":"subject","submitted_by":"owner"},
        "artifacts":artifacts,"export":{"root":str(exports),"step_id":"step_7","output":"review_note"}}
    p = tmp_path / "workflow.json";write(p,canonical(value))
    return load_workflow(profile,str(p),sha(p.read_bytes()))


class Gateway:
    def __init__(self, workflow, journal):
        self.workflow,self.journal = workflow,journal
        self.validate = ContractValidator(json.loads(files("process_runtime_client").joinpath("runtime-v1.schema.json").read_text()))
        self.sent,self.replayed,self.blobs = [],[],{}
        self.lose = False
        self.actual_compiled = workflow.compiled
        self.run_data = {"run_id":"run","pin":workflow.process_pin,"inputs":workflow.value["inputs"],"state":"pending",
            "steps":[{"step_id":s["step_id"],"state":"ready" if not s["depends_on"] else "waiting",
                      "attempt_id":None,"fence":0} for s in workflow.compiled["steps"]]}
        self.output = self.receipt = None

    async def send(self, command):
        self.validate(command,"command");self.journal.command(command);self.sent.append(command)
        if self.lose:
            raise UnknownOutcome("test lost response")
        return self.complete(command)

    def complete(self, command):
        op,p = command["operation"],command["payload"]
        if op == "artifact.put":
            self.blobs[p["artifact"]["content_hash"]] = (p["artifact"],base64.b64decode(p["content_base64"]))
            result = {"artifact":p["artifact"]}
        elif op == "process.draft.put": result = {"revision":1}
        elif op == "process.publish": result = {"pin":self.workflow.process_pin}
        else: result = {}
        response = {"schema":"runtime.result.v1","request_id":command["request_id"],"operation":op,
            "resource":command["resource"],"duplicate":False,"version":1,"result":result}
        self.validate(response,"result");self.journal.command_result(command["request_id"],response)
        return response

    async def replay(self, request_id):
        self.replayed.append(request_id)
        return self.complete(json.loads(self.journal.saved_command(request_id)["body"]))

    async def query(self, operation, payload):
        if operation == "version.get": return {"pin":self.workflow.process_pin,"compiled":self.actual_compiled}
        if operation == "run.get": return self.run_data
        if operation == "output.get": return self.output
        if operation == "receipt.get": return self.receipt
        if operation == "artifact.get":
            ref,raw = self.blobs[payload["content_hash"]]
            return {"artifact":ref,"content_base64":base64.b64encode(raw).decode()}
        raise AssertionError(operation)


def executor(tmp_path, workflow):
    journal = Journal(tmp_path / "workflow.sqlite")
    return SimpleNamespace(journal=journal,gateway=Gateway(workflow,journal))


def test_initialize_readbacks_and_repeated_command_identity_without_reissue(tmp_path):
    workflow = selected(tmp_path);engine = executor(tmp_path,workflow)
    assert asyncio.run(initialize(workflow,engine))["run_id"] == "run"
    before = list(engine.gateway.sent)
    assert len(before) == 7  # Three artifacts, draft, publication, actor and exact run.
    assert asyncio.run(initialize(workflow,engine))["pin"] == workflow.process_pin
    assert engine.gateway.sent == before and not engine.gateway.replayed


def test_unknown_saved_command_requires_explicit_no_create_resume(tmp_path):
    workflow = selected(tmp_path);engine = executor(tmp_path,workflow)
    engine.gateway.lose = True
    async def call():
        return await saved_command(workflow,engine,"actor","actor.register",{
            "actor_id":"worker","capabilities":["review.annotate"],"resources":[]},None)
    with pytest.raises(UnknownOutcome): asyncio.run(call())
    with pytest.raises(UnknownOutcome): asyncio.run(call())
    assert len(engine.gateway.sent) == 1
    selection = recovery_selection(workflow,engine.journal)
    assert selection == {"kind":"command","request_id":workflow.request_id("actor")}
    asyncio.run(engine.gateway.replay(selection["request_id"]))
    assert asyncio.run(call())["operation"] == "actor.register"
    assert len(engine.gateway.sent) == len(engine.gateway.replayed) == 1


@pytest.mark.parametrize("mutation",["profile","run","missing-input","changed-file","extra"])
def test_workflow_rejects_wrong_selection_before_runtime_calls(tmp_path,mutation):
    original = selected(tmp_path);value = original.value
    if mutation == "profile": value["profile_sha256"] = "f"*64
    elif mutation == "run": value["run_id"] = "foreign"
    elif mutation == "missing-input": value["artifacts"].pop()
    elif mutation == "changed-file": write(Path(value["artifacts"][0]["path"]),b"changed")
    else: value["allow_local_dev"] = True
    write(original.selected,canonical(value))
    with pytest.raises(Rejected):load_workflow(original.profile,str(original.selected),sha(original.selected.read_bytes()))


def test_initialize_denies_actual_published_source_mismatch_before_run_creation(tmp_path):
    workflow = selected(tmp_path);engine = executor(tmp_path,workflow)
    engine.gateway.actual_compiled = {**workflow.compiled,"title":"changed"}
    with pytest.raises(Rejected):asyncio.run(initialize(workflow,engine))
    assert "run.create" not in [c["operation"] for c in engine.gateway.sent]


@pytest.mark.parametrize("mode",["eligible","foreign","unknown"])
def test_next_uses_only_actual_work_and_published_operation_without_retry(tmp_path,mode):
    workflow = selected(tmp_path);engine = executor(tmp_path,workflow);calls=[]
    async def work(actor,**kwargs):
        return {"work":[{"run_id":"foreign" if mode == "foreign" else "run","step_id":"step_1","version":1,"pin":workflow.process_pin}]}
    async def claim(actor,offered,**kwargs):
        calls.append(("claim",offered["step_id"]));return "attempt"
    async def run(attempt,**kwargs):
        calls.append(("run",kwargs["operation"]))
        assert kwargs["scope"] == "local-review" and kwargs["wait_seconds"] == 2
        if mode == "unknown":raise UnknownOutcome("test unknown")
        return {"state":"committed"}
    engine.work,engine.claim,engine.run = work,claim,run
    if mode == "unknown":
        with pytest.raises(UnknownOutcome):asyncio.run(next_step(workflow,engine,lease_ms=1000,wait_seconds=2))
    else:asyncio.run(next_step(workflow,engine,lease_ms=1000,wait_seconds=2))
    assert calls == ([] if mode == "foreign" else [("claim","step_1"),("run","review.load_review")])


def committed(engine,raw):
    workflow = engine.gateway.workflow
    ref = {"content_hash":sha(raw),"byte_length":len(raw),"media_type":"text/markdown"}
    step = next(s for s in engine.gateway.run_data["steps"] if s["step_id"] == "step_7")
    step.update(state="succeeded",attempt_id="attempt",fence=1)
    fields = {"run_id":"run","step_id":"step_7","attempt_id":"attempt","fence":1,"actor_id":"worker","pin":workflow.process_pin}
    output = {**fields,"receipt_id":"receipt-attempt","outputs":{"review_note":ref},"inputs_digest":"c"*64}
    output["output_digest"] = digest(output["outputs"])
    receipt = {**fields,"receipt_id":"receipt-attempt","input_digest":"c"*64,"output_digest":output["output_digest"],"outcome":"succeeded"}
    engine.gateway.output,engine.gateway.receipt = output,receipt
    engine.gateway.blobs[ref["content_hash"]] = (ref,raw)
    return ref


def test_inspect_and_export_use_actual_receipt_output_and_create_only_bytes(tmp_path):
    workflow = selected(tmp_path);engine = executor(tmp_path,workflow);raw=b"# Actual review\n"
    ref = committed(engine,raw)
    inspected = asyncio.run(inspect_workflow(workflow,engine))
    assert inspected["export_available"] and not inspected["recoverable"]
    result = asyncio.run(export_workflow(workflow,engine))
    target = Path(result["path"])
    assert target.name == ref["content_hash"]+".md" and target.read_bytes() == raw
    write(target,b"foreign")
    with pytest.raises(Rejected):asyncio.run(export_workflow(workflow,engine))
    assert target.read_bytes() == b"foreign"


@pytest.mark.parametrize("mutation",["receipt-digest","fence","artifact-bytes"])
def test_export_rejects_actual_evidence_mismatch(tmp_path,mutation):
    workflow = selected(tmp_path);engine = executor(tmp_path,workflow);ref=committed(engine,b"# Actual\n")
    if mutation == "receipt-digest":engine.gateway.receipt["output_digest"] = "f"*64
    elif mutation == "fence":engine.gateway.output["fence"] = 2
    else:engine.gateway.blobs[ref["content_hash"]] = (ref,b"changed")
    with pytest.raises(ReviewFailure if mutation == "artifact-bytes" else Rejected):
        asyncio.run(export_workflow(workflow,engine))
    assert not list(Path(workflow.value["export"]["root"]).iterdir())
