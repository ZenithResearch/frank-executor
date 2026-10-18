"""Storage/port unit controls only; fixtures do not attest real computation."""
import asyncio
from copy import deepcopy
import hashlib
import json
import multiprocessing
from pathlib import Path

import pytest
from frank_executor.journal import Journal
from frank_executor.model import Actor, Binding, Rejected, canonical, digest, work_packet
from frank_executor.connector_capture import CapturePending
from frank_review_adapter.local_capture import LocalReviewCapture, LocalReviewPolicy, ObservationRecorder, exact_file, sha


def setup_capture(tmp_path):
    root = tmp_path / "capture"
    root.mkdir(mode=0o700)
    blobs = root / "blobs"
    blobs.mkdir(mode=0o700)
    bodies = [b"selected test producer",b"selected test normalizer",b"selected test composition"]
    pins = [sha(raw) for raw in bodies]
    for raw,pin in zip(bodies,pins):
        exact_file(blobs / pin,raw)
    manifest = {"schema":"frank.local-review.source-manifest.v1","producer_artifact_sha256":pins[0],
        "normalizer_sha256":pins[1],"configuration_sha256":pins[2],
        "entries":[{"sha256":pin,"byte_length":len(raw)} for pin,raw in zip(pins,bodies)]}
    exact_file(root / "source-manifest.json",canonical(manifest))
    journal = Journal(tmp_path / "frank.sqlite")
    policy = LocalReviewPolicy("worker","fixture","local",*pins,sha(canonical(manifest)))
    capture = LocalReviewCapture(journal,root,policy)
    work = work_packet(Binding("run","step","attempt",1),Actor("worker","fixture",(),(),"local"),
        effect_id="effect-1",operation="review.bind_source",scope="scope",inputs={"observations":[],"subject_id":"subject"},
        output_types={"codebase_context":{"kind":"array","items":{"kind":"string"}}})
    return capture, work


def result_for(work, outputs=None, outcome="succeeded"):
    outputs = {} if outputs is None else outputs
    key = digest({n:work[n] for n in ("binding","actor_id","integration_id","route","effect_id")})
    return {"schema":"frank.result.v1", "event_id":"review-"+digest({"effect":work["effect_id"],"outcome":outcome,"outputs":outputs})[:48],
        **{n:work[n] for n in ("binding","actor_id","integration_id","route","effect_id")},
        "provider_reference":"local-review:review-"+key,"outcome":outcome,"outputs":outputs}


def completed(capture,work):
    capture.reserve(work)
    recorder = ObservationRecorder(capture,work)
    recorder.add("claim-check",canonical(work),canonical({"fixture":"unit-current-claim","current":True}))
    result = result_for(work,{"codebase_context":[]})
    capture.complete(work,result,"computed",recorder)
    return result


def reserve_child(journal_path,root,policy,work,queue):
    capture = LocalReviewCapture(Journal(journal_path),root,LocalReviewPolicy(**policy))
    queue.put(capture.reserve(work)[1])


def test_reservation_survives_restart_without_permission_to_compute_again(tmp_path):
    capture,work = setup_capture(tmp_path)
    identifier,fresh = capture.reserve(work)
    assert fresh
    reopened = LocalReviewCapture(Journal(capture.journal.path),capture.root,capture.policy)
    assert reopened.reserve(work) == (identifier,False)
    with pytest.raises(CapturePending,match="unresolved"):
        reopened.retained(work)


def test_two_processes_can_reserve_only_one_computation(tmp_path):
    from dataclasses import asdict
    capture,work = setup_capture(tmp_path)
    context = multiprocessing.get_context("spawn")
    queue = context.Queue()
    children = [context.Process(target=reserve_child,args=(capture.journal.path,str(capture.root),asdict(capture.policy),work,queue)) for _ in range(2)]
    try:
        for child in children: child.start()
        for child in children:
            child.join(10)
            assert not child.is_alive() and child.exitcode == 0
        assert sorted([queue.get(timeout=1),queue.get(timeout=1)]) == [False,True]
    finally:
        for child in children:
            if child.is_alive(): child.terminate()
            child.join(5)
        queue.close()


@pytest.mark.parametrize("field",["inputs","binding","operation"])
def test_same_effect_cannot_change_complete_work(tmp_path,field):
    capture,work = setup_capture(tmp_path)
    capture.reserve(work)
    changed = deepcopy(work)
    if field == "inputs": changed[field]["subject_id"] = "changed"
    elif field == "binding": changed[field]["fence"] = 2
    else: changed[field] = "review.extract"
    if field == "binding":
        # Fence belongs to the reservation identity: a distinct actual Attempt
        # may compute, but the original reservation never changes.
        assert capture.reserve(changed)[1] is True
        assert capture.reserve(work)[1] is False
    else:
        with pytest.raises(Rejected,match="changed work"):
            capture.reserve(changed)


def test_complete_publishes_only_four_exact_files_after_commit(tmp_path):
    capture,work = setup_capture(tmp_path)
    result = completed(capture,work)
    row = capture.retained(work)
    directory = capture.root / row["capture_id"]
    assert {p.name for p in directory.iterdir()} == {"reservation.json","work.json","payload.json","receipt.json"}
    assert sha((directory / "reservation.json").read_bytes()) == row["capture_id"]
    assert (directory / "work.json").read_bytes() == canonical(work)
    assert json.loads((directory / "payload.json").read_bytes())["result"] == result
    assert all(p.stat().st_mode & 0o777 == 0o600 for p in directory.iterdir())
    assert row["receipt_value"]["observations"][-1]["kind"] == "claim-check"


def test_failed_publication_republishes_committed_capture_without_recomputation(tmp_path,monkeypatch):
    import frank_review_adapter.local_capture as module
    capture,work = setup_capture(tmp_path)
    capture.reserve(work)
    recorder = ObservationRecorder(capture,work)
    recorder.add("claim-check",canonical(work),canonical({"current":True}))
    result = result_for(work,{"codebase_context":[]})
    real = module.os.rename
    with monkeypatch.context() as patch:
        patch.setattr(module.os,"rename",lambda *a: (_ for _ in ()).throw(OSError("publication interrupted")))
        with pytest.raises(OSError): capture.complete(work,result,"computed",recorder)
    assert capture.retained(work)["result"] == result
    assert capture.reserve(work)[1] is False
    assert capture.publish(work)["result"] == result
    assert module.os.rename is real


@pytest.mark.parametrize("mutation",["source","receipt","payload","blob"])
def test_retained_evidence_tampering_denies(tmp_path,mutation):
    capture,work = setup_capture(tmp_path)
    completed(capture,work)
    row = capture.retained(work)
    if mutation == "source":
        (capture.root / "source-manifest.json").write_bytes(b"{}")
    elif mutation == "blob":
        pin = row["receipt_value"]["observations"][-1]["output_sha256"]
        (capture.blobs / pin).write_bytes(b"changed")
    else:
        (capture.root / row["capture_id"] / (mutation+".json")).write_bytes(b"{}")
    with pytest.raises((Rejected,KeyError)):
        capture.publish(work)


def test_no_reservation_or_final_claim_cannot_form_capture(tmp_path):
    capture,work = setup_capture(tmp_path)
    recorder = ObservationRecorder(capture,work)
    with pytest.raises(Rejected): capture.complete(work,result_for(work),"computed",recorder)
    capture.reserve(work)
    recorder.add("source-snapshot-read",b"actual input",b"actual output")
    with pytest.raises(Rejected,match="claim"):
        capture.complete(work,result_for(work),"computed",recorder)


def test_known_failure_has_no_outputs_and_unknown_failure_is_not_terminal(tmp_path):
    capture,work = setup_capture(tmp_path)
    capture.reserve(work)
    recorder = ObservationRecorder(capture,work)
    recorder.add("claim-check",canonical(work),canonical({"current":True}))
    with pytest.raises(Rejected): capture.complete(work,result_for(work,{},"failed"),"invented",recorder)
    capture.complete(work,result_for(work,{},"failed"),"malformed_source_evidence",recorder)
    assert capture.retained(work)["result"]["outputs"] == {}


def test_capacity_never_evicts_old_body_identity(tmp_path,monkeypatch):
    import frank_review_adapter.local_capture as module
    capture,work = setup_capture(tmp_path)
    capture.reserve(work)
    monkeypatch.setattr(module,"MAX_STORE",module.RESERVATION_BYTES)
    changed = deepcopy(work);changed["effect_id"] = "other-effect"
    with pytest.raises(Rejected,match="capacity"): capture.reserve(changed)
    assert capture.reserve(work)[1] is False


def test_real_wrapped_port_output_is_retained_at_call_time(tmp_path):
    from frank_review_adapter.ports import ReviewPorts
    capture,work = setup_capture(tmp_path)
    class ActualUnitPort:
        effects_disabled = True
        async def inspect(self,*args): return [{"actual":"output"}]
        async def check(self,*args): return {"current":True}
    port = ActualUnitPort()
    recorder = ObservationRecorder(capture,work)
    wrapped = recorder.wrap(ReviewPorts(port,port,port,port,port,port,port))
    async def calls():
        assert await wrapped.sources.inspect("subject",[]) == [{"actual":"output"}]
        await wrapped.claims.check(work)
    asyncio.run(calls())
    assert [r["kind"] for r in recorder.observations] == ["source-snapshot-read","claim-check"]
    first = recorder.observations[0]
    assert (capture.blobs / first["output_sha256"]).read_bytes() == canonical([{"actual":"output"}])
    assert first["reference"] == first["output_sha256"]
    assert first["byte_length"] == len(canonical([{"actual":"output"}]))
