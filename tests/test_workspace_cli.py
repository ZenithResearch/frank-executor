"""Generic authoring over public contracts; no signer, provider or live installation."""
import asyncio
import hashlib
import json
from importlib.resources import files
from pathlib import Path
from types import SimpleNamespace

import pytest
from process_runtime_client import command_envelope

from frank_executor.journal import Journal
from frank_executor.model import Rejected, UnknownOutcome, canonical
from frank_executor.runtime import ContractValidator, RuntimeGateway
from frank_executor.workspace_cli import (
    CleanupUnresolved, Operation, OwnedRuntimeAdapter, arguments, catalog, dispatch,
    load_profile, read_input, validate_draft,
)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def write(path, value):
    path.write_bytes(value if type(value) is bytes else canonical(value))
    path.chmod(0o600)
    return path


def fixture(tmp_path):
    tmp_path.chmod(0o700)
    program = tmp_path / "never-executed"
    write(program, b"unit artifact inspected only").chmod(0o500)
    wallet = write(tmp_path / "wallet.json", {
        "schema":"castalia.wallet-service-command.v1", "application":"runtime",
        "native_configuration":str(tmp_path / "native.json"),
        "native_configuration_sha256":"a"*64, "wallet_root":str(tmp_path / "custody"),
        "store_binding":{}, "expected_state":{},
    })
    value = {"schema":"frank.workspace.v1", "runtime_endpoint":"http://127.0.0.1:8292",
        "journal":str(tmp_path / "workspace.db"), "wallet":{
            "executable":str(program), "executable_sha256":sha(program.read_bytes()),
            "configuration":str(wallet), "configuration_sha256":sha(wallet.read_bytes())}}
    selected = write(tmp_path / "workspace.json", value)
    return selected, value


def draft(name="mine"):
    return {"schema":"process.draft.v1", "process_id":name, "inputs":{}, "steps":[{
        "step_id":"first", "depends_on":[], "capabilities":[], "resources":[],
        "inputs":{}, "bindings":{}, "outputs":{}, "max_attempts":1}]}


def command(request_id="saved", operation="process.draft.put"):
    payload = ({"draft":draft(), "provenance":{"source_id":"editor", "media_type":"application/json",
        "content_hash":sha(canonical(draft())), "parser":"explicit-json-v1", "uncertainties":[]}}
        if operation == "process.draft.put" else {"process_id":"mine", "draft_revision":1,"version_id":"mine-v1"})
    return command_envelope(operation,request_id=request_id,expected_version=None if operation.endswith("put") else 1,payload=payload)


def test_profile_is_review_free_and_health_admission_creates_nothing(tmp_path, monkeypatch):
    selected, value = fixture(tmp_path)
    monkeypatch.setattr("sqlite3.connect",lambda *a,**k:pytest.fail("health opened storage"))
    monkeypatch.setattr("subprocess.Popen",lambda *a,**k:pytest.fail("health launched child"))
    profile = load_profile(str(selected),sha(selected.read_bytes()))
    profile.current()
    assert profile.value == value
    assert not Path(value["journal"]).exists()
    assert not (tmp_path / "frank-workspace-cleanup.json").exists()


@pytest.mark.parametrize("change",["hash","extra","endpoint","journal","mode","symlink","duplicate","wallet-change"])
def test_profile_rejects_unsafe_or_substituted_inputs(tmp_path,change):
    selected,value = fixture(tmp_path);expected=sha(selected.read_bytes())
    if change=="hash": expected="0"*64
    elif change=="extra": value["review"]={};write(selected,value);expected=sha(selected.read_bytes())
    elif change=="endpoint": value["runtime_endpoint"]="http://example.org:8292";write(selected,value);expected=sha(selected.read_bytes())
    elif change=="journal": value["journal"]="relative.db";write(selected,value);expected=sha(selected.read_bytes())
    elif change=="mode": selected.chmod(0o644)
    elif change=="symlink": alias=tmp_path/"alias";alias.symlink_to(selected);selected=alias
    elif change=="duplicate": write(selected,b'{"schema":"shadow",'+selected.read_bytes()[1:]);expected=sha(selected.read_bytes())
    else: write(Path(value["wallet"]["configuration"]),b"{}")
    with pytest.raises(Rejected):load_profile(str(selected),expected)


def test_input_pin_closed_parser_fifo_and_byte_bound(tmp_path):
    selected,_=fixture(tmp_path)
    assert read_input(str(selected),sha(selected.read_bytes()))["schema"]=="frank.workspace.v1"
    with pytest.raises(Rejected):read_input(str(selected),"0"*64)
    write(selected,b"x"*65537)
    with pytest.raises(Rejected):read_input(str(selected),sha(selected.read_bytes()))
    import os
    fifo=tmp_path/"fifo";os.mkfifo(fifo,0o600)
    with pytest.raises(Rejected):read_input(str(fifo),"0"*64)


def test_generic_validation_has_no_audio_or_review_requirement():
    result=validate_draft(draft())
    assert result["valid"] and result["compiled"]["process_id"]=="mine"
    changed=draft();changed["steps"][0]["depends_on"]=["first"]
    invalid=validate_draft(changed)
    assert not invalid["valid"] and invalid["code"]=="invalid_dag"


def event(sequence,process_id="mine",kind="process.draft_updated"):
    return {"schema":"runtime.event.v1","event_id":"e"+str(sequence),"sequence":sequence,
        "kind":kind,"resource":"processes/"+process_id,"resource_version":1,
        "request_id":"c"+str(sequence),"correlation_id":"c"+str(sequence),"recorded_at_ms":1,
        "data":{"process_id":process_id}}


class Pages:
    def __init__(self,pages):self.pages=list(pages);self.calls=[]
    async def query(self,operation,payload):
        self.calls.append((operation,payload));return self.pages.pop(0)


def test_catalog_empty_is_actual_empty_and_bounded_pages_are_honest():
    async def call():
        empty=await catalog(Pages([{"events":[],"next_cursor":0,"high_watermark":0}]),{"after":0,"limit":100,"max_pages":1})
        assert empty["process_ids"]==[] and empty["complete"]
        pages=Pages([{"events":[event(1)],"next_cursor":1,"high_watermark":2}])
        partial=await catalog(pages,{"after":0,"limit":1,"max_pages":1})
        assert partial["process_ids"]==["mine"] and not partial["complete"] and partial["next_cursor"]==1
        page=Pages([{"events":[event(2,"other")],"next_cursor":2,"high_watermark":2}])
        final=await catalog(page,{"after":1,"limit":1,"max_pages":1})
        assert final["process_ids"]==["other"] and final["cursor_exhausted"] and not final["complete"]
    asyncio.run(call())


@pytest.mark.parametrize("kind",["gap","cursor","empty","duplicate","future","resource"])
def test_catalog_rejects_incomplete_or_inconsistent_streams(kind):
    row=event(1);page={"events":[row],"next_cursor":1,"high_watermark":1}
    if kind=="gap":row["sequence"]=2;page.update(next_cursor=2,high_watermark=2)
    elif kind=="cursor":page["next_cursor"]=0
    elif kind=="empty":page.update(events=[],next_cursor=0)
    elif kind=="duplicate":page.update(events=[row,row],next_cursor=2,high_watermark=2)
    elif kind=="future":page["high_watermark"]=0
    else:row["resource"]="runs/wrong"
    with pytest.raises(Rejected):asyncio.run(catalog(Pages([page]),{"after":0,"limit":100,"max_pages":1}))


class Authority:
    def __init__(self):self.fresh=[];self.resumed=[]
    async def evidence(self,raw):self.fresh.append(raw);return b"fresh"
    async def resume_evidence(self,raw):self.resumed.append(raw);return b"original"


class Client:
    def __init__(self):self.calls=[];self.lose=False
    async def command(self,envelope,*,authority):
        self.calls.append((envelope,authority))
        if self.lose:raise ConnectionError("lost")
        return {"schema":"runtime.result.v1","request_id":envelope["request_id"],
            "operation":envelope["operation"],"resource":envelope["resource"],"version":1,
            "duplicate":False,"result":{"revision":1}}
    async def query(self,envelope,*,authority):
        self.calls.append((envelope,authority))
        return {"schema":"runtime.query-result.v1","operation":envelope["operation"],"data":{
            "process_id":envelope["payload"]["process_id"],"version":1,"revision":1,
            "draft":draft(envelope["payload"]["process_id"]),"provenance":command()["payload"]["provenance"],
            "last_ordinal":0,"active_version":None}}


def gateway(tmp_path):
    authority,client=Authority(),Client()
    validator=ContractValidator(json.loads(files("process_runtime_client").joinpath("runtime-v1.schema.json").read_text()))
    return RuntimeGateway(client,authority,Journal(tmp_path/"client.db"),validator)


def test_mutation_is_durable_and_duplicate_submission_does_not_reissue(tmp_path):
    async def call():
        g=gateway(tmp_path);body=command()
        first=await dispatch(g,"draft-put",body)
        assert await dispatch(g,"draft-put",body)==first
        assert len(g.authority.fresh)==len(g.client.calls)==1
        changed=json.loads(canonical(body));changed["payload"]["draft"]["title"]="changed"
        with pytest.raises(Rejected):await dispatch(g,"draft-put",changed)
        assert len(g.authority.fresh)==1
    asyncio.run(call())


def test_lost_response_requires_exact_resume_not_another_issue(tmp_path):
    async def call():
        g=gateway(tmp_path);g.client.lose=True;body=command()
        with pytest.raises(UnknownOutcome):await dispatch(g,"draft-put",body)
        with pytest.raises(UnknownOutcome):await dispatch(g,"draft-put",body)
        assert len(g.authority.fresh)==1
        g.client.lose=False
        await dispatch(g,"resume-command",{"request_id":"saved"})
        assert g.authority.resumed==[canonical(body)]
        assert len(g.authority.fresh)==1
    asyncio.run(call())


@pytest.mark.parametrize("action,body",[("draft-put",command(operation="process.publish")),
    ("publish",command()),("get",{"process_id":"x","url":"bad"})])
def test_fixed_actions_cannot_submit_other_operations(tmp_path,action,body):
    with pytest.raises(Rejected):asyncio.run(dispatch(gateway(tmp_path),action,body))


def test_new_process_get_queries_use_fresh_acquisitions_and_exact_payload(tmp_path):
    async def call():
        g=gateway(tmp_path)
        for _ in range(2):assert (await dispatch(g,"get",{"process_id":"mine"}))["process"]["process_id"]=="mine"
        assert len(g.authority.fresh)==2 and not g.authority.resumed
        assert g.authority.fresh[0]==g.authority.fresh[1]
        from frank_executor.wallet_authority import WalletCallAuthority
        a=WalletCallAuthority(executable="/unit",executable_sha256="a"*64,configuration="/unit-config",configuration_sha256="b"*64)
        calls=[]
        async def worker(fn,mode,raw):calls.append(mode);return b"envelope"
        a._worker=worker
        await a.evidence(g.authority.fresh[0])
        assert calls==["query"]
        with pytest.raises(Rejected):await a.resume_evidence(g.authority.fresh[0])
    asyncio.run(call())


def test_sdk_worker_cancellation_retains_ownership_until_actual_completion():
    async def call():
        import threading
        entered,release=threading.Event(),threading.Event()
        class Blocking:
            def query(self,*a,**kw):entered.set();release.wait(2);return {"ok":True}
        client=OwnedRuntimeAdapter(Blocking())
        task=asyncio.create_task(client.query({},authority=b"x"))
        while not entered.is_set():await asyncio.sleep(.001)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):await task
        assert client.pending
        release.set();await client.drain()
        assert not client.pending
    asyncio.run(call())


def test_cleanup_marker_retains_unknown_workers_and_rejects_reentry(tmp_path):
    selected,value=fixture(tmp_path);profile=load_profile(str(selected),sha(selected.read_bytes()))
    op=Operation(profile,"get")
    with pytest.raises(CleanupUnresolved):Operation(profile,"get")
    with pytest.raises(CleanupUnresolved):op.finish(runtime=SimpleNamespace(pending=True))
    marker=tmp_path/"frank-workspace-cleanup.json"
    saved=json.loads(marker.read_bytes())
    assert saved["state"]=="cleanup_unresolved" and saved["unresolved"]["runtime"]
    assert "pid" not in saved


def test_cleanup_removes_only_matching_resolved_owner(tmp_path):
    selected,_=fixture(tmp_path);profile=load_profile(str(selected),sha(selected.read_bytes()))
    op=Operation(profile,"get");op.finish()
    assert not (tmp_path/"frank-workspace-cleanup.json").exists()
    op=Operation(profile,"get")
    write(tmp_path/"frank-workspace-cleanup.json",{"foreign":True})
    with pytest.raises(CleanupUnresolved):op.finish()


def test_cli_requires_input_pin_and_rejects_unknown_options():
    base=["get","--config","/private/config","--config-sha256","a"*64]
    with pytest.raises(SystemExit):arguments(base)
    with pytest.raises(SystemExit):arguments(base+["--input","/private/input","--input-sha256","b"*64,"--signer","bad"])


def test_published_catalog_identity_and_active_version_readback(tmp_path):
    async def call():
        row=event(1,kind="process.published")
        row["data"]={"pin":{"process_id":"mine","process_version":"mine-v1","compilation_hash":"a"*64}}
        result=await catalog(Pages([{"events":[row],"next_cursor":1,"high_watermark":1}]),{"after":0,"limit":10,"max_pages":1})
        assert result["process_ids"]==["mine"]
        g=gateway(tmp_path)
        original=g.client.query
        async def malformed(*a,**kw):
            value=await original(*a,**kw)
            value["data"]["active_version"]={"process_id":"other","process_version":"v1","compilation_hash":"a"*64}
            return value
        g.client.query=malformed
        with pytest.raises(Rejected):await dispatch(g,"get",{"process_id":"mine"})
    asyncio.run(call())


def test_read_only_cli_health_observes_dangling_cleanup_marker(tmp_path):
    from frank_executor.workspace_cli import run
    selected,_=fixture(tmp_path)
    (tmp_path/"frank-workspace-cleanup.json").symlink_to(tmp_path/"missing")
    _,args=arguments(["check-config","--config",str(selected),"--config-sha256",sha(selected.read_bytes())])
    result=asyncio.run(run(args))
    assert result["cleanup_retained"] and result["runtime_checked"] is False
    assert not (tmp_path/"workspace.db").exists()


def test_reused_journal_cannot_adopt_acknowledgement_from_another_runtime(tmp_path, monkeypatch):
    import frank_executor.workspace_cli as module
    selected,value=fixture(tmp_path)
    calls=[]
    class Wallet(Authority):
        def check_available(self):pass
        async def aclose(self):pass
    class Runtime:
        def __init__(self, endpoint, **kw):self.endpoint=endpoint
        def execute(self, envelope, *, evidence):
            calls.append(self.endpoint)
            return {"schema":"runtime.result.v1","request_id":envelope["request_id"],
                "operation":envelope["operation"],"resource":envelope["resource"],"version":1,
                "duplicate":False,"result":{"revision":1,"endpoint":self.endpoint}}
    monkeypatch.setattr(module,"WalletCallAuthority",lambda **kw:Wallet())
    monkeypatch.setattr(module,"RuntimeClient",Runtime)
    body=write(tmp_path/"command.json",command())
    def invoke(selected):
        _,args=arguments(["draft-put","--config",str(selected),"--config-sha256",sha(selected.read_bytes()),
            "--input",str(body),"--input-sha256",sha(body.read_bytes())])
        return asyncio.run(module.run(args))
    assert invoke(selected)["result"]["endpoint"]==value["runtime_endpoint"]
    assert invoke(selected)["result"]["endpoint"]==value["runtime_endpoint"]
    assert len(calls)==1
    value["runtime_endpoint"]="http://127.0.0.1:8293"
    other=write(tmp_path/"other.json",value)
    with pytest.raises(Rejected,match="binding"):
        invoke(other)
    assert len(calls)==1


def test_nonempty_unbound_client_journal_is_preserved_not_adopted(tmp_path):
    from frank_executor.workspace_cli import bind_journal
    selected,value=fixture(tmp_path);profile=load_profile(str(selected),sha(selected.read_bytes()))
    journal=Journal(value["journal"]);journal.command(command())
    before=journal.saved_command("saved")
    with pytest.raises(Rejected,match="binding"):bind_journal(profile,journal)
    assert journal.saved_command("saved")==before
    with journal.connection() as db:
        assert db.execute("SELECT name FROM sqlite_master WHERE name='workspace_binding'").fetchone() is None
