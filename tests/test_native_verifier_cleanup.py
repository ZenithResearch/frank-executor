"""Worker/process/pipe lifetime controls; synthetic output, no native crypto claim."""
import asyncio
import hashlib
import json
import os
import subprocess
import sys
import threading
from types import SimpleNamespace

import pytest

from frank_executor.local_review_cleanup import CleanupUnresolved, Operation, marker_status
from frank_executor.model import Rejected
from frank_executor.native_results import NativeResultVerifier, NativeSecSHelper, payload_for
from native_result_support import SyntheticHelper, policy, work_result
from test_local_review_cleanup import profile


async def until(predicate):
    async with asyncio.timeout(5):
        while not predicate():
            await asyncio.sleep(.01)


def test_cancelled_cli_waits_for_real_verifier_child_and_closes_actual_pipes(tmp_path, monkeypatch):
    from frank_executor.local_review_cli import arguments, run
    selected = profile(tmp_path)
    work, result = work_result()
    output = SyntheticHelper(work, result).verify({"request_hex":payload_for(result,work).hex()})
    entered, release = tmp_path / "entered", tmp_path / "release"
    executable = tmp_path / "verifier"
    executable.write_text("#!" + sys.executable + "\n" +
        "import json,pathlib,sys,time\n" +
        "json.load(sys.stdin)\n" +
        f"pathlib.Path({str(entered)!r}).write_text('entered')\n" +
        "deadline=time.monotonic()+10\n" +
        f"while not pathlib.Path({str(release)!r}).exists() and time.monotonic()<deadline: time.sleep(.01)\n" +
        f"print({json.dumps(output)!r})\n")
    executable.chmod(0o700)
    children=[];popen=subprocess.Popen
    def record_child(*args,**kwargs):
        child=popen(*args,**kwargs);children.append(child);return child
    monkeypatch.setattr("frank_executor.native_results.subprocess.Popen",record_child)
    helper = NativeSecSHelper(executable, hashlib.sha256(executable.read_bytes()).hexdigest())
    verifier = NativeResultVerifier(helper, policy, clock=lambda:1001)
    calls=[]
    async def opened(): pass
    async def closed(): calls.append("registry-close")
    async def authority_close(): calls.append("wallet-close")
    async def perform(*args, **kwargs): return await verifier.verify(result, work)
    engine = SimpleNamespace(journal=None,result_verifier=verifier,work=perform,
        gateway=SimpleNamespace(authority=SimpleNamespace(aclose=authority_close)),
        registry=SimpleNamespace(connect=opened,close=closed))
    monkeypatch.setattr("frank_executor.local_review_cli.compose",lambda *_:(engine,None))
    _,args=arguments(["work","--config",str(selected.config_path),"--config-sha256",selected.config_sha256])
    async def exercise():
        task=asyncio.create_task(run(args))
        owned=None
        try:
            await until(entered.exists)
            assert len(children)==1
            owned=children[0]
            assert owned.returncode is None
            streams=(owned.stdin,owned.stdout,owned.stderr)
            assert len(streams)==3 and any(not stream.closed for stream in streams)
            task.cancel()
            await until(lambda: "wallet-close" in calls)
            await asyncio.sleep(0)
            assert not task.done() and marker_status(selected)=="running"
            with pytest.raises(CleanupUnresolved): Operation(selected,"next")
            release.write_text("release")
            with pytest.raises(asyncio.CancelledError): await task
            assert owned.returncode==0 and all(stream.closed for stream in streams)
            assert not verifier.cleanup_pending and helper._owned is None
            assert marker_status(selected)=="clear"
        finally:
            release.touch()
            if not task.done():
                try: await task
                except BaseException: pass
            close=getattr(verifier,"aclose",None)
            if close is not None:await close()
            if owned is not None:await until(lambda: owned.returncode is not None)
    asyncio.run(exercise())


@pytest.mark.parametrize("close_path",["timeout","second_cancel"])
def test_cancelled_blocked_verifier_worker_retains_marker_and_real_fds(tmp_path,monkeypatch,close_path):
    import frank_executor.native_results as native
    selected=profile(tmp_path);operation=Operation(selected,"next")
    work,result=work_result();helper=SyntheticHelper(work,result)
    original=helper.verify;entered=threading.Event();release=threading.Event();fds=[]
    def blocked(value):
        fds.extend(os.pipe())
        entered.set()
        try:
            assert release.wait(10)
            return original(value)
        finally:
            for fd in fds: os.close(fd)
    helper.verify=blocked
    verifier=NativeResultVerifier(helper,policy,clock=lambda:1001)
    monkeypatch.setattr(native,"VERIFIER_CLOSE_SECONDS",.05)
    async def exercise():
        task=asyncio.create_task(verifier.verify(result,work))
        try:
            await until(entered.is_set)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):await task
            if close_path == "timeout":
                with pytest.raises(Rejected):await verifier.aclose()
            else:
                closing=asyncio.create_task(verifier.aclose())
                await asyncio.sleep(0)
                closing.cancel()
                with pytest.raises(asyncio.CancelledError):await closing
            assert verifier.cleanup_pending
            for fd in fds:os.fstat(fd)
            with pytest.raises(CleanupUnresolved):operation.finish(verifier=verifier)
            assert marker_status(selected)=="cleanup_unresolved"
            with pytest.raises(CleanupUnresolved):Operation(selected,"next")
            with pytest.raises(Rejected):await verifier.verify(result,work)
        finally:
            release.set()
            await until(lambda: all(worker.done() for worker in verifier._workers))
            await verifier.aclose()
    asyncio.run(exercise())
    for fd in fds:
        with pytest.raises(OSError):os.fstat(fd)
    # Resolution never erases a prior persisted blocked observation automatically.
    assert marker_status(selected)=="cleanup_unresolved"


def test_helper_cleanup_failure_retains_direct_child_and_attempts_every_pipe_close(tmp_path,monkeypatch):
    helper=NativeSecSHelper(tmp_path/'helper','a'*64)
    monkeypatch.setattr(helper,'check_available',lambda:None)
    calls=[];streams=[]
    for _ in range(3):
        read,write=os.pipe();os.close(write);streams.append(os.fdopen(read,'rb',buffering=0))
    class Child:
        returncode=None
        stdin,stdout,stderr=streams
        def kill(self):calls.append('kill');raise PermissionError('injected')
        def wait(self,timeout):calls.append(('wait',timeout));raise subprocess.TimeoutExpired('test',timeout)
    child=Child()
    def launch(*args,**kwargs):calls.append('launch');return child
    monkeypatch.setattr('frank_executor.native_results.subprocess.Popen',launch)
    def denied_selector():raise OSError('injected selector failure after launch')
    monkeypatch.setattr('frank_executor.native_results.selectors.DefaultSelector',denied_selector)
    try:
        with pytest.raises(Rejected):helper.verify({})
        assert helper.cleanup_pending and helper._owned is child
        assert all(stream.closed for stream in streams)
        assert calls==['launch','kill',('wait',1)]
        with pytest.raises(Rejected):helper.verify({})
        assert calls.count('launch')==1
        # Explicitly resolved direct child can drain; no new launch or evidence.
        child.returncode=0
        helper.close()
        assert not helper.cleanup_pending and helper._owned is None
    finally:
        for stream in streams:
            if not stream.closed:stream.close()


def test_helper_close_failure_retains_actual_open_fd_until_explicit_cleanup(tmp_path,monkeypatch):
    helper=NativeSecSHelper(tmp_path/'helper','a'*64)
    monkeypatch.setattr(helper,'check_available',lambda:None)
    read,write=os.pipe();os.close(write);stream=os.fdopen(read,'rb',buffering=0)
    class FailedClose:
        fail=True
        @property
        def closed(self):return stream.closed
        def close(self):
            if self.fail:raise OSError('injected close failure')
            stream.close()
    held=FailedClose()
    class Child:
        returncode=0
        stdin=stdout=stderr=held
    monkeypatch.setattr('frank_executor.native_results.subprocess.Popen',lambda *a,**k:Child())
    monkeypatch.setattr('frank_executor.native_results.selectors.DefaultSelector',lambda:(_ for _ in ()).throw(OSError('injected')))
    try:
        with pytest.raises(Rejected):helper.verify({})
        assert helper.cleanup_pending;os.fstat(read)
        with pytest.raises(Rejected):helper.close()
        held.fail=False;helper.close()
        assert not helper.cleanup_pending
        with pytest.raises(OSError):os.fstat(read)
    finally:
        stream.close()


def test_actual_nonzero_helper_denies_and_resolves_child_and_pipe_ownership(tmp_path,monkeypatch):
    executable=tmp_path/'failed-verifier'
    executable.write_text('#!'+sys.executable+'\nimport sys\nsys.stdin.buffer.read()\nsys.exit(7)\n')
    executable.chmod(0o700)
    children=[];popen=subprocess.Popen
    def launch(*args,**kwargs):
        child=popen(*args,**kwargs);children.append(child);return child
    monkeypatch.setattr('frank_executor.native_results.subprocess.Popen',launch)
    helper=NativeSecSHelper(executable,hashlib.sha256(executable.read_bytes()).hexdigest())
    with pytest.raises(Rejected,match='^Native result authority rejected$'):helper.verify({})
    assert len(children)==1 and children[0].returncode==7
    assert all(stream.closed for stream in (children[0].stdin,children[0].stdout,children[0].stderr))
    assert not helper.cleanup_pending
