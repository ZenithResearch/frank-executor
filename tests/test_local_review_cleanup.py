"""Durable observation controls; no subprocess or future-PID authority."""
import json
from types import SimpleNamespace
import threading

import pytest

from frank_executor.local_review_cleanup import Operation, CleanupUnresolved, marker_path, marker_status
from frank_executor.local_review_profile import load_profile
from test_local_review_profile import fixture, sha, write


def profile(tmp_path):
    selected,_,_ = fixture(tmp_path)
    return load_profile(str(selected),sha(selected.read_bytes()))


def test_running_operation_blocks_reentry_and_resolved_owner_removes_only_its_marker(tmp_path):
    selected = profile(tmp_path);operation = Operation(selected,"next")
    assert marker_status(selected) == "running"
    with pytest.raises(CleanupUnresolved):Operation(selected,"next")
    operation.finish()
    assert marker_status(selected) == "clear"


@pytest.mark.parametrize("kind",["leader","census","fd","observer","busy"])
def test_unresolved_ownership_is_retained_and_never_becomes_future_signal_authority(tmp_path,kind):
    selected = profile(tmp_path);operation = Operation(selected,"next")
    transport = SimpleNamespace(_owned=None,_census=None,_loose_fds=[],_loose_observers=[],_operation=threading.Lock())
    if kind == "leader":transport._owned=object()
    elif kind == "census":transport._census=object()
    elif kind == "fd":transport._loose_fds=[7]
    elif kind == "observer":transport._loose_observers=[object()]
    else:transport._operation.acquire()
    with pytest.raises(CleanupUnresolved):operation.finish(wallet=transport)
    raw = marker_path(selected).read_bytes();value = json.loads(raw)
    assert value["state"] == "cleanup_unresolved" and value["unresolved"] == {"wallet":True,"result":False,"verifier":False}
    assert b'"pid"' not in raw and b'"pgid"' not in raw
    with pytest.raises(CleanupUnresolved):Operation(selected,"resume")


def test_changed_marker_is_not_deleted_by_prior_owner(tmp_path):
    selected = profile(tmp_path);operation=Operation(selected,"next")
    marker_path(selected).unlink();write(marker_path(selected),b'{"foreign":true}')
    with pytest.raises(CleanupUnresolved):operation.finish()
    assert marker_path(selected).read_bytes() == b'{"foreign":true}'
    assert marker_status(selected) == "invalid-retained"


@pytest.mark.parametrize("held",[False,True])
def test_cli_preserves_first_unknown_or_persists_cleanup_block_and_refuses_reentry(tmp_path,monkeypatch,held):
    import asyncio
    from frank_executor.local_review_cli import arguments, run
    from frank_executor.model import Rejected, UnknownOutcome
    selected = profile(tmp_path)
    calls=[]
    async def opened():pass
    async def closed():calls.append("registry-close")
    async def authority_close():
        calls.append("authority-close")
        if held:raise Rejected("test unresolved cleanup")
    async def work(*args,**kwargs):raise UnknownOutcome("original outcome")
    authority=SimpleNamespace(aclose=authority_close,_owned=object() if held else None)
    engine=SimpleNamespace(journal=None,gateway=SimpleNamespace(authority=authority),work=work,
                           registry=SimpleNamespace(connect=opened,close=closed))
    def composed(*args):calls.append("compose");return engine,None
    monkeypatch.setattr("frank_executor.local_review_cli.compose",composed)
    _,args=arguments(["work","--config",str(selected.config_path),"--config-sha256",selected.config_sha256])
    with pytest.raises(CleanupUnresolved if held else UnknownOutcome):asyncio.run(run(args))
    assert calls == ["compose","registry-close","authority-close"]
    assert marker_status(selected) == ("cleanup_unresolved" if held else "clear")
    if held:
        with pytest.raises(CleanupUnresolved):asyncio.run(run(args))
        assert calls == ["compose","registry-close","authority-close"]


def test_cli_cancellation_drains_and_clears_only_its_marker(tmp_path,monkeypatch):
    import asyncio
    from frank_executor.local_review_cli import arguments, run
    selected=profile(tmp_path);calls=[]
    entered=None
    async def opened():pass
    async def closed():calls.append("registry-close")
    async def authority_close():calls.append("authority-close")
    async def work(*args,**kwargs):
        entered.set()
        await asyncio.Event().wait()
    engine=SimpleNamespace(journal=None,gateway=SimpleNamespace(authority=SimpleNamespace(aclose=authority_close)),
        work=work,registry=SimpleNamespace(connect=opened,close=closed))
    monkeypatch.setattr("frank_executor.local_review_cli.compose",lambda *_:(engine,None))
    _,args=arguments(["work","--config",str(selected.config_path),"--config-sha256",selected.config_sha256])
    async def exercise():
        nonlocal entered
        entered=asyncio.Event()
        task=asyncio.create_task(run(args))
        await asyncio.wait_for(entered.wait(),5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):await task
    asyncio.run(exercise())
    assert calls == ["registry-close","authority-close"] and marker_status(selected) == "clear"
