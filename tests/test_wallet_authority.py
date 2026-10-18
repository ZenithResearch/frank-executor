"""Owned fake-process protocol tests, not Native signing/installed qualification."""
import asyncio
import base64
import hashlib
import io
import json
import os
import signal
import time
import sys
from types import SimpleNamespace

import pytest
from frank_executor.model import Rejected, UnknownOutcome, canonical
from process_runtime_client import RuntimeClient, command_envelope

DENIAL = "Native Wallet call authority unavailable"
ENVELOPE = b'{"packet_hex":"00","schema":"runtime.secs-envelope.v1","signed_context_hex":"00"}'
QUERY_PAYLOADS = {
    "work.list": {"actor_id": "actor", "limit": 1},
    "events.list": {"after": 0, "limit": 1},
    "attempt.get": {"run_id": "run", "step_id": "step", "attempt_id": "attempt"},
    "output.get": {"run_id": "run", "step_id": "step", "attempt_id": "attempt"},
    "run.get": {"run_id": "run"},
    "artifact.get": {"content_hash": "a" * 64},
    "version.get": {"process_version": "version"},
    "receipt.get": {"receipt_id": "receipt"},
}


COMPLETED_JOURNAL = f"""ledger=base/"completed.json"
mode=sys.argv[1]
if mode=="issue":
    if ledger.exists():
        sys.exit(19)
    ledger.write_text(json.dumps({{"request":raw.hex(),"state":"completed","expired":False}}))
elif mode=="resume":
    if not ledger.exists():
        sys.exit(20)
    saved=json.loads(ledger.read_text())
    if saved != {{"request":raw.hex(),"state":"completed","expired":False}}:
        sys.exit(21)
else:
    sys.exit(22)
sys.stdout.buffer.write({ENVELOPE!r})
"""


def command():
    return command_envelope("actor.register", request_id="exact-command", expected_version=None,
                            payload={"actor_id": "actor", "capabilities": ["compute"], "resources": []})


def setup(tmp_path, behavior=None, *, timeout=2):
    # Import inside test setup so the separate test-first patch collects normally
    # before the production module exists, then fails on that missing module.
    from frank_executor.wallet_authority import WalletCallAuthority
    tmp_path.chmod(0o700)
    configuration = tmp_path / "command.json"
    configuration.write_bytes(canonical({
        "schema": "castalia.wallet-service-command.v1", "application": "runtime",
        "native_configuration": "/unused/native.json", "native_configuration_sha256": "a" * 64,
        "wallet_root": "/unused/wallet", "store_binding": {}, "expected_state": {},
    }))
    configuration.chmod(0o600)
    executable = tmp_path / "fake-wallet-command"
    prelude = f'''#!{sys.executable}
import hashlib,json,os,pathlib,sys,time
base=pathlib.Path(__file__).parent
assert sys.argv[1] in ("issue","query","resume")
assert sys.argv[2]=="--config" and sys.argv[4]=="--config-sha256" and len(sys.argv)==6
actual=pathlib.Path(sys.argv[3]).read_bytes()
assert hashlib.sha256(actual).hexdigest()==sys.argv[5]
raw=sys.stdin.buffer.read()
(base/"stdin.bin").write_bytes(raw)
with (base/"calls.jsonl").open("a") as f:
    f.write(json.dumps({{"argv":sys.argv[1:],"request_hex":raw.hex(),"pid":os.getpid()}})+"\\n")
(base/"pid").write_text(str(os.getpid()))
'''
    executable.write_text(prelude + (behavior or f"sys.stdout.buffer.write({ENVELOPE!r})\n"))
    executable.chmod(0o700)
    authority = WalletCallAuthority(
        executable=executable, executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
        configuration=configuration, configuration_sha256=hashlib.sha256(configuration.read_bytes()).hexdigest(),
        timeout=timeout,
    )
    return authority, executable, configuration


def calls(tmp_path):
    return [json.loads(line) for line in (tmp_path / "calls.jsonl").read_text().splitlines()]


def reaped(tmp_path):
    pid = int((tmp_path / "pid").read_text())
    with pytest.raises(ChildProcessError):
        os.waitpid(pid, os.WNOHANG)
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_exact_canonical_stdin_and_explicit_public_sdk_evidence(tmp_path):
    authority, _, config = setup(tmp_path)
    # Opaque run inputs exercise Unicode, controls and numeric JSON without
    # selecting authority flags, paths, environment or policy.
    body = command_envelope("run.create", request_id="exact-command", expected_version=None,
        payload={"run_id":"run", "pin":{"process_id":"process","process_version":"version",
                 "compilation_hash":"a"*64}, "inputs":{"text":"é😀\n\x7f", "number":1.25, "large":9007199254740991}})
    raw = canonical(body)
    evidence = asyncio.run(authority.evidence(raw))
    assert evidence == ENVELOPE and (tmp_path / "stdin.bin").read_bytes() == raw
    assert calls(tmp_path)[0]["argv"] == ["issue", "--config", str(config), "--config-sha256", hashlib.sha256(config.read_bytes()).hexdigest()]
    captured = []
    client = RuntimeClient("http://127.0.0.1:1")
    def open_call(request, timeout):
        captured.append(json.loads(request.data))
        return io.BytesIO(canonical({"schema":"runtime.result.v1", "request_id":body["request_id"],
            "operation":body["operation"],"resource":body["resource"],"duplicate":False,"version":1,"result":{}}))
    client.opener.open = open_call
    client.execute(body, evidence=evidence)
    assert canonical(captured[0]["request"]) == raw
    assert base64.b64decode(captured[0]["authority_base64"], validate=True) == evidence
    reaped(tmp_path)


@pytest.mark.parametrize("operation,payload", QUERY_PAYLOADS.items())
def test_only_accepted_query_profiles_select_query_mode(tmp_path, operation, payload):
    authority, _, _ = setup(tmp_path)
    raw = canonical({"schema":"runtime.query.v1","operation":operation,"payload":payload})
    assert asyncio.run(authority.evidence(raw)) == ENVELOPE
    assert (tmp_path / "stdin.bin").read_bytes() == raw
    assert calls(tmp_path)[0]["argv"][0] == "query"
    reaped(tmp_path)


@pytest.mark.parametrize("raw", [
    canonical({"schema":"runtime.query.v1","operation":"process.get","payload":{"process_id":"p"}}),
    canonical({"schema":"runtime.query.v1","operation":"effect.get","payload":{"effect_id":"e"}}),
    b'{"schema":"runtime.command.v1"}', b'{}', b'[]',
    b'{"schema":"runtime.query.v1","schema":"runtime.query.v1"}',
    b'{"schema":"runtime.query.v1","operation":"work.list","payload":{"actor_id":"a","limit":true}}',
])
def test_invalid_or_unselected_requests_never_spawn(tmp_path, raw):
    authority, _, _ = setup(tmp_path)
    with pytest.raises(Rejected, match=DENIAL):
        asyncio.run(authority.evidence(raw))
    assert not (tmp_path / "pid").exists()


def test_noncanonical_and_mutable_bytes_deny_without_normalizing(tmp_path):
    authority, _, _ = setup(tmp_path)
    for raw in (canonical(command()) + b' ', bytearray(canonical(command()))):
        with pytest.raises(Rejected, match=DENIAL):
            asyncio.run(authority.evidence(raw))
    assert not (tmp_path / "pid").exists()


@pytest.mark.parametrize("change", ["executable", "configuration", "configuration-mode", "executable-link", "configuration-link", "configuration-hardlink"])
def test_exact_file_pins_and_storage_fail_closed_before_spawn(tmp_path, change):
    authority, executable, config = setup(tmp_path)
    if change == "executable":
        executable.write_text(executable.read_text() + "# replaced\n")
    elif change == "configuration":
        config.write_bytes(config.read_bytes() + b' ')
    elif change == "configuration-mode":
        config.chmod(0o640)
    elif change == "configuration-hardlink":
        os.link(config, tmp_path / "extra-link")
    else:
        original = executable if change == "executable-link" else config
        saved = original.with_suffix(".saved")
        original.rename(saved)
        original.symlink_to(saved)
    with pytest.raises(Rejected, match=DENIAL):
        asyncio.run(authority.evidence(canonical(command())))
    assert not (tmp_path / "pid").exists()


@pytest.mark.parametrize("output", [
    b'{}', b'{"schema":"service.secs-envelope.v1","packet_hex":"00","signed_context_hex":"00"}',
    b'{"schema":"runtime.secs-envelope.v1","packet_hex":"00","packet_hex":"00","signed_context_hex":"00"}',
    b'{"schema":"runtime.secs-envelope.v1","packet_hex":"0A","signed_context_hex":"00"}',
    b'{"schema":"runtime.secs-envelope.v1","packet_hex":"0","signed_context_hex":"00"}',
    b'{"schema":"runtime.secs-envelope.v1","packet_hex":"","signed_context_hex":"00"}',
    b'{"schema":"runtime.secs-envelope.v1","packet_hex":"00","signed_context_hex":"00","qualified":true}',
    ENVELOPE + b' trailing',
])
def test_closed_bounded_authority_envelope_has_no_assertion_fallback(tmp_path, output):
    authority, _, _ = setup(tmp_path, f"sys.stdout.buffer.write({output!r})\n")
    with pytest.raises(Rejected, match=DENIAL):
        asyncio.run(authority.evidence(canonical(command())))
    reaped(tmp_path)


@pytest.mark.parametrize("behavior", [
    "sys.stderr.write('sensitive diagnostic');sys.exit(2)\n",
    "sys.stdout.buffer.write(b'x'*4_400_001)\n",
    "sys.stderr.buffer.write(b'x'*4097)\n",
    "time.sleep(30)\n",
])
def test_failure_output_limit_and_timeout_reap_without_retry_or_leaking(tmp_path, behavior):
    authority, _, _ = setup(tmp_path, behavior, timeout=0.8)
    with pytest.raises(Rejected) as exc:
        asyncio.run(authority.evidence(canonical(command())))
    assert str(exc.value) == DENIAL
    assert len(calls(tmp_path)) == 1  # never retry, resume or fall back
    reaped(tmp_path)


def test_cancellation_waits_for_owned_child_cleanup(tmp_path):
    authority, _, _ = setup(tmp_path, "time.sleep(30)\n")
    async def run():
        task = asyncio.create_task(authority.evidence(canonical(command())))
        async with asyncio.timeout(3):
            while not (tmp_path / "pid").exists():
                await asyncio.sleep(0.01)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
    asyncio.run(run())
    reaped(tmp_path)


def test_changed_config_after_child_read_discards_authority(tmp_path):
    behavior = f"pathlib.Path(sys.argv[3]).write_bytes(actual+b' ');sys.stdout.buffer.write({ENVELOPE!r})\n"
    authority, _, _ = setup(tmp_path, behavior)
    with pytest.raises(Rejected, match=DENIAL):
        asyncio.run(authority.evidence(canonical(command())))
    reaped(tmp_path)


def test_saved_command_replay_resumes_completed_without_changing_intent(tmp_path):
    from frank_executor.journal import Journal
    from frank_executor.runtime import ContractValidator, RuntimeGateway
    from importlib.resources import files
    authority, _, _ = setup(tmp_path, COMPLETED_JOURNAL)
    sent = []
    class Client:
        async def command(self, envelope, *, authority):
            sent.append((canonical(envelope), authority))
            if len(sent) == 1:
                raise TimeoutError()
            return {"schema":"runtime.result.v1","request_id":envelope["request_id"],
                    "operation":envelope["operation"],"resource":envelope["resource"],
                    "duplicate":True,"version":1,"result":{}}
    gateway = RuntimeGateway(Client(), authority, Journal(tmp_path / "frank.db"),
        ContractValidator(json.loads(files("process_runtime_client").joinpath("runtime-v1.schema.json").read_text())))
    async def run():
        with pytest.raises(UnknownOutcome):
            await gateway.send(command())
        await gateway.replay(command()["request_id"])
    asyncio.run(run())
    assert len(sent) == 2 and sent[0] == sent[1] == (canonical(command()), ENVELOPE)
    assert [row["argv"][0] for row in calls(tmp_path)] == ["issue", "resume"]
    assert len({row["request_hex"] for row in calls(tmp_path)}) == 1
    reaped(tmp_path)


def test_existing_default_authority_remains_denied_in_production():
    from frank_executor.authority import DenyAuthority, check_authority
    with pytest.raises(Rejected, match="qualified native secS"):
        check_authority("production", DenyAuthority(), SimpleNamespace(mode="secs_verified"))


def test_identical_queries_acquire_again_without_body_change(tmp_path):
    authority, _, _ = setup(tmp_path)
    raw = canonical({"schema":"runtime.query.v1","operation":"events.list","payload":{"after":0,"limit":1}})
    async def run():
        assert await authority.evidence(raw) == ENVELOPE
        assert await authority.evidence(raw) == ENVELOPE
    asyncio.run(run())
    records = calls(tmp_path)
    assert len(records) == 2
    assert [row["argv"][0] for row in records] == ["query", "query"]
    assert [row["request_hex"] for row in records] == [raw.hex(), raw.hex()]
    # The fake bytes are deliberately identical; fresh cryptographic nonces are
    # the future actual Native query integration's responsibility, not asserted here.
    reaped(tmp_path)


def test_existing_frank_request_ceiling_is_not_widened(tmp_path):
    authority, _, _ = setup(tmp_path)
    body = command()
    body["payload"]["actor_id"] = "a" * 1_048_577
    raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    with pytest.raises(Rejected, match=DENIAL):
        asyncio.run(authority.evidence(raw))
    assert not (tmp_path / "pid").exists()


@pytest.mark.parametrize("field,maximum", [("packet_hex", 2_097_152 + 16_384 + 69), ("signed_context_hex", 65_536)])
def test_individual_native_field_caps_apply_below_outer_limit(tmp_path, field, maximum):
    behavior = f'''value={{"schema":"runtime.secs-envelope.v1","packet_hex":"00","signed_context_hex":"00"}}
value[{field!r}]="00"*({maximum}+1)
sys.stdout.write(json.dumps(value,separators=(",",":")))
'''
    authority, _, _ = setup(tmp_path, behavior)
    with pytest.raises(Rejected, match=DENIAL):
        asyncio.run(authority.evidence(canonical(command())))
    reaped(tmp_path)


def test_completed_issue_denial_does_not_silently_resume(tmp_path):
    authority, _, _ = setup(tmp_path, COMPLETED_JOURNAL)
    raw = canonical(command())
    assert asyncio.run(authority.evidence(raw)) == ENVELOPE
    with pytest.raises(Rejected, match=DENIAL):
        asyncio.run(authority.evidence(raw))
    assert [row["argv"][0] for row in calls(tmp_path)] == ["issue", "issue"]
    assert asyncio.run(authority.resume_evidence(raw)) == ENVELOPE
    assert [row["argv"][0] for row in calls(tmp_path)] == ["issue", "issue", "resume"]
    reaped(tmp_path)


@pytest.mark.parametrize("state", ["missing", "expired", "changed"])
def test_explicit_resume_never_creates_or_renews(tmp_path, state):
    authority, _, _ = setup(tmp_path, COMPLETED_JOURNAL)
    ledger = tmp_path / "completed.json"
    raw = canonical(command())
    if state != "missing":
        ledger.write_text(json.dumps({"request":raw.hex() if state != "changed" else "00",
                                     "state":"completed", "expired":state == "expired"}))
    before = ledger.read_bytes() if ledger.exists() else None
    with pytest.raises(Rejected, match=DENIAL):
        asyncio.run(authority.resume_evidence(raw))
    assert (ledger.read_bytes() if ledger.exists() else None) == before
    assert [row["argv"][0] for row in calls(tmp_path)] == ["resume"]
    reaped(tmp_path)


def test_query_resume_is_rejected_before_spawn(tmp_path):
    authority, _, _ = setup(tmp_path)
    raw = canonical({"schema":"runtime.query.v1","operation":"events.list","payload":{"after":0,"limit":1}})
    with pytest.raises(Rejected, match=DENIAL):
        asyncio.run(authority.resume_evidence(raw))
    assert not (tmp_path / "pid").exists()


def test_generic_authority_replay_preserves_old_interface(tmp_path):
    from frank_executor.journal import Journal
    from frank_executor.runtime import RuntimeGateway
    acquired = []
    class Generic:
        async def evidence(self, raw):
            acquired.append(raw)
            return b"existing-generic-evidence"
    class Client:
        async def command(self, envelope, *, authority):
            assert authority == b"existing-generic-evidence"
            return {"schema":"runtime.result.v1", "request_id":envelope["request_id"],
                "operation":envelope["operation"],"resource":envelope["resource"],
                "duplicate":True,"version":1,"result":{}}
    journal = Journal(tmp_path / "generic.db")
    journal.command(command())
    gateway = RuntimeGateway(Client(), Generic(), journal, lambda value, kind: None)
    asyncio.run(gateway.replay(command()["request_id"]))
    assert acquired == [canonical(command())]


def test_gate_attaches_before_fast_wallet_exit(tmp_path, monkeypatch):
    import frank_executor.wallet_authority as module
    authority, _, _ = setup(tmp_path)
    observed = []
    real = module._observe
    def checked(owned, changes=None):
        if changes:
            # Wallet cannot have reached its first marker before NOTE_EXIT attach.
            time.sleep(0.05)
            assert not (tmp_path / "pid").exists()
            observed.append(owned.process.pid)
        return real(owned, changes)
    monkeypatch.setattr(module, "_observe", checked)
    assert asyncio.run(authority.evidence(canonical(command()))) == ENVELOPE
    assert observed == [int((tmp_path / "pid").read_text())]
    reaped(tmp_path)


@pytest.mark.parametrize("fault", ["attach", "gate-release", "wrapper-startup"])
def test_gate_failure_never_executes_wallet_and_reaps(tmp_path, monkeypatch, fault):
    import frank_executor.wallet_authority as module
    authority, _, _ = setup(tmp_path)
    spawned = []
    real_popen, real_write = module.subprocess.Popen, module.os.write
    def capture(*args, **kwargs):
        process = real_popen(*args, **kwargs)
        if args[0][0] != module._PS:
            spawned.append(process)
        return process
    monkeypatch.setattr(module.subprocess, "Popen", capture)
    if fault == "attach":
        def fail_attach(*args, **kwargs):
            raise OSError("injected attach failure")
        monkeypatch.setattr(module, "_observe", fail_attach)
    elif fault == "gate-release":
        def fail_release(fd, raw):
            if raw == b"G":
                raise OSError("injected release failure")
            return real_write(fd, raw)
        monkeypatch.setattr(module.os, "write", fail_release)
    else:
        monkeypatch.setattr(module, "_GATE", "import os;os._exit(23)\n")
    with pytest.raises(Rejected, match=DENIAL):
        asyncio.run(authority.evidence(canonical(command())))
    assert not (tmp_path / "pid").exists()
    assert len(spawned) == 1 and spawned[0].returncode is not None
    assert authority._owned is None
    with pytest.raises(ChildProcessError):
        os.waitpid(spawned[0].pid, os.WNOHANG)


# Descendants stay in the owned group; no service, provider or Native is started.
DESCENDANT = f'''import signal
child=os.fork()
if child==0:
    signal.signal(signal.SIGTERM,signal.SIG_IGN)
    (base/"descendant-ready").write_text(str(os.getpid()))
    time.sleep(30)
    os._exit(0)
while not (base/"descendant-ready").exists():
    time.sleep(.001)
sys.stdout.buffer.write({ENVELOPE!r})
sys.stdout.buffer.flush()
'''


@pytest.mark.parametrize("leader", ["exit", "term-resistant"])
def test_owned_descendant_retained_pipe_and_term_resistance_are_cleaned(tmp_path, leader):
    suffix = "os._exit(0)\n" if leader == "exit" else "signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(30)\n"
    authority, _, _ = setup(tmp_path, DESCENDANT + suffix, timeout=0.8)
    try:
        with pytest.raises(Rejected, match=DENIAL):
            asyncio.run(authority.evidence(canonical(command())))
        # A brief zombie/group-presence quarantine is conservative; aclose only
        # observes the reaped group's disappearance and never signals it again.
        if authority._owned is not None:
            time.sleep(0.2)
            asyncio.run(authority.aclose())
        reaped(tmp_path)
        pid = int((tmp_path / "descendant-ready").read_text())
        with pytest.raises(ProcessLookupError):
            os.kill(pid, 0)
    finally:
        asyncio.run(authority.aclose())


def test_cleanup_term_error_still_kills_and_reaps_preserving_first(tmp_path, monkeypatch):
    import frank_executor.wallet_authority as module
    authority, _, _ = setup(tmp_path, "time.sleep(30)\n", timeout=0.8)
    real = module.os.killpg
    signals = []
    def term_error(pid, sig):
        signals.append(sig)
        if sig == signal.SIGTERM:
            raise PermissionError("injected term error")
        return real(pid, sig)
    with monkeypatch.context() as patch:
        patch.setattr(module.os, "killpg", term_error)
        with pytest.raises(Rejected, match=DENIAL):
            asyncio.run(authority.evidence(canonical(command())))
    assert signal.SIGTERM in signals and signal.SIGKILL in signals
    assert authority._first_failure == "timeout"
    assert "term" in authority._cleanup_failures and authority._owned is None
    reaped(tmp_path)


@pytest.mark.parametrize("fault", ["kill", "reap", "group-probe"])
def test_unresolved_cleanup_quarantines_until_explicit_resolution(tmp_path, monkeypatch, fault):
    import frank_executor.wallet_authority as module
    authority, _, _ = setup(tmp_path, "import signal;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(30)\n", timeout=0.8)
    real_killpg, real_wait = module.os.killpg, module.subprocess.Popen.wait
    attempted = []
    def injected_killpg(pid, sig):
        attempted.append(sig)
        if (fault == "kill" and sig == signal.SIGKILL) or (fault == "group-probe" and sig == 0):
            raise PermissionError("injected cleanup failure")
        return real_killpg(pid, sig)
    def injected_wait(process, *args, **kwargs):
        if fault == "reap":
            raise TimeoutError("injected reap failure")
        return real_wait(process, *args, **kwargs)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(module.os, "killpg", injected_killpg)
            patch.setattr(module.subprocess.Popen, "wait", injected_wait)
            with pytest.raises(Rejected, match=DENIAL):
                asyncio.run(authority.evidence(canonical(command())))
            assert authority._owned is not None
            with pytest.raises(Rejected, match=DENIAL):
                asyncio.run(authority.evidence(canonical(command())))
            assert len(calls(tmp_path)) == 1
        before_cleanup = len(attempted)
        with monkeypatch.context() as patch:
            def track(pid, sig):
                attempted.append(sig)
                return real_killpg(pid, sig)
            patch.setattr(module.os, "killpg", track)
            asyncio.run(authority.aclose())
        assert authority._owned is None and authority._first_failure == "timeout"
        if fault == "group-probe":
            assert all(sig == 0 for sig in attempted[before_cleanup:])
        reaped(tmp_path)
    finally:
        asyncio.run(authority.aclose())


def test_real_exited_leader_is_reaped_only_after_sole_zombie_census(tmp_path, monkeypatch):
    import frank_executor.wallet_authority as module
    authority, _, _ = setup(tmp_path)
    observed = []
    real_killpg, real_snapshot = module.os.killpg, authority._snapshot_bytes
    def snapshot(pid):
        raw = real_snapshot(pid)
        observed.append(raw)
        return raw
    def track(pid, sig):
        # A valid sole-Z proof needs no TERM/KILL; post-reap absence uses signal0.
        assert sig == 0
        return real_killpg(pid, sig)
    monkeypatch.setattr(authority, "_snapshot_bytes", snapshot)
    monkeypatch.setattr(module.os, "killpg", track)
    try:
        assert asyncio.run(authority.evidence(canonical(command()))) == ENVELOPE
        pid = int((tmp_path / "pid").read_text())
        assert len(observed) == 1
        fields = observed[0].decode("ascii").split()
        assert fields[:4] == [str(pid), str(os.getpid()), str(pid), str(os.getuid())]
        assert fields[4].startswith("Z")
        assert authority._owned is None and authority._census is None
        reaped(tmp_path)
    finally:
        monkeypatch.setattr(module.os, "killpg", real_killpg)
        asyncio.run(authority.aclose())


def test_live_group_eperm_never_becomes_zombie_permission(tmp_path, monkeypatch):
    import frank_executor.wallet_authority as module
    authority, _, _ = setup(tmp_path, "time.sleep(30)\n", timeout=0.8)
    real = module.os.killpg
    def denied(pid, sig):
        if sig in (signal.SIGTERM, signal.SIGKILL):
            raise PermissionError("injected live group EPERM")
        return real(pid, sig)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(module.os, "killpg", denied)
            with pytest.raises(Rejected, match=DENIAL):
                asyncio.run(authority.evidence(canonical(command())))
            owned = authority._owned
            assert owned is not None and not owned.reaped
            assert owned.process.returncode is None
            os.kill(owned.process.pid, 0)  # It is genuinely still alive.
            with pytest.raises(Rejected, match=DENIAL):
                asyncio.run(authority.evidence(canonical(command())))
            assert len(calls(tmp_path)) == 1
        asyncio.run(authority.aclose())
        assert authority._owned is None and authority._first_failure == "timeout"
        reaped(tmp_path)
    finally:
        asyncio.run(authority.aclose())


@pytest.mark.parametrize("case", ["live", "other-zombie", "wrong-parent", "wrong-owner", "duplicate", "malformed", "empty", "foreign"])
def test_only_exact_sole_zombie_rows_authorize_the_exception(tmp_path, monkeypatch, case):
    authority, _, _ = setup(tmp_path)
    pid, parent, uid = 7654321, os.getpid(), os.getuid()
    row = f"{pid} {parent} {pid} {uid} Z\n"
    raws = {
        "live":row.replace(" Z", " S"),
        "other-zombie":row + f"{pid + 1} {parent} {pid} {uid} Z\n",
        "wrong-parent":f"{pid} {parent + 1} {pid} {uid} Z\n",
        "wrong-owner":f"{pid} {parent} {pid} {uid + 1} Z\n",
        "duplicate":row + row, "malformed":"not a process row\n", "empty":"",
        "foreign":f"{pid} {parent} {pid + 1} {uid} Z\n",
    }
    monkeypatch.setattr(authority, "_snapshot_bytes", lambda ignored: raws[case].encode("ascii"))
    owned = SimpleNamespace(process=SimpleNamespace(pid=pid))
    if case in {"duplicate", "malformed", "empty", "foreign"}:
        with pytest.raises(Rejected):
            authority._sole_zombie(owned)
    else:
        assert authority._sole_zombie(owned) is False


@pytest.mark.parametrize("fault", ["stdout-limit", "stderr-limit", "timeout", "malformed", "unreadable"])
def test_census_failure_is_bounded_reaped_and_quarantines_wallet(tmp_path, monkeypatch, fault):
    import frank_executor.wallet_authority as module
    authority, _, _ = setup(tmp_path)
    real_popen = module.subprocess.Popen
    helpers = []
    behaviors = {
        "stdout-limit":"import sys;sys.stdout.buffer.write(b'x'*65537)",
        "stderr-limit":"import sys;sys.stderr.buffer.write(b'x'*1025)",
        "timeout":"import time;time.sleep(5)",
        "malformed":"print('not a process row')",
    }
    def census_fault(argv, **kwargs):
        if argv[0] != module._PS:
            return real_popen(argv, **kwargs)
        assert argv == ["/bin/ps", "-x", "-g", str(authority._owned.process.pid),
                        "-o", "pid=,ppid=,pgid=,uid=,stat="]
        if fault == "unreadable":
            raise PermissionError("injected census denial")
        child = real_popen([sys.executable, "-I", "-S", "-B", "-c", behaviors[fault]], **kwargs)
        helpers.append(child)
        return child
    try:
        with monkeypatch.context() as patch:
            patch.setattr(module.subprocess, "Popen", census_fault)
            with pytest.raises(Rejected, match=DENIAL):
                asyncio.run(authority.evidence(canonical(command())))
            assert authority._owned is not None and not authority._owned.reaped
            assert authority._census is None
            assert "census" in authority._cleanup_failures
            with pytest.raises(Rejected, match=DENIAL):
                asyncio.run(authority.evidence(canonical(command())))
            assert len(calls(tmp_path)) == 1
            assert all(child.returncode is not None for child in helpers)
            for child in helpers:
                with pytest.raises(ChildProcessError):
                    os.waitpid(child.pid, os.WNOHANG)
        asyncio.run(authority.aclose())
        assert authority._owned is None and authority._census is None
        reaped(tmp_path)
    finally:
        asyncio.run(authority.aclose())
