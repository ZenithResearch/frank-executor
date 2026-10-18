"""Closed installed composition controls. Dummy artifact bytes are never executed."""
import asyncio
import hashlib
import json
from pathlib import Path
import time

import pytest

from frank_executor.authority import check_authority, DenyAuthority, DenyResults
from frank_executor.local_review_profile import load_profile, compose, DECLARED_CAPABILITIES
from frank_executor.local_review_cli import arguments, run
from frank_executor.model import Rejected, canonical
from frank_executor.native_results import NativeResultVerifier
from frank_review_adapter.local_capture import OPERATIONS
from native_result_support import admitted, policy


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def write(path, raw, mode=0o600):
    path.write_bytes(raw)
    path.chmod(mode)


def fixture(tmp_path, change=None):
    tmp_path.chmod(0o700)
    capture = tmp_path / "captures"
    capture.mkdir(mode=0o700)
    blobs = capture / "blobs"
    blobs.mkdir(mode=0o700)
    program = tmp_path / "never-executed-artifact"
    write(program, b"not a qualified native executable\n", 0o700)
    wallet = tmp_path / "wallet.json"
    write(wallet, canonical({"schema":"castalia.wallet-service-command.v1", "application":"runtime",
        "native_configuration":str(tmp_path / "native.json"), "native_configuration_sha256":"d"*64,
        "wallet_root":str(tmp_path / "wallet"), "store_binding":{}, "expected_state":{}}))
    result = tmp_path / "result.json"
    write(result, canonical({"capture_root":str(capture)}))
    receiver = tmp_path / "receiver.json"
    current = policy().snapshot()
    now = int(time.time() * 1000)
    current["rules"][0].update(not_before_ms=now-10000, not_after_ms=now+120000)
    write(receiver, canonical(current))
    artifact = {"content_hash":"c"*64, "byte_length":0, "media_type":"application/json"}
    producer, normalizer = b"unit producer artifact", b"unit normalizer artifact"
    value = {"schema":"frank.local-review.composition.v1", "runtime_endpoint":"http://127.0.0.1:8192",
        "journal":str(tmp_path / "frank.sqlite"), "capture_root":str(capture),
        "actor":{"actor_id":"worker", "integration_id":"fixture", "route":"local",
                 "capabilities":sorted(DECLARED_CAPABILITIES), "resources":[]}, "run_ids":["run"],
        "producer_artifact_sha256":sha(producer), "normalizer_sha256":sha(normalizer),
        "transcript":{"audio_sha256":"b"*64, "artifact":artifact}, "snapshots":{}}
    if change:
        change(value)
    composition = tmp_path / "composition.json"
    write(composition, canonical(value))
    contents = [producer, normalizer, composition.read_bytes()]
    for raw in contents:
        write(blobs / sha(raw), raw)
    manifest = {"schema":"frank.local-review.source-manifest.v1",
        "producer_artifact_sha256":sha(producer), "normalizer_sha256":sha(normalizer),
        "configuration_sha256":sha(composition.read_bytes()),
        "entries":[{"sha256":sha(raw), "byte_length":len(raw)} for raw in contents]}
    write(capture / "source-manifest.json", canonical(manifest))
    command = lambda config: {"executable":str(program), "executable_sha256":sha(program.read_bytes()),
                             "configuration":str(config), "configuration_sha256":sha(config.read_bytes())}
    master = {"schema":"frank.local-review.config.v1",
        "composition":{"path":str(composition), "sha256":sha(composition.read_bytes())},
        "source_manifest_sha256":sha(canonical(manifest)), "wallet":command(wallet), "result":command(result),
        "verifier":{"executable":str(program), "sha256":sha(program.read_bytes()), "policy":str(receiver)}}
    selected = tmp_path / "selected.json"
    write(selected, canonical(master))
    return selected, master, value


def load(selected):
    return load_profile(str(selected), sha(selected.read_bytes()))


def test_closed_profile_preserves_published_thirteen_caps_without_creating_journal(tmp_path):
    selected, master, value = fixture(tmp_path)
    profile = load(selected)
    published = json.loads((Path(__file__).parent / "fixtures/independent-review/personal-review-v1.compiled.json").read_bytes())
    required = {cap for step in published["steps"] for cap in step["capabilities"]}
    assert set(profile.composition["actor"]["capabilities"]) == required == DECLARED_CAPABILITIES
    assert len(required) == 13 and len(OPERATIONS) == 9
    assert profile.policy.configuration_sha256 == master["composition"]["sha256"]
    assert profile.policy.source_manifest_sha256 == master["source_manifest_sha256"]
    assert not Path(value["journal"]).exists()
    assert not (Path(value["capture_root"]) / "capture.lock").exists()


@pytest.mark.parametrize("mutation", ["extra", "unknown-capability", "duplicate-capability", "empty-runs",
    "duplicate-runs", "endpoint-credentials", "journal-relative", "snapshot-extra", "transcript-extra"])
def test_closed_composition_rejects_unsupported_fields_and_scope(tmp_path, mutation):
    def change(value):
        if mutation == "extra": value["qualified"] = True
        elif mutation == "unknown-capability": value["actor"]["capabilities"] = ["arbitrary.sign"]
        elif mutation == "duplicate-capability": value["actor"]["capabilities"] = ["review.annotate"] * 2
        elif mutation == "empty-runs": value["run_ids"] = []
        elif mutation == "duplicate-runs": value["run_ids"] = ["run", "run"]
        elif mutation == "endpoint-credentials": value["runtime_endpoint"] = "http://user:pass@127.0.0.1:8192"
        elif mutation == "journal-relative": value["journal"] = "relative.sqlite"
        elif mutation == "snapshot-extra": value["snapshots"] = {"subject":[{"path":"x", "artifact":{}, "url":"x"}]}
        else: value["transcript"]["fallback"] = "synthetic"
    selected, _, _ = fixture(tmp_path, change)
    with pytest.raises(Rejected):
        load(selected)


@pytest.mark.parametrize("mutation", ["hash", "permissive", "symlink", "duplicate", "extra", "composition-change", "manifest-change"])
def test_master_same_read_pin_private_bytes_and_cycle_free_manifest_are_required(tmp_path, mutation):
    selected, master, value = fixture(tmp_path)
    pin = sha(selected.read_bytes())
    if mutation == "hash": pin = "0" * 64
    elif mutation == "permissive": selected.chmod(0o644)
    elif mutation == "symlink":
        alias = tmp_path / "alias.json"; alias.symlink_to(selected); selected = alias
    elif mutation == "duplicate":
        raw = selected.read_bytes().replace(b'{', b'{"schema":"shadow",', 1); write(selected, raw); pin = sha(raw)
    elif mutation == "extra":
        master["allow_local_dev_untrusted"] = True; write(selected, canonical(master)); pin = sha(selected.read_bytes())
    elif mutation == "composition-change": write(Path(master["composition"]["path"]), b"{}")
    else: write(Path(value["capture_root"]) / "source-manifest.json", b"{}")
    with pytest.raises(Rejected):
        load_profile(str(selected), pin)


def test_health_checks_real_fixed_sources_without_process_network_or_store_creation(tmp_path, monkeypatch):
    selected, _, value = fixture(tmp_path)
    def forbidden(*args, **kwargs):
        raise AssertionError("read-only health launched a process/network/store")
    monkeypatch.setattr("subprocess.Popen", forbidden)
    monkeypatch.setattr("sqlite3.connect", forbidden)
    monkeypatch.setattr("socket.socket.connect", forbidden)
    _, args = arguments(["health", "--config", str(selected), "--config-sha256", sha(selected.read_bytes())])
    result = asyncio.run(run(args))
    assert result["native_artifacts_available"] and result["current_result_policy_valid"]
    assert result["runtime_checked"] is False
    assert not Path(value["journal"]).exists()
    assert not (Path(value["capture_root"]) / "capture.lock").exists()
    # These pinned dummy bytes were inspected, never run and never called qualified.


def test_concrete_readiness_uses_current_policy_and_never_mode_labels(tmp_path):
    selected, master, _ = fixture(tmp_path)
    profile = load(selected)
    authority, verifier = profile.native_sources()
    assert verifier.mode == "native_unqualified"  # Compatibility label cannot activate it.
    check_authority("production", authority, verifier)
    current = json.loads(Path(master["verifier"]["policy"]).read_bytes())
    current["rules"] = []
    write(Path(master["verifier"]["policy"]), canonical(current))
    with pytest.raises(Rejected):
        check_authority("production", authority, verifier)
    with pytest.raises(Rejected):
        check_authority("production", DenyAuthority(), DenyResults())


def test_synthetic_helper_or_clock_cannot_enter_production_by_relabeling(tmp_path):
    selected, _, _ = fixture(tmp_path)
    authority, real = load(selected).native_sources()
    _, synthetic, _, _, _, _ = admitted()
    synthetic.mode = "secs_verified"
    with pytest.raises(Rejected):
        check_authority("production", authority, synthetic)
    changed_clock = NativeResultVerifier(real.helper, real.load_policy, clock=lambda:time.time())
    with pytest.raises(Rejected):
        check_authority("production", authority, changed_clock)
    changed_loader = NativeResultVerifier(real.helper, lambda:real.load_policy())
    with pytest.raises(Rejected):
        check_authority("production", authority, changed_loader)


def test_explicit_compose_uses_concrete_ports_without_authority_execution(tmp_path, monkeypatch):
    selected, _, value = fixture(tmp_path)
    monkeypatch.setattr("subprocess.Popen", lambda *a, **k: (_ for _ in ()).throw(AssertionError("process")))
    executor, adapter = compose(load(selected))
    from frank_review_adapter.local_ports import RuntimeArtifacts, RuntimeClaims, RuntimeSnapshotSources, SuppliedTranscript
    assert type(adapter.ports.artifacts) is RuntimeArtifacts
    assert type(adapter.ports.claims) is RuntimeClaims
    assert type(adapter.ports.sources) is RuntimeSnapshotSources
    assert type(adapter.ports.stt) is SuppliedTranscript
    assert adapter.ports.components is adapter.ports.sources
    assert executor.gateway is adapter.ports.claims.gateway
    assert Path(value["journal"]).is_file()
    assert adapter._local_environment == "production"


@pytest.mark.parametrize("operation", ["transcribe-review-audio", "arbitrary.sign"])
def test_cli_operation_is_canonical_even_when_actor_publishes_legacy_capabilities(tmp_path, operation, monkeypatch):
    selected, _, _ = fixture(tmp_path)
    monkeypatch.setattr("frank_executor.local_review_cli.compose", lambda *_: (_ for _ in ()).throw(AssertionError("compose")))
    _, args = arguments(["execute", "--config", str(selected), "--config-sha256", sha(selected.read_bytes()),
        "--run-id", "run", "--step-id", "step", "--operation", operation, "--scope", "review"])
    with pytest.raises(Rejected, match="selected"):
        asyncio.run(run(args))


def test_cli_requires_pin_selection_and_finite_wait():
    for argv in (["health", "--config", "/private/missing"],
                 ["resume", "--config", "/private/missing", "--config-sha256", "a"*64],
                 ["work", "--config", "/private/missing", "--config-sha256", "a"*64, "--wait-seconds", "inf"]):
        with pytest.raises(SystemExit):
            arguments(argv)


@pytest.mark.parametrize("outcome", ["eligible", "not-eligible", "unknown"])
def test_bounded_cli_uses_runtime_eligibility_and_never_retries_unknown(tmp_path, monkeypatch, outcome):
    from types import SimpleNamespace
    from frank_executor.model import UnknownOutcome
    selected, _, _ = fixture(tmp_path)
    calls = []
    async def opened(): calls.append("connect")
    async def closed(): calls.append("close")
    async def authority_closed(): calls.append("authority-close")
    async def work(actor, **kwargs):
        assert actor == "worker" and kwargs == {"limit":100}
        return {"work":[] if outcome == "not-eligible" else [{"run_id":"run", "step_id":"step", "version":7}]}
    async def claim(actor, offered, **kwargs):
        calls.append("claim")
        assert offered["version"] == 7 and kwargs == {"lease_ms":60000, "request_id":None}
        return "unit-attempt"
    async def execute(attempt, **kwargs):
        calls.append("run")
        assert attempt == "unit-attempt"
        assert kwargs == {"operation":"review.annotate", "scope":"review", "lease_ms":60000, "wait_seconds":20}
        if outcome == "unknown": raise UnknownOutcome("unit unknown")
        return {"state":"committed"}
    executor = SimpleNamespace(work=work, claim=claim, run=execute, journal=None,
        registry=SimpleNamespace(connect=opened, close=closed),
        gateway=SimpleNamespace(authority=SimpleNamespace(aclose=authority_closed)))
    monkeypatch.setattr("frank_executor.local_review_cli.compose", lambda *_:(executor, None))
    _, args = arguments(["execute", "--config", str(selected), "--config-sha256", sha(selected.read_bytes()),
        "--run-id", "run", "--step-id", "step", "--operation", "review.annotate", "--scope", "review",
        "--lease-ms", "60000", "--wait-seconds", "20"])
    if outcome == "eligible": assert asyncio.run(run(args)) == {"state":"committed"}
    else:
        with pytest.raises(UnknownOutcome if outcome == "unknown" else Rejected):
            asyncio.run(run(args))
    assert calls == (["connect", "close", "authority-close"] if outcome == "not-eligible"
                     else ["connect", "claim", "run", "close", "authority-close"])


def test_current_policy_opener_cannot_block_on_a_substituted_nonregular_file(tmp_path, monkeypatch):
    import os
    from frank_executor.native_results import FileReceiverPolicy
    _, master, _ = fixture(tmp_path)
    real_open = os.open
    observed = []
    def bounded_open(path, flags, *args, **kwargs):
        observed.append(flags)
        assert flags & os.O_NONBLOCK and flags & os.O_NOFOLLOW
        return real_open(path, flags, *args, **kwargs)
    monkeypatch.setattr("frank_executor.native_results.os.open", bounded_open)
    assert FileReceiverPolicy(master["verifier"]["policy"])().keys
    assert len(observed) == 1


@pytest.mark.parametrize("mutation", ["revoked-key", "other-actor", "other-subject-rule"])
def test_readiness_correlates_selected_actor_current_key_and_allow_rule(tmp_path, mutation):
    selected, master, _ = fixture(tmp_path)
    profile = load(selected)
    receiver = Path(master["verifier"]["policy"])
    current = json.loads(receiver.read_bytes())
    if mutation == "revoked-key":
        current["keys"][0]["status"] = "revoked"
    elif mutation == "other-actor":
        current["subjects"][0]["actor_id"] = "another-actor"
    else:
        current["rules"][0]["subject_id"] = "another-subject"
    write(receiver, canonical(current))
    with pytest.raises(Rejected):
        profile.native_sources()
