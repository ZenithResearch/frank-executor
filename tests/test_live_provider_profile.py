from __future__ import annotations

import hashlib
import json

import pytest

import frank_executor.live_provider_profile as live_profile
from frank_executor.live_provider_profile import (
    BRAND_CAPABILITIES,
    BRAND_RESOURCES,
    MOCK_EXECUTION_LABEL,
    load_profile,
)
from frank_executor.model import Rejected


def test_live_provider_cli_rejects_non_brand_execution_scope(monkeypatch):
    import asyncio
    from types import SimpleNamespace
    import frank_executor.live_provider_cli as cli

    selected_run = "handoff-" + "a" * 48
    monkeypatch.setattr(cli, "load_profile", lambda *_: SimpleNamespace(
        actor={"actor_id": "frank-hermes-pilot"},
        composition={"run_ids": [selected_run]},
    ))
    with pytest.raises(Rejected, match="outside selected live-provider scope"):
        asyncio.run(cli._run(SimpleNamespace(
            config="/tmp/profile.json", config_sha256="b" * 64,
            action="execute", run_id=selected_run, step_id="qualify-intake",
            operation="compute", scope="other", lease_ms=120000,
            request_id="claim-1", effect_key=None, wait_seconds=10)))


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def profile(tmp_path):
    tmp_path.chmod(0o700)
    files = {}
    for name in ("wallet", "wallet-config", "result", "result-config", "authority", "verifier", "policy", "python", "run_agent.py"):
        selected = tmp_path / name
        selected.write_bytes(b"#!/bin/sh\n" if name in {"wallet", "result", "verifier", "python"} else b"{}")
        selected.chmod(0o700 if name in {"wallet", "result", "verifier", "python"} else 0o600)
        files[name] = selected
    hermes_home = tmp_path / "hermes-home"
    hermes_home.mkdir(mode=0o700)
    source_root = tmp_path / "source"
    source_root.mkdir(mode=0o700)
    (source_root / "run_agent.py").write_bytes(files["run_agent.py"].read_bytes())
    composition = {
        "schema": "frank.live-provider.composition.v1",
        "runtime_endpoint": "http://127.0.0.1:8292",
        "journal": str(tmp_path / "journal.db"),
        "actor": {
            "actor_id": "frank-hermes-pilot",
            "integration_id": "hermes-sophia-pilot",
            "route": "local",
            "capabilities": list(BRAND_CAPABILITIES),
            "resources": list(BRAND_RESOURCES),
        },
        "run_ids": ["handoff-" + "a" * 48],
        "provider": {"model": "openai-codex/gpt-5.6-sol", "toolsets": [], "routes": ["local"], "max_iterations": 4},
        "producer_artifact_sha256": "1" * 64,
        "normalizer_sha256": "2" * 64,
        "source_manifest_sha256": "3" * 64,
    }
    composition_path = tmp_path / "composition.json"
    composition_path.write_bytes(canonical(composition))
    def command(executable, configuration, *, connector=False):
        value = {"executable": str(executable), "executable_sha256": sha(executable.read_bytes()),
                 "configuration": str(configuration), "configuration_sha256": sha(configuration.read_bytes())}
        if connector:
            value.update(authority_configuration=str(files["authority"]),
                         authority_configuration_sha256=sha(files["authority"].read_bytes()))
        return value
    master = {
        "schema": "frank.live-provider.config.v1",
        "composition": {"path": str(composition_path), "sha256": sha(composition_path.read_bytes())},
        "wallet": command(files["wallet"], files["wallet-config"]),
        "result": command(files["result"], files["result-config"], connector=True),
        "verifier": {"executable": str(files["verifier"]), "sha256": sha(files["verifier"].read_bytes()), "policy": str(files["policy"])},
        "hermes": {"python": str(files["python"]), "python_sha256": sha(files["python"].read_bytes()),
                   "source_root": str(source_root), "run_agent_sha256": sha((source_root / "run_agent.py").read_bytes()),
                   "hermes_home": str(hermes_home), "version": "0.20.0", "timeout_seconds": 600},
    }
    master_path = tmp_path / "master.json"
    master_path.write_bytes(canonical(master))
    return master_path, composition_path, composition


def allow_fixture_reads(monkeypatch):
    def read(path, expected, maximum, **_):
        raw = path.read_bytes()
        if not 0 < len(raw) <= maximum or sha(raw) != expected:
            raise Rejected("fixture pin mismatch")
        return raw
    monkeypatch.setattr(live_profile, "_pinned_file", read)


def test_live_provider_accepts_only_finite_automated_brand_actor(tmp_path, monkeypatch):
    allow_fixture_reads(monkeypatch)
    master, _, _ = profile(tmp_path)
    loaded = load_profile(str(master), sha(master.read_bytes()))
    assert loaded.actor["capabilities"] == list(BRAND_CAPABILITIES)
    assert "brand.review.human" not in loaded.actor["capabilities"]
    assert "brand.human-review" not in loaded.actor["resources"]


def test_live_provider_accepts_only_the_fixed_mock_execution_binding(tmp_path, monkeypatch):
    allow_fixture_reads(monkeypatch)
    master, composition_path, composition = profile(tmp_path)
    composition["execution"] = {"mode": "mock", "label": MOCK_EXECUTION_LABEL}
    composition_path.write_bytes(canonical(composition))
    selected = json.loads(master.read_bytes())
    selected["composition"]["sha256"] = sha(composition_path.read_bytes())
    master.write_bytes(canonical(selected))
    loaded = load_profile(str(master), sha(master.read_bytes()))
    assert loaded.execution == {"mode": "mock", "label": MOCK_EXECUTION_LABEL}

    composition["execution"]["label"] = "looks real"
    composition_path.write_bytes(canonical(composition))
    selected["composition"]["sha256"] = sha(composition_path.read_bytes())
    master.write_bytes(canonical(selected))
    with pytest.raises(Rejected, match="execution binding"):
        load_profile(str(master), sha(master.read_bytes()))


@pytest.mark.parametrize("field,value", [
    ("capabilities", [*BRAND_CAPABILITIES, "brand.review.human"]),
    ("resources", [*BRAND_RESOURCES, "brand.human-review"]),
    ("capabilities", ["compute"]),
])
def test_live_provider_rejects_scope_expansion_or_legacy_canary(tmp_path, monkeypatch, field, value):
    allow_fixture_reads(monkeypatch)
    master, composition_path, composition = profile(tmp_path)
    composition["actor"][field] = list(value)
    composition_path.write_bytes(canonical(composition))
    current = json.loads(master.read_bytes())
    current["composition"]["sha256"] = sha(composition_path.read_bytes())
    master.write_bytes(canonical(current))
    with pytest.raises(Rejected):
        load_profile(str(master), sha(master.read_bytes()))
