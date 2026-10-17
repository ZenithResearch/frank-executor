from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import json
from pathlib import Path
import sqlite3
import subprocess
import pytest
from jsonschema import Draft202012Validator
from process_runtime_client import command_envelope
from frank_executor.journal import Journal
from frank_executor.model import (
    Actor,
    Binding,
    Rejected,
    canonical,
    effect_key,
    work_packet,
)
from frank_executor.registry import Registry
from conftest import Adapter, arun, child_environment, python_child, registry_for

ROOT = Path(__file__).resolve().parents[1]


def packet():
    return work_packet(
        Binding("run", "step", "attempt", 1),
        Actor("worker", "fixture", ("compute",), (), "local"),
        effect_id="effect-1",
        operation="compute",
        scope="answer",
        inputs={"number": 7},
        output_types={"answer": {"kind": "integer"}},
    )


@pytest.mark.parametrize("name", ["work", "result"])
def test_owned_contract_fixtures(name):
    schema = json.loads((ROOT / "contracts/integration-adapter-v1.schema.json").read_text())
    validator = Draft202012Validator({**schema, "$ref": "#/$defs/" + name})
    fixture = json.loads((ROOT / f"contracts/fixtures/{name}.v1.json").read_text())
    validator.validate(fixture)
    fixture["schema"] = "frank." + name + ".v99"
    assert list(validator.iter_errors(fixture))


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), {1: "bad"}, ("tuple",), "\ud800"])
def test_invalid_json_fail_closed(bad):
    with pytest.raises(Rejected):
        canonical(bad)


def test_depth_bound_and_effect_identity_scope():
    deep = {}
    cursor = deep
    for _ in range(65):
        cursor["next"] = {}
        cursor = cursor["next"]
    with pytest.raises(Rejected):
        canonical(deep)
    binding = Binding("run", "step", "attempt", 1)
    first = effect_key(binding, "compute", "answer")
    assert first == effect_key(binding, "compute", "answer")
    assert (
        len(
            {
                first,
                effect_key(binding, "compute", "other"),
                effect_key(Binding("run", "step", "attempt2", 2), "compute", "answer"),
            }
        )
        == 3
    )


def test_concurrent_journal_dispatch_one_winner_and_actual_process_crash(tmp_path):
    path = tmp_path / "journal.db"
    journal = Journal(path)
    journal.delivery("key", packet())
    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(lambda _: Journal(path).begin_dispatch("key"), range(8))) == 1
    assert journal.get("key")["state"] == "unknown"
    code = "from frank_executor.journal import Journal; import os,sys; j=Journal(sys.argv[1]); j.begin_dispatch('crash'); os._exit(29)"
    journal.delivery("crash", packet())
    result = subprocess.run(python_child(["-c", code, str(path)]), env=child_environment(),
                            cwd=ROOT, timeout=90)
    assert result.returncode == 29 and Journal(path).get("crash")["state"] == "unknown"
    assert Journal(path).begin_dispatch("crash") is False


def test_foreign_database_rejected_without_journal_mode_mutation(tmp_path):
    path = tmp_path / "foreign.db"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE private_runtime(value TEXT)")
    before = path.read_bytes()
    with pytest.raises(Rejected, match="another component"):
        Journal(path)
    assert path.read_bytes() == before and not path.with_suffix(".db-wal").exists()


def test_exact_command_key_and_terminal_effect_immutability(tmp_path):
    journal = Journal(tmp_path / "journal.db")
    command = command_envelope(
        "actor.register",
        request_id="exact",
        expected_version=None,
        payload={"actor_id": "worker", "capabilities": [], "resources": []},
    )
    journal.command(command)
    assert journal.command(command)["state"] == "pending"
    changed = deepcopy(command)
    changed["payload"]["capabilities"] = ["compute"]
    with pytest.raises(Rejected, match="different bytes"):
        journal.command(changed)
    work = packet()
    journal.delivery("key", work)
    journal.begin_dispatch("key")
    result = Adapter().result(work)
    assert journal.observation("key", result)
    assert not journal.observation("key", result)
    different = deepcopy(result)
    different["event_id"] = "different"
    different["outputs"]["answer"] = 55
    with pytest.raises(Rejected, match="immutable"):
        journal.observation("key", different)
    journal.committed("key")
    assert journal.unresolved() == []


@pytest.mark.parametrize(
    "mutate",
    [
        lambda c: c["integrations"][0].update(plugin="unknown"),
        lambda c: c["integrations"][0].update(enabled="yes"),
        lambda c: c["actors"][0].update(capabilities="compute"),
        lambda c: c["actors"][0].update(resources=["x", "x"]),
        lambda c: c["integrations"].append(deepcopy(c["integrations"][0])),
    ],
)
def test_registry_rejects_ambiguous_configuration(mutate):
    config = {
        "schema": "frank.integrations.v1",
        "integrations": [
            {"id": "fixture", "plugin": "fixture.plugin", "enabled": True, "config": {}}
        ],
        "actors": [
            {
                "actor_id": "worker",
                "integration_id": "fixture",
                "capabilities": ["compute"],
                "resources": [],
                "route": "local",
            }
        ],
    }
    mutate(config)
    with pytest.raises(Rejected):
        Registry(config, {"fixture.plugin": lambda *_: Adapter()})


def test_new_plugin_needs_configuration_only_and_explains_no_match():
    registry = registry_for(Adapter())
    eligible, reason = registry.match(["compute"], [])
    assert [actor.actor_id for actor in eligible] == ["worker"]
    eligible, reason = registry.match(["review"], ["gpu"])
    assert eligible == [] and reason == {
        "worker": {"capabilities": ["review"], "resources": ["gpu"]}
    }
    arun(registry.connect())
    assert arun(registry.adapters["fixture"].health())["ready"]
    arun(registry.close())


def test_failed_connection_closes_partial_adapter():
    adapter = Adapter()

    async def broken():
        adapter.ready = True
        raise Rejected("Unavailable")

    adapter.connect = broken
    with pytest.raises(Rejected):
        arun(registry_for(adapter).connect())
    assert not adapter.ready


@pytest.mark.parametrize("raw", ['{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}', "{bad}"])
def test_strict_transport_json_rejects_ambiguity(raw):
    from frank_executor.model import decode_json

    with pytest.raises(Rejected):
        decode_json(raw)


def test_public_runtime_schema_copy_matches_pinned_client():
    from importlib.resources import files

    assert json.loads((ROOT / "contracts/runtime-v1.schema.json").read_text()) == json.loads(
        files("process_runtime_client").joinpath("runtime-v1.schema.json").read_text()
    )
