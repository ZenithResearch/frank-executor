import json
import os
from pathlib import Path
import subprocess
from conftest import child_environment, installed_test_mode, python_child, seed

ROOT = Path(__file__).resolve().parents[1]


def invoke(config, action, *args, env=None):
    return subprocess.run(
        python_child(["-m", "frank_executor", action, "--config", str(config), *args]),
        cwd=ROOT,
        env=child_environment(env),
        capture_output=True,
        text=True,
        timeout=90,
    )


def test_cli_actual_execution_health_and_restart_inspection(provider, tmp_path):
    endpoint, client = provider
    run_id, actor = seed(client)
    fixture = tmp_path / "sdk-fixture"
    fixture.mkdir()
    (fixture / "run_agent.py").write_text("""class AIAgent:
    def __init__(self, **kwargs): pass
    def run_conversation(self, prompt, *, task_id): return {'final_response':'{"answer":14}'}
    def interrupt(self, reason): pass
""")
    config = {
        "schema": "frank.config.v1",
        "environment": "test",
        "runtime_endpoint": endpoint,
        "journal": str(tmp_path / "frank-cli.db"),
        "allow_local_dev_untrusted": True,
        "integrations": {
            "schema": "frank.integrations.v1",
            "integrations": [
                {
                    "id": "hermes-test",
                    "plugin": "frank.hermes.v1",
                    "enabled": True,
                    "config": {
                        "model": "fixture/model",
                        "toolsets": [],
                        "routes": ["local"],
                        "max_iterations": 1,
                    },
                }
            ],
            "actors": [
                {
                    "actor_id": actor,
                    "integration_id": "hermes-test",
                    "capabilities": ["compute"],
                    "resources": [],
                    "route": "local",
                }
            ],
        },
    }
    path = tmp_path / "config.json"
    path.write_text(json.dumps(config))
    paths = [str(fixture)]
    if not installed_test_mode():
        paths.append(str(ROOT / "src"))
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(paths)}
    for action, extra in [
        ("check-config", []),
        ("health", []),
        ("register", ["--actor", actor]),
        ("work", ["--actor", actor]),
    ]:
        result = invoke(path, action, *extra, env=env)
        assert result.returncode == 0, result.stderr
    result = invoke(
        path,
        "execute",
        "--actor",
        actor,
        "--run-id",
        run_id,
        "--step-id",
        "compute",
        "--operation",
        "compute",
        "--scope",
        "answer",
        "--wait-seconds",
        "10",
        env=env,
    )
    assert result.returncode == 0, result.stderr
    output = json.loads(result.stdout)
    assert output["state"] == "committed"
    result = invoke(path, "resume", "--effect-key", output["effect_key"], env=env)
    assert result.returncode == 0 and json.loads(result.stdout)["state"] == "committed"
    result = invoke(path, "inspect", env=env)
    assert result.returncode == 0 and json.loads(result.stdout) == {
        "deliveries": [],
        "pending_commands": [],
    }
    assert (
        client.query(
            {"schema": "runtime.query.v1", "operation": "run.get", "payload": {"run_id": run_id}}
        )["data"]["state"]
        == "succeeded"
    )


def test_production_cli_default_deny_before_adapter_or_runtime(tmp_path):
    config = {
        "schema": "frank.config.v1",
        "environment": "production",
        "runtime_endpoint": "http://127.0.0.1:1",
        "journal": str(tmp_path / "journal.db"),
        "allow_local_dev_untrusted": False,
        "integrations": {"schema": "frank.integrations.v1", "integrations": [], "actors": []},
    }
    path = tmp_path / "config.json"
    path.write_text(json.dumps(config))
    health = invoke(path, "health")
    assert health.returncode == 0
    assert json.loads(health.stdout) == {
        "live": True,
        "configuration": "valid",
        "adapter_ready": True,
        "ready": False,
        "authority": "adapter_required",
        "integrations": [],
    }
    result = invoke(path, "register", "--actor", "missing")
    assert result.returncode == 2 and "qualified native secS" in result.stderr
    config["allow_local_dev_untrusted"] = True
    path.write_text(json.dumps(config))
    result = invoke(path, "check-config")
    assert result.returncode == 2 and "prohibited in production" in result.stderr
