from __future__ import annotations
import asyncio
import json
import os
from importlib.resources import files
from pathlib import Path
import socket
import subprocess
import sys
import time
import uuid
import pytest
from process_runtime_client import (
    RuntimeClient,
    LocalDevAuthority as SDKAuthority,
    command_envelope,
)
from frank_executor.authority import LocalDevAuthority, LocalDevResults
from frank_executor.executor import Executor
from frank_executor.journal import Journal
from frank_executor.model import digest
from frank_executor.registry import Registry
from frank_executor.runtime import ContractValidator, GeneratedClientAdapter, RuntimeGateway


def installed_test_mode():
    return os.environ.get("FRANK_TESTS_INSTALLED") == "1"


def child_environment(env=None):
    """Retain fixture/provider configuration while removing component source overlays."""
    selected = dict(os.environ if env is None else env)
    if installed_test_mode() and "PYTHONPATH" in selected:
        root = Path(__file__).resolve().parents[1]
        component_sources = {root / "src", root.parent / "process-runtime" / "src"}
        component_sources = {path.resolve() for path in component_sources}
        retained = [
            item for item in selected["PYTHONPATH"].split(os.pathsep)
            if Path(item or ".").resolve() not in component_sources
        ]
        selected["PYTHONPATH"] = os.pathsep.join(retained)
    return selected


def python_child(arguments, *, modules=("frank_executor", "process_runtime_client")):
    """Assert wheel origins inside every installed-mode component subprocess."""
    if not installed_test_mode():
        return [sys.executable, *arguments]
    preamble = (
        "import importlib, sys; from pathlib import Path; "
        f"_modules = {modules!r}; "
        "_prefix = Path(sys.prefix).resolve(); "
        "_origins = [Path(importlib.import_module(name).__file__).resolve() for name in _modules]; "
        "assert all(path.is_relative_to(_prefix) for path in _origins), "
        "'Installed Frank test child imported component source';\n"
    )
    if arguments[0] == "-c":
        return [sys.executable, "-c", preamble + arguments[1], *arguments[2:]]
    if arguments[0] == "-m":
        return [sys.executable, "-c", preamble +
                "import runpy; sys.argv = sys.argv[1:]; "
                "runpy.run_module(sys.argv[0], run_name='__main__')", *arguments[1:]]
    raise AssertionError("Installed test child must use an explicit module or code entrypoint")


def arun(awaitable):
    return asyncio.run(awaitable)


class Adapter:
    contract_version = "frank.integration.v1"
    provider_idempotent = False
    integration_id = "fixture"

    def __init__(self, outcome="succeeded"):
        self.outcome = outcome
        self.sent = []
        self.cancelled = []
        self.ready = False
        self.events = []
        self.failure = None

    async def connect(self):
        self.ready = True

    async def close(self):
        self.ready = False

    async def capabilities(self):
        return frozenset({"send", "receive", "health", "cancel", "reconcile"})

    async def health(self):
        return {"ready": self.ready}

    def result(self, work, outcome=None):
        outcome = outcome or self.outcome
        return {
            "schema": "frank.result.v1",
            "event_id": "result-" + digest({"effect": work["effect_id"], "outcome": outcome})[:48],
            **{
                key: work[key]
                for key in ("binding", "actor_id", "integration_id", "route", "effect_id")
            },
            "provider_reference": "provider-" + work["effect_id"],
            "outcome": outcome,
            "outputs": {"answer": 14} if outcome == "succeeded" else {},
        }

    async def send(self, work):
        self.sent.append(work)
        if self.failure:
            raise self.failure
        return self.result(work)

    async def receive(self, cursor):
        events, self.events = self.events, []
        return events, "next-cursor"

    async def cancel(self, work):
        self.cancelled.append(work)
        return False

    async def reconcile(self, work, reference):
        return None


def registry_for(adapter, actor="worker"):
    return Registry(
        {
            "schema": "frank.integrations.v1",
            "integrations": [
                {"id": "fixture", "plugin": "fixture.plugin", "enabled": True, "config": {}}
            ],
            "actors": [
                {
                    "actor_id": actor,
                    "integration_id": "fixture",
                    "capabilities": ["compute"],
                    "resources": [],
                    "route": "local",
                }
            ],
        },
        {"fixture.plugin": lambda *_: adapter},
    )


@pytest.fixture(scope="session")
def provider(tmp_path_factory):
    path = tmp_path_factory.mktemp("runtime-provider")
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    command = python_child([
        "-m",
        "process_runtime",
        "--database",
        str(path / "runtime.db"),
        "--port",
        str(port),
        "--environment",
        "test",
        "--local-dev-untrusted",
        "--local-dev-subject",
        "frank-test",
    ], modules=("process_runtime", "process_runtime_client"))
    log = (path / "provider.log").open("wb")
    process = subprocess.Popen(command, env=child_environment(), stdout=log, stderr=subprocess.STDOUT)
    endpoint = f"http://127.0.0.1:{port}"
    client = RuntimeClient(endpoint, authority=SDKAuthority(environment="test"), timeout=3)
    deadline = time.monotonic() + 90
    try:
        while time.monotonic() < deadline:
            if process.poll() is not None:
                pytest.fail(
                    "Runtime provider did not start: " + (path / "provider.log").read_text()
                )
            try:
                client.query(
                    {
                        "schema": "runtime.query.v1",
                        "operation": "events.list",
                        "payload": {"after": 0, "limit": 1},
                    }
                )
                break
            except Exception:
                time.sleep(0.1)
        else:
            pytest.fail("Runtime provider startup timed out")
        yield endpoint, client
    finally:
        process.terminate()
        try:
            process.wait(10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(10)
        log.close()


def seed(client):
    suffix = uuid.uuid4().hex
    process_id = "process-" + suffix
    run_id = "run-" + suffix
    actor = "actor-" + suffix
    draft = {
        "schema": "process.draft.v1",
        "process_id": process_id,
        "inputs": {"number": {"kind": "integer"}},
        "steps": [
            {
                "step_id": "compute",
                "depends_on": [],
                "capabilities": ["compute"],
                "resources": [],
                "inputs": {"number": {"kind": "integer"}},
                "bindings": {"number": {"source": "run_input", "name": "number"}},
                "outputs": {"answer": {"kind": "integer"}},
                "max_attempts": 3,
            }
        ],
    }

    def command(op, payload, version):
        return client.execute(
            command_envelope(
                op, request_id=uuid.uuid4().hex, expected_version=version, payload=payload
            )
        )

    command(
        "process.draft.put",
        {
            "draft": draft,
            "provenance": {
                "source_id": "test-fixture",
                "media_type": "application/json",
                "content_hash": digest(draft),
                "parser": "explicit-json-v1",
                "uncertainties": [],
            },
        },
        None,
    )
    pin = command(
        "process.publish",
        {"process_id": process_id, "draft_revision": 1, "version_id": "version-" + suffix},
        1,
    )["result"]["pin"]
    command("run.create", {"run_id": run_id, "pin": pin, "inputs": {"number": 7}}, None)
    return run_id, actor


@pytest.fixture
def harness(provider, tmp_path):
    endpoint, client = provider
    run_id, actor = seed(client)
    adapter = Adapter()
    registry = registry_for(adapter, actor)
    journal = Journal(tmp_path / "frank.db")
    signer = SDKAuthority(environment="test")
    authority = LocalDevAuthority(
        lambda raw: signer(json.loads(raw)), environment="test", enabled=True
    )
    schema = json.loads(
        files("process_runtime_client").joinpath("runtime-v1.schema.json").read_text()
    )
    gateway = RuntimeGateway(
        GeneratedClientAdapter(RuntimeClient(endpoint)),
        authority,
        journal,
        ContractValidator(schema),
    )
    executor = Executor(
        gateway,
        registry,
        journal,
        LocalDevResults(environment="test", enabled=True),
        environment="test",
    )
    arun(registry.connect())
    arun(executor.register(actor))
    work = next(item for item in arun(executor.work(actor))["work"] if item["run_id"] == run_id)
    return executor, adapter, journal, work, actor, client
