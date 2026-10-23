import asyncio
import hashlib
import json

import pytest

from frank_executor.model import Rejected
from frank_executor.live_provider_profile import MOCK_EXECUTION_LABEL
from frank_executor.output_materializer import RuntimeOutputMaterializer


def work(output_types):
    return {
        "schema": "frank.work.v1",
        "binding": {
            "run_id": "run-1",
            "step_id": "step-1",
            "attempt_id": "attempt-1",
            "fence": 1,
        },
        "actor_id": "worker",
        "integration_id": "hermes",
        "route": "local",
        "effect_id": "effect-1",
        "operation": "compute",
        "scope": "test",
        "inputs": {},
        "output_types": output_types,
    }


class Artifacts:
    def __init__(self):
        self.calls = []

    async def write(self, content, media_type, *, request_id=None):
        self.calls.append((content, media_type, request_id))
        return {
            "content_hash": hashlib.sha256(content).hexdigest(),
            "byte_length": len(content),
            "media_type": media_type,
        }


def run(value):
    return asyncio.run(value)


def test_materializes_only_declared_artifacts_and_preserves_scalar_outputs():
    artifacts = Artifacts()
    materializer = RuntimeOutputMaterializer(artifacts)
    value = run(materializer.materialize(
        work({"brand_package": {"kind": "artifact"}, "approved": {"kind": "boolean"}}),
        {
            "brand_package": {
                "content_utf8": "# Brand package\n",
                "media_type": "text/markdown",
            },
            "approved": True,
        },
    ))
    assert value["approved"] is True
    assert value["brand_package"] == {
        "content_hash": hashlib.sha256(b"# Brand package\n").hexdigest(),
        "byte_length": 16,
        "media_type": "text/markdown",
    }
    assert artifacts.calls[0][2].startswith("artifact-")


@pytest.mark.parametrize(
    "outputs,message",
    [
        ({}, "exactly the declared"),
        ({"document": {"content_utf8": "x", "media_type": "text/html"}}, "media type"),
        ({"document": {"content_utf8": "x"}}, "content_utf8"),
        ({"document": {"content_utf8": 1, "media_type": "text/plain"}}, "UTF-8"),
    ],
)
def test_artifact_descriptor_fails_closed(outputs, message):
    materializer = RuntimeOutputMaterializer(Artifacts())
    with pytest.raises(Rejected, match=message):
        run(materializer.materialize(work({"document": {"kind": "artifact"}}), outputs))


def test_prompt_contract_names_artifact_outputs_without_requesting_fake_refs():
    value = RuntimeOutputMaterializer(Artifacts()).prompt_contract(
        work({"document": {"kind": "artifact"}, "score": {"kind": "integer"}})
    )
    assert "document" in value and "content_utf8" in value
    assert "Do not return an artifact reference" in value


def test_scalar_type_failure_happens_before_any_artifact_write():
    artifacts = Artifacts()
    materializer = RuntimeOutputMaterializer(artifacts)
    with pytest.raises(Rejected, match="declared Runtime types"):
        run(materializer.materialize(
            work({"document": {"kind": "artifact"}, "score": {"kind": "integer"}}),
            {
                "document": {"content_utf8": "ready", "media_type": "text/plain"},
                "score": True,
            },
        ))
    assert artifacts.calls == []


def test_mock_binding_labels_and_rejects_unlabelled_artifacts_before_write():
    artifacts = Artifacts()
    materializer = RuntimeOutputMaterializer(
        artifacts, test_label=MOCK_EXECUTION_LABEL)
    prompt = materializer.prompt_contract(work({"document": {"kind": "artifact"}}))
    assert MOCK_EXECUTION_LABEL in prompt and "not brand work" in prompt

    with pytest.raises(Rejected, match="missing its test label"):
        run(materializer.materialize(
            work({"document": {"kind": "artifact"}}),
            {"document": {"content_utf8": "looks real", "media_type": "text/plain"}},
        ))
    assert artifacts.calls == []

    value = run(materializer.materialize(
        work({"document": {"kind": "artifact"}}),
        {"document": {"content_utf8": json.dumps({"test_label": MOCK_EXECUTION_LABEL,
                                                    "result": "fixture"}),
                      "media_type": "application/json"}},
    ))
    assert value["document"]["media_type"] == "application/json"
