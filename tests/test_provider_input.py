import asyncio
import base64
import hashlib

import pytest

from frank_executor.model import Rejected, canonical
from frank_executor.provider_input import RuntimeInputHydrator


class Artifacts:
    effects_disabled = True

    def __init__(self, values):
        self.values = values
        self.reads = []

    async def read(self, reference):
        self.reads.append(reference)
        return self.values[reference["content_hash"]]


def artifact(raw):
    return {"content_hash": hashlib.sha256(raw).hexdigest(), "byte_length": len(raw),
            "media_type": "application/json"}


def fixture(content=b"verified-image"):
    values = {"organization_name": "North Shore Field Notes", "brand_brief": "Make it clear."}
    brief = canonical({"schema": "service.reviewed-brief.v1", "revision": 1,
                       "content_hash": hashlib.sha256(canonical(values)).hexdigest(),
                       "values": values})
    manifest = {"schema": "service.artifact-manifest.v1", "artifact_id": "reference-1",
                "content_hash": hashlib.sha256(content).hexdigest(),
                "byte_length": len(content), "media_type": "image/png",
                "filename": "reference.png", "content_base64": base64.b64encode(content).decode()}
    references = canonical({"schema": "service.reference-manifest.v2",
                            "references": [manifest]})
    brief_ref, reference_ref = artifact(brief), artifact(references)
    work = {"inputs": {"organization_name": "North Shore Field Notes",
                       "reviewed_brief": brief_ref, "reference_manifest": reference_ref}}
    return work, {brief_ref["content_hash"]: brief, reference_ref["content_hash"]: references}


def run(value):
    return asyncio.run(value)


def test_hydrates_closed_brief_and_exact_image_attachment():
    work, values = fixture()
    hydrated = run(RuntimeInputHydrator(Artifacts(values)).hydrate(work))
    assert hydrated.value["schema"] == "frank.provider-input.v1"
    assert hydrated.value["reviewed_brief"]["values"]["organization_name"] == work["inputs"]["organization_name"]
    assert "content_base64" not in hydrated.value["references"][0]
    assert hydrated.attachments[0]["content_hash"] == hydrated.value["references"][0]["content_hash"]
    assert base64.b64decode(hydrated.attachments[0]["content_base64"]) == b"verified-image"


@pytest.mark.parametrize("mutation", ["brief_hash", "reference_hash", "organization", "media_type", "extra"])
def test_rejects_changed_or_unsupported_runtime_input(mutation):
    work, values = fixture()
    brief_key, reference_key = [item["content_hash"] for item in work["inputs"].values()
                                if isinstance(item, dict)]
    if mutation == "brief_hash":
        parsed = __import__("json").loads(values[brief_key]); parsed["content_hash"] = "0" * 64
        values[brief_key] = canonical(parsed)
    elif mutation in {"reference_hash", "media_type", "extra"}:
        parsed = __import__("json").loads(values[reference_key])
        item = parsed["references"][0]
        if mutation == "reference_hash": item["content_hash"] = "0" * 64
        if mutation == "media_type": item["media_type"] = "application/pdf"
        if mutation == "extra": item["path"] = "/tmp/untrusted"
        values[reference_key] = canonical(parsed)
    else:
        work["inputs"]["organization_name"] = "Changed"
    with pytest.raises(Rejected):
        run(RuntimeInputHydrator(Artifacts(values)).hydrate(work))

