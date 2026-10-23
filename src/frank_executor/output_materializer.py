"""Closed conversion of provider-authored artifact bodies into Runtime references."""

from __future__ import annotations

import hashlib
import json

from process_runtime.compiler import validate_values

from .model import Rejected, canonical, decode_json, digest


MAX_ARTIFACT_BYTES = 1024 * 1024
TEXT_MEDIA_TYPES = frozenset({"application/json", "text/markdown", "text/plain"})


class RuntimeOutputMaterializer:
    """Materialize declared artifact outputs through a supplied Runtime artifact port."""

    def __init__(self, artifacts, *, test_label=None):
        if not callable(getattr(artifacts, "write", None)):
            raise Rejected("Runtime artifact writer required")
        if test_label is not None and (type(test_label) is not str
                or not 1 <= len(test_label.encode("utf-8")) <= 200):
            raise Rejected("Bounded mock execution label required")
        self.artifacts = artifacts
        self.test_label = test_label

    async def materialize(self, work, outputs):
        work, outputs = decode_json(canonical(work)), decode_json(canonical(outputs))
        output_types = work.get("output_types")
        if type(output_types) is not dict or type(outputs) is not dict:
            raise Rejected("Declared output object required")
        if set(outputs) != set(output_types):
            raise Rejected("Hermes must return exactly the declared output names")
        materialized = {}
        pending = {}
        for name, type_spec in output_types.items():
            value = outputs[name]
            if type_spec == {"kind": "artifact"}:
                if type(value) is not dict or set(value) != {"content_utf8", "media_type"}:
                    raise Rejected("Artifact output requires content_utf8 and media_type")
                content, media_type = value["content_utf8"], value["media_type"]
                if type(content) is not str or type(media_type) is not str:
                    raise Rejected("Artifact output must contain UTF-8 text")
                if media_type not in TEXT_MEDIA_TYPES:
                    raise Rejected("Artifact output media type is not allowed")
                if self.test_label is not None:
                    if media_type == "application/json":
                        try:
                            decoded = json.loads(content)
                        except json.JSONDecodeError:
                            raise Rejected("Mock JSON artifact must be valid JSON") from None
                        if (type(decoded) is not dict
                                or decoded.get("test_label") != self.test_label):
                            raise Rejected("Mock JSON artifact is missing its test label")
                    elif not content.startswith(self.test_label):
                        raise Rejected("Mock text artifact is missing its test label")
                raw = content.encode("utf-8")
                if len(raw) > MAX_ARTIFACT_BYTES:
                    raise Rejected("Artifact output exceeds bound")
                reference = {
                    "content_hash": hashlib.sha256(raw).hexdigest(),
                    "byte_length": len(raw),
                    "media_type": media_type,
                }
                request_id = "artifact-" + digest(
                    {
                        "schema": "frank.runtime-output-artifact.v1",
                        "effect_id": work["effect_id"],
                        "name": name,
                        "content_sha256": hashlib.sha256(raw).hexdigest(),
                        "media_type": media_type,
                    }
                )[:48]
                materialized[name] = reference
                pending[name] = (raw, media_type, request_id, reference)
            else:
                materialized[name] = value
        try:
            validate_values(materialized, output_types)
        except Exception:
            raise Rejected("Hermes outputs do not match the declared Runtime types") from None
        for name, (raw, media_type, request_id, reference) in pending.items():
            actual = await self.artifacts.write(raw, media_type, request_id=request_id)
            if actual != reference:
                raise Rejected("Runtime artifact reference differs from committed bytes")
            materialized[name] = actual
        return decode_json(canonical(materialized))

    def prompt_contract(self, work):
        artifact_names = [
            name
            for name, spec in work.get("output_types", {}).items()
            if spec == {"kind": "artifact"}
        ]
        if not artifact_names:
            return ""
        contract = (
            " For each artifact output ("
            + ", ".join(sorted(artifact_names))
            + "), return exactly {\"content_utf8\": string, \"media_type\": one of "
            + "\"text/markdown\", \"text/plain\", \"application/json\"}. "
            + "Do not return an artifact reference; Frank commits the bytes to Runtime."
        )
        if self.test_label is not None:
            contract += (
                " This is a mock transport test, not brand work. Every text artifact must begin exactly with "
                + json.dumps(self.test_label)
                + ". Every application/json artifact must be a JSON object whose test_label field equals that exact value."
            )
        return contract
