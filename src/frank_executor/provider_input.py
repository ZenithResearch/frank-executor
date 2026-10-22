"""Closed hydration of immutable Runtime inputs for the first live provider."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import re

from .model import Rejected, canonical, decode_json, identity


SHA256 = re.compile(r"[a-f0-9]{64}\Z")
REFERENCE_MEDIA = frozenset({"image/jpeg", "image/png"})
MAX_REFERENCE_BYTES = 524_288


@dataclass(frozen=True)
class HydratedProviderInput:
    """Prompt-safe verified values and separately carried model attachments."""

    value: dict
    attachments: tuple[dict, ...]


class RuntimeInputHydrator:
    """Resolve and verify the exact Runtime artifacts selected by a claimed step."""

    effects_disabled = True

    def __init__(self, artifacts):
        if (not getattr(artifacts, "effects_disabled", False)
                or not callable(getattr(artifacts, "read", None))):
            raise Rejected("Read-only Runtime artifact port required")
        self.artifacts = artifacts

    @staticmethod
    def _hash(value, label):
        if type(value) is not str or SHA256.fullmatch(value) is None:
            raise Rejected(f"Invalid {label} digest")
        return value

    async def hydrate(self, work) -> HydratedProviderInput:
        try:
            inputs = work["inputs"]
            if (type(inputs) is not dict
                    or not {"organization_name", "reviewed_brief", "reference_manifest"}
                    <= set(inputs)):
                raise Rejected("Required provider inputs are absent")
            organization = inputs["organization_name"]
            if type(organization) is not str or not organization.strip() or len(organization) > 200:
                raise Rejected("Invalid provider organization input")
            brief = decode_json(await self.artifacts.read(inputs["reviewed_brief"]))
            if (type(brief) is not dict
                    or set(brief) != {"schema", "revision", "content_hash", "values"}
                    or brief["schema"] != "service.reviewed-brief.v1"
                    or type(brief["revision"]) is not int
                    or not 1 <= brief["revision"] <= 2**53 - 1
                    or type(brief["values"]) is not dict
                    or brief["values"].get("organization_name") != organization):
                raise Rejected("Malformed reviewed brief artifact")
            expected_brief_hash = self._hash(brief["content_hash"], "reviewed brief")
            if hashlib.sha256(canonical(brief["values"])).hexdigest() != expected_brief_hash:
                raise Rejected("Reviewed brief digest mismatch")

            reference_value = decode_json(
                await self.artifacts.read(inputs["reference_manifest"]))
            if (type(reference_value) is not dict
                    or set(reference_value) != {"schema", "references"}
                    or reference_value["schema"] != "service.reference-manifest.v2"
                    or type(reference_value["references"]) is not list
                    or len(reference_value["references"]) > 1):
                raise Rejected("Malformed reference manifest artifact")

            references, attachments = [], []
            for item in reference_value["references"]:
                required = {"schema", "artifact_id", "content_hash", "byte_length",
                            "media_type", "filename", "content_base64"}
                if (type(item) is not dict or set(item) != required
                        or item["schema"] != "service.artifact-manifest.v1"):
                    raise Rejected("Malformed provider reference")
                artifact_id = identity(item["artifact_id"])
                content_hash = self._hash(item["content_hash"], "reference")
                length = item["byte_length"]
                media_type, filename = item["media_type"], item["filename"]
                if (type(length) is not int or not 1 <= length <= MAX_REFERENCE_BYTES
                        or media_type not in REFERENCE_MEDIA
                        or type(filename) is not str or not filename or len(filename) > 1024
                        or "\x00" in filename):
                    raise Rejected("Unsupported provider reference")
                try:
                    content = base64.b64decode(item["content_base64"], validate=True)
                except (ValueError, TypeError):
                    raise Rejected("Malformed provider reference bytes") from None
                if len(content) != length or hashlib.sha256(content).hexdigest() != content_hash:
                    raise Rejected("Provider reference digest mismatch")
                manifest = {key: item[key] for key in required - {"content_base64"}}
                references.append(manifest)
                attachments.append({"artifact_id": artifact_id, "content_hash": content_hash,
                                    "media_type": media_type,
                                    "content_base64": item["content_base64"]})

            value = decode_json(canonical({
                "schema": "frank.provider-input.v1",
                "reviewed_brief": brief,
                "references": references,
            }))
            return HydratedProviderInput(value, tuple(attachments))
        except Rejected:
            raise
        except (KeyError, TypeError, ValueError):
            raise Rejected("Provider inputs are unavailable") from None

