"""Explicit private synthetic ports. No vault, URI, model or credential access."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import re

from frank_executor.model import Rejected, digest

from .ports import ReviewFailure


class MemoryArtifacts:
    effects_disabled = True

    def __init__(self):
        self.contents = {}

    async def read(self, reference):
        payload = self.contents.get(reference["content_hash"])
        if payload is None:
            raise ReviewFailure("artifact_unavailable")
        return payload

    async def write(self, content, media_type):
        key = hashlib.sha256(content).hexdigest()
        self.contents[key] = bytes(content)
        return {"content_hash": key, "byte_length": len(content), "media_type": media_type}


class FrozenSTT:
    effects_disabled = True

    def __init__(self, audio: bytes, response: dict):
        self.audio, self.response, self.calls = bytes(audio), deepcopy(response), 0

    async def transcribe(self, audio, reference):
        self.calls += 1
        if audio != self.audio:
            raise ReviewFailure("transcription_input_mismatch")
        return deepcopy(self.response)


class SnapshotSources:
    effects_disabled = True

    def __init__(self, snapshots: dict):
        self.snapshots = deepcopy(snapshots)

    async def inspect(self, subject, selectors):
        matches = []
        for path, text in sorted(self.snapshots.get(subject, {}).items()):
            for line_number, line in enumerate(text.splitlines(), 1):
                for selector in selectors:
                    parts = selector.split(".")
                    tag = parts[0]
                    classes = parts[1:]
                    match = re.search(r'className="([^"]*)"', line)
                    if tag and re.search(r"<" + re.escape(tag) + r"\b", line) and (not classes or match and set(classes).issubset(match[1].split())):
                        matches.append({"path": path, "line": line_number, "selector": selector,
                                        "content_hash": hashlib.sha256(text.encode()).hexdigest(), "text": line})
        return matches

    async def resolve(self, subject, events):
        rows = []
        for selector in sorted({event["target"] for event in events if event["target"]}):
            references = await self.inspect(subject, [selector])
            if len(references) == 1:
                reference = references[0]
                rows.append({"component": selector, "selectors": [selector], "aliases": [],
                             "source": f"{reference['path']}:{reference['line']}", "spatial_hint": "",
                             "resolution_status": "resolved"})
        return rows


class SimulatedIntents:
    effects_disabled = True

    def __init__(self):
        self.intents = []

    async def record(self, binding, operation, payload):
        entry = {"binding": deepcopy(binding), "operation": operation, "payload": deepcopy(payload),
                 "simulation": True, "external_send_count": 0, "native_authority": False}
        self.intents.append(entry)
        return {"simulation": True, "recorded": True, "intent_digest": digest(entry)}


class SyntheticResults:
    effects_disabled = True

    async def bind(self, result, work):
        return {**deepcopy(result), "proof": {"mode": "local_dev_untrusted", "simulation": True,
                                              "work_digest": digest(work), "native_authority": False}}


class SyntheticClaims:
    effects_disabled = True

    def __init__(self):
        self.confirmed = {}

    def confirm(self, work):
        self.confirmed[digest(work["binding"])] = digest(work)

    async def check(self, work):
        if self.confirmed.get(digest(work["binding"])) != digest(work):
            raise Rejected("No explicit synthetic claim for this work")
