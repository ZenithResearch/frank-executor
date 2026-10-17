from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


class ArtifactPort(Protocol):
    effects_disabled: bool

    async def read(self, reference: dict) -> bytes: ...
    async def write(self, content: bytes, media_type: str) -> dict: ...


class STTPort(Protocol):
    effects_disabled: bool

    async def transcribe(self, audio: bytes, reference: dict) -> dict: ...


class ComponentPort(Protocol):
    effects_disabled: bool

    async def resolve(self, subject: str, events: list[dict]) -> list[dict]: ...


class SourcePort(Protocol):
    effects_disabled: bool

    async def inspect(self, subject: str, selectors: list[str]) -> list[dict]: ...


class IntentPort(Protocol):
    effects_disabled: bool

    async def record(self, binding: dict, operation: str, payload: dict) -> dict: ...


class ClaimPort(Protocol):
    effects_disabled: bool

    async def check(self, work: dict) -> None: ...


class ResultPort(Protocol):
    effects_disabled: bool

    async def bind(self, result: dict, work: dict) -> dict: ...


@dataclass(frozen=True)
class ReviewPorts:
    artifacts: ArtifactPort
    stt: STTPort
    components: ComponentPort
    sources: SourcePort
    intents: IntentPort
    claims: ClaimPort
    results: ResultPort


class ReviewFailure(ValueError):
    """A bounded semantic decision, never a credential/provider body."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code
