from __future__ import annotations
from typing import Protocol, Callable, TYPE_CHECKING

if TYPE_CHECKING:
    from .native_results import NativeResultAdmission

DispatchGuard = Callable[[dict], None]


class RuntimeClient(Protocol):
    async def command(self, envelope: dict, *, authority: bytes) -> dict: ...
    async def query(self, envelope: dict, *, authority: bytes) -> dict: ...


class GuardedRuntimeClient(RuntimeClient, Protocol):
    """Run the synchronous guard at the actual transport boundary, after local waits."""

    async def command_guarded(
        self, envelope: dict, *, authority: bytes, guard: DispatchGuard
    ) -> dict: ...


class CallAuthority(Protocol):
    mode: str

    async def evidence(self, envelope: bytes) -> bytes: ...


class ResumableCallAuthority(CallAuthority, Protocol):
    """Optional no-create recovery selected only by explicit saved-command replay."""

    async def resume_evidence(self, envelope: bytes) -> bytes: ...


class ResultVerifier(Protocol):
    mode: str

    async def verify(self, result: dict, work: dict) -> NativeResultAdmission | None: ...


class IntegrationAdapter(Protocol):
    contract_version: str
    integration_id: str
    provider_idempotent: bool

    async def connect(self) -> None: ...
    async def close(self) -> None: ...
    async def capabilities(self) -> frozenset[str]: ...
    async def health(self) -> dict: ...
    async def send(self, work: dict) -> dict: ...
    async def receive(self, cursor: str | None) -> tuple[list[dict], str | None]: ...
    async def cancel(self, work: dict) -> bool: ...
    async def reconcile(self, work: dict, provider_reference: str | None) -> dict | None: ...
