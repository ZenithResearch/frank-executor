from __future__ import annotations
from .model import Rejected


class DenyAuthority:
    mode = "unavailable"

    async def evidence(self, envelope):
        raise Rejected("Native secS command authority is not qualified")


class DenyResults:
    mode = "unavailable"

    async def verify(self, result, work):
        raise Rejected("Native result verifier is not qualified")


class LocalDevAuthority:
    """Explicit injection of the runtime SDK's local-dev evidence helper only."""

    mode = "local_dev_untrusted"

    def __init__(self, signer, *, environment, enabled=False):
        if environment not in {"development", "test"} or not enabled:
            raise Rejected("Local development authority is disabled")
        self.signer = signer

    async def evidence(self, envelope):
        return self.signer(envelope)


class LocalDevResults:
    mode = "local_dev_untrusted"

    def __init__(self, *, environment, enabled=False):
        if environment not in {"development", "test"} or not enabled:
            raise Rejected("Untrusted integration results are disabled")

    async def verify(self, result, work):
        # Correlation is checked independently before this deliberately untrusted port.
        return None


def check_authority(environment, authority, result_verifier):
    if environment not in {"production", "development", "test"}:
        raise Rejected("Unknown environment")
    if environment == "production":
        from .native_results import NativeResultVerifier

        if isinstance(result_verifier, NativeResultVerifier):
            from .wallet_authority import WalletCallAuthority
            if type(authority) is not WalletCallAuthority:
                raise Rejected("Native local review requires pinned Wallet authority")
            # Inspect real sources, never mutable mode labels or qualification flags.
            authority.check_available()
            result_verifier.require_native_sources()
            return
    if environment == "production" and (
        authority.mode != "secs_verified" or result_verifier.mode != "secs_verified"
    ):
        raise Rejected(
            "Production requires qualified native secS authority and result verification"
        )
