"""First production Hermes provider entrypoint; Runtime owns all eligibility."""
from __future__ import annotations

import argparse
import asyncio
import json

from .live_provider_profile import load_profile, compose
from .model import Binding, Rejected, UnknownOutcome

BRAND_SCOPE = "zenith.anima.brand-package"


async def run(args):
    try:
        async with asyncio.timeout(args.wait_seconds):
            return await _run(args)
    except TimeoutError:
        raise UnknownOutcome("Live-provider deadline expired; inspect retained state") from None


async def _run(args):
    profile = await asyncio.to_thread(load_profile, args.config, args.config_sha256)
    actor = profile.actor
    if args.action in {"check-config", "health"}:
        await asyncio.to_thread(profile.native_sources)
        return {"configuration":"valid", "provider":"openai-codex", "model":"gpt-5.6-sol",
                "native_artifacts_available":True, "runtime_checked":False,
                "authorization":"checked per request", "tools":[]}
    if args.action == "execute" and (args.run_id not in profile.composition["run_ids"]
            or args.operation != "compute" or args.scope != BRAND_SCOPE):
        raise Rejected("Execution is outside selected live-provider scope")
    executor = adapter = None
    try:
        executor, adapter = compose(profile); journal = executor.journal
        await executor.registry.connect()
        if args.action == "register":
            result = await executor.register(actor["actor_id"])
        elif args.action == "work":
            result = await executor.work(actor["actor_id"], limit=100)
            result = {**result, "work":[w for w in result["work"] if w["run_id"] in profile.composition["run_ids"]]}
        elif args.action == "execute":
            work = (await executor.work(actor["actor_id"], limit=100))["work"]
            selected = next((w for w in work if w["run_id"] == args.run_id and w["step_id"] == args.step_id), None)
            if selected is None: raise Rejected("Selected step is not currently eligible")
            attempt = await executor.claim(actor["actor_id"], selected, lease_ms=args.lease_ms,
                                           request_id=args.request_id)
            result = await executor.run(attempt, operation="compute", scope=args.scope,
                                        lease_ms=args.lease_ms, wait_seconds=args.wait_seconds)
        elif args.action in {"resume", "renew"}:
            saved = journal.get(args.effect_key); work = saved["work"]
            if (work["actor_id"] != actor["actor_id"] or work["integration_id"] != actor["integration_id"]
                    or work["route"] != actor["route"] or work["binding"]["run_id"] not in profile.composition["run_ids"]):
                raise Rejected("Retained effect is outside selected provider scope")
            if saved["state"] in {"committed", "failed_committed"}:
                return {"effect_key":args.effect_key, "state":saved["state"]}
            attempt = await executor.recover(Binding.read(work["binding"]), actor["actor_id"])
            if args.action == "renew":
                proved = await adapter.connector_producer.renew(work)
                await executor.observe(attempt, args.effect_key, proved)
            result = await executor.run(attempt, operation="compute", scope=work["scope"],
                                        lease_ms=args.lease_ms, wait_seconds=args.wait_seconds, resume=True)
        else:
            raise Rejected("Unsupported live-provider action")
        await asyncio.to_thread(profile.current); return result
    finally:
        if executor is not None:
            await executor.registry.close()
            await executor.gateway.authority.aclose()
            await executor.result_verifier.aclose()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check-config", "health", "register", "work", "execute", "resume", "renew"))
    parser.add_argument("--config", required=True); parser.add_argument("--config-sha256", required=True)
    for name in ("run-id", "step-id", "operation", "scope", "effect-key", "request-id"):
        parser.add_argument("--" + name)
    parser.add_argument("--lease-ms", type=int, default=120000); parser.add_argument("--wait-seconds", type=float, default=600)
    args = parser.parse_args()
    if args.action == "execute" and not all((args.run_id,args.step_id,args.operation,args.scope)):
        parser.error("execute requires --run-id, --step-id, --operation and --scope")
    if args.action in {"resume","renew"} and not args.effect_key: parser.error("--effect-key is required")
    try: result = asyncio.run(run(args))
    except UnknownOutcome: parser.exit(3, "Live-provider outcome unknown; use exact reconciliation\n")
    except (Rejected,OSError,ValueError,TypeError,KeyError): parser.exit(2, "Live-provider configuration or current authority unavailable\n")
    print(json.dumps(result,sort_keys=True))


if __name__ == "__main__": main()
