from __future__ import annotations
import argparse
import asyncio
import json
from importlib.resources import files
from pathlib import Path
import httpx
from .authority import DenyAuthority, DenyResults, LocalDevAuthority, LocalDevResults
from .bootstrap import configured_registry
from .executor import Executor
from .journal import Journal
from .model import Binding, Rejected, UnknownOutcome, decode_json
from .runtime import ContractValidator, GeneratedClientAdapter, RuntimeGateway


async def run(args):
    config = decode_json(Path(args.config).read_bytes())
    if (
        set(config)
        != {
            "schema",
            "environment",
            "runtime_endpoint",
            "journal",
            "allow_local_dev_untrusted",
            "integrations",
        }
        or config["schema"] != "frank.config.v1"
    ):
        raise Rejected("Unsupported Frank configuration")
    environment = config["environment"]
    if environment not in {"production", "development", "test"}:
        raise Rejected("Unknown environment")
    if type(config["allow_local_dev_untrusted"]) is not bool:
        raise Rejected("Local-dev opt-in must be boolean")
    if environment == "production" and config["allow_local_dev_untrusted"]:
        raise Rejected("Local development authority is prohibited in production")
    async with httpx.AsyncClient() as http:
        registry = configured_registry(
            config["integrations"], http_client=http, environment=environment
        )
        if args.action == "check-config":
            return {
                "configuration": "valid",
                "authority": "local_dev_untrusted"
                if config["allow_local_dev_untrusted"]
                else "adapter_required",
                "actor_count": len(registry.actors),
            }
        if args.action == "health":
            await registry.connect()
            try:
                return {
                    "live": True,
                    "configuration": "valid",
                    "adapter_ready": True,
                    "ready": bool(
                        config["allow_local_dev_untrusted"]
                        and environment in {"development", "test"}
                    ),
                    "authority": "local_dev_untrusted"
                    if config["allow_local_dev_untrusted"]
                    else "adapter_required",
                    "integrations": [
                        await adapter.health() for adapter in registry.adapters.values()
                    ],
                }
            finally:
                await registry.close()
        journal = Journal(config["journal"])
        if args.action == "inspect":
            return {
                "deliveries": journal.unresolved(),
                "pending_commands": journal.pending_commands(),
            }
        from process_runtime_client import RuntimeClient, LocalDevAuthority as SDKLocalDevAuthority

        authority = DenyAuthority()
        results = DenyResults()
        if config["allow_local_dev_untrusted"]:
            signer = SDKLocalDevAuthority(environment=environment)
            authority = LocalDevAuthority(
                lambda raw: signer(json.loads(raw)), environment=environment, enabled=True
            )
            results = LocalDevResults(environment=environment, enabled=True)
        schema = json.loads(
            files("process_runtime_client").joinpath("runtime-v1.schema.json").read_text()
        )
        gateway = RuntimeGateway(
            GeneratedClientAdapter(RuntimeClient(config["runtime_endpoint"])),
            authority,
            journal,
            ContractValidator(schema),
        )
        executor = Executor(gateway, registry, journal, results, environment=environment)
        await registry.connect()
        try:
            if args.action == "register":
                return await executor.register(args.actor)
            if args.action == "work":
                return await executor.work(args.actor)
            if args.action == "reconcile-command":
                return await gateway.replay(args.request_id)
            if args.action == "receive":
                return {"receipts": await executor.receive(args.integration)}
            if args.action == "execute":
                work = (await executor.work(args.actor, limit=100))["work"]
                selected = next(
                    (
                        item
                        for item in work
                        if item["run_id"] == args.run_id and item["step_id"] == args.step_id
                    ),
                    None,
                )
                if selected is None:
                    raise Rejected("Selected work is not eligible in the runtime result")
                attempt = await executor.claim(
                    args.actor, selected, lease_ms=args.lease_ms, request_id=args.request_id
                )
                return await executor.run(
                    attempt,
                    operation=args.operation,
                    scope=args.scope,
                    lease_ms=args.lease_ms,
                    wait_seconds=args.wait_seconds,
                )
            if args.action in {"resume", "heartbeat", "release", "fail"}:
                saved = journal.get(args.effect_key)
                if saved["state"] in {"committed", "failed_committed"}:
                    return {"effect_key": args.effect_key, "state": saved["state"]}
                if args.action == "resume":
                    try:
                        failure = journal.saved_command(args.effect_key + "-fail")
                    except Rejected:
                        failure = None
                    if failure is not None:
                        return await executor.reconcile_failure(args.effect_key)
                    try:
                        completion = journal.saved_command(args.effect_key + "-complete")
                    except Rejected:
                        completion = None
                    if completion is not None:
                        return await executor.reconcile_completion(args.effect_key)
                attempt = await executor.recover(
                    Binding.read(saved["work"]["binding"]), saved["work"]["actor_id"]
                )
                if args.action == "heartbeat":
                    await executor.heartbeat(attempt, lease_ms=args.lease_ms)
                    return {
                        "binding": attempt.binding.json(),
                        "lease_expires_at_ms": attempt.lease_expires_at_ms,
                        "step_version": attempt.step_version,
                    }
                if args.action == "release":
                    return await executor.release(attempt, args.reason)
                if args.action == "fail":
                    if saved["state"] == "failed":
                        return await executor.fail_delivery(attempt, args.effect_key, args.reason)
                    return await executor.fail(attempt, args.reason)
                return await executor.run(
                    attempt,
                    operation=saved["work"]["operation"],
                    scope=saved["work"]["scope"],
                    lease_ms=args.lease_ms,
                    wait_seconds=args.wait_seconds,
                    resume=True,
                )
            raise Rejected("Unsupported action")
        finally:
            await registry.close()


def main():
    parser = argparse.ArgumentParser(
        description="Frank executor: explicit, bounded operations; runtime owns scheduling"
    )
    parser.add_argument(
        "action",
        choices=(
            "check-config",
            "health",
            "inspect",
            "register",
            "work",
            "execute",
            "resume",
            "heartbeat",
            "release",
            "fail",
            "receive",
            "reconcile-command",
        ),
    )
    parser.add_argument("--config", required=True)
    parser.add_argument("--actor")
    parser.add_argument("--run-id")
    parser.add_argument("--step-id")
    parser.add_argument("--operation")
    parser.add_argument("--scope")
    parser.add_argument("--effect-key")
    parser.add_argument("--request-id")
    parser.add_argument("--integration")
    parser.add_argument("--reason")
    parser.add_argument("--lease-ms", type=int, default=120000)
    parser.add_argument("--wait-seconds", type=float, default=60)
    args = parser.parse_args()
    if args.action == "execute" and not all(
        (args.actor, args.run_id, args.step_id, args.operation, args.scope)
    ):
        parser.error("execute requires --actor, --run-id, --step-id, --operation and --scope")
    if args.action in {"resume", "heartbeat", "release", "fail"} and not args.effect_key:
        parser.error("--effect-key is required")
    if args.action in {"release", "fail"} and not args.reason:
        parser.error("--reason is required")
    if args.action == "reconcile-command" and not args.request_id:
        parser.error("--request-id is required")
    if args.action == "receive" and not args.integration:
        parser.error("--integration is required")
    if not 1000 <= args.lease_ms <= 3600000 or not 0 < args.wait_seconds <= 3600:
        parser.error("lease or wait budget exceeds bounds")
    if args.action in {"register", "work"} and not args.actor:
        parser.error("--actor is required")
    try:
        result = asyncio.run(run(args))
    except Rejected as exc:
        parser.exit(2, str(exc) + "\n")
    except UnknownOutcome as exc:
        parser.exit(3, str(exc) + "\n")
    except (KeyError, TypeError, OSError, ValueError):
        parser.exit(2, "Configuration or local evidence is unavailable or malformed\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
