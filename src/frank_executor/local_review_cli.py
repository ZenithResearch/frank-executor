"""Installed native local-review entrypoint; Runtime alone supplies eligibility."""
from __future__ import annotations

import argparse
import asyncio
import json
import sys

from .local_review_profile import load_profile, compose
from frank_review_adapter.local_capture import OPERATIONS
from .model import Binding, Rejected, UnknownOutcome
from .local_review_cleanup import CleanupUnresolved, Operation, marker_status
from .local_review_workflow import (load_workflow, initialize, next_step, inspect_workflow,
                                    export_workflow, recovery_selection)


async def run(args):
    try:
        async with asyncio.timeout(args.wait_seconds):
            return await _run(args)
    except TimeoutError:
        raise UnknownOutcome("Local-review action deadline expired; inspect retained state") from None


async def _run(args):
    profile = await asyncio.to_thread(load_profile, args.config, args.config_sha256)
    value = profile.composition
    actor = value["actor"]
    if args.action in {"check-config", "health"}:
        # No Journal/capture initialization, authority process or network request.
        await asyncio.to_thread(profile.native_sources)
        return {"configuration":"valid", "native_artifacts_available":True,
                "current_result_policy_valid":True, "runtime_checked":False,
                "authorization":"checked per request", "external_effects":"disabled",
                "cleanup_state":await asyncio.to_thread(marker_status,profile)}
    workflow = (await asyncio.to_thread(load_workflow,profile,args.workflow,args.workflow_sha256)
                if args.workflow else None)
    if args.action == "execute" and (args.run_id not in value["run_ids"]
            or args.operation not in OPERATIONS or args.operation not in actor["capabilities"]):
        raise Rejected("Execution is outside selected local-review scope")
    operation = Operation(profile,args.action)
    executor = adapter = None
    try:
        executor, adapter = compose(profile)
        gateway, journal, registry = executor.gateway, executor.journal, executor.registry
        await registry.connect()
        if args.action == "initialize":
            result = await initialize(workflow,executor)
        elif args.action == "next":
            result = await next_step(workflow,executor,lease_ms=args.lease_ms,wait_seconds=args.wait_seconds)
        elif args.action == "inspect":
            result = await inspect_workflow(workflow,executor)
        elif args.action == "export":
            result = await export_workflow(workflow,executor)
        elif args.action == "register":
            result = await executor.register(actor["actor_id"])
        elif args.action == "work":
            result = await executor.work(actor["actor_id"], limit=100)
            result = {**result, "work":[w for w in result["work"] if w["run_id"] in value["run_ids"]]}
        elif args.action == "reconcile-command":
            saved = journal.saved_command(args.request_id)
            command = json.loads(saved["body"])
            selected_run = command["payload"].get("run_id")
            if selected_run is not None and selected_run not in value["run_ids"]:
                raise Rejected("Saved command is outside selected runs")
            # Terminal native results require their durable verifier/guard path.
            if command["operation"] in {"executor.complete", "executor.fail", "executor.effect.observe"}:
                raise Rejected("Use effect resume for guarded terminal recovery")
            result = await gateway.replay(args.request_id)
        elif args.action == "execute":
            work = (await executor.work(actor["actor_id"], limit=100))["work"]
            selected = next((w for w in work if w["run_id"] == args.run_id and w["step_id"] == args.step_id), None)
            if selected is None:
                raise Rejected("Selected step is not currently eligible")
            attempt = await executor.claim(actor["actor_id"], selected,
                lease_ms=args.lease_ms, request_id=args.request_id)
            result = await executor.run(attempt, operation=args.operation, scope=args.scope,
                lease_ms=args.lease_ms, wait_seconds=args.wait_seconds)
        elif args.action in {"resume", "renew"}:
            key = args.effect_key
            selected = (recovery_selection(workflow,journal,renewal=args.action == "renew")
                        if key is None else {"kind":"effect","effect_key":key})
            if selected["kind"] == "command":
                result = await gateway.replay(selected["request_id"])
            else:
                if workflow is not None and journal.get(selected["effect_key"])["work"]["binding"]["run_id"] != workflow.value["run_id"]:
                    raise Rejected("Retained effect is outside the selected workflow")
                result = await resume_effect(executor,adapter,profile,selected["effect_key"],
                    renewal=args.action == "renew",lease_ms=args.lease_ms,wait_seconds=args.wait_seconds)
        else:
            raise Rejected("Unsupported local-review action")
        await asyncio.to_thread(workflow.current if workflow is not None else profile.current)
        return result
    finally:
        prior_error = sys.exc_info()[0] is not None
        close_error = False
        wallet = result_transport = verifier = None
        if executor is not None:
            wallet = executor.gateway.authority
            verifier = getattr(executor,"result_verifier",None)
            result_transport = (adapter._local_producer.transport
                                if adapter is not None and adapter._local_producer is not None else None)
            for close in (executor.registry.close,wallet.aclose,
                          getattr(verifier,"aclose",None)):
                if close is None:
                    continue
                try:
                    await close()
                except BaseException:
                    close_error = True
        operation.finish(wallet=wallet,result=result_transport,verifier=verifier)
        if close_error and not prior_error:
            raise Rejected("Local-review transport close failed after ownership resolved")


async def resume_effect(executor,adapter,profile,key,*,renewal,lease_ms,wait_seconds):
    journal, actor = executor.journal, profile.composition["actor"]
    saved = journal.get(key)
    work = saved["work"]
    if (work["actor_id"] != actor["actor_id"] or work["integration_id"] != actor["integration_id"]
            or work["route"] != actor["route"] or work["binding"]["run_id"] not in profile.composition["run_ids"]
            or work["operation"] not in OPERATIONS or work["operation"] not in actor["capabilities"]):
        raise Rejected("Retained work is outside selected local-review scope")
    if saved["state"] in {"committed", "failed_committed"}:
        return {"effect_key":key,"state":saved["state"]}
    for suffix in ("-complete", "-fail"):
        try:
            journal.saved_command(key+suffix)
        except Rejected:
            continue
        return (await executor.reconcile_completion(key) if suffix == "-complete"
                else await executor.reconcile_failure(key))
    attempt = await executor.recover(Binding.read(work["binding"]),actor["actor_id"])
    if renewal:
        original = await asyncio.to_thread(adapter._local_capture.retained,work)
        if original is None:
            raise Rejected("Explicit renewal requires original computation")
        renewed = await adapter.renew_result(work,original["result"]["provider_reference"])
        await executor.observe(attempt,key,renewed)
    return await executor.run(attempt,operation=work["operation"],scope=work["scope"],
        lease_ms=lease_ms,wait_seconds=wait_seconds,resume=True)


def arguments(argv=None):
    parser = argparse.ArgumentParser(description="Bounded native local review; Runtime owns readiness")
    parser.add_argument("action", choices=("check-config", "health", "register", "work", "execute",
                                          "resume", "renew", "reconcile-command", "initialize", "next", "inspect", "export"))
    parser.add_argument("--config", required=True)
    parser.add_argument("--config-sha256", required=True)
    parser.add_argument("--workflow")
    parser.add_argument("--workflow-sha256")
    for name in ("run-id", "step-id", "operation", "scope", "effect-key", "request-id"):
        parser.add_argument("--" + name)
    parser.add_argument("--lease-ms", type=int, default=120000)
    parser.add_argument("--wait-seconds", type=float, default=60)
    args = parser.parse_args(argv)
    if args.action == "execute" and not all((args.run_id, args.step_id, args.operation, args.scope)):
        parser.error("execute requires --run-id, --step-id, --operation and --scope")
    if bool(args.workflow) != bool(args.workflow_sha256):
        parser.error("--workflow and --workflow-sha256 are required together")
    if args.action in {"initialize", "next", "inspect", "export"} and not args.workflow:
        parser.error("--workflow and --workflow-sha256 are required")
    if args.action in {"resume", "renew"} and not args.effect_key and not args.workflow:
        parser.error("--effect-key or a pinned workflow is required")
    if args.action == "reconcile-command" and not args.request_id:
        parser.error("--request-id is required")
    if not 1000 <= args.lease_ms <= 3600000 or not 0 < args.wait_seconds <= 3600:
        parser.error("lease or wait budget exceeds bounds")
    return parser, args


def main():
    parser, args = arguments()
    try:
        result = asyncio.run(run(args))
    except CleanupUnresolved:
        parser.exit(4, "Local-review cleanup state is retained; native actions are blocked\n")
    except UnknownOutcome:
        parser.exit(3, "Local-review outcome unknown; use exact reconciliation\n")
    except (Rejected, OSError, ValueError, TypeError, KeyError):
        parser.exit(2, "Native local-review configuration or current authority unavailable\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
