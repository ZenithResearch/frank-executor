"""Finite operator approval boundary for the first brand-package workflow."""
from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit

from .model import Rejected, UnknownOutcome, canonical, decode_json, digest, identity
from .wallet_authority import WalletCallAuthority, _pinned_file


ACTOR_ID = "zenith-brand-reviewer"
STEP_ID = "human-approval"
CAPABILITIES = ["brand.review.human"]
RESOURCES = ["brand.human-review", "brand.workspace"]
MAX_RECORD_BYTES = 1024 * 1024


def pin(value):
    if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise Rejected("Exact SHA256 required")
    return value


def path(value):
    result = Path(value)
    if type(value) is not str or not result.is_absolute() or ".." in result.parts:
        raise Rejected("Absolute approval path required")
    return result


def closed(value, fields):
    if type(value) is not dict or set(value) != set(fields):
        raise Rejected("Unsupported approval shape")
    return value


def load_config(selected, expected):
    selected = path(selected)
    raw = _pinned_file(selected, pin(expected), 65_536)
    value = closed(decode_json(raw), ("schema", "runtime_endpoint", "run_id", "wallet"))
    if value["schema"] != "frank.brand-approval.config.v1":
        raise Rejected("Unsupported approval configuration")
    endpoint = urlsplit(value["runtime_endpoint"])
    if (endpoint.scheme != "http" or endpoint.hostname != "127.0.0.1" or endpoint.port is None
            or endpoint.username is not None or endpoint.password is not None
            or endpoint.query or endpoint.fragment or endpoint.path not in ("", "/")):
        raise Rejected("Approval requires numeric-loopback Runtime")
    identity(value["run_id"])
    wallet = closed(value["wallet"], ("executable", "executable_sha256", "configuration", "configuration_sha256"))
    for name in ("executable", "configuration"):
        path(wallet[name])
    for name in ("executable_sha256", "configuration_sha256"):
        pin(wallet[name])
    return value, WalletCallAuthority(**wallet)


async def call(client, authority, operation, payload, expected_version, request_id):
    from process_runtime_client import RuntimeClientError, command_envelope

    envelope = command_envelope(operation, request_id=request_id,
                                expected_version=expected_version, payload=payload)
    evidence = await authority.evidence(canonical(envelope))
    try:
        result = await asyncio.to_thread(client.execute, envelope, evidence=evidence)
    except RuntimeClientError as exc:
        if exc.uncertain:
            raise UnknownOutcome("Approval outcome unknown; retry the exact reviewed file") from None
        raise Rejected("Runtime rejected the approval command") from None
    if result.get("schema") != "runtime.result.v1":
        raise Rejected("Runtime approval result schema mismatch")
    if any(result.get(field) != envelope[field] for field in ("request_id", "operation", "resource")):
        raise Rejected("Runtime approval result correlation mismatch")
    return result


async def query(client, authority, operation, payload):
    from process_runtime_client import RuntimeClientError

    envelope = {"schema": "runtime.query.v1", "operation": operation, "payload": payload}
    evidence = await authority.evidence(canonical(envelope))
    try:
        result = await asyncio.to_thread(client.query, envelope, evidence=evidence)
    except RuntimeClientError:
        raise Rejected("Runtime rejected the approval query") from None
    if result.get("schema") != "runtime.query-result.v1" or result.get("operation") != operation:
        raise Rejected("Runtime approval query correlation mismatch")
    return result["data"]


def decision(selected, expected, run_id):
    raw = _pinned_file(path(selected), pin(expected), MAX_RECORD_BYTES + 65_536)
    value = closed(decode_json(raw), ("schema", "run_id", "claim", "approved", "approval_record",
                                           "reason", "artifact_request_id", "terminal_request_id"))
    if value["schema"] != "frank.brand-approval-decision.v1" or value["run_id"] != run_id:
        raise Rejected("Approval decision selects another Run")
    claim = closed(value["claim"], ("run_id", "step_id", "attempt_id", "fence", "step_version", "input_digest"))
    if claim["run_id"] != run_id or claim["step_id"] != STEP_ID:
        raise Rejected("Approval decision selects another Attempt")
    identity(claim["attempt_id"])
    if any(type(claim[name]) is not int or claim[name] < 1 for name in ("fence", "step_version")):
        raise Rejected("Invalid approval fence or version")
    pin(claim["input_digest"])
    for name in ("artifact_request_id", "terminal_request_id"):
        identity(value[name])
    if type(value["approved"]) is not bool or type(value["reason"]) is not str or not value["reason"]:
        raise Rejected("Explicit approval decision and reason required")
    if value["approved"]:
        record = closed(value["approval_record"], ("content_utf8", "media_type"))
        if (type(record["content_utf8"]) is not str or record["media_type"] != "text/markdown"
                or not 0 < len(record["content_utf8"].encode()) <= MAX_RECORD_BYTES):
            raise Rejected("Bounded Markdown approval record required")
    elif value["approval_record"] is not None:
        raise Rejected("Rejected direction cannot carry an approval artifact")
    return value


async def run(args):
    config, authority = await asyncio.to_thread(load_config, args.config, args.config_sha256)
    from process_runtime_client import RuntimeClient
    client = RuntimeClient(config["runtime_endpoint"])
    run_id = config["run_id"]
    try:
        if args.action == "register":
            result = await call(client, authority, "actor.register", {
                "actor_id": ACTOR_ID, "capabilities": CAPABILITIES, "resources": RESOURCES,
            }, None, "brand-reviewer-" + digest({"run_id": run_id})[:48])
        elif args.action == "work":
            page = await query(client, authority, "work.list", {"actor_id": ACTOR_ID, "limit": 100})
            result = {**page, "work": [row for row in page["work"]
                                       if row["run_id"] == run_id and row["step_id"] == STEP_ID]}
        elif args.action == "claim":
            page = await query(client, authority, "work.list", {"actor_id": ACTOR_ID, "limit": 100})
            selected = next((row for row in page["work"]
                             if row["run_id"] == run_id and row["step_id"] == STEP_ID), None)
            if selected is None:
                raise Rejected("Human approval is not currently eligible")
            response = await call(client, authority, "executor.claim", {
                "run_id": run_id, "step_id": STEP_ID, "actor_id": ACTOR_ID, "lease_ms": 300_000,
            }, selected["version"], args.request_id)
            claim = response["result"]
            result = {"schema": "frank.brand-approval-claim.v1",
                      **{name: claim[name] for name in ("run_id", "step_id", "attempt_id", "fence",
                                                        "step_version", "lease_expires_at_ms", "input_digest", "inputs")}}
        else:
            value = await asyncio.to_thread(decision, args.decision, args.decision_sha256, run_id)
            claim = value["claim"]
            current = await query(client, authority, "attempt.get", {
                "run_id": run_id, "step_id": STEP_ID, "attempt_id": claim["attempt_id"],
            })
            if any(current.get(name) != claim[name] for name in ("run_id", "step_id", "attempt_id", "fence",
                                                                   "input_digest", "step_version")):
                raise Rejected("Approval decision differs from the current claimed inputs")
            binding = {name: claim[name] for name in ("run_id", "step_id", "attempt_id", "fence")}
            if value["approved"]:
                raw = value["approval_record"]["content_utf8"].encode()
                reference = {"content_hash": hashlib.sha256(raw).hexdigest(), "byte_length": len(raw),
                             "media_type": "text/markdown"}
                await call(client, authority, "artifact.put", {
                    "artifact": reference, "content_base64": base64.b64encode(raw).decode(),
                }, None, value["artifact_request_id"])
                response = await call(client, authority, "executor.complete", {
                    **binding, "outputs": {"approval_record": reference, "approved": True},
                }, claim["step_version"], value["terminal_request_id"])
            else:
                response = await call(client, authority, "executor.fail", {
                    **binding, "reason": value["reason"], "retryable": False,
                }, claim["step_version"], value["terminal_request_id"])
            result = {"schema": "frank.brand-approval-result.v1", "approved": value["approved"],
                      "decision_sha256": args.decision_sha256, "runtime": response}
        return result
    finally:
        await authority.aclose()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("register", "work", "claim", "decide"))
    parser.add_argument("--config", required=True)
    parser.add_argument("--config-sha256", required=True)
    parser.add_argument("--request-id")
    parser.add_argument("--decision")
    parser.add_argument("--decision-sha256")
    args = parser.parse_args()
    if args.action == "claim" and not args.request_id:
        parser.error("claim requires --request-id")
    if args.action == "decide" and not (args.decision and args.decision_sha256):
        parser.error("decide requires --decision and --decision-sha256")
    try:
        result = asyncio.run(run(args))
    except UnknownOutcome:
        parser.exit(3, "Brand approval outcome unknown; retry exact request identities\n")
    except (Rejected, OSError, ValueError, TypeError, KeyError):
        parser.exit(2, "Brand approval configuration or current authority unavailable\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
