from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from typing import Any

ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


class Rejected(ValueError):
    """Safe bounded diagnostics; never embed raw transport bodies or credentials."""


class UnknownOutcome(RuntimeError):
    pass


def canonical(value: Any) -> bytes:
    def check(item, depth=0):
        if depth > 64:
            raise Rejected("JSON nesting exceeds bound")
        if isinstance(item, dict):
            if any(not isinstance(key, str) for key in item):
                raise Rejected("JSON object keys must be strings")
            for child in item.values():
                check(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                check(child, depth + 1)
        elif item is not None and type(item) not in (str, int, float, bool):
            raise Rejected("Only JSON values are supported")

    check(value)
    try:
        data = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode()
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise Rejected("Invalid JSON value") from exc
    if len(data) > 1024 * 1024:
        raise Rejected("Envelope exceeds one MiB")
    return data


def decode_json(raw):
    if (
        not isinstance(raw, (str, bytes))
        or len(raw.encode() if isinstance(raw, str) else raw) > 1024 * 1024
    ):
        raise Rejected("JSON input exceeds bound")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise Rejected("Duplicate JSON field")
            result[key] = value
        return result

    def constant(_):
        raise Rejected("Non-finite JSON number")

    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError):
        raise Rejected("Malformed JSON input") from None
    canonical(value)
    return value


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def identity(value: Any) -> str:
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise Rejected("Invalid correlation identity")
    return value


@dataclass(frozen=True)
class Binding:
    run_id: str
    step_id: str
    attempt_id: str
    fence: int

    def __post_init__(self):
        for value in (self.run_id, self.step_id, self.attempt_id):
            identity(value)
        if type(self.fence) is not int or self.fence < 1:
            raise Rejected("Invalid fence")

    def json(self):
        return asdict(self)

    @classmethod
    def read(cls, value):
        if not isinstance(value, dict) or set(value) != {
            "run_id",
            "step_id",
            "attempt_id",
            "fence",
        }:
            raise Rejected("Invalid attempt binding")
        return cls(**value)


@dataclass(frozen=True)
class Actor:
    actor_id: str
    integration_id: str
    capabilities: tuple[str, ...]
    resources: tuple[str, ...]
    route: str

    def __post_init__(self):
        for item in (
            self.actor_id,
            self.integration_id,
            self.route,
            *self.capabilities,
            *self.resources,
        ):
            identity(item)

    def missing(self, capabilities, resources):
        return {
            "capabilities": sorted(set(capabilities) - set(self.capabilities)),
            "resources": sorted(set(resources) - set(self.resources)),
        }


def effect_name(operation: str, scope: str) -> str:
    identity(operation)
    if not isinstance(scope, str) or not scope or len(scope) > 4096:
        raise Rejected("Invalid effect scope")
    return (
        "dispatch-"
        + digest({"schema": "frank.effect-name.v1", "operation": operation, "scope": scope})[:48]
    )


def effect_key(binding: Binding, operation: str, scope: str) -> str:
    return (
        "delivery-"
        + digest(
            {
                "schema": "frank.effect-key.v1",
                **binding.json(),
                "effect_name": effect_name(operation, scope),
            }
        )[:48]
    )


def work_packet(binding, actor, *, effect_id, operation, scope, inputs, output_types):
    packet = {
        "schema": "frank.work.v1",
        "binding": binding.json(),
        "actor_id": actor.actor_id,
        "integration_id": actor.integration_id,
        "route": actor.route,
        "effect_id": identity(effect_id),
        "operation": identity(operation),
        "scope": scope,
        "inputs": inputs,
        "output_types": output_types,
    }
    return json.loads(canonical(packet))


def validate_result(result, packet):
    required = {
        "schema",
        "event_id",
        "binding",
        "actor_id",
        "integration_id",
        "route",
        "effect_id",
        "provider_reference",
        "outcome",
        "outputs",
    }
    if not isinstance(result, dict) or set(result) - required - {"proof"} or required - set(result):
        raise Rejected("Malformed integration result")
    if result["schema"] != "frank.result.v1" or result["outcome"] not in {
        "acknowledged",
        "succeeded",
        "failed",
        "unknown",
    }:
        raise Rejected("Unsupported integration result")
    Binding.read(result["binding"])
    for field in ("binding", "actor_id", "integration_id", "route", "effect_id"):
        if result[field] != packet[field]:
            raise Rejected("Result correlation mismatch")
    identity(result["event_id"])
    if (
        not isinstance(result["provider_reference"], str)
        or not result["provider_reference"]
        or len(result["provider_reference"]) > 4096
    ):
        raise Rejected("Missing provider reference")
    if not isinstance(result["outputs"], dict):
        raise Rejected("Outputs must be an object")
    if result["outcome"] != "succeeded" and result["outputs"]:
        raise Rejected("Only successful results can contain outputs")
    canonical(result)
    return result
