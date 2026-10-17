"""Synthetic policy/port tests only. No native signature or custody claims."""

from copy import deepcopy
import hashlib
from frank_executor.model import Actor, Binding, work_packet, Rejected
from frank_executor.native_results import (
    Descriptor,
    NativeResultVerifier,
    PermissionRule,
    ReceiverPolicy,
    SubjectBinding,
    VerifierKey,
    payload_for,
)
from conftest import Adapter, arun


def work_result():
    work = work_packet(
        Binding("run", "step", "attempt", 1),
        Actor("worker", "fixture", ("compute",), (), "local"),
        effect_id="effect-1",
        operation="compute",
        scope="answer",
        inputs={"number": 7},
        output_types={"answer": {"kind": "integer"}},
    )
    result = Adapter().result(work)
    result["proof"] = {
        "schema": "frank.secs-result-envelope.v1",
        "packet_hex": "00",
        "signed_context_hex": "00",
    }
    return work, result


def policy():
    return ReceiverPolicy(
        (VerifierKey("synthetic-verifier", "a" * 64),),
        Descriptor(200, "a" * 64, "frank-result-test"),
        (SubjectBinding("synthetic-subject", "synthetic-holder", "worker", "fixture", "local"),),
        (
            PermissionRule(
                "synthetic-subject",
                "runs/run/steps/step/attempts/attempt/effects/effect-1",
                "allow",
                999000,
                1100000,
            ),
        ),
    )


class SyntheticHelper:
    def __init__(self, work, result):
        self.request_hex = payload_for(result, work).hex()
        self.available = True
        self.context = {
            "schema_version": 4,
            "context_id": "synthetic-context",
            "packet_hash": list(
                hashlib.sha256(bytes.fromhex(result["proof"]["packet_hex"])).digest()
            ),
            "subject": {"subject_id": "synthetic-subject", "key_id": "synthetic-holder"},
            "audience": "frank://result-receiver",
            "operation": "frank.result.attest.v1",
            "resource": "runs/run/steps/step/attempts/attempt/effects/effect-1",
            "descriptor_fingerprint": "a" * 64,
            "handler_id": "frank-result-test",
            "replay_scope": "session:opcode:nonce",
            "issued_at": 1000,
            "expires_at": 1060,
            "session_id": [1] * 16,
            "nonce": [2] * 12,
            "opcode": 200,
            "evidence_summary": [],
            "proof_metadata": None,
            "capability_result": "frank.result.attest",
            "credential_result": "synthetic-only",
        }

    def check_available(self):
        if not self.available:
            raise Rejected("Native result authority rejected")

    def verify(self, value):
        self.check_available()
        if value["request_hex"] != self.request_hex:
            raise Rejected("Native result authority rejected")
        return {
            "schema": "process-runtime.secs-check-output.v1",
            "context": deepcopy(self.context),
            "signer_key_id": "synthetic-verifier",
            "authenticator_kind": "ed25519_node_and_verifier",
        }


def admitted(work=None, result=None, *, state=None):
    if work is None:
        work, result = work_result()
    state = state or {"policy": policy(), "now": 1001.0}
    helper = SyntheticHelper(work, result)
    verifier = NativeResultVerifier(helper, lambda: state["policy"], clock=lambda: state["now"])
    return arun(verifier.verify(result, work)), verifier, helper, state, work, result
