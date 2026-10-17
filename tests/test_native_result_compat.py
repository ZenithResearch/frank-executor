"""Actual native signature compatibility. Historical synthetic scope only."""

from copy import deepcopy
from dataclasses import replace
import hashlib
import os
import json
from pathlib import Path
import shutil
import time
import pytest
from frank_executor.model import Rejected
from frank_executor.native_results import NativeResultVerifier, NativeSecSHelper
from native_result_support import policy
from conftest import arun

ROOT = Path(__file__).resolve().parents[1]
VECTORS = json.loads(
    (ROOT / "tests/fixtures/native-result-public/native-result-v1.json").read_text()
)
SOURCE = Path(os.environ.get("FRANK_NATIVE_VERIFIER", str(ROOT.parent / "process-runtime/native/secs-verifier/target/release/process-runtime-secs-verifier")))
HELPER_SHA256 = os.environ.get("FRANK_NATIVE_VERIFIER_SHA256", "b044785f3b9b45e9858ecee108a997d3c577a8262f4284e40e42e6b506b8e280")


@pytest.fixture
def native_helper(tmp_path):
    # Native test execution is mandatory for this gate slice; absence is a failure.
    assert SOURCE.is_file(), "Build the documented pinned native helper first"
    assert (
        hashlib.sha256(SOURCE.read_bytes()).hexdigest()
        == HELPER_SHA256
    ), "Reviewed helper artifact differs"
    binary = tmp_path / "native-verifier"
    shutil.copyfile(SOURCE, binary)
    binary.chmod(0o700)
    return NativeSecSHelper(binary, hashlib.sha256(binary.read_bytes()).hexdigest())


def fixture(name):
    return deepcopy(next(x for x in VECTORS["fixtures"] if x["name"] == name))


def native_verifier(helper, case, state=None):
    current = state or {
        "now": case["now_seconds"],
        "policy": replace(
            policy(), keys=(replace(policy().keys[0], public_key_hex=VECTORS["public_key_hex"]),)
        ),
    }
    return NativeResultVerifier(
        helper, lambda: current["policy"], clock=lambda: current["now"]
    ), current


@pytest.mark.parametrize("name", ["success", "renewed", "failed"])
def test_actual_native_crypto_frank_namespace_and_exact_result_bytes(native_helper, name):
    case = fixture(name)
    verifier, state = native_verifier(native_helper, case)
    token = arun(verifier.verify(case["result"], case["work"]))
    token.revalidate(case["result"], case["work"])
    assert token.identity
    for field in ["event_id", "provider_reference", "outputs"]:
        changed = deepcopy(case["result"])
        changed[field] = {"answer": 99} if field == "outputs" else "changed"
        with pytest.raises(Rejected):
            arun(verifier.verify(changed, case["work"]))


@pytest.mark.parametrize(
    "name", ["wrong-audience", "wrong-operation", "wrong-subject", "wrong-opcode"]
)
def test_actual_signed_wrong_scope_cannot_authorize(native_helper, name):
    case = fixture(name)
    verifier, state = native_verifier(native_helper, case)
    with pytest.raises(Rejected):
        arun(verifier.verify(case["result"], case["work"]))


def test_actual_tampered_native_bytes_and_exclusive_expiration(native_helper):
    case = fixture("success")
    verifier, state = native_verifier(native_helper, case)
    for field in ["packet_hex", "signed_context_hex"]:
        changed = deepcopy(case["result"])
        changed["proof"][field] += "00"
        with pytest.raises(Rejected):
            arun(verifier.verify(changed, case["work"]))
    state["now"] = 1060
    with pytest.raises(Rejected):
        arun(verifier.verify(case["result"], case["work"]))


def test_actual_helper_bounded_output_timeout_and_fixed_diagnostics(tmp_path):
    for body in ["head -c 200000 /dev/zero", "echo private-result >&2", "sleep 3"]:
        executable = tmp_path / "helper"
        executable.write_text("#!/bin/sh\n" + body + "\n")
        executable.chmod(0o700)
        helper = NativeSecSHelper(
            executable, hashlib.sha256(executable.read_bytes()).hexdigest(), timeout=0.1
        )
        begin = time.monotonic()
        with pytest.raises(Rejected, match="^Native result authority rejected$"):
            helper.verify({})
        assert time.monotonic() - begin < 1.5


def test_native_key_policy_and_helper_paths_fail_closed(native_helper, tmp_path):
    case = fixture("success")
    verifier, state = native_verifier(native_helper, case)
    for key in [
        replace(state["policy"].keys[0], status="revoked"),
        replace(state["policy"].keys[0], production_authority=False),
        replace(state["policy"].keys[0], not_after=1001),
    ]:
        state["policy"] = replace(state["policy"], keys=(key,))
        with pytest.raises(Rejected):
            arun(verifier.verify(case["result"], case["work"]))
    link = tmp_path / "alias"
    link.symlink_to(native_helper.executable)
    with pytest.raises(Rejected):
        NativeSecSHelper(link, native_helper.sha256).verify({})
    native_helper.executable.write_bytes(b"changed")
    with pytest.raises(Rejected):
        native_helper.verify({})


def test_public_native_profile_matches_exact_result_and_proof_boundaries():
    from jsonschema import Draft202012Validator
    from frank_executor.native_results import payload_for

    schema = json.loads((ROOT / "contracts/native-result-authority-v1.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    for name in ("success", "renewed", "failed"):
        case = fixture(name)
        payload = json.loads(payload_for(case["result"], case["work"]))
        validator.validate(payload)
        validator.validate(case["result"]["proof"])
        for field in ("event_id", "actor_id", "integration_id", "route", "effect_id"):
            changed = deepcopy(payload)
            changed["result"][field] += "\n"
            assert not validator.is_valid(changed), field
        for field in ("run_id", "step_id", "attempt_id"):
            changed = deepcopy(payload)
            changed["result"]["binding"][field] += "\n"
            assert not validator.is_valid(changed), field
        changed = deepcopy(payload)
        changed["result"]["proof"] = case["result"]["proof"]
        assert not validator.is_valid(changed)
        changed = deepcopy(case["result"]["proof"])
        changed["packet_hex"] += "\n"
        assert not validator.is_valid(changed)
        changed = deepcopy(case["result"]["proof"])
        changed["audience"] = "caller-selected"
        assert not validator.is_valid(changed)
    changed = json.loads(payload_for(fixture("failed")["result"], fixture("failed")["work"]))
    changed["result"]["outputs"] = {"answer": 1}
    assert not validator.is_valid(changed)
