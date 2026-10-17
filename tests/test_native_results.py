from copy import deepcopy
from dataclasses import replace
import json
import pytest
from frank_executor.authority import check_authority
from frank_executor.model import Rejected, canonical, digest
from frank_executor.native_results import NativeResultAdmission, payload_for
from native_result_support import admitted, work_result
from conftest import arun


def test_payload_contains_complete_normalized_body_and_exact_work_digest():
    work, result = work_result()
    payload = json.loads(payload_for(result, work))
    assert payload == {
        "schema": "frank.native-result-payload.v1",
        "work_sha256": digest(work),
        "result": {k: v for k, v in result.items() if k != "proof"},
    }
    for field in [
        "event_id",
        "provider_reference",
        "outcome",
        "outputs",
        "binding",
        "actor_id",
        "integration_id",
        "route",
        "effect_id",
    ]:
        changed = deepcopy(result)
        changed[field] = "changed"
        assert canonical({k: v for k, v in changed.items() if k != "proof"}) != canonical(
            payload["result"]
        )


def test_native_token_is_exact_and_cannot_admit_altered_work_body_or_proof():
    token, verifier, helper, state, work, result = admitted()
    assert isinstance(token, NativeResultAdmission)
    assert token.identity == digest({k: v for k, v in result.items() if k != "proof"})
    token.revalidate(result, work)
    assert token.replay_key == ("synthetic-subject", "01" * 16, 200, "02" * 12)
    assert verifier.mode == "native_unqualified"
    for value in ["outputs", "event_id", "provider_reference", "proof"]:
        changed = deepcopy(result)
        changed[value] = {"answer": 99} if value == "outputs" else "changed"
        with pytest.raises(Rejected):
            token.revalidate(changed, work)
    changed = deepcopy(work)
    changed["inputs"] = {"number": 99}
    with pytest.raises(Rejected):
        token.revalidate(result, changed)


def test_current_clock_policy_key_bytes_and_helper_pin_are_rechecked():
    token, verifier, helper, state, work, result = admitted()
    state["now"] = 1060
    with pytest.raises(Rejected):
        token.revalidate(result, work)
    state["now"] = 1001
    state["policy"] = replace(
        state["policy"], keys=(replace(state["policy"].keys[0], public_key_hex="b" * 64),)
    )
    with pytest.raises(Rejected):
        token.revalidate(result, work)
    token, verifier, helper, state, work, result = admitted()
    helper.available = False
    with pytest.raises(Rejected):
        token.revalidate(result, work)


@pytest.mark.parametrize(
    "field,value",
    [
        ("audience", "runtime://receiver-local"),
        ("operation", "runtime.run.get.v1"),
        ("resource", "runs/other"),
        ("opcode", True),
        ("descriptor_fingerprint", "b" * 64),
        ("handler_id", "runtime-v1"),
        ("schema_version", 3),
        ("replay_scope", ""),
        ("nonce", [1] * 11),
        ("issued_at", 1002),
        ("expires_at", 1001),
        ("expires_at", 1061),
    ],
)
def test_result_namespace_descriptor_replay_and_lifetime_are_closed(field, value):
    token, verifier, helper, state, work, result = admitted()
    helper.context[field] = value
    with pytest.raises(Rejected):
        arun(verifier.verify(result, work))


def test_deny_mapping_revocation_and_unknown_outcomes_cannot_authorize():
    token, verifier, helper, state, work, result = admitted()
    allow = state["policy"]
    for policy in [
        replace(allow, rules=()),
        replace(allow, rules=(*allow.rules, replace(allow.rules[0], effect="deny"))),
        replace(allow, revoked_subject_keys=frozenset({("synthetic-subject", "synthetic-holder")})),
        replace(allow, subjects=(replace(allow.subjects[0], route="elsewhere"),)),
    ]:
        state["policy"] = policy
        with pytest.raises(Rejected):
            arun(verifier.verify(result, work))
    state["policy"] = allow
    result["outcome"] = "unknown"
    result["outputs"] = {}
    with pytest.raises(Rejected):
        arun(verifier.verify(result, work))


def test_library_cannot_admit_production_without_qualified_chain():
    token, verifier, helper, state, work, result = admitted()

    class NativeCommand:
        mode = "secs_verified"

    with pytest.raises(Rejected):
        check_authority("production", NativeCommand(), verifier)


def test_closed_private_file_policy_reload_and_operator_controls(tmp_path):
    from frank_executor.native_results import FileReceiverPolicy
    from native_result_support import policy

    path = tmp_path / "policy.json"
    path.write_bytes(canonical(policy().snapshot()))
    path.chmod(0o600)
    loader = FileReceiverPolicy(path)
    assert loader() == policy()
    value = policy().snapshot()
    value["rules"] = []
    path.write_bytes(canonical(value))
    assert loader().rules == ()
    for changed in [
        {**value, "private_seed": "never-read"},
        {**value, "operation": "runtime.run.get.v1"},
        {**value, "audience": "service://receiver-local"},
    ]:
        path.write_bytes(canonical(changed))
        with pytest.raises(Rejected):
            loader()
    path.write_bytes(canonical(policy().snapshot()))
    path.chmod(0o644)
    with pytest.raises(Rejected):
        loader()
    path.chmod(0o600)
    alias = tmp_path / "alias.json"
    alias.symlink_to(path)
    with pytest.raises(Rejected):
        FileReceiverPolicy(alias)()
    path.write_text('{"schema":"x","schema":"y"}')
    with pytest.raises(Rejected):
        loader()


def test_helper_delay_reload_and_async_heartbeat_are_not_silently_bypassed():
    import asyncio
    import time
    from frank_executor.native_results import NativeResultVerifier
    from native_result_support import SyntheticHelper, policy

    work, result = work_result()
    state = {"now": 1001, "policy": policy()}
    helper = SyntheticHelper(work, result)
    original = helper.verify

    def delayed(value):
        time.sleep(0.04)
        return original(value)

    helper.verify = delayed
    verifier = NativeResultVerifier(helper, lambda: state["policy"], clock=lambda: state["now"])

    async def run():
        task = asyncio.create_task(verifier.verify(result, work))
        await asyncio.sleep(0.005)
        assert not task.done()
        state["now"] = 1060
        with pytest.raises(Rejected):
            await task

    arun(run())
    state["now"] = 1001

    def changed(value):
        state["policy"] = replace(state["policy"], rules=())
        return original(value)

    helper.verify = changed
    with pytest.raises(Rejected):
        arun(verifier.verify(result, work))


def test_final_policy_loader_delay_cannot_cross_expiry():
    token, verifier, helper, state, work, result = admitted()
    count = 0

    def delayed():
        nonlocal count
        count += 1
        if count == 2:
            state["now"] = 1060
        return state["policy"]

    object.__setattr__(token, "_load_policy", delayed)
    with pytest.raises(Rejected):
        token.revalidate(result, work)


def test_mode_label_cannot_qualify_builtin_native_verifier():
    token, verifier, helper, state, work, result = admitted()
    verifier.mode = "secs_verified"

    class NativeCommand:
        mode = "secs_verified"

    with pytest.raises(Rejected):
        check_authority("production", NativeCommand(), verifier)
