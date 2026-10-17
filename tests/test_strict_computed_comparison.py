"""Comparator-only expectations/mutations; no golden is supplied to a handler."""
from __future__ import annotations

import asyncio
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from frank_review_adapter.comparison import compare_computed, compare_expected_computed, validate_computed_report
from frank_review_adapter.verification import execute_case


FIXTURES = Path(__file__).parent / "fixtures/independent-review"
DEVELOPMENT = json.loads((FIXTURES / "development-sop-v1.json").read_text())
COMPILED = json.loads((FIXTURES / "development-sop-v1.compiled.json").read_text())
GOLDENS = json.loads((FIXTURES / "legacy-comparison.json").read_text())["scenarios"]
BEFORE = "def add(a, b):\n    return a - b\n"
AFTER = "def add(a, b):\n    return a + b\n"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def development_expectation():
    """Authored from the documented fixed fixture, not from running its handlers.

    This is a proposed comparator expectation for independent review. Its values
    do not come from runtime shadow artifacts, whose inputs/contents differ.
    """
    def artifact(value):
        content = value if isinstance(value, bytes) else canonical(value)
        return {"content_hash": hashlib.sha256(content).hexdigest(), "byte_length": len(content), "media_type": "application/json"}

    snapshot = artifact(b'{"calc.py":"def add(a, b):\\n    return a - b\\n"}')
    request = "Make add(a, b) return a + b."
    plan = artifact({"change_request": request, "source": snapshot,
                     "verification": ["integer addition cases", "public two-argument function contract"],
                     "qualification": "synthetic bounded fixture"})
    patch = artifact({"before": BEFORE, "after": AFTER, "path": "calc.py"})
    unit = artifact({"cases": [{"a": 2, "b": 3, "actual": 5, "expected": 5},
                               {"a": -3, "b": 3, "actual": 0, "expected": 0},
                               {"a": 0, "b": 4, "actual": 4, "expected": 4}],
                     "passed": True, "mode": "AST-whitelisted computation; no exec"})
    contract = artifact({"passed": True, "public_signature": "add(a, b)", "qualification": "synthetic fixture"})
    review = artifact({"approved": True, "unit": unit, "contract": contract,
                       "qualification": "automated synthetic fixture decision; no human review claim"})
    bundle = artifact({"patch": patch, "review": review, "external_effects": "disabled"})
    outputs = {"scope": {"plan": plan}, "implement": {"patch": patch},
               "unit-tests": {"passed": True, "report": unit}, "contract-tests": {"passed": True, "report": contract},
               "review": {"approved": True, "review": review}, "package": {"bundle": bundle}}
    return {"schema": "review.computed-expectation.v1", "provenance": {
        "basis": "Separately authored fixed development input, three integer sums, public signature, and documented artifact schemas/qualification labels; no candidate handler run.",
        "resource_sha256": "05449a8f1757b630cf08121b0849fb3c056932713218f0043747f3eaa62d078d",
        "semantic_approval": "pending root and independent source review; unrelated to 62 personal-review divergence decisions"},
        "expected": {"process_id": "development-sop-v1", "compilation_hash": digest(COMPILED),
            "root_inputs": {"change_request": request, "repository_snapshot": snapshot},
            "runnable_batches": [["scope"], ["implement"], ["contract-tests", "unit-tests"], ["review"], ["package"], []],
            "step_states": {name: "succeeded" for name in outputs}, "run_state": "succeeded",
            "steps": {name: {"outcome": "succeeded", "outputs": value} for name, value in outputs.items()}}}


def synthetic_observation(*, failed=False):
    """Public-report-shaped unit data, explicitly not claimed as runtime evidence."""
    expected = development_expectation()["expected"]
    pin = {"process_id": "development-sop-v1", "process_version": "strict-unit-version", "compilation_hash": digest(COMPILED)}
    specs = {step["step_id"]: step for step in COMPILED["steps"]}
    batches = expected["runnable_batches"] if not failed else [["scope"], ["implement"], ["contract-tests", "unit-tests"], []]
    report = {"observation_schema": "review.computed-observations.v1", "published_version": {"pin": pin, "compiled": deepcopy(COMPILED)},
              "pin": pin, "process_id": "development-sop-v1", "run_id": "strict-unit-run", "actor_id": "strict-unit-actor",
              "root_inputs": deepcopy(expected["root_inputs"]), "runnable_batches": deepcopy(batches),
              "run_state": "failed" if failed else "succeeded", "steps": []}
    rows = {}
    for index, name in enumerate(name for batch in batches for name in batch):
        spec = specs[name]
        inputs = {port: (report["root_inputs"][source["name"]] if source["source"] == "run_input"
                         else rows[source["step_id"]]["outputs"][source["name"]]) for port, source in spec["bindings"].items()}
        outcome = "failed" if failed and name == "contract-tests" else "succeeded"
        outputs = {} if outcome == "failed" else deepcopy(expected["steps"][name]["outputs"])
        binding = {"run_id": report["run_id"], "step_id": name, "attempt_id": "strict-unit-attempt-" + str(index), "fence": 1}
        receipt = {**binding, "schema": "runtime.receipt.v1", "receipt_id": "strict-unit-receipt-" + str(index),
                   "actor_id": report["actor_id"], "pin": pin, "input_digest": digest(inputs),
                   "outcome": outcome, "output_digest": None if outcome == "failed" else digest(outputs),
                   "started_at_ms": 1000 + index, "recorded_at_ms": 2000 + index, "signature": None}
        attempt = {**binding, "actor_id": report["actor_id"], "pin": pin, "inputs": deepcopy(inputs),
                   "input_digest": digest(inputs), "input_types": spec["inputs"], "output_types": spec["outputs"],
                   "current": True, "ordinal": 1, "state": outcome, "started_at_ms": receipt["started_at_ms"],
                   "span": {"actor_id": report["actor_id"], "fence": 1, "outcome": outcome,
                            "started_at_ms": receipt["started_at_ms"], "ended_at_ms": receipt["recorded_at_ms"]}}
        commit = None if outcome == "failed" else {**binding, "actor_id": report["actor_id"], "pin": pin,
                  "inputs_digest": digest(inputs), "receipt_id": receipt["receipt_id"], "outputs": deepcopy(outputs),
                  "output_types": spec["outputs"], "output_digest": digest(outputs), "committed_at_ms": receipt["recorded_at_ms"]}
        row = {"step_id": name, "binding": binding, "actor_id": report["actor_id"], "operation": spec["capabilities"][0],
               "inputs": deepcopy(inputs), "input_digest": digest(inputs), "outcome": outcome, "outputs": outputs,
               "attempt": attempt, "receipt": receipt, "receipt_digest": digest(receipt), "output_commit": commit,
               "output_query": {"operation": "output.get", "payload": {key: binding[key] for key in ("run_id", "step_id", "attempt_id")},
                                "code": "not_found" if outcome == "failed" else "ok"},
               "delivery_state": "failed_committed" if outcome == "failed" else "committed"}
        rows[name] = row
        report["steps"].append(row)
    report["step_states"] = {name: rows[name]["outcome"] if name in rows else "waiting" for name in specs}
    return report


def retained_development_shadow_structure(*, failed):
    """Projection of retained replay goldens; deliberately excludes their output hashes.

    development-success.golden.json SHA d80f1b33453d7843b01042f9a4ea4fb510126af7ce46059fadda11c94d30d8c1
    development-failure.golden.json SHA eb53b14c5fe43bd941e6af323016474d379b8ace08f3bac2a38c958988484b1a
    Their synthetic change request, repository and artifact bytes differ from the
    bounded AST example. Only this explicit structural projection is reused.
    """
    batches = [["scope"], ["implement"], ["contract-tests", "unit-tests"]]
    batches += [[]] if failed else [["review"], ["package"], []]
    states = {"scope": "succeeded", "implement": "succeeded", "unit-tests": "succeeded",
              "contract-tests": "failed" if failed else "succeeded",
              "review": "waiting" if failed else "succeeded", "package": "waiting" if failed else "succeeded"}
    return {"process_id": "development-sop-v1", "compilation_hash": "f0fff8e5f98ab2132632b1f810af130d6a0c2b8ad29e08d4d3bab769539ce711",
            "runnable_trace": [{"round": index, "runnable": batch} for index, batch in enumerate(batches)],
            "run_state": "failed" if failed else "succeeded", "final_step_states": states,
            "steps": [{"step_id": name, "outcome": state,
                       "receipt": {"outcome": state, **({"output_digest": None} if state == "failed" else {})}}
                      for name, state in states.items() if state != "waiting"]}


@pytest.mark.parametrize("failed", [False, True])
def test_complete_synthetic_public_chain_is_structurally_valid(failed):
    assert validate_computed_report(synthetic_observation(failed=failed)) == []
    assert validate_computed_report(synthetic_observation(failed=failed),
                                    expected_structure=retained_development_shadow_structure(failed=failed)) == []


@pytest.mark.parametrize("target,field", [
    (target, field) for target in ("receipt", "attempt", "output_commit")
    for field in ("run_id", "step_id", "attempt_id", "actor_id", "fence", "pin")
] + [("receipt", "input_digest"), ("receipt", "output_digest"), ("attempt", "input_digest"),
     ("output_commit", "inputs_digest"), ("output_commit", "output_digest"), ("output_commit", "receipt_id")])
def test_public_binding_mutations_remain_unclassified(target, field):
    report = synthetic_observation()
    row = report["steps"][0]
    row[target][field] = "changed"
    row["receipt_digest"] = digest(row["receipt"])
    assert validate_computed_report(report)


@pytest.mark.parametrize("mutation", ["duplicate", "missing", "batch", "root-input", "ancestor-input", "receipt-hash", "missing-attempt", "duplicate-receipt", "compiled", "pin"])
def test_identity_readiness_and_resolved_input_mutations_fail(mutation):
    report = synthetic_observation()
    if mutation == "duplicate":
        report["steps"][-1] = deepcopy(report["steps"][0])
        assert len(report["steps"]) == 6
    elif mutation == "missing":
        report["steps"].pop()
    elif mutation == "batch":
        report["runnable_batches"][0] = ["implement"]
    elif mutation == "root-input":
        report["root_inputs"]["change_request"] = "changed"
    elif mutation == "ancestor-input":
        row = next(item for item in report["steps"] if item["step_id"] == "unit-tests")
        row["inputs"]["patch"] = {"content_hash": "0" * 64, "byte_length": 1, "media_type": "text/plain"}
    elif mutation == "receipt-hash":
        report["steps"][0]["receipt_digest"] = "0" * 64
    elif mutation == "duplicate-receipt":
        row = report["steps"][1]
        row["receipt"]["receipt_id"] = report["steps"][0]["receipt"]["receipt_id"]
        row["receipt_digest"] = digest(row["receipt"])
        row["output_commit"]["receipt_id"] = row["receipt"]["receipt_id"]
    elif mutation == "compiled":
        report["published_version"]["compiled"]["title"] = "tampered"
    elif mutation == "pin":
        report["pin"]["compilation_hash"] = "0" * 64
    else:
        del report["steps"][0]["attempt"]
    assert validate_computed_report(report)


@pytest.mark.parametrize("mutation", ["outputs", "digest", "commit", "query"])
def test_failed_attempt_cannot_claim_successful_output(mutation):
    report = synthetic_observation(failed=True)
    row = next(item for item in report["steps"] if item["outcome"] == "failed")
    if mutation == "outputs":
        row["outputs"] = {"passed": False}
    elif mutation == "digest":
        row["receipt"]["output_digest"] = digest({})
        row["receipt_digest"] = digest(row["receipt"])
    elif mutation == "commit":
        row["output_commit"] = {}
    else:
        row["output_query"]["code"] = "ok"
    assert validate_computed_report(report)


def test_strict_development_expectation_detects_boolean_and_artifact_drift():
    report = synthetic_observation()
    expectation = development_expectation()
    assert compare_expected_computed(report, expectation)["unclassified_divergences"] == []
    expectation["expected"]["steps"]["unit-tests"]["outputs"]["passed"] = 1
    assert compare_expected_computed(report, expectation)["unclassified_divergences"]
    expectation = development_expectation()
    expectation["expected"]["steps"]["package"]["outputs"]["bundle"]["content_hash"] = "0" * 64
    assert compare_expected_computed(report, expectation)["unclassified_divergences"]


def test_old_thin_comparison_remains_readable_and_explicitly_incomplete():
    result = compare_computed({"steps": [], "run_state": "succeeded"}, GOLDENS[0])
    assert result["unclassified_divergences"] and result["review_required"]
    assert all({"actual", "expected", "path", "reason"} <= item.keys() for item in result["unclassified_divergences"])
    missing = next(item for item in result["unclassified_divergences"] if item["category"] == "incomplete-public-evidence")
    assert missing["actual"] == {"missing_or_malformed": True, "error_type": "KeyError", "missing_key": "published_version"}
    assert missing["expected"]["observation_schema"] == "review.computed-observations.v1"


@pytest.mark.parametrize("field", ["transcript", "quote"])
def test_structural_ledger_entries_preserve_the_existing_speech_consumer(field):
    from frank_review_adapter.comparison import expected_values

    golden = GOLDENS[0]
    rows = [{"step_id": step, **deepcopy(value)} for step, value in expected_values(golden["retained_replay_fixture"]).items()]
    if field == "transcript":
        next(row for row in rows if row["step_id"] == "step_2")["outputs"]["transcript"] = "invented speech"
    else:
        next(row for row in rows if row["step_id"] == "step_5")["outputs"]["observations"][0]["what_they_said"] = "invented speech"
    result = compare_computed({"steps": rows, "run_state": "succeeded"}, golden)
    assert result["unclassified_divergences"][0]["category"] == "public-evidence-profile"
    assert all({"actual", "expected", "path", "reason"} <= item.keys() for item in result["unclassified_divergences"])
    assert any(item["actual"] == "invented speech" for item in result["unclassified_divergences"])
    assert not any(item["actual"] == "invented speech" for item in result["classified_divergences"])


@pytest.mark.parametrize("mutation", ["schema", "missing"])
def test_incomplete_expectation_records_have_meaningful_actual_and_expected(mutation):
    expectation = development_expectation()
    if mutation == "schema":
        expectation["schema"] = "unsupported"
    else:
        del expectation["expected"]
    result = compare_expected_computed(synthetic_observation(), expectation)
    assert result["review_required"]
    assert len(result["unclassified_divergences"]) == 1
    record = result["unclassified_divergences"][0]
    assert record["category"] == "incomplete-computed-expectation"
    assert {"actual", "expected", "path", "reason"} <= record.keys()
    if mutation == "schema":
        assert record["actual"] == "unsupported" and record["expected"] == "review.computed-expectation.v1"
    else:
        assert record["actual"]["missing_key"] == "expected" and "expected" in record["expected"]["required"]


def test_nonobject_public_report_keeps_the_structural_ledger_contract():
    record, = validate_computed_report(None)
    assert record["actual"] is None and record["expected"] == {"type": "object"}
    assert record["category"] == "incomplete-public-evidence" and record["path"] == []


@pytest.mark.parametrize("target,field,category", [
    ("span", "fence", "attempt-span"), ("span", "started_at_ms", "attempt-span"), ("span", "ended_at_ms", "attempt-span"),
    ("receipt", "started_at_ms", "receipt-time"), ("receipt", "recorded_at_ms", "receipt-time"),
    ("attempt", "started_at_ms", "receipt-time"), ("output_commit", "committed_at_ms", "successful-output"),
])
@pytest.mark.parametrize("replacement", [True, 1.0], ids=["boolean", "float"])
def test_numeric_span_and_direct_timestamp_bindings_require_json_integers(target, field, category, replacement):
    report = synthetic_observation()
    row = report["steps"][0]
    # One is an honest positive timestamp/fence and also Python-equal to true/1.0.
    # Establish each valid control before changing exactly one numeric JSON type.
    row["receipt"]["started_at_ms"] = row["receipt"]["recorded_at_ms"] = 1
    row["attempt"]["started_at_ms"] = 1
    row["attempt"]["span"]["started_at_ms"] = row["attempt"]["span"]["ended_at_ms"] = 1
    row["output_commit"]["committed_at_ms"] = 1
    row["receipt_digest"] = digest(row["receipt"])
    assert validate_computed_report(report) == []
    changed = row["attempt"]["span"] if target == "span" else row[target]
    changed[field] = replacement
    row["receipt_digest"] = digest(row["receipt"])
    errors = validate_computed_report(report)
    assert [item["category"] for item in errors] == [category]
    assert errors[0]["path"] == ["steps", "scope"]
    assert {"actual", "expected", "reason"} <= errors[0].keys()


@pytest.mark.parametrize("scenario", ["source-available", "source-unavailable"])
def test_fresh_personal_reports_compare_frozen_values_and_full_public_evidence(provider, tmp_path, scenario):
    source = json.loads((FIXTURES / "inputs.json").read_text())
    if scenario == "source-unavailable":
        source["source_snapshot"] = {}
    draft = json.loads((FIXTURES / "personal-review-v1.json").read_text())
    report = asyncio.run(execute_case(provider[0], draft, source, source, tmp_path, scenario=scenario))
    comparison = compare_computed(report, next(golden for golden in GOLDENS if golden["scenario"] == scenario))
    assert comparison["unclassified_divergences"] == []
    assert comparison["classified_divergences"] and comparison["production_semantic_equivalence"] is False


def test_fresh_development_outputs_match_separately_authored_expectation(provider, tmp_path):
    report = asyncio.run(execute_case(provider[0], DEVELOPMENT, {}, {}, tmp_path, scenario="development", development=True))
    result = compare_expected_computed(report, development_expectation())
    assert result["unclassified_divergences"] == []
    assert result["production_semantic_equivalence"] is False
