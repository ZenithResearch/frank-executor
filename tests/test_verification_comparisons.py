"""Post-execution aggregation controls, not genuine five-run execution evidence.

The provider and execute_case boundaries are mocked. Synthetic public-shaped
reports exercise the real comparison functions and their overall ledger/status.
No golden or expected value is passed to a real handler by these controls.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest

from frank_executor.model import Rejected, digest
from frank_review_adapter import verify_main
from frank_review_adapter.comparison import compare_computed, execution_shape, expected_values, validate_computed_report


FIXTURES = Path(__file__).parent / "fixtures" / "independent-review"
SCENARIOS = ["source-available", "source-unavailable", "silent-repeat", "transcript-only", "development"]
EXPECTATION = "development-computed-v1.json"
EXPECTATION_SHA256 = "8dca22aea531860ec97389275380a3d7ea62a928ec0b2751fe76631e1a9e38ba"


def public_shaped_report(compiled, root_inputs, outputs, scenario):
    """Synthetic comparator data only; no claim of runtime-observed records.

    Reuse the separately tested shape helper only to populate this aggregation
    fixture; these controls do not qualify the scheduler or shape algorithm.
    """
    pin = {"process_id": compiled["process_id"], "process_version": "integration-unit-version-" + scenario,
           "compilation_hash": digest(compiled)}
    batches, states = execution_shape(compiled, {name: row["outcome"] for name, row in outputs.items()})
    report = {"scenario": scenario, "synthetic_mock_report": True, "process_id": compiled["process_id"],
              "pin": pin, "published_version": {"pin": pin, "compiled": deepcopy(compiled)},
              "observation_schema": "review.computed-observations.v1", "run_id": "integration-unit-run-" + scenario,
              "actor_id": "integration-unit-actor", "root_inputs": deepcopy(root_inputs), "steps": [],
              "runnable_batches": batches, "step_states": states,
              "run_state": "failed" if "failed" in states.values() else "succeeded"}
    specs, rows = {step["step_id"]: step for step in compiled["steps"]}, {}
    for index, name in enumerate(name for batch in batches for name in batch):
        spec = specs[name]
        inputs = {}
        for port, source in spec["bindings"].items():
            if source["source"] == "literal":
                inputs[port] = deepcopy(source["value"])
            elif source["source"] == "run_input":
                inputs[port] = deepcopy(root_inputs[source["name"]])
            else:
                inputs[port] = deepcopy(rows[source["step_id"]]["outputs"][source["name"]])
        outcome, value = outputs[name]["outcome"], deepcopy(outputs[name]["outputs"])
        binding = {"run_id": report["run_id"], "step_id": name, "attempt_id": scenario + "-attempt-" + str(index), "fence": 1}
        receipt = {**binding, "schema": "runtime.receipt.v1", "receipt_id": scenario + "-receipt-" + str(index),
                   "actor_id": report["actor_id"], "pin": pin, "input_digest": digest(inputs), "outcome": outcome,
                   "output_digest": digest(value) if outcome == "succeeded" else None,
                   "started_at_ms": 1000 + index, "recorded_at_ms": 2000 + index, "signature": None}
        attempt = {**binding, "actor_id": report["actor_id"], "pin": pin, "inputs": deepcopy(inputs),
                   "input_digest": digest(inputs), "input_types": spec["inputs"], "output_types": spec["outputs"],
                   "state": outcome, "current": True, "ordinal": 1, "started_at_ms": receipt["started_at_ms"],
                   "span": {"actor_id": report["actor_id"], "fence": 1, "outcome": outcome,
                            "started_at_ms": receipt["started_at_ms"], "ended_at_ms": receipt["recorded_at_ms"]}}
        commit = None if outcome == "failed" else {**binding, "actor_id": report["actor_id"], "pin": pin,
                   "inputs_digest": digest(inputs), "receipt_id": receipt["receipt_id"], "outputs": deepcopy(value),
                   "output_types": spec["outputs"], "output_digest": digest(value), "committed_at_ms": receipt["recorded_at_ms"]}
        row = {"step_id": name, "operation": spec["capabilities"][0], "binding": binding, "actor_id": report["actor_id"],
               "inputs": inputs, "input_digest": digest(inputs), "outcome": outcome, "outputs": value,
               "attempt": attempt, "receipt": receipt, "receipt_digest": digest(receipt), "output_commit": commit,
               "output_query": {"operation": "output.get", "payload": {key: binding[key] for key in ("run_id", "step_id", "attempt_id")},
                                "code": "not_found" if outcome == "failed" else "ok"},
               "delivery_state": "failed_committed" if outcome == "failed" else "committed"}
        report["steps"].append(row)
        rows[name] = row
    assert validate_computed_report(report) == []
    report["report_validation"] = {"schema": "review.report-validation.v1", "public_bindings_complete": True,
                                   "profile": "one non-retrying Attempt per step", "golden_outputs_compared": False}
    return report


@pytest.fixture
def integration(tmp_path, monkeypatch):
    fixtures = tmp_path / "external-comparison-fixtures"
    shutil.copytree(FIXTURES, fixtures)
    review = json.loads((fixtures / "personal-review-v1.compiled.json").read_text())
    development = json.loads((fixtures / "development-sop-v1.compiled.json").read_text())
    inputs = json.loads((fixtures / "inputs.json").read_text())
    goldens = json.loads((fixtures / "legacy-comparison.json").read_text())["scenarios"]
    expectation = json.loads((fixtures / EXPECTATION).read_bytes())
    review_root = {name: deepcopy(inputs[name]) for name in review["inputs"] if name not in {"audio_asset", "events_asset"}}
    review_root.update({name: {"content_hash": letter * 64, "byte_length": 1, "media_type": "application/json"}
                        for name, letter in [("audio_asset", "a"), ("events_asset", "e")]})
    values = {golden["scenario"]: expected_values(golden["retained_replay_fixture"]) for golden in goldens}
    reports = {scenario: public_shaped_report(review, review_root,
               values[scenario if scenario in values else "source-available"], scenario) for scenario in SCENARIOS[:-1]}
    reports["development"] = public_shaped_report(development, expectation["expected"]["root_inputs"],
                                                 expectation["expected"]["steps"], "development")
    calls, events, comparison_reads = [], [], []

    class Reservation:
        def __enter__(self):
            events.append("reservation")
            return self
        def __exit__(self, *args):
            return False
        def bind(self, address):
            assert address == ("127.0.0.1", 0)
        def getsockname(self):
            return ("127.0.0.1", 31415)

    class Provider:
        def poll(self):
            return None
        def terminate(self):
            events.append("terminate")
        def wait(self, timeout):
            assert timeout == 10
            events.append("wait")
            return 0

    def start(argv, **kwargs):
        assert argv[:3] == [sys.executable, "-m", "process_runtime"]
        events.append("provider")
        return Provider()

    class Client:
        def __init__(self, endpoint, **kwargs):
            assert endpoint == "http://127.0.0.1:31415"
        def query(self, envelope):
            assert envelope["operation"] == "events.list"
            return {"data": []}

    async def execute(endpoint, draft, supplied_inputs, source, directory, *, scenario, development=False):
        assert endpoint == "http://127.0.0.1:31415"
        assert draft["process_id"] == ("development-sop-v1" if development else "personal-review-v1")
        assert {"expected", "retained_replay_fixture", "computed_expectation_sha256"}.isdisjoint(draft)
        assert supplied_inputs == source
        if development:
            assert scenario == "development" and supplied_inputs == source == {}
        else:
            wanted = deepcopy(inputs)
            if scenario == "source-unavailable":
                wanted["source_snapshot"] = {}
            elif scenario == "silent-repeat":
                wanted["events"].append({"id": 2, "type": "stroke", "target": "button.review-dismiss", "elapsedMs": 5000, "bounds": {"x": 10, "y": 20}})
            elif scenario == "transcript-only":
                wanted["stt_response"] = {"transcript": "Just looking around.", "audio_offset_ms": 0, "words": []}
            assert supplied_inputs == wanted
        assert comparison_reads == []
        calls.append(scenario)
        events.append("execute:" + scenario)
        return deepcopy(reports[scenario])

    read_bytes, read_text = Path.read_bytes, Path.read_text
    def observe(path):
        if path.parent == fixtures and path.name in {EXPECTATION, "legacy-comparison.json"}:
            assert calls == SCENARIOS
            assert events[-1] == "wait"
            comparison_reads.append(path.name)
    def observed_bytes(path):
        observe(path)
        return read_bytes(path)
    def observed_text(path, *args, **kwargs):
        observe(path)
        return read_text(path, *args, **kwargs)
    monkeypatch.setattr(verify_main, "socket", SimpleNamespace(socket=Reservation))
    monkeypatch.setattr(verify_main, "subprocess", SimpleNamespace(Popen=start, STDOUT=subprocess.STDOUT, TimeoutExpired=subprocess.TimeoutExpired))
    monkeypatch.setattr(verify_main, "sys", SimpleNamespace(executable=sys.executable, addaudithook=lambda hook: None))
    monkeypatch.setattr(verify_main, "RuntimeClient", Client)
    monkeypatch.setattr(verify_main, "execute_case", execute)
    monkeypatch.setattr(Path, "read_bytes", observed_bytes)
    monkeypatch.setattr(Path, "read_text", observed_text)
    return SimpleNamespace(fixtures=fixtures, reports=reports, calls=calls, events=events, goldens=goldens,
                           reads=comparison_reads, inputs=inputs, values=values, review=review, review_root=review_root,
                           directory=tmp_path / "verification", unobserved_read_bytes=read_bytes)


def test_valid_five_report_aggregate_passes_after_computation_with_separate_output_comparisons(integration):
    report = verify_main.verify(integration.fixtures, integration.directory)
    assert integration.calls == SCENARIOS
    assert set(integration.reads) == {EXPECTATION, "legacy-comparison.json"}
    assert report["status"] == "passed" and report["unclassified_divergences"] == []
    assert len(report["scenarios"]) == 5 and len(report["legacy_comparisons"]) == 2
    comparison, = report["computed_comparisons"]
    assert comparison["scenario"] == "development" and comparison["expectation_sha256"] == EXPECTATION_SHA256
    assert comparison["unclassified_divergences"] == []
    assert all(item["report_validation"]["golden_outputs_compared"] is False for item in report["scenarios"])
    assert report["comparison_scope"]["structural_validation_is_output_equivalence"] is False
    assert report["computed_expectation_origin"]["mode"] == "post_execution_comparator_only"
    assert report["resource_sha256"] == json.loads((integration.fixtures / "manifest.json").read_text())["resource_sha256"]
    assert report["production_ready"] is report["native_authority_qualified"] is report["production_semantic_equivalence"] is False


@pytest.mark.parametrize("mutation,error", [
    ("missing-file", "Frozen computed expectation missing or unreadable"),
    ("altered-bytes", "Frozen computed expectation hash mismatch"),
    ("missing-manifest-pin", "Frozen computed expectation manifest mismatch"),
    ("coherent-repin", "Frozen computed expectation manifest mismatch"),
])
def test_missing_or_tampered_expectation_denies_only_after_all_computation(integration, mutation, error):
    path = integration.fixtures / EXPECTATION
    manifest_path = integration.fixtures / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    if mutation == "missing-file":
        path.unlink()
    elif mutation == "altered-bytes":
        path.write_bytes(integration.unobserved_read_bytes(path) + b"\n")
    elif mutation == "missing-manifest-pin":
        del manifest["computed_expectation_sha256"]
        manifest_path.write_text(json.dumps(manifest))
    else:
        changed = integration.unobserved_read_bytes(path) + b"\n"
        path.write_bytes(changed)
        manifest["computed_expectation_sha256"][EXPECTATION] = hashlib.sha256(changed).hexdigest()
        manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(Rejected, match="^" + error + "$"):
        verify_main.verify(integration.fixtures, integration.directory)
    assert integration.calls == SCENARIOS
    assert integration.events[-1] == "wait"
    assert "legacy-comparison.json" in integration.reads


def test_changed_development_output_cannot_pass_with_clean_personal_comparisons(integration):
    report = integration.reports["development"]
    row = next(item for item in report["steps"] if item["step_id"] == "package")
    row["outputs"]["bundle"]["content_hash"] = "0" * 64
    row["receipt"]["output_digest"] = digest(row["outputs"])
    row["receipt_digest"] = digest(row["receipt"])
    row["output_commit"]["outputs"] = deepcopy(row["outputs"])
    row["output_commit"]["output_digest"] = digest(row["outputs"])
    assert validate_computed_report(report) == []  # Reach the full-output comparator, not a cheap broken digest.
    result = verify_main.verify(integration.fixtures, integration.directory)
    assert all(not item["unclassified_divergences"] for item in result["legacy_comparisons"])
    unknown = result["computed_comparisons"][0]["unclassified_divergences"]
    assert unknown and all(item["category"] == "computed-expectation" for item in unknown)
    assert result["status"] == "review_required" and result["unclassified_divergences"] == unknown
    assert any(item["actual"] == "0" * 64 for item in unknown)


def test_development_structural_unknown_is_in_the_overall_ledger(integration):
    integration.reports["development"]["steps"][0]["attempt"]["span"]["fence"] = True
    result = verify_main.verify(integration.fixtures, integration.directory)
    unknown = result["computed_comparisons"][0]["unclassified_divergences"]
    assert [item["category"] for item in unknown] == ["attempt-span"]
    assert result["status"] == "review_required" and result["unclassified_divergences"] == unknown


def test_personal_unknown_still_aggregates_alongside_clean_development(integration):
    values = deepcopy(integration.values["source-available"])
    values["step_2"]["outputs"]["transcript"] = "invented speech"
    integration.reports["source-available"] = public_shaped_report(integration.review, integration.review_root, values, "source-available")
    result = verify_main.verify(integration.fixtures, integration.directory)
    assert result["status"] == "review_required"
    assert result["computed_comparisons"][0]["unclassified_divergences"] == []
    assert any(item["actual"] == "invented speech" for item in result["unclassified_divergences"])
    assert result["unclassified_divergences"] == [row for comparison in result["legacy_comparisons"] for row in comparison["unclassified_divergences"]]


@pytest.mark.parametrize("scenario", ["source-available", "source-unavailable"])
@pytest.mark.parametrize("field,replacement", [
    ("what_they_said", "invented speech"),
    ("selectors", []),
    ("component", "unrelated component"),
])
@pytest.mark.parametrize("shape", ["list-growth", "item-key-removal"])
def test_observation_container_change_cannot_hide_protected_drift(integration, scenario, field, replacement, shape):
    golden = next(item for item in integration.goldens if item["scenario"] == scenario)
    baseline = compare_computed(integration.reports[scenario], golden)
    assert baseline["unclassified_divergences"] == baseline["classified_divergences"] == []
    assert baseline["review_required"] is False and baseline["production_semantic_equivalence"] is False
    values = deepcopy(integration.values[scenario])
    observations = values["step_5"]["outputs"]["observations"]
    prior = deepcopy(observations)
    assert len(prior) == 1 and prior[0][field] != replacement
    observations[0][field] = deepcopy(replacement)
    if shape == "list-growth":
        extra = deepcopy(prior[0])
        extra["observation_id"] = "fb_extra"
        observations.append(extra)
        path, actual, expected = ["observations"], observations, prior
    else:
        # Malformed record data is a comparator control, not runtime admission.
        del observations[0]["issue"]
        path, actual, expected = ["observations", 0], observations[0], prior[0]
    report = public_shaped_report(integration.review, integration.review_root, values, scenario)
    assert validate_computed_report(report) == []  # Reach semantics with coherent public bindings.
    comparison = compare_computed(report, golden)
    unknown = [{"step_id": "step_5", "path": path, "actual": actual, "expected": expected,
                "legacy_expected": expected, "category": None, "reason": "Unclassified difference requires review."}]
    assert comparison["unclassified_divergences"] == unknown
    assert comparison["classified_divergences"] == []
    assert comparison["review_required"] is True and comparison["production_semantic_equivalence"] is False
    assert integration.calls == []  # No mocked or real five-run/provider path is invoked.


@pytest.mark.parametrize("scenario", ["source-available", "source-unavailable"])
def test_nonprotected_observation_leaf_stays_classified_for_review(integration, scenario):
    golden = next(item for item in integration.goldens if item["scenario"] == scenario)
    values = deepcopy(integration.values[scenario])
    observation = values["step_5"]["outputs"]["observations"][0]
    prior = observation["issue"]
    observation["issue"] = observation["what_they_said"]
    assert observation["issue"] != prior
    report = public_shaped_report(integration.review, integration.review_root, values, scenario)
    assert validate_computed_report(report) == []
    comparison = compare_computed(report, golden)
    assert comparison["unclassified_divergences"] == []
    assert comparison["classified_divergences"] == [{
        "step_id": "step_5", "path": ["observations", 0, "issue"], "actual": observation["issue"],
        "expected": prior, "legacy_expected": prior, "category": "bounded-extraction",
        "reason": "Independent lexical evidence preserves quotes directly and explicitly discloses unqualified inference instead of replaying legacy analysis.",
    }]
    assert comparison["review_required"] is True and comparison["production_semantic_equivalence"] is False
    assert integration.calls == []  # Classification is not semantic approval or a handler run.
