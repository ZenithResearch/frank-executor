"""Compare computed outputs to frozen goldens; never supply handler results."""
from __future__ import annotations

import hashlib
from collections import Counter

from frank_executor.model import Binding, Rejected, digest


REASONS = {
    "component-evidence": "Independent component resolution uses only exact injected source matches; raw geometry is unavailable and remains explicitly uncertain.",
    "annotation-artifact": "Independent annotation retains verbatim speech with separate timing/component evidence in a content-addressed JSON note.",
    "feedback-identity": "Independent observations derive identities from quoted speech and local occurrence, not legacy allocation counters.",
    "bounded-extraction": "Independent lexical evidence preserves quotes directly and explicitly discloses unqualified inference instead of replaying legacy analysis.",
    "quality-uncertainty": "An unresolved component target fails more conservatively than an event-derived candidate; both degraded runs fail before status/note work.",
    "handoff-evidence": "Independent handoff retains uncertainty and source evidence without inventing tasks, likely causes, fixes or acceptance criteria.",
    "immutable-artifact": "Fresh independent documents/packets have their own schema/content hashes; Step7 publishes a separate final packet without rewriting Step5.",
    "source-evidence": "Independent binding uses relative injected source paths, exact matching lines/content hashes, and unknown implementation cause.",
    "simulated-status": "The explicit simulated_processed label records a fixture intent and makes no claim of actual provider status writeback.",
}


def expected_values(fixture):
    def materialize(value):
        if isinstance(value, dict) and set(value) == {"$artifact"}:
            artifact = fixture["artifacts"][value["$artifact"]]
            content = artifact["content_utf8"].encode()
            return {"content_hash": hashlib.sha256(content).hexdigest(), "byte_length": len(content), "media_type": artifact["media_type"]}
        if isinstance(value, dict):
            return {key: materialize(child) for key, child in value.items()}
        if isinstance(value, list):
            return [materialize(child) for child in value]
        return value
    return {step: {"outcome": row["outcome"], "outputs": materialize(row.get("outputs", {}))}
            for step, row in fixture["steps"].items()}


def categorize(step, path, actual, expected):
    if not path:
        return None
    port = path[0]
    if step == "step_3" and port == "component_names" and path[-1] in {"source", "resolution_status", "spatial_hint"}:
        return "component-evidence"
    if step == "step_4" and port == "transcript_note":
        return "annotation-artifact"
    if step == "step_5":
        if port == "observations" and "what_they_said" not in path and "selectors" not in path and "component" not in path:
            return "feedback-identity" if path[-1] == "observation_id" else "bounded-extraction"
        if port == "review_packet_status":
            return "quality-uncertainty"
        if port in {"actionability", "implementation_handoff"}:
            return "handoff-evidence"
        if port == "review_packet":
            return "immutable-artifact"
    if step == "step_6" and port == "codebase_context":
        return "source-evidence"
    if step == "step_7" and port in {"review_note", "review_packet"}:
        return "immutable-artifact"
    if step == "step_7" and port == "review_packet_status":
        return "quality-uncertainty"
    if step == "step_8" and port == "review_status_updated":
        if "review_note" in path:
            return "immutable-artifact"
        if path[-1] == "status" and actual == "simulated_processed" and expected == "processed":
            return "simulated-status"
    return None


def execution_shape(compiled, outcomes):
    """Compare a retained trace to a pinned DAG; never decide actual work readiness."""
    specs = {step["step_id"]: step for step in compiled["steps"]}
    completed, batches = {}, []
    for _ in range(len(specs) + 1):
        ready = [] if "failed" in completed.values() else sorted(
            name for name, step in specs.items() if name not in completed
            and all(completed.get(parent) == "succeeded" for parent in step["depends_on"]))
        batches.append(ready)
        if not ready:
            return batches, {name: completed.get(name, "waiting") for name in specs}
        completed.update({name: outcomes[name] for name in ready})
    raise Rejected("Computed report exceeds its pinned DAG")


def _structural_divergence(category, path, actual, expected, reason):
    """Keep structural diagnostics readable by the same ledger consumers as outputs."""
    return {"category": category, "path": path, "actual": actual,
            "expected": expected, "reason": reason}


def _missing_observation(exc):
    return {"missing_or_malformed": True, "error_type": type(exc).__name__,
            "missing_key": exc.args[0] if isinstance(exc, KeyError) and exc.args
            and type(exc.args[0]) in (str, int) else None}


def validate_computed_report(report, *, expected_structure=None):
    """Validate additive public-query evidence; old thin reports stay readable but incomplete.

    This profile covers one non-retrying Attempt per executed step. An optional
    runtime shadow golden compares only runnable/terminal/outcome semantics;
    its synthetic artifact digests are never treated as fresh handler outputs.
    """
    errors = []
    if not isinstance(report, dict):
        return [_structural_divergence("incomplete-public-evidence", [], report, {"type": "object"},
                                      "Expected a computed report object.")]

    def check(condition, category, path, actual, expected):
        if not condition:
            errors.append(_structural_divergence(category, path, actual, expected,
                          "Computed public evidence is missing or inconsistent."))

    try:
        check(report.get("observation_schema") == "review.computed-observations.v1", "public-evidence-profile", [],
              report.get("observation_schema", {"missing": True}), "review.computed-observations.v1")
        version, pin = report["published_version"], report["pin"]
        compiled = version["compiled"]
        check(version["pin"] == pin and digest(compiled) == pin["compilation_hash"], "publication-pin", ["published_version"],
              {"pin": version["pin"], "compiled_digest": digest(compiled)},
              {"pin": pin, "compiled_digest": pin["compilation_hash"]})
        check(compiled["schema"] == "process.compiled.v1" and report["process_id"] == compiled["process_id"] == pin["process_id"],
              "process-identity", ["process_id"],
              {"schema": compiled["schema"], "report": report["process_id"], "compiled": compiled["process_id"]},
              {"schema": "process.compiled.v1", "report": pin["process_id"], "compiled": pin["process_id"]})
        specs = {step["step_id"]: step for step in compiled["steps"]}
        check(len(specs) == len(compiled["steps"]), "process-step-identity", ["published_version", "compiled", "steps"],
              [step["step_id"] for step in compiled["steps"]], {"unique_step_ids": sorted(specs)})
        check(isinstance(report["actor_id"], str) and bool(report["actor_id"]), "actor-identity", ["actor_id"],
              report["actor_id"], {"type": "nonempty string"})
        check(set(report["root_inputs"]) == set(compiled["inputs"]), "root-input-coverage", ["root_inputs"],
              sorted(report["root_inputs"]), sorted(compiled["inputs"]))
        rows = report["steps"]
        names = [row["step_id"] for row in rows]
        check(len(names) == len(set(names)) and set(names) <= specs.keys(), "step-identity-coverage", ["steps"],
              names, {"unique_subset_of": sorted(specs)})
        by_step = {row["step_id"]: row for row in rows}
        attempts, receipts = [], []
        for row in rows:
            name, binding = row["step_id"], Binding.read(row["binding"]).json()
            spec, attempt, receipt = specs[name], row["attempt"], row["receipt"]
            path = ["steps", name]
            check(binding["run_id"] == report["run_id"] and binding["step_id"] == name, "step-binding", path,
                  {key: binding[key] for key in ("run_id", "step_id")}, {"run_id": report["run_id"], "step_id": name})
            check(type(binding["fence"]) is int and binding["fence"] > 0, "fence", path,
                  binding["fence"], {"type": "positive integer"})
            check(row["operation"] in spec["capabilities"], "capability-binding", path,
                  row["operation"], {"one_of": spec["capabilities"]})
            check(row["outcome"] in {"succeeded", "failed"}, "outcome", path,
                  row["outcome"], {"one_of": ["succeeded", "failed"]})
            for key, value in {**binding, "actor_id": report["actor_id"], "pin": pin,
                               "input_digest": row["input_digest"]}.items():
                check(digest(attempt.get(key)) == digest(value) and digest(receipt.get(key)) == digest(value),
                      "attempt-receipt-binding", path + [key],
                      {"attempt": attempt.get(key, {"missing": True}), "receipt": receipt.get(key, {"missing": True})},
                      {"attempt": value, "receipt": value})
            check(row["actor_id"] == report["actor_id"], "actor-binding", path, row["actor_id"], report["actor_id"])
            resolved = {}
            for port, source in spec["bindings"].items():
                if source["source"] == "literal":
                    resolved[port] = source["value"]
                elif source["source"] == "run_input":
                    resolved[port] = report["root_inputs"][source["name"]]
                else:
                    resolved[port] = by_step[source["step_id"]]["outputs"][source["name"]]
            check(digest(row["inputs"]) == digest(attempt["inputs"]) == digest(resolved) == row["input_digest"], "resolved-input-binding", path,
                  {"row_digest": digest(row["inputs"]), "attempt_digest": digest(attempt["inputs"]), "input_digest": row["input_digest"]},
                  {"row_digest": digest(resolved), "attempt_digest": digest(resolved), "input_digest": digest(resolved)})
            check(attempt["input_types"] == spec["inputs"] and attempt["output_types"] == spec["outputs"], "attempt-types", path,
                  {"inputs": attempt["input_types"], "outputs": attempt["output_types"]},
                  {"inputs": spec["inputs"], "outputs": spec["outputs"]})
            check(attempt["state"] == receipt["outcome"] == row["outcome"] and attempt["current"] is True
                  and type(attempt["ordinal"]) is int and attempt["ordinal"] == 1, "terminal-attempt", path,
                  {"state": attempt["state"], "receipt_outcome": receipt["outcome"], "current": attempt["current"], "ordinal": attempt["ordinal"]},
                  {"state": row["outcome"], "receipt_outcome": row["outcome"], "current": True, "ordinal": 1})
            check(receipt["schema"] == "runtime.receipt.v1" and digest(receipt) == row["receipt_digest"], "receipt-integrity", path,
                  {"schema": receipt["schema"], "digest": row["receipt_digest"]},
                  {"schema": "runtime.receipt.v1", "digest": digest(receipt)})
            check(type(receipt["started_at_ms"]) is int and type(attempt["started_at_ms"]) is int
                  and receipt["started_at_ms"] == attempt["started_at_ms"] and type(receipt["recorded_at_ms"]) is int
                  and receipt["recorded_at_ms"] >= receipt["started_at_ms"], "receipt-time", path,
                  {"receipt_start": receipt["started_at_ms"], "attempt_start": attempt["started_at_ms"], "recorded": receipt["recorded_at_ms"]},
                  {"timestamp_types": "integer", "receipt_start_equals_attempt_start": True, "recorded_at_or_after_start": True})
            span = attempt["span"]
            check(span["outcome"] == row["outcome"] and span["actor_id"] == report["actor_id"]
                  and type(span["fence"]) is int and span["fence"] == binding["fence"]
                  and type(span["started_at_ms"]) is int and span["started_at_ms"] == receipt["started_at_ms"]
                  and type(span["ended_at_ms"]) is int and span["ended_at_ms"] == receipt["recorded_at_ms"], "attempt-span", path,
                  {key: span[key] for key in ("outcome", "actor_id", "fence", "started_at_ms", "ended_at_ms")},
                  {"outcome": row["outcome"], "actor_id": report["actor_id"], "fence": binding["fence"],
                   "started_at_ms": receipt["started_at_ms"], "ended_at_ms": receipt["recorded_at_ms"], "numeric_types": "integer"})
            payload = {key: binding[key] for key in ("run_id", "step_id", "attempt_id")}
            check(row["output_query"]["operation"] == "output.get" and row["output_query"]["payload"] == payload,
                  "output-query-binding", path, {key: row["output_query"][key] for key in ("operation", "payload")},
                  {"operation": "output.get", "payload": payload})
            if row["outcome"] == "failed":
                check(row["outputs"] == {} and receipt["output_digest"] is None and row["output_commit"] is None
                      and row["output_query"]["code"] == "not_found" and row["delivery_state"] == "failed_committed",
                      "failed-output", path,
                      {"outputs": row["outputs"], "output_digest": receipt["output_digest"], "output_commit": row["output_commit"],
                       "query_code": row["output_query"]["code"], "delivery_state": row["delivery_state"]},
                      {"outputs": {}, "output_digest": None, "output_commit": None, "query_code": "not_found", "delivery_state": "failed_committed"})
            else:
                commit = row["output_commit"]
                for key, value in {**binding, "actor_id": report["actor_id"], "pin": pin,
                                   "inputs_digest": row["input_digest"], "receipt_id": receipt["receipt_id"]}.items():
                    check(digest(commit.get(key)) == digest(value), "output-commit-binding", path + [key],
                          commit.get(key, {"missing": True}), value)
                check(digest(commit["outputs"]) == digest(row["outputs"]) and commit["output_types"] == spec["outputs"]
                      and commit["output_digest"] == receipt["output_digest"] == digest(row["outputs"])
                      and type(commit["committed_at_ms"]) is int and commit["committed_at_ms"] == receipt["recorded_at_ms"]
                      and row["output_query"]["code"] == "ok" and row["delivery_state"] == "committed", "successful-output", path,
                      {"commit_outputs_digest": digest(commit["outputs"]), "output_types": commit["output_types"],
                       "output_digest": commit["output_digest"], "receipt_output_digest": receipt["output_digest"],
                       "committed_at_ms": commit["committed_at_ms"], "query_code": row["output_query"]["code"], "delivery_state": row["delivery_state"]},
                      {"commit_outputs_digest": digest(row["outputs"]), "output_types": spec["outputs"],
                       "output_digest": digest(row["outputs"]), "receipt_output_digest": digest(row["outputs"]),
                       "committed_at_ms": receipt["recorded_at_ms"], "integer_committed_at_ms": True, "query_code": "ok", "delivery_state": "committed"})
            attempts.append(binding["attempt_id"])
            receipts.append(receipt["receipt_id"])
        check(len(attempts) == len(set(attempts)) and len(receipts) == len(set(receipts)), "attempt-receipt-identity", ["steps"],
              {"attempt_ids": attempts, "receipt_ids": receipts}, {"unique_attempt_ids": sorted(set(attempts)), "unique_receipt_ids": sorted(set(receipts))})
        batches, states = execution_shape(compiled, {name: row["outcome"] for name, row in by_step.items()})
        check(report["runnable_batches"] == batches, "runnable-batches", ["runnable_batches"], report["runnable_batches"], batches)
        check(set(names) == {name for batch in batches for name in batch}, "step-identity-coverage", ["steps"],
              sorted(set(names)), sorted(name for batch in batches for name in batch))
        check(report["step_states"] == states, "terminal-steps", ["step_states"], report["step_states"], states)
        terminal = "failed" if "failed" in states.values() else "succeeded"
        check(report["run_state"] == terminal, "terminal-state", ["run_state"], report["run_state"], terminal)
        if expected_structure is not None:
            check(expected_structure["process_id"] == report["process_id"]
                  and expected_structure["compilation_hash"] == pin["compilation_hash"], "golden-process-pin", [],
                  {"process_id": report["process_id"], "compilation_hash": pin["compilation_hash"]},
                  {key: expected_structure[key] for key in ("process_id", "compilation_hash")})
            check(report["runnable_batches"] == [item["runnable"] for item in expected_structure["runnable_trace"]], "golden-runnable", [],
                  report["runnable_batches"], [item["runnable"] for item in expected_structure["runnable_trace"]])
            check(report["run_state"] == expected_structure["run_state"] and states == expected_structure["final_step_states"], "golden-terminal", [],
                  {"run_state": report["run_state"], "step_states": states},
                  {"run_state": expected_structure["run_state"], "step_states": expected_structure["final_step_states"]})
            check({name: row["outcome"] for name, row in by_step.items()}
                  == {row["step_id"]: row["outcome"] for row in expected_structure["steps"]}, "golden-outcomes", [],
                  {name: row["outcome"] for name, row in by_step.items()},
                  {row["step_id"]: row["outcome"] for row in expected_structure["steps"]})
            for reference in expected_structure["steps"]:
                check(reference["receipt"]["outcome"] == by_step[reference["step_id"]]["receipt"]["outcome"]
                      and (reference["outcome"] != "failed" or reference["receipt"]["output_digest"] is None),
                      "golden-receipt-semantics", [reference["step_id"]],
                      {"outcome": by_step[reference["step_id"]]["receipt"]["outcome"], "golden_receipt": reference["receipt"]},
                      {"outcome": reference["receipt"]["outcome"], "failed_output_digest": None})
    except (KeyError, TypeError, ValueError, AttributeError, Rejected) as exc:
        errors.append(_structural_divergence("incomplete-public-evidence", [], _missing_observation(exc),
                      {"observation_schema": "review.computed-observations.v1", "public_queries": ["version.get", "attempt.get", "receipt.get", "output.get"],
                       "coverage": "each reachable executed step"},
                      "Required public observations or a reachable step are missing/malformed; no synthetic replacement is inferred."))
    return errors


def compare_expected_computed(report, expectation):
    """Strict comparator-only expectation; never invoke handlers or normalize outputs."""
    unknown = validate_computed_report(report)

    def visit(actual, expected, path):
        if isinstance(actual, dict) and isinstance(expected, dict) and actual.keys() == expected.keys():
            for key in sorted(actual):
                visit(actual[key], expected[key], path + [key])
        elif isinstance(actual, list) and isinstance(expected, list) and len(actual) == len(expected):
            for index, (left, right) in enumerate(zip(actual, expected)):
                visit(left, right, path + [index])
        elif type(actual) is not type(expected) or actual != expected:
            unknown.append({"category": "computed-expectation", "path": path, "actual": actual, "expected": expected,
                            "reason": "Fresh output/execution differs from separately authored expectation; no equivalence inferred."})

    try:
        actual = {"process_id": report["process_id"], "compilation_hash": report["pin"]["compilation_hash"],
                  "root_inputs": report["root_inputs"], "runnable_batches": report["runnable_batches"],
                  "step_states": report["step_states"], "run_state": report["run_state"],
                  "steps": {row["step_id"]: {"outcome": row["outcome"], "outputs": row["outputs"]} for row in report["steps"]}}
        if expectation["schema"] != "review.computed-expectation.v1":
            unknown.append(_structural_divergence("incomplete-computed-expectation", ["schema"], expectation["schema"],
                           "review.computed-expectation.v1", "Comparator expectation schema is missing or unsupported."))
        else:
            visit(actual, expectation["expected"], [])
    except (KeyError, TypeError, ValueError, Rejected) as exc:
        unknown.append(_structural_divergence("incomplete-computed-expectation", [], _missing_observation(exc),
                       {"schema": "review.computed-expectation.v1", "required": ["expected", "complete computed execution"]},
                       "Comparator expectation or computed execution is missing/malformed."))
    return {"mode": "strict-computed-expectation", "unclassified_divergences": unknown,
            "review_required": bool(unknown), "production_semantic_equivalence": False,
            "expectation_provenance": expectation.get("provenance"), "classified_divergences": []}


def compare_computed(report, golden):
    expected = expected_values(golden["retained_replay_fixture"])
    differences, unknown, comparisons = [], validate_computed_report(report), []

    def visit(step, actual, prior, path):
        if isinstance(actual, dict) and isinstance(prior, dict) and actual.keys() == prior.keys():
            for key in sorted(actual):
                visit(step, actual[key], prior[key], path + [key])
        elif isinstance(actual, list) and isinstance(prior, list) and len(actual) == len(prior):
            for index, (left, right) in enumerate(zip(actual, prior)):
                visit(step, left, right, path + [index])
        elif type(actual) is not type(prior) or actual != prior:
            category = categorize(step, path, actual, prior)
            # A container mismatch bypasses visits to protected observation fields.
            # Keep it unknown rather than admitting all of its children by port.
            if step == "step_5" and path[:1] == ["observations"] and len(path) < 3:
                category = None
            record = {"step_id": step, "path": path, "actual": actual, "expected": prior, "legacy_expected": prior, "category": category,
                      "reason": REASONS.get(category, "Unclassified difference requires review.")}
            (differences if category else unknown).append(record)

    for row in report["steps"]:
        prior = expected.get(row["step_id"])
        if prior is None or row["outcome"] != prior["outcome"]:
            unknown.append({**_structural_divergence("outcome", ["steps", row["step_id"], "outcome"], row["outcome"],
                              prior["outcome"] if prior is not None else {"missing_golden_step": True},
                              "Computed outcome has no matching frozen step/outcome."),
                            "step_id": row["step_id"], "legacy_expected": prior})
            continue
        visit(row["step_id"], row["outputs"], prior["outputs"], [])
        comparisons.append({"step_id": row["step_id"], "outcome": row["outcome"], "computed_output_digest": digest(row["outputs"]), "legacy_migrated_output_digest": digest(prior["outputs"])})
    legacy_state = {"completed": "succeeded", "failed": "failed"}[golden["legacy_state"]]
    if report["run_state"] != legacy_state:
        unknown.append({**_structural_divergence("terminal-state", ["run_state"], report["run_state"], legacy_state,
                          "Computed terminal state differs from the retained replay fixture."), "legacy_expected": legacy_state})
    try:
        batches, states = execution_shape(report["published_version"]["compiled"],
                                          {name: row["outcome"] for name, row in expected.items()})
        executed = [name for batch in batches for name in batch]
        if Counter(row["step_id"] for row in report["steps"]) != Counter(executed):
            unknown.append(_structural_divergence("golden-step-identity", ["steps"], [row["step_id"] for row in report["steps"]],
                           executed, "Missing, duplicate or unexpected executed step identity."))
        if report["runnable_batches"] != batches or report["step_states"] != states:
            unknown.append(_structural_divergence("golden-execution-shape", [],
                           {"runnable_batches": report["runnable_batches"], "step_states": report["step_states"]},
                           {"runnable_batches": batches, "step_states": states},
                           "Frozen outcomes and published DAG disagree with observed readiness/terminal steps."))
    except (KeyError, TypeError, ValueError, Rejected) as exc:
        unknown.append(_structural_divergence("incomplete-golden-execution", [], _missing_observation(exc),
                       {"required": ["published_version.compiled", "runnable_batches", "step_states", "reachable frozen outcomes"]},
                       "Frozen outcomes cannot be bound to a public published DAG."))
    return {"mode": "independent-computation-from-frozen-inputs", "scenario": golden["scenario"],
            "step_comparisons": comparisons, "classified_divergences": differences, "unclassified_divergences": unknown,
            "legacy_state": golden["legacy_state"], "independent_state": report["run_state"],
            "production_semantic_equivalence": False, "review_required": bool(differences or unknown),
            "execution_expectation_provenance": "Frozen fixture outcomes projected through hash-bound version.get compiled DAG; not a new legacy receipt-byte equality claim."}
