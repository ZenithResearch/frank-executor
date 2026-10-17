"""Reproduce independent fixture receipts from an installed Frank/runtime tuple."""
from __future__ import annotations

import argparse
import asyncio
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import sys
import time

from frank_executor.model import Rejected
from process_runtime_client import RuntimeClient, LocalDevAuthority

from .comparison import compare_computed, compare_expected_computed
from .resource_origin import load_process_resources
from .verification import execute_case


DEVELOPMENT_EXPECTATION_SHA256 = "8dca22aea531860ec97389275380a3d7ea62a928ec0b2751fe76631e1a9e38ba"


def verify(fixtures, directory, *, require_installed=False):
    import frank_executor, frank_review_adapter, process_runtime, process_runtime_client
    modules = {module.__name__: str(Path(module.__file__).resolve())
               for module in (frank_executor, frank_review_adapter, process_runtime, process_runtime_client)}
    if require_installed and any("site-packages" not in Path(path).parts for path in modules.values()):
        raise Rejected("Installed verification rejects source import overrides")
    fixtures, directory = Path(fixtures), Path(directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if directory.stat().st_mode & 0o077:
        raise Rejected("Verification directory must be owner-private")
    if any(directory.iterdir()):
        raise Rejected("Verification requires a fresh empty directory")
    manifest = json.loads((fixtures / "manifest.json").read_text())
    resources, resource_origin = load_process_resources(
        fixtures, manifest["resource_sha256"], runtime_module_file=process_runtime.__file__,
        require_installed=require_installed)
    inputs = json.loads((fixtures / "inputs.json").read_text())
    review = json.loads(resources["personal-review-v1.json"])
    development = json.loads(resources["development-sop-v1.json"])
    from process_runtime.compiler import compile_draft
    for draft in (review, development):
        frozen = json.loads(resources[draft["process_id"] + ".compiled.json"])
        if compile_draft(draft).snapshot.value != frozen:
            raise Rejected("Frozen compiled process resource mismatch")
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    endpoint = f"http://127.0.0.1:{port}"
    child_log = directory / "runtime-provider.log"
    log = child_log.open("wb")
    process = subprocess.Popen([sys.executable, "-m", "process_runtime", "--database", str(directory / "runtime.db"),
                "--port", str(port), "--environment", "test", "--local-dev-untrusted", "--local-dev-subject", "independent-fixture"],
                cwd=directory, stdout=log, stderr=subprocess.STDOUT)
    client = RuntimeClient(endpoint, authority=LocalDevAuthority(environment="test"), timeout=2)
    reports, network = [], []

    def network_audit(event, args):
        if event == "socket.connect":
            address = args[1]
            if not isinstance(address, tuple) or address[0] not in {"127.0.0.1", "::1"}:
                raise Rejected("Independent verification prohibits external network connections")
            network.append({"host": address[0], "port": address[1]})

    sys.addaudithook(network_audit)
    try:
        deadline = time.monotonic() + 30
        while True:
            if process.poll() is not None:
                raise Rejected("Disposable runtime did not start; inspect retained provider log")
            try:
                client.query({"schema": "runtime.query.v1", "operation": "events.list", "payload": {"after": 0, "limit": 1}})
                break
            except Exception:
                if time.monotonic() >= deadline:
                    raise Rejected("Disposable runtime startup exceeded bound") from None
                time.sleep(.1)
        for scenario in ("source-available", "source-unavailable", "silent-repeat", "transcript-only"):
            source = deepcopy(inputs)
            if scenario == "source-unavailable":
                source["source_snapshot"] = {}
            if scenario == "silent-repeat":
                source["events"].append({"id": 2, "type": "stroke", "target": "button.review-dismiss", "elapsedMs": 5000, "bounds": {"x": 10, "y": 20}})
            if scenario == "transcript-only":
                source["stt_response"] = {"transcript": "Just looking around.", "audio_offset_ms": 0, "words": []}
            reports.append(asyncio.run(execute_case(endpoint, review, source, source, directory, scenario=scenario)))
        reports.append(asyncio.run(execute_case(endpoint, development, {}, {}, directory, scenario="development", development=True)))
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)
        log.close()
    # Comparison fixtures are loaded only after all fresh handler execution has completed.
    goldens = json.loads((fixtures / "legacy-comparison.json").read_text())
    comparisons = [compare_computed(report, next(golden for golden in goldens["scenarios"] if golden["scenario"] == report["scenario"]))
                   for report in reports[:2]]
    expectation_name = "development-computed-v1.json"
    if manifest.get("computed_expectation_sha256") != {expectation_name: DEVELOPMENT_EXPECTATION_SHA256}:
        raise Rejected("Frozen computed expectation manifest mismatch")
    expectation_path = fixtures / expectation_name
    try:
        expectation_bytes = expectation_path.read_bytes()
    except OSError:
        raise Rejected("Frozen computed expectation missing or unreadable") from None
    if hashlib.sha256(expectation_bytes).hexdigest() != DEVELOPMENT_EXPECTATION_SHA256:
        raise Rejected("Frozen computed expectation hash mismatch")
    expectation = json.loads(expectation_bytes)
    development_report = next(report for report in reports if report["scenario"] == "development")
    computed_comparisons = [{"scenario": development_report["scenario"], "process_id": development_report["process_id"],
                             "expectation_sha256": DEVELOPMENT_EXPECTATION_SHA256,
                             **compare_expected_computed(development_report, expectation)}]
    unknown = [row for comparison in comparisons + computed_comparisons for row in comparison["unclassified_divergences"]]
    status = "passed" if not unknown else "review_required"
    sources = {str(path.relative_to(Path(__file__).parent)): hashlib.sha256(path.read_bytes()).hexdigest()
               for path in Path(__file__).parent.glob("*.py")}
    return {"schema": "review.independent-verification.v1", "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
            "status": status, "mode": "fresh-independent-capability-handlers", "production_ready": False,
            "production_semantic_equivalence": False, "native_authority_qualified": False, "module_paths": modules,
            "source_sha256": sources, "fixture_sha256": {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in fixtures.iterdir() if path.is_file()},
            "resource_sha256": manifest["resource_sha256"], "process_resource_origin": resource_origin,
            "scenarios": reports, "legacy_comparisons": comparisons, "computed_comparisons": computed_comparisons,
            "computed_expectation_origin": {"mode": "post_execution_comparator_only", "path": str(expectation_path),
                                            "sha256": DEVELOPMENT_EXPECTATION_SHA256, "bytes": len(expectation_bytes)},
            "comparison_scope": {"public_bindings": "All five fresh reports are validated by execute_case before return; one non-retrying Attempt per executed step.",
                                 "legacy_outputs": [comparison["scenario"] for comparison in comparisons],
                                 "separately_authored_outputs": [comparison["scenario"] for comparison in computed_comparisons],
                                 "structural_validation_is_output_equivalence": False},
            "divergence_categories": dict(Counter(row["category"] for comparison in comparisons for row in comparison["classified_divergences"])),
            "unclassified_divergences": unknown, "zero_send_evidence": {"external_send_count": 0, "network_connections": len(network),
                  "network_destinations": sorted({(entry["host"], entry["port"]) for entry in network}),
                  "enabled_adapter": "frank.review.effect-disabled.v1", "ports": "private synthetic artifact/STT/component/source/claim/result/intent ports",
                  "status_and_vault": "simulated intents only; no provider or vault API client"},
            "runtime_provider_log": str(child_log), "limitations": [
                "Typed process/version/compilation hashes are unchanged. Classified output/schema/citation/quality differences require semantic review before any production handler release or live migration.",
                "Frozen STT responses and source snapshots are raw injected fixture ports, not qualified live speech/model/provider behavior.",
                "Extracted feedback uses a bounded lexical detector and exact word/event overlap; uncertain component/source and missing timing remain degraded.",
                "The normalized process event type omits raw geometry; original root artifact refs and claim/receipt provenance remain retained.",
                "The original nine obligations require confirmed status/vault effects. simulated_processed and daily-note intents intentionally make no such production claim.",
                "Production adapter construction is disabled while supported native command and result authority remain absent.",
                "No Service Request or Case exists for the development SOP. Its implementation/testing/review are an explicitly bounded synthetic AST fixture, not a general coding agent or human approval.",
                "Public report structural validation and full output comparisons are separate. Historical thin reports remain explicitly incomplete; the development expectation is separately authored comparator data, not production semantic approval.",
                "The existing 62 categorized personal-review differences still require owner disposition; a passed unknown-divergence check does not approve them or qualify native authority or real effects.",
            ]}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--require-installed", action="store_true")
    args = parser.parse_args(argv)
    try:
        report = verify(args.fixtures, args.directory, require_installed=args.require_installed)
    except Exception as exc:
        report = {"schema": "review.independent-verification.v1", "status": "failed", "production_ready": False, "error_type": type(exc).__name__}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
