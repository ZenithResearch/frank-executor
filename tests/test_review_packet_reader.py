"""Read-only reader contract; retained producer bytes are never handler inputs."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

from frank_executor.model import Rejected, canonical
from frank_review_adapter.packet_reader import PACKET_FORMAT, inspect_packet, main

FIXTURES = Path(__file__).parent / "fixtures" / "review-packet-reader"
MANIFEST = json.loads((FIXTURES / "manifest.json").read_bytes())
INDEPENDENT = [row for row in MANIFEST["packets"] if row["kind"] != "legacy"]
LEGACY = [row for row in MANIFEST["packets"] if row["kind"] == "legacy"]


def load(row):
    raw = (FIXTURES / row["file"]).read_bytes()
    assert len(raw) == row["reference"]["byte_length"]
    assert hashlib.sha256(raw).hexdigest() == row["reference"]["content_hash"]
    return raw


def current():
    return json.loads(load(next(row for row in INDEPENDENT if row["kind"] == "current-v1"
                               and row["scenario"] == "source-available" and row["step"] == "step_7")))


@pytest.mark.parametrize("row", INDEPENDENT, ids=lambda row: row["file"])
def test_exact_initial_final_stored_and_current_packets(row):
    raw = load(row)
    expected = json.loads(raw)
    result = inspect_packet(raw, packet_format=PACKET_FORMAT, expected_reference=row["reference"])
    assert result["packet"] == expected
    assert result["input_reference"] == row["reference"]
    assert result["expected_reference_checked"] is True
    assert result["review_metadata_present"] == (row["step"] == "step_7")
    assert result["scope"] == "read_only_inspection"
    assert result["reported_quality"] == expected["quality"]
    for item, view in zip(expected["observations"], result["observations"], strict=True):
        assert view["what_they_said"] == item["what_they_said"]
        assert view["reported_type"] == item["type"] == "feedback"
        assert view["issue_category"] == {"state": "missing"}
        assert view["target"]["selectors"] == item["selectors"]
        evidence = json.loads(item["evidence"])
        assert view["evidence"] == evidence
        assert view["linked_event_indices"] == evidence["event_indices"]
        assert "linked_events" not in view
        assert all(any(event["event_index"] == index for event in result["packet"]["events"])
                   for index in view["linked_event_indices"])
        context = next((context for context in expected["codebase_context"]
                        if context["observation_id"] == item["observation_id"]), None)
        assert view["source_binding"]["reported"] == context
        assert view["source_binding"]["state"] == ("reported" if context else "missing")
        assert view["reported_confidence"] == (context["confidence"] if context else None)
        assert view["source_binding"]["decoded_references"] == ([json.loads(ref) for ref in context["references"]] if context else [])
        assert {"confidence_basis", "semantic_eligibility_policy", "root_input_artifact_references",
                "typed_triage_decision_and_reason"} <= set(view["missing_dimensions"])
    assert "feedback_items" not in result["packet"]
    assert "source_bindings" not in result["packet"]
    assert isinstance(result["reported_quality"], str)
    assert (FIXTURES / row["file"]).read_bytes() == raw


@pytest.mark.parametrize("row", LEGACY, ids=lambda row: row["file"])
def test_new_reader_explicitly_rejects_legacy_packets(row):
    with pytest.raises(Rejected):
        inspect_packet(load(row), packet_format=PACKET_FORMAT)


@pytest.fixture(scope="module")
def legacy_consumer():
    # Retained full helper bytes, unchanged. Its guarded main is not invoked.
    path = FIXTURES / "legacy_consumer.py"
    assert hashlib.sha256(path.read_bytes()).hexdigest() == "4ff112c8944c41d109be225349ea373e3164eea40f89b8b14b2c8637eff870c3"
    spec = importlib.util.spec_from_file_location("retained_legacy_packet_consumer", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("row,consumer", [(row, consumer) for row in LEGACY
                                         for consumer in ("summarize_packet", "validate_packet")],
                         ids=[row["file"] + ":" + consumer for row in LEGACY
                              for consumer in ("summarize_packet", "validate_packet")])
def test_eight_unchanged_legacy_positive_controls(row, consumer, legacy_consumer, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Legacy pure control attempted an effect/path load")
    monkeypatch.setattr(legacy_consumer, "http_json", forbidden)
    monkeypatch.setattr(legacy_consumer, "load_packet_from_path", forbidden)
    packet = json.loads(load(row))
    retained = json.loads((FIXTURES / "legacy-compatibility-results.json").read_bytes())
    expected = next(result for result in retained if result["packet"] == "legacy"
                    and result["consumer"] == consumer and result["scenario"] == row["scenario"]
                    and result["step"] == row["step"])
    assert expected["status"] == "returned"
    before = copy.deepcopy(packet)
    kwargs = {"expect_status": packet["quality"]["status"]} if consumer == "validate_packet" else {}
    assert getattr(legacy_consumer, consumer)(packet, **kwargs) == expected["result"]
    assert packet == before


def test_selection_required_and_never_autodetected():
    raw = canonical(current())
    with pytest.raises(TypeError):
        inspect_packet(raw)
    for selected in (None, "", "schema_version=2", "review.independent-packet.v2"):
        with pytest.raises(Rejected):
            inspect_packet(raw, packet_format=selected)


# Each mutation changes one admitted type/identity/status boundary, without
# changing the producer or using a comparison golden as execution input.
SHAPE_MUTATIONS = [
    (("schema",), "review.independent-packet.v2"),
    (("quality",), {"status": "review_packet_ready"}),
    (("quality",), "approved"),
    (("observations", 0, "type"), "layout"),
    (("observations", 0, "observation_id"), "bad identity /"),
    (("observations", 0, "selectors"), "button.review-dismiss"),
    (("observations", 0, "what_they_said"), None),
    (("observations", 0, "match_type"), "verified"),
    (("events", 0, "event_index"), True),
    (("events", 0, "start_ms"), 0.0),
    (("events", 0, "end_ms"), -1),
    (("events", 0, "kind"), {}),
    (("component_names", 0, "resolution_status"), "candidate"),
    (("codebase_context", 0, "observation_id"), "missing-observation"),
    (("codebase_context", 0, "resolution_status"), "approved"),
    (("codebase_context", 0, "confidence"), "high"),
    (("codebase_context", 0, "references"), "view.tsx"),
    (("negative_evidence", "silent_annotations"), [dict(issue="invented")]),
    (("actionability", "actionable_now"), ["missing-observation"]),
    (("implementation_handoff", "implementation_tasks"), [dict(command="run")]),
    (("implementation_handoff", "non_goals"), "missing list"),
    (("review", "duration_ms"), True),
    (("review", "review_id"), {}),
    (("uncertainties",), [None]),
]


@pytest.mark.parametrize("path,value", SHAPE_MUTATIONS, ids=[".".join(map(str, path)) for path, _ in SHAPE_MUTATIONS])
def test_malformed_type_status_identity_boundaries(path, value):
    packet = current()
    target = packet
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(Rejected):
        inspect_packet(canonical(packet), packet_format=PACKET_FORMAT)


@pytest.mark.parametrize("boundary", ["observation", "event", "context", "extra_field", "missing_field"])
def test_duplicate_identities_and_unsupported_shape(boundary):
    packet = current()
    if boundary in {"observation", "event", "context"}:
        key = {"observation": "observations", "event": "events", "context": "codebase_context"}[boundary]
        packet[key].append(copy.deepcopy(packet[key][0]))
    elif boundary == "extra_field":
        packet["feedback_items"] = []
    else:
        del packet["negative_evidence"]
    with pytest.raises(Rejected):
        inspect_packet(canonical(packet), packet_format=PACKET_FORMAT)


@pytest.mark.parametrize("field,value", [("quote", "changed speech"), ("event_indices", [999]),
                                        ("event_indices", [True]), ("event_indices", [0, 0]),
                                        ("timing", {"start_ms": False, "end_ms": 1})])
def test_evidence_quote_timing_and_event_links(field, value):
    packet = current()
    evidence = json.loads(packet["observations"][0]["evidence"])
    evidence[field] = value
    packet["observations"][0]["evidence"] = canonical(evidence).decode()
    with pytest.raises(Rejected):
        inspect_packet(canonical(packet), packet_format=PACKET_FORMAT)


@pytest.mark.parametrize("field,value", [("path", ""), ("path", []), ("line", True), ("line", 0),
                                        ("content_hash", "not-a-digest"), ("selector", None)])
def test_malformed_references_fail_in_both_locations(field, value):
    packet = current()
    ref = json.loads(packet["codebase_context"][0]["references"][0])
    ref[field] = value
    for location in ("context", "handoff"):
        malformed = copy.deepcopy(packet)
        if location == "context":
            malformed["codebase_context"][0]["references"] = [canonical(ref).decode()]
        else:
            malformed["implementation_handoff"]["files_to_inspect_first"] = [canonical(ref).decode()]
        with pytest.raises(Rejected):
            inspect_packet(canonical(malformed), packet_format=PACKET_FORMAT)


@pytest.mark.parametrize("raw", [b'{"schema":1,"schema":2}', b'{"x":NaN}', b'[]', b'{', b' ' * (1024 * 1024 + 1)])
def test_strict_json_and_bounds(raw):
    with pytest.raises(Rejected):
        inspect_packet(raw, packet_format=PACKET_FORMAT)


@pytest.mark.parametrize("field,value", [("content_hash", "0" * 64), ("byte_length", True),
                                        ("byte_length", 1), ("media_type", "text/plain")])
def test_exact_input_reference_mismatch(field, value):
    raw = canonical(current())
    ref = {"content_hash": hashlib.sha256(raw).hexdigest(), "byte_length": len(raw), "media_type": "application/json"}
    ref[field] = value
    with pytest.raises(Rejected):
        inspect_packet(raw, packet_format=PACKET_FORMAT, expected_reference=ref)


def test_hostile_text_opaque_strings_and_references_are_inert(monkeypatch):
    import builtins
    import socket
    import sqlite3
    import subprocess
    from urllib import request

    packet = current()
    hostile = '</code><script>alert(1)</script> [x](https://invalid.test)\n``` /private/no-read'
    packet["observations"][0]["what_they_said"] = hostile
    evidence = json.loads(packet["observations"][0]["evidence"])
    evidence["quote"] = hostile
    packet["observations"][0]["evidence"] = canonical(evidence).decode()
    ref = json.loads(packet["codebase_context"][0]["references"][0])
    ref["path"], ref["text"] = hostile, hostile
    packet["codebase_context"][0]["references"] = [canonical(ref).decode()]
    packet["implementation_handoff"]["files_to_inspect_first"] = [canonical(ref).decode()]
    packet["negative_evidence"]["silent_annotations"] = [hostile]
    packet["actionability"]["discarded_or_filtered"] = [hostile]
    packet["implementation_handoff"]["implementation_tasks"] = [hostile]
    packet["review"]["review_id"] = hostile  # display metadata, not a command principal
    raw = canonical(packet)
    def forbidden(*args, **kwargs):
        raise AssertionError("Pure packet inspection attempted an effect")
    with monkeypatch.context() as guard:
        for target, name in ((builtins, "open"), (Path, "open"), (socket, "create_connection"),
                             (sqlite3, "connect"), (subprocess, "Popen"), (request, "urlopen")):
            guard.setattr(target, name, forbidden)
        result = inspect_packet(raw, packet_format=PACKET_FORMAT)
    assert result["packet"] == packet
    assert result["observations"][0]["what_they_said"] == hostile
    assert result["observations"][0]["source_binding"]["decoded_references"][0]["path"] == hostile
    assert result["handoff_references"] == [ref]


def test_historical_actionability_and_confidence_are_not_promoted():
    row = next(row for row in INDEPENDENT if row["kind"] == "stored-v1"
               and row["scenario"] == "source-available" and row["step"] == "step_7")
    result = inspect_packet(load(row), packet_format=PACKET_FORMAT)
    assert result["packet"]["actionability"]["actionable_now"]
    assert result["reported_quality"] == "review_packet_ready"
    assert result["observations"][0]["reported_confidence"] == "source_match_only"
    assert "semantic_eligibility_policy" in result["observations"][0]["missing_dimensions"]
    assert "authorization" in result["limitations"][1]
    assert set(result).isdisjoint({"approved", "eligible", "confidence", "triage"})


def test_cli_reads_only_explicit_input_and_outputs_json(tmp_path, capsys, monkeypatch):
    packet = current()
    explicit = tmp_path / "packet.json"
    explicit.write_bytes(canonical(packet))
    original = Path.open
    reads = []
    def only_explicit(path, mode="r", *args, **kwargs):
        assert path == explicit and mode == "rb"
        reads.append(path)
        return original(path, mode, *args, **kwargs)
    with monkeypatch.context() as guard:
        guard.setattr(Path, "open", only_explicit)
        assert main(["--format", PACKET_FORMAT, "--packet", str(explicit)]) == 0
    assert reads == [explicit]
    assert json.loads(capsys.readouterr().out)["packet"] == packet


@pytest.mark.parametrize("argv", [["--packet", "unused"], ["--format", "legacy", "--packet", "unused"]])
def test_cli_requires_explicit_admitted_format(argv):
    with pytest.raises(SystemExit) as stopped:
        main(argv)
    assert stopped.value.code == 2


def test_shared_large_event_does_not_amplify_inspection_output():
    # A structurally admitted <1 MiB input may link many observations to one
    # large event. Event bodies belong once in packet.events, never per view.
    packet = current()
    large_target = "T" * 500_000
    packet["events"] = [dict(packet["events"][0], target=large_target)]
    prototype = packet["observations"][0]
    observations = []
    for index in range(1000):
        item = copy.deepcopy(prototype)
        item["observation_id"] = f"observation-shared-{index}"
        evidence = json.loads(item["evidence"])
        evidence["event_indices"] = [packet["events"][0]["event_index"]]
        item["evidence"] = canonical(evidence).decode()
        observations.append(item)
    packet["observations"] = observations
    packet["codebase_context"] = []
    packet.pop("review")
    packet["quality"] = "needs_human_review"
    packet["actionability"] = {key: [] for key in packet["actionability"]}
    packet["implementation_handoff"] = {key: [] for key in packet["implementation_handoff"]}
    raw = canonical(packet)
    assert len(raw) < 1024 * 1024
    result = inspect_packet(raw, packet_format=PACKET_FORMAT)
    assert result["packet"] == packet
    event_index = packet["events"][0]["event_index"]
    assert len(result["observations"]) == 1000
    assert all(view["linked_event_indices"] == [event_index] and "linked_events" not in view
               for view in result["observations"])
    rendered = json.dumps(result, ensure_ascii=True, indent=2, allow_nan=False)
    assert rendered.count(large_target) == 1
    assert len(rendered.encode()) < 8 * 1024 * 1024
