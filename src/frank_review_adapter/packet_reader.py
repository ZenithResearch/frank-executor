"""Explicit, read-only inspection of independent packet-v1/v2 profiles.

V1 preserves reported values; v2 recomputes its bounded processing/semantic policy.
Source-confidence and semantic confidence remain separate. References are inert;
this module grants no effects or authority and never adapts a legacy packet.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

from frank_executor.model import ID, Rejected, decode_json
from .ports import ReviewFailure
from .semantic import PACKET_FORMAT_V2, validate_v2_packet
from .quality import packet_quality

PACKET_FORMAT = "review.independent-packet.v1"
QUALITY = {"failed", "transcript_only", "needs_human_review", "needs_source_binding", "review_packet_ready"}
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
PACKET_FIELDS = {"schema", "transcript", "observations", "events", "component_names", "codebase_context",
                 "negative_evidence", "actionability", "implementation_handoff", "uncertainties", "quality"}
NEGATIVE_FIELDS = {"silent_annotations", "filtered_points", "discarded_events"}
ACTION_FIELDS = {"actionable_now", "design_preference", "discarded_or_filtered", "needs_human_clarification", "non_issue"}
HANDOFF_FIELDS = {"implementation_tasks", "files_to_inspect_first", "open_questions", "non_goals", "verification_notes"}


def require(condition, path):
    if not condition:
        # Diagnostics identify a structural field, never embed caller data.
        raise Rejected("Unsupported independent packet at " + path)


def record(value, fields, path):
    require(isinstance(value, dict) and set(value) == fields, path)
    return value


def text(value, path):
    require(isinstance(value, str), path)
    return value


def array(value, path):
    require(isinstance(value, list), path)
    return value


def texts(value, path):
    return [text(item, path) for item in array(value, path)]


def choice(value, allowed, path):
    text(value, path)
    require(value in allowed, path)


def integer(value, minimum, path):
    require(type(value) is int and value >= minimum, path)


def identity(value, path):
    text(value, path)
    require(bool(ID.fullmatch(value)), path)
    return value


def timing(value, path):
    record(value, {"start_ms", "end_ms"}, path)
    integer(value["start_ms"], 0, path + ".start_ms")
    integer(value["end_ms"], value["start_ms"], path + ".end_ms")


def source_reference(raw, path):
    ref = record(decode_json(text(raw, path)), {"path", "line", "content_hash", "selector", "text"}, path)
    require(bool(text(ref["path"], path + ".path")), path + ".path")
    integer(ref["line"], 1, path + ".line")
    require(bool(SHA256.fullmatch(text(ref["content_hash"], path + ".content_hash"))), path + ".content_hash")
    text(ref["selector"], path + ".selector")
    text(ref["text"], path + ".text")
    return ref


def _inspect_v1(raw: bytes, *, packet_format: str, expected_reference: dict | None = None) -> dict:
    """Admit only the selected v1 profile and return data for inert JSON display.

    ``expected_reference`` optionally binds these exact input bytes to an existing
    content reference. Neither that comparison nor admission authenticates origin.
    The returned ``packet`` retains the producer fields, including encoded strings.
    """
    require(packet_format == PACKET_FORMAT, "format")
    require(isinstance(raw, bytes), "input_bytes")
    packet = decode_json(raw)
    require(isinstance(packet, dict) and set(packet) in (PACKET_FIELDS, PACKET_FIELDS | {"review"}), "packet")
    choice(packet["schema"], {PACKET_FORMAT}, "schema")
    choice(packet["quality"], QUALITY, "quality")
    text(packet["transcript"], "transcript")
    texts(packet["uncertainties"], "uncertainties")
    reference = {"content_hash": hashlib.sha256(raw).hexdigest(), "byte_length": len(raw), "media_type": "application/json"}
    if expected_reference is not None:
        record(expected_reference, set(reference), "expected_reference")
        integer(expected_reference["byte_length"], 0, "expected_reference.byte_length")
        require(expected_reference == reference, "expected_reference")

    events = {}
    for event in array(packet["events"], "events"):
        record(event, {"event_index", "start_ms", "end_ms", "kind", "target"}, "events[]")
        integer(event["event_index"], 0, "events[].event_index")
        require(event["event_index"] not in events, "events[].event_index")
        timing({key: event[key] for key in ("start_ms", "end_ms")}, "events[]")
        text(event["kind"], "events[].kind")
        text(event["target"], "events[].target")
        events[event["event_index"]] = event
    for component in array(packet["component_names"], "component_names"):
        record(component, {"component", "selectors", "aliases", "source", "spatial_hint", "resolution_status"}, "component_names[]")
        for key in ("component", "source", "spatial_hint"):
            text(component[key], "component_names[]." + key)
        for key in ("selectors", "aliases"):
            texts(component[key], "component_names[]." + key)
        choice(component["resolution_status"], {"resolved", "unresolved"}, "component_names[].resolution_status")

    observations, evidence_by_id = {}, {}
    for item in array(packet["observations"], "observations"):
        record(item, {"observation_id", "type", "component", "selectors", "what_they_said", "issue", "evidence", "match_type"}, "observations[]")
        oid = identity(item["observation_id"], "observations[].observation_id")
        require(oid not in observations, "observations[].observation_id")
        choice(item["type"], {"feedback"}, "observations[].type")
        choice(item["match_type"], {"verbal_and_event", "unresolved"}, "observations[].match_type")
        for key in ("component", "what_they_said", "issue"):
            text(item[key], "observations[]." + key)
        texts(item["selectors"], "observations[].selectors")
        evidence = record(decode_json(text(item["evidence"], "observations[].evidence")),
                          {"quote", "timing", "event_indices", "component_resolution", "inference"}, "observations[].evidence")
        require(evidence["quote"] == item["what_they_said"], "observations[].evidence.quote")
        if evidence["timing"] is not None:
            timing(evidence["timing"], "observations[].evidence.timing")
        linked = array(evidence["event_indices"], "observations[].evidence.event_indices")
        for index in linked:
            integer(index, 0, "observations[].evidence.event_indices")
            require(index in events, "observations[].evidence.event_indices")
        require(len(set(linked)) == len(linked), "observations[].evidence.event_indices")
        choice(evidence["component_resolution"], {"resolved", "unresolved"}, "observations[].evidence.component_resolution")
        text(evidence["inference"], "observations[].evidence.inference")
        observations[oid], evidence_by_id[oid] = item, evidence

    contexts, references_by_id = {}, {}
    for context in array(packet["codebase_context"], "codebase_context"):
        record(context, {"observation_id", "component", "references", "likely_cause", "reasoning", "confidence", "caveats", "resolution_status"}, "codebase_context[]")
        oid = identity(context["observation_id"], "codebase_context[].observation_id")
        require(oid in observations and oid not in contexts, "codebase_context[].observation_id")
        for key in ("component", "likely_cause", "reasoning"):
            text(context[key], "codebase_context[]." + key)
        choice(context["confidence"], {"source_match_only", "low"}, "codebase_context[].confidence")
        choice(context["resolution_status"], {"verified", "deferred", "blocked"}, "codebase_context[].resolution_status")
        texts(context["caveats"], "codebase_context[].caveats")
        references_by_id[oid] = [source_reference(ref, "codebase_context[].references[]")
                                 for ref in array(context["references"], "codebase_context[].references")]
        contexts[oid] = context

    for name, fields in (("negative_evidence", NEGATIVE_FIELDS), ("actionability", ACTION_FIELDS),
                         ("implementation_handoff", HANDOFF_FIELDS)):
        for key, value in record(packet[name], fields, name).items():
            texts(value, name + "." + key)
    for key in ACTION_FIELDS - {"discarded_or_filtered"}:
        require(all(oid in observations for oid in packet["actionability"][key]), "actionability." + key)
    handoff_references = [source_reference(ref, "implementation_handoff.files_to_inspect_first[]")
                          for ref in packet["implementation_handoff"]["files_to_inspect_first"]]
    if "review" in packet:
        review = record(packet["review"], {"review_id", "subject_id", "submitted_by", "reviewed_at", "duration_ms"}, "review")
        for key in ("review_id", "subject_id", "submitted_by", "reviewed_at"):
            text(review[key], "review." + key)
        integer(review["duration_ms"], 0, "review.duration_ms")

    views = []
    notes = packet["implementation_handoff"]
    for oid, item in observations.items():
        context = contexts.get(oid)
        evidence = evidence_by_id[oid]
        views.append({
            "observation_id": oid, "reported_type": item["type"], "issue_category": {"state": "missing"},
            "what_they_said": item["what_they_said"], "reported_issue": item["issue"],
            "target": {"component": item["component"], "selectors": item["selectors"], "match_type": item["match_type"]},
            "evidence": evidence, "linked_event_indices": list(evidence["event_indices"]),
            "source_binding": {"state": "reported" if context is not None else "missing", "reported": context,
                               "decoded_references": references_by_id.get(oid, [])},
            "reported_confidence": context["confidence"] if context is not None else None,
            "reported_notes": {key: [note for note in notes[key] if note.startswith(oid + ": ")]
                               for key in ("open_questions", "verification_notes")},
            "missing_dimensions": ["issue_category", "confidence_basis", "semantic_eligibility_policy",
                                   "typed_triage_decision_and_reason", "root_input_artifact_references"],
        })
    return {"schema": "review.packet-inspection.v1", "admitted_format": PACKET_FORMAT,
            "scope": "read_only_inspection", "input_reference": reference,
            "expected_reference_checked": expected_reference is not None,
            "limitations": ["Admission validates this reader profile, not producer provenance or semantic truth.",
                            "Quality, confidence and actionability are reported values, never authorization.",
                            "Source references are inert data; no path, URL or reference is followed.",
                            "Root geometry/provenance and semantic eligibility require separate evidence."],
            "reported_quality": packet["quality"], "review_metadata_present": "review" in packet,
            "observations": views, "handoff_references": handoff_references, "packet": packet}


def inspect_packet(raw: bytes, *, packet_format: str, expected_reference: dict | None = None) -> dict:
    """Read only the explicitly selected profile. V1 is never inferred into v2."""
    if packet_format == PACKET_FORMAT:
        return _inspect_v1(raw, packet_format=packet_format, expected_reference=expected_reference)
    require(packet_format == PACKET_FORMAT_V2, "format")
    require(isinstance(raw, bytes), "input_bytes")
    packet = decode_json(raw)
    try:
        evidence, references = validate_v2_packet(packet)
        require(packet["quality"] in QUALITY and packet_quality(packet) == packet["quality"], "quality")
    except ReviewFailure as exc:
        raise Rejected("Unsupported independent packet at semantic_metadata") from exc
    reference = {"content_hash": hashlib.sha256(raw).hexdigest(), "byte_length": len(raw), "media_type": "application/json"}
    if expected_reference is not None:
        record(expected_reference, set(reference), "expected_reference")
        integer(expected_reference["byte_length"], 0, "expected_reference.byte_length")
        require(expected_reference == reference, "expected_reference")
    contexts = {row["observation_id"]: row for row in packet["codebase_context"]}
    views = []
    metadata = packet["semantic_metadata"]
    for item in packet["observations"]:
        oid = item["observation_id"]
        assessment = metadata["observations"][oid]
        context = contexts.get(oid)
        views.append({"observation_id": oid, "record_kind": assessment["record_kind"], "reported_type": item["type"],
                      "issue_category": {"state": "reported", "value": assessment["issue_category"], "basis": assessment["category_basis"]},
                      "what_they_said": item["what_they_said"], "reported_issue": item["issue"],
                      "target": {"component": item["component"], "selectors": item["selectors"], "match_type": item["match_type"]},
                      "evidence": evidence[oid], "linked_event_indices": list(evidence[oid]["event_indices"]),
                      "source_binding": {"state": "reported" if context else "missing", "reported": context, "decoded_references": references.get(oid, [])},
                      "reported_source_confidence": context["confidence"] if context else None,
                      "semantic_confidence": assessment["semantic_confidence"], "source_evidence": assessment["source_evidence"],
                      "layout_action": assessment["layout_action"],
                      "triage": assessment["triage"], "semantic_policy": {key: metadata[key] for key in ("policy_id", "scope", "stage")},
                      "reported_notes": {key: [note for note in packet["implementation_handoff"][key] if note.startswith(oid + ": ")]
                                         for key in ("open_questions", "verification_notes")},
                      "missing_dimensions": ["root_input_artifact_references"]})
    return {"schema": "review.packet-inspection.v1", "admitted_format": PACKET_FORMAT_V2,
            "scope": "read_only_inspection", "input_reference": reference, "expected_reference_checked": expected_reference is not None,
            "limitations": ["Admission validates this bounded policy profile, not producer provenance or semantic truth.",
                            "Planning eligibility is reported policy data: no ISS, fix, effects or authority grant.",
                            "Reported source-confidence is verbatim source data; semantic confidence remains unassessed.",
                            "References are inert; root input provenance is not reconstructed or followed."],
            "reported_quality": packet["quality"], "review_metadata_present": "review" in packet,
            "observations": views, "handoff_references": [source_reference(ref, "implementation_handoff.files_to_inspect_first[]")
                                                          for ref in packet["implementation_handoff"]["files_to_inspect_first"]],
            "packet": packet}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Inspect an explicitly selected independent review packet; no effects")
    parser.add_argument("--format", required=True, choices=[PACKET_FORMAT, PACKET_FORMAT_V2])
    parser.add_argument("--packet", required=True, type=Path, help="Explicit local JSON input; embedded references are never opened")
    args = parser.parse_args(argv)
    try:
        # Bound the only file read. The pure API accepts bytes and reads no files.
        with args.packet.open("rb") as stream:
            raw = stream.read(1024 * 1024 + 1)
        result = inspect_packet(raw, packet_format=args.format)
    except (Rejected, OSError):
        parser.exit(2, "Packet inspection rejected: unsupported/malformed packet or unreadable explicit input.\n")
    # JSON strings escape controls; this is not an HTML or Markdown renderer.
    print(json.dumps(result, ensure_ascii=True, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
