"""Canonical v2 producer/consumer policy controls; no provider, runtime or effects."""
import asyncio
from copy import deepcopy
import json
from pathlib import Path

import pytest

from frank_executor.model import Rejected, canonical
from frank_review_adapter import ReviewAdapter, ReviewPorts
from frank_review_adapter.fixture_ports import (MemoryArtifacts, FrozenSTT, SnapshotSources,
    SimulatedIntents, SyntheticClaims, SyntheticResults)
from frank_review_adapter.packet_reader import PACKET_FORMAT, PACKET_FORMAT_V2, inspect_packet, main
from frank_review_adapter.ports import ReviewFailure
from frank_review_adapter.quality import packet_quality

ROOT = Path(__file__).parent
FIXTURES = ROOT / "fixtures/independent-review"
INPUTS = json.loads((FIXTURES / "inputs.json").read_bytes())
REVIEW = json.loads((FIXTURES / "personal-review-v1.json").read_bytes())
V1 = ROOT / "fixtures/review-packet-reader"


async def send(adapter, ports, state, index, suffix=""):
    step = REVIEW["steps"][index]
    work = {"schema": "frank.work.v1", "binding": {"run_id": "semantic-run", "step_id": step["step_id"],
            "attempt_id": "semantic-attempt", "fence": 1}, "actor_id": "worker", "integration_id": "semantic-test",
            "route": "local", "effect_id": "semantic-" + step["step_id"] + suffix, "operation": step["capabilities"][0],
            "scope": "test", "inputs": {k: state[k] for k in step["inputs"]}, "output_types": step["outputs"]}
    ports.claims.confirm(work)
    return await adapter.send(work)


async def produce(quote="This button is not centered.", mode="verified"):
    source = deepcopy(INPUTS)
    if mode == "deferred":
        source["source_snapshot"] = {}
    if mode == "contradictory_location":
        source["source_snapshot"] = {source["subject_id"]: {"other.tsx": "\n" * 8 + '<button className="review-dismiss" />'}}
    if mode == "separate_targets":
        source["source_snapshot"][source["subject_id"]]["secondary.tsx"] = '<button className="review-secondary" />'
    if mode == "conflicting":
        source["source_snapshot"][source["subject_id"]]["other.tsx"] = '<button className="review-dismiss" />'
    snapshots = SnapshotSources(source["source_snapshot"])
    ports = ReviewPorts(MemoryArtifacts(), FrozenSTT(b"audio", source["stt_response"]), snapshots,
                        snapshots, SimulatedIntents(), SyntheticClaims(), SyntheticResults())
    adapter = ReviewAdapter("semantic-test", {"effects": "disabled", "route": "local"}, ports=ports, environment="test")
    await adapter.connect()
    words = [{"text": word, "start_ms": n * 50, "end_ms": n * 50 + 40} for n, word in enumerate(quote.split())]
    component = {"component": "button.review-dismiss", "selectors": ["button.review-dismiss"], "aliases": [],
                 "source": "view.tsx:1", "spatial_hint": "", "resolution_status": "unresolved" if mode == "blocked" else "resolved"}
    events = [{"event_index": 7, "start_ms": 0, "end_ms": max(40, len(words) * 50), "kind": "click", "target": "button.review-dismiss"}]
    if mode == "general":
        events, components = [], []
    else:
        components = [component]
    if mode == "separate_targets":
        boundary = len(quote.split(". ", 1)[0].split()) * 50
        events[0]["end_ms"] = boundary - 10
        events.append({"event_index": 11, "start_ms": boundary, "end_ms": len(words) * 50,
                       "kind": "click", "target": "button.review-secondary"})
        components.append({**component, "component": "button.review-secondary", "selectors": ["button.review-secondary"], "source": "secondary.tsx:1"})
    if mode == "silent":
        events.append({"event_index": 11, "start_ms": 5000, "end_ms": 5000, "kind": "stroke", "target": "button.review-dismiss"})
    state = {key: source[key] for key in ("review_id", "subject_id", "submitted_by", "reviewed_at", "duration_ms")}
    state.update(resolved_transcript=quote, words=words, events=events, component_names=components,
                 transcript_note=await ports.artifacts.write(b"unit annotation", "text/plain"))
    for index in (4, 5, 6):
        result = await send(adapter, ports, state, index)
        assert result["outcome"] == "succeeded", adapter.decisions
        state.update(result["outputs"])
        if index == 4:
            initial_reference = deepcopy(state["review_packet"])
            initial_raw = await ports.artifacts.read(initial_reference)
    final_raw = await ports.artifacts.read(state["review_packet"])
    assert final_raw != initial_raw and await ports.artifacts.read(initial_reference) == initial_raw
    assert ports.stt.calls == 0 and ports.intents.intents == []
    return adapter, ports, state, initial_raw, final_raw


@pytest.mark.parametrize("mode,decision,reason", [
    ("verified", "planning_eligible", "supported_layout_and_binding"),
    ("deferred", "not_eligible", "source_deferred"),
    ("blocked", "not_eligible", "target_unresolved"),
    ("conflicting", "not_eligible", "source_conflicting"),
    ("general", "not_eligible", "target_unresolved"),
])
def test_canonical_initial_final_policy_is_stage_and_source_specific(mode, decision, reason):
    async def run():
        _, ports, _, initial_raw, final_raw = await produce(mode=mode)
        initial, final = json.loads(initial_raw), json.loads(final_raw)
        assert initial["schema"] == final["schema"] == PACKET_FORMAT_V2
        assert initial["observations"] == final["observations"]
        assert initial["negative_evidence"] == final["negative_evidence"]
        oid = final["observations"][0]["observation_id"]
        a, b = (packet["semantic_metadata"]["observations"][oid] for packet in (initial, final))
        assert a["record_kind"] == b["record_kind"] == "feedback"
        assert a["issue_category"] == b["issue_category"] == "layout"
        assert a["semantic_confidence"] == b["semantic_confidence"]
        assert b["semantic_confidence"]["state"] == "unassessed"
        assert a["triage"]["reason"] == ("target_unresolved" if mode in {"blocked", "general"} else "source_pending")
        assert a["triage"]["decision"] == "not_eligible"
        assert b["triage"]["decision"] == decision and b["triage"]["reason"] == reason
        expected = [oid] if decision == "planning_eligible" else []
        assert final["actionability"]["actionable_now"] == expected
        assert final["actionability"]["needs_human_clarification"] == ([] if expected else [oid])
        assert not final["implementation_handoff"]["implementation_tasks"]
        if expected:
            assert not any(note.startswith(oid + ": ") for note in final["implementation_handoff"]["open_questions"])
        for raw in (initial_raw, final_raw):
            view = inspect_packet(raw, packet_format=PACKET_FORMAT_V2)
            assert view["packet"] == json.loads(raw)
            assert view["observations"][0]["linked_event_indices"] == ([] if mode == "general" else [7])
            assert "root_input_artifact_references" in view["observations"][0]["missing_dimensions"]
        context = final["codebase_context"][0]
        assert context["confidence"] == ("source_match_only" if context["resolution_status"] == "verified" else "low")
        assert inspect_packet(final_raw, packet_format=PACKET_FORMAT_V2)["observations"][0]["reported_source_confidence"] == context["confidence"]
        assert ports.intents.intents == []
    asyncio.run(run())


@pytest.mark.parametrize("quote,decision,reason,category", [
    ("Please center this button.", "planning_eligible", "supported_layout_and_binding", "layout"),
    ("The button is misaligned.", "planning_eligible", "supported_layout_and_binding", "layout"),
    ("Align the button to the left.", "planning_eligible", "supported_layout_and_binding", "layout"),
    ("I prefer this button centered.", "design_preference", "explicit_preference", "layout"),
    ("This button looks great.", "non_issue", "explicit_non_issue", "unknown"),
    ("This is centered correctly.", "non_issue", "explicit_non_issue", "layout"),
    ("There is no issue with this button.", "non_issue", "explicit_non_issue", "unknown"),
    ("Do not center this button.", "not_eligible", "explicit_refusal", "layout"),
    ("Should this button be centered?", "not_eligible", "unsupported_intent", "layout"),
    ("This button is not centered correctly.", "not_eligible", "unsupported_intent", "layout"),
    ("Please center this button but maybe leave it.", "not_eligible", "unsupported_intent", "layout"),
    ("This button needs contrast.", "not_eligible", "unsupported_intent", "unknown"),
])
def test_finite_speech_policy_has_positive_and_negative_precedence(quote, decision, reason, category):
    async def run():
        _, ports, _, _, raw = await produce(quote)
        packet = json.loads(raw)
        oid = packet["observations"][0]["observation_id"]
        row = packet["semantic_metadata"]["observations"][oid]
        assert packet["observations"][0]["what_they_said"] == packet["observations"][0]["issue"] == quote
        assert row["issue_category"] == category and row["triage"]["decision"] == decision and row["triage"]["reason"] == reason
        bucket = {"planning_eligible": "actionable_now", "design_preference": "design_preference", "non_issue": "non_issue"}.get(decision, "needs_human_clarification")
        assert packet["actionability"][bucket] == [oid]
        assert sum(oid in packet["actionability"][name] for name in ("actionable_now", "design_preference", "non_issue", "needs_human_clarification")) == 1
        assert packet_quality(packet) == "review_packet_ready"  # Processing quality alone is insufficient.
        assert inspect_packet(raw, packet_format=PACKET_FORMAT_V2)["observations"][0]["triage"] == row["triage"]
        assert ports.intents.intents == []
    asyncio.run(run())


@pytest.mark.parametrize("quote", ["Centered?", "Not centered.", "This button needs"])
def test_fragments_stay_negative_evidence_without_invented_observations(quote):
    async def run():
        _, _, _, initial_raw, final_raw = await produce(quote)
        packet = json.loads(final_raw)
        assert packet["observations"] == [] and packet["semantic_metadata"]["observations"] == {}
        assert packet["quality"] == "transcript_only"
        assert packet["actionability"]["actionable_now"] == []
        assert any(json.loads(point)["quote"] == quote for point in packet["negative_evidence"]["filtered_points"])
        assert packet["negative_evidence"] == json.loads(initial_raw)["negative_evidence"]
        inspect_packet(final_raw, packet_format=PACKET_FORMAT_V2)
    asyncio.run(run())


def test_later_silent_gesture_and_unknown_source_ready_speech_never_become_planning_tasks():
    async def run():
        _, _, _, _, raw = await produce("This button needs contrast.", "silent")
        packet = json.loads(raw)
        assert packet["actionability"]["actionable_now"] == [] and packet["implementation_handoff"]["implementation_tasks"] == []
        silent = packet["negative_evidence"]["silent_annotations"]
        assert len(silent) == 1 and json.loads(silent[0])["event"]["event_index"] == 11
        assert packet["actionability"]["discarded_or_filtered"] == silent
    asyncio.run(run())


@pytest.mark.parametrize("mutation", ["policy", "scope", "coverage", "extra_id", "stage", "category", "confidence", "reported_confidence",
                                       "source_state", "reason", "contradictory_bucket", "stale_question", "cross_context", "cross_reference", "source_hash", "event_link", "wrong_quality", "numeric_type", "record_type", "malformed_id"])
def test_v2_reader_rejects_malformed_or_cross_record_metadata(mutation):
    async def make():
        return (await produce())[4]
    packet = json.loads(asyncio.run(make()))
    oid = packet["observations"][0]["observation_id"]
    sem = packet["semantic_metadata"]; row = sem["observations"][oid]
    if mutation == "policy": sem["policy_id"] = "unknown"
    elif mutation == "scope": sem["scope"] = "execute_fixes"
    elif mutation == "coverage": sem["observations"].clear()
    elif mutation == "extra_id": sem["observations"]["foreign"] = deepcopy(row)
    elif mutation == "stage": sem["stage"] = "initial"
    elif mutation == "category": row["issue_category"] = "interaction"
    elif mutation == "confidence": row["semantic_confidence"]["state"] = "high"
    elif mutation == "reported_confidence": row["source_evidence"]["reported_source_confidence"] = "high"
    elif mutation == "source_state": row["source_evidence"]["binding_state"] = "pending"
    elif mutation == "reason": row["triage"]["reason"] = "source_pending"
    elif mutation == "contradictory_bucket": packet["actionability"]["needs_human_clarification"] = [oid]
    elif mutation == "stale_question": packet["implementation_handoff"]["open_questions"] = [oid + ": Semantic review remains needed"]
    elif mutation == "cross_context": packet["codebase_context"][0]["observation_id"] = "foreign"
    elif mutation in {"cross_reference", "source_hash"}:
        ref = json.loads(packet["codebase_context"][0]["references"][0]);ref["selector" if mutation == "cross_reference" else "content_hash"] = "foreign"
        packet["codebase_context"][0]["references"][0] = canonical(ref).decode()
    elif mutation == "event_link":
        ev = json.loads(packet["observations"][0]["evidence"]);ev["event_indices"] = [999];packet["observations"][0]["evidence"] = canonical(ev).decode()
    elif mutation == "wrong_quality": packet["quality"] = "needs_source_binding"
    elif mutation == "numeric_type": row["source_evidence"]["reference_count"] = True
    elif mutation == "record_type": packet["observations"][0]["type"] = "layout"
    elif mutation == "malformed_id": packet["observations"][0]["observation_id"] = "_invalid"
    with pytest.raises(Rejected): inspect_packet(canonical(packet), packet_format=PACKET_FORMAT_V2)


@pytest.mark.parametrize("scenario", ["source-available", "source-unavailable"])
def test_retained_v1_initial_writer_stays_v1_and_exact_old_final(scenario):
    async def run():
        adapter, ports, state, _, _ = await produce()
        initial_raw = (V1 / f"current-v1-{scenario}-step_5.json").read_bytes()
        expected_raw = (V1 / f"current-v1-{scenario}-step_7.json").read_bytes()
        old_final = json.loads(expected_raw)
        state.update(old_final["review"])
        state.update(resolved_transcript=old_final["transcript"], observations=old_final["observations"], codebase_context=old_final["codebase_context"])
        state["review_packet"] = await ports.artifacts.write(initial_raw, "application/json")
        # A distinct exact synthetic claim/effect permits this separate compatibility work.
        step = REVIEW["steps"][6]
        work = {"schema": "frank.work.v1", "binding": {"run_id": "old-run", "step_id": "step_7", "attempt_id": "old-attempt", "fence": 1},
                "actor_id": "worker", "integration_id": "semantic-test", "route": "local", "effect_id": "v1-compat", "operation": step["capabilities"][0],
                "scope": "test", "inputs": {k: state[k] for k in step["inputs"]}, "output_types": step["outputs"]}
        ports.claims.confirm(work); result = await adapter.send(work)
        assert result["outcome"] == "succeeded"
        raw = await ports.artifacts.read(result["outputs"]["review_packet"])
        assert raw == expected_raw and "semantic_metadata" not in json.loads(raw)
        assert await ports.artifacts.read(state["review_packet"]) == initial_raw
        assert inspect_packet(raw, packet_format=PACKET_FORMAT)["packet"] == old_final
        with pytest.raises(Rejected): inspect_packet(raw, packet_format=PACKET_FORMAT_V2)
        assert ports.intents.intents == []
    asyncio.run(run())


def test_explicit_v2_cli_selection_and_v1_format_never_fall_through(tmp_path, capsys):
    raw = asyncio.run(produce())[4]
    path = tmp_path / "explicit.json";path.write_bytes(raw)
    assert main(["--format", PACKET_FORMAT_V2, "--packet", str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["admitted_format"] == PACKET_FORMAT_V2
    with pytest.raises(Rejected): inspect_packet(raw, packet_format=PACKET_FORMAT)
    for args in (["--packet", str(path)], ["--format", "unknown", "--packet", str(path)]):
        with pytest.raises(SystemExit) as stopped: main(args)
        assert stopped.value.code == 2


def test_forged_v2_metadata_fails_before_status_intent():
    async def run():
        adapter, ports, state, _, raw = await produce()
        packet = json.loads(raw);packet["semantic_metadata"]["policy_id"] = "unrecognized"
        state["review_packet"] = await ports.artifacts.write(canonical(packet), "application/json")
        result = await send(adapter, ports, state, 7)
        assert result["outcome"] == "failed" and result["outputs"] == {}
        assert adapter.decisions[-1]["code"] == "malformed_semantic_packet" and ports.intents.intents == []
    asyncio.run(run())


def test_new_semantics_and_untrusted_text_are_inside_fenced_human_blocks():
    async def run():
        adapter, ports, state, _, raw = await produce('This button needs <script>x</script> [fix](javascript:1) ```')
        packet = json.loads(raw);note = (await ports.artifacts.read(state["review_note"])).decode()
        blocks, body, fence = [], [], None
        for line in note.splitlines():
            if fence is None and line.endswith("text") and set(line[:-4]) == {"`"}:
                fence, body = line[:-4], []
            elif fence is not None and line == fence:
                blocks.append("\n".join(body)); fence = None
            elif fence is not None: body.append(line)
        assert fence is None
        assert "Reported source-confidence and location evidence" in note
        assert canonical(packet["semantic_metadata"]).decode() in blocks
        assert packet["transcript"] in blocks
        assert all(goal in note for goal in packet["implementation_handoff"]["non_goals"])
        assert ports.intents.intents == []
    asyncio.run(run())


def test_same_target_explicit_reversal_blocks_the_other_positive_utterance():
    async def run():
        _, _, _, _, raw = await produce("Please center this button. Do not center this button.")
        packet = json.loads(raw)
        assert len(packet["observations"]) == 2 and packet["actionability"]["actionable_now"] == []
        first, second = packet["observations"]
        rows = packet["semantic_metadata"]["observations"]
        assert rows[first["observation_id"]]["triage"]["reason"] == "conflicting_intent"
        assert rows[second["observation_id"]]["triage"]["reason"] == "explicit_refusal"
        inspect_packet(raw, packet_format=PACKET_FORMAT_V2)
    asyncio.run(run())


def test_unknown_packet_writer_profile_fails_before_any_output_write():
    async def run():
        adapter, ports, state, initial_raw, _ = await produce()
        unknown = json.loads(initial_raw); unknown["schema"] = "review.unknown.v9"
        state["review_packet"] = await ports.artifacts.write(canonical(unknown), "application/json")
        before = deepcopy(ports.artifacts.contents)
        result = await send(adapter, ports, state, 6, suffix="-unknown-profile")
        assert result["outcome"] == "failed" and result["outputs"] == {}
        assert ports.artifacts.contents == before and ports.intents.intents == []
    asyncio.run(run())


def test_duplicate_v2_json_fields_are_rejected_without_profile_guessing():
    raw = asyncio.run(produce())[4]
    marker = b'"schema":"review.independent-packet.v2"'
    assert raw.count(marker) == 1
    duplicate = raw.replace(marker, marker + b',' + marker, 1)
    with pytest.raises(Rejected): inspect_packet(duplicate, packet_format=PACKET_FORMAT_V2)


def test_cross_observation_assessments_cannot_be_swapped_with_matching_buckets():
    raw = asyncio.run(produce("This button is not centered. This button needs contrast."))[4]
    packet = json.loads(raw); first, second = [x["observation_id"] for x in packet["observations"]]
    rows = packet["semantic_metadata"]["observations"]
    rows[first], rows[second] = rows[second], rows[first]
    packet["actionability"]["actionable_now"] = [second]
    packet["actionability"]["needs_human_clarification"] = [first]
    with pytest.raises(Rejected): inspect_packet(canonical(packet), packet_format=PACKET_FORMAT_V2)


def test_malformed_returned_source_reference_is_a_failed_write_not_an_intent():
    async def run():
        adapter, ports, state, initial_raw, _ = await produce()
        state["review_packet"] = await ports.artifacts.write(initial_raw, "application/json")
        ref = json.loads(state["codebase_context"][0]["references"][0]); ref["line"] = True
        state["codebase_context"][0]["references"][0] = canonical(ref).decode()
        before = deepcopy(ports.artifacts.contents)
        result = await send(adapter, ports, state, 6, suffix="-malformed-source")
        assert result["outcome"] == "failed" and result["outputs"] == {}
        assert ports.artifacts.contents == before and ports.intents.intents == []
    asyncio.run(run())


@pytest.mark.parametrize("quote,eligible_count,first_reason,second_reason", [
    ("Please center this button. Never center this button.", 0, "conflicting_intent", "explicit_refusal"),
    ("Never center this button. Please center this button.", 0, "explicit_refusal", "conflicting_intent"),
    ("Align this button left. Never align this button left.", 0, "conflicting_intent", "explicit_refusal"),
    ("Never align this button left. Align this button left.", 0, "explicit_refusal", "conflicting_intent"),
    ("Align this button left. Align this button right.", 0, "conflicting_intent", "conflicting_intent"),
    ("Align the button to the left. Align the button to the right.", 0, "conflicting_intent", "conflicting_intent"),
    ("This button is not centered. This button is centered correctly.", 0, "conflicting_intent", "explicit_non_issue"),
    ("This button is centered correctly. This button is not centered.", 0, "explicit_non_issue", "conflicting_intent"),
    ("Please center this button. Please center this button.", 2, "supported_layout_and_binding", "supported_layout_and_binding"),
    ("Align this button left. Align this button left.", 2, "supported_layout_and_binding", "supported_layout_and_binding"),
    ("This button is not centered. This button looks great.", 1, "supported_layout_and_binding", "explicit_non_issue"),
    ("Align this button left. Never align this button.", 0, "conflicting_intent", "explicit_refusal"),
    ("Never align this button. Align this button left.", 0, "explicit_refusal", "conflicting_intent"),
])
def test_bounded_same_target_actions_keep_all_speech_and_resolve_no_conflicts(quote, eligible_count, first_reason, second_reason):
    async def run():
        _, ports, _, initial_raw, final_raw = await produce(quote)
        initial, final = json.loads(initial_raw), json.loads(final_raw)
        utterances = [x["what_they_said"] for x in final["observations"]]
        assert utterances == [x + "." for x in quote.rstrip(".").split(". ")]
        assert final["observations"] == initial["observations"] and len(utterances) == 2
        ids = [x["observation_id"] for x in final["observations"]]
        assert len(final["actionability"]["actionable_now"]) == eligible_count
        assert [final["semantic_metadata"]["observations"][oid]["triage"]["reason"] for oid in ids] == [first_reason, second_reason]
        assert initial["actionability"]["actionable_now"] == []
        for raw in (initial_raw, final_raw):
            view = inspect_packet(raw, packet_format=PACKET_FORMAT_V2)
            assert view["packet"]["transcript"] == quote
            assert [x["what_they_said"] for x in view["observations"]] == utterances
        assert final["implementation_handoff"]["implementation_tasks"] == [] and ports.intents.intents == []
    asyncio.run(run())


@pytest.mark.parametrize("quote", [
    "This button looks great, yet the alignment is wrong.",
    "I prefer this button centered, plus the alignment is wrong.",
    "This button looks great and the alignment is wrong.",
    "I prefer this button centered and the alignment is wrong.",
])
def test_complete_negative_rules_cannot_hide_an_unrecognized_compound(quote):
    async def run():
        _, ports, _, _, raw = await produce(quote)
        packet = json.loads(raw); oid = packet["observations"][0]["observation_id"]
        assert packet["observations"][0]["what_they_said"] == quote
        assert packet["semantic_metadata"]["observations"][oid]["triage"]["reason"] == "unsupported_intent"
        assert packet["actionability"]["non_issue"] == packet["actionability"]["design_preference"] == packet["actionability"]["actionable_now"] == []
        assert inspect_packet(raw, packet_format=PACKET_FORMAT_V2)["observations"][0]["what_they_said"] == quote
        assert ports.intents.intents == [] and packet["implementation_handoff"]["implementation_tasks"] == []
    asyncio.run(run())


@pytest.mark.parametrize("mode,expected_reason", [("verified", "supported_layout_and_binding"), ("contradictory_location", "source_conflicting")])
def test_single_source_location_must_match_the_retained_component_pointer(mode, expected_reason):
    async def run():
        _, ports, _, initial_raw, raw = await produce(mode=mode)
        packet = json.loads(raw); oid = packet["observations"][0]["observation_id"]
        reference = json.loads(packet["codebase_context"][0]["references"][0])
        assert len(packet["codebase_context"][0]["references"]) == 1
        assert packet["component_names"][0]["source"] == "view.tsx:1"
        assert (reference["path"], reference["line"]) == (("view.tsx", 1) if mode == "verified" else ("other.tsx", 9))
        assessment = packet["semantic_metadata"]["observations"][oid]
        assert assessment["triage"]["reason"] == expected_reason
        assert packet["actionability"]["actionable_now"] == ([oid] if mode == "verified" else [])
        assert inspect_packet(raw, packet_format=PACKET_FORMAT_V2)["observations"][0]["source_evidence"] == assessment["source_evidence"]
        assert json.loads(initial_raw)["observations"] == packet["observations"]
        assert ports.intents.intents == [] and packet["implementation_handoff"]["implementation_tasks"] == []
    asyncio.run(run())


def test_reader_rejects_a_claimed_positive_after_location_data_is_contradicted():
    packet = json.loads(asyncio.run(produce())[4])
    ref = json.loads(packet["codebase_context"][0]["references"][0]); ref.update(path="other.tsx", line=9)
    raw_ref = canonical(ref).decode()
    packet["codebase_context"][0]["references"] = [raw_ref]
    packet["implementation_handoff"]["files_to_inspect_first"] = [raw_ref]
    with pytest.raises(Rejected): inspect_packet(canonical(packet), packet_format=PACKET_FORMAT_V2)



def test_opposing_directions_on_unrelated_targets_remain_independently_eligible():
    async def run():
        quote = "Align this button left. Align this button right."
        _, ports, _, initial_raw, final_raw = await produce(quote, "separate_targets")
        initial, final = json.loads(initial_raw), json.loads(final_raw)
        observations = final["observations"]
        assert [row["what_they_said"] for row in observations] == ["Align this button left.", "Align this button right."]
        assert [row["selectors"] for row in observations] == [["button.review-dismiss"], ["button.review-secondary"]]
        ids = [row["observation_id"] for row in observations]
        assert initial["actionability"]["actionable_now"] == [] and final["actionability"]["actionable_now"] == ids
        assert all(final["semantic_metadata"]["observations"][oid]["triage"]["reason"] == "supported_layout_and_binding" for oid in ids)
        assert final["implementation_handoff"]["open_questions"] == final["implementation_handoff"]["implementation_tasks"] == []
        for raw in (initial_raw, final_raw):
            assert inspect_packet(raw, packet_format=PACKET_FORMAT_V2)["packet"]["observations"] == observations
        assert ports.intents.intents == []
    asyncio.run(run())


@pytest.mark.parametrize("schema", [[], {}])
@pytest.mark.parametrize("step", [6, 7])
def test_malformed_schema_containers_fail_writer_or_status_without_writes_or_intents(schema, step):
    async def run():
        adapter, ports, state, initial_raw, final_raw = await produce()
        packet = json.loads(initial_raw if step == 6 else final_raw)
        packet["schema"] = schema
        state["review_packet"] = await ports.artifacts.write(canonical(packet), "application/json")
        before = deepcopy(ports.artifacts.contents)
        result = await send(adapter, ports, state, step, suffix="-schema-container")
        assert result["outcome"] == "failed" and result["outputs"] == {}
        assert adapter.decisions[-1]["code"] == "malformed_packet"
        assert ports.artifacts.contents == before and ports.intents.intents == []
        with pytest.raises(Rejected):
            inspect_packet(canonical(packet), packet_format=PACKET_FORMAT_V2)
    asyncio.run(run())



@pytest.mark.parametrize("quote", [
    "Maybe align this button left.",
    "Please centre this button, perhaps after review.",
])
def test_uncertain_action_subject_speech_is_retained_without_planning_or_silent_inference(quote):
    async def run():
        _, ports, _, initial_raw, final_raw = await produce(quote, "silent")
        initial, final = json.loads(initial_raw), json.loads(final_raw)
        assert initial["observations"] == final["observations"]
        assert [row["what_they_said"] for row in final["observations"]] == [quote]
        oid = final["observations"][0]["observation_id"]
        assert initial["negative_evidence"] == final["negative_evidence"]
        assert final["negative_evidence"]["filtered_points"] == []
        silent = final["negative_evidence"]["silent_annotations"]
        assert len(silent) == 1 and json.loads(silent[0])["event"]["event_index"] == 11
        for raw in (initial_raw, final_raw):
            packet = json.loads(raw)
            row = packet["semantic_metadata"]["observations"][oid]
            assert row["layout_action"] is None and row["triage"]["reason"] == "unsupported_intent"
            assert packet["actionability"]["actionable_now"] == packet["implementation_handoff"]["implementation_tasks"] == []
            assert packet["actionability"]["needs_human_clarification"] == [oid]
            assert packet["actionability"]["discarded_or_filtered"] == silent
            view = inspect_packet(raw, packet_format=PACKET_FORMAT_V2)
            assert view["observations"][0]["what_they_said"] == quote
            assert view["observations"][0]["triage"]["decision"] == "not_eligible"
        assert ports.intents.intents == []
    asyncio.run(run())
