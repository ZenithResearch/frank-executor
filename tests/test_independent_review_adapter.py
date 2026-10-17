from __future__ import annotations

import asyncio
import base64
from copy import deepcopy
import json
from pathlib import Path

import pytest

from frank_executor.model import Rejected, digest
from frank_executor.registry import Registry
from frank_review_adapter import ReviewAdapter, ReviewPorts
from frank_review_adapter.fixture_ports import MemoryArtifacts, FrozenSTT, SnapshotSources, SimulatedIntents, SyntheticClaims, SyntheticResults
from frank_review_adapter.quality import packet_quality
from frank_review_adapter.verification import execute_case

FIXTURES = Path(__file__).parent / "fixtures/independent-review"
INPUTS = json.loads((FIXTURES / "inputs.json").read_text())
REVIEW = json.loads((FIXTURES / "personal-review-v1.json").read_text())
DEVELOPMENT = json.loads((FIXTURES / "development-sop-v1.json").read_text())


def fixture_ports(source=None):
    source = source or INPUTS
    sources = SnapshotSources(source["source_snapshot"])
    return ReviewPorts(MemoryArtifacts(), FrozenSTT(source["audio_utf8"].encode(), source["stt_response"]),
                       sources, sources, SimulatedIntents(), SyntheticClaims(), SyntheticResults())


def work(operation, inputs, outputs, *, step_id="independent-renamed-step"):
    return {"schema": "frank.work.v1", "binding": {"run_id": "synthetic-run", "step_id": step_id, "attempt_id": "synthetic-attempt", "fence": 1},
            "actor_id": "worker", "integration_id": "review-fixture", "route": "local", "effect_id": "effect-fixture",
            "operation": operation, "scope": "test", "inputs": inputs, "output_types": outputs}


def test_production_and_missing_ports_are_closed_before_calls():
    ports = fixture_ports()
    with pytest.raises(Rejected, match="native command/result"):
        ReviewAdapter("review-fixture", {"effects": "disabled", "route": "local"}, ports=ports)
    assert ports.stt.calls == 0 and not ports.intents.intents
    missing = ReviewPorts(ports.artifacts, None, ports.components, ports.sources, ports.intents, ports.claims, ports.results)
    with pytest.raises(Rejected, match="ports"):
        ReviewAdapter("review-fixture", {"effects": "disabled", "route": "local"}, ports=missing, environment="test")


def test_missing_claim_denies_even_a_structurally_valid_packet():
    async def run():
        ports = fixture_ports()
        adapter = ReviewAdapter("review-fixture", {"effects": "disabled", "route": "local"}, ports=ports, environment="test")
        await adapter.connect()
        packet = work("review.daily_note", {}, {})
        with pytest.raises(Rejected, match="claim"):
            await adapter.send(packet)
        assert ports.intents.intents == [] and adapter.decisions == []
    asyncio.run(run())


def test_capability_not_ordinal_selects_handler_and_replay_is_exact():
    async def run():
        ports = fixture_ports()
        adapter = ReviewAdapter("review-fixture", {"effects": "disabled", "route": "local"}, ports=ports, environment="test")
        await adapter.connect()
        audio = await ports.artifacts.write(b"audio", "text/plain")
        events = await ports.artifacts.write(json.dumps(INPUTS["events"]).encode(), "application/json")
        inputs = {key: INPUTS[key] for key in REVIEW["inputs"] if key not in {"audio_asset", "events_asset"}}
        inputs.update(audio_asset=audio, events_asset=events)
        packet = work("review.load_review", inputs, REVIEW["steps"][0]["outputs"])
        ports.claims.confirm(packet)
        result = await adapter.send(packet)
        assert result["outcome"] == "succeeded"
        assert result["outputs"]["events"][0]["target"] == INPUTS["events"][0]["target"]
        assert await adapter.send(packet) == result and len(adapter.decisions) == 1
        changed = deepcopy(packet)
        changed["inputs"]["review_id"] = "another-review"
        ports.claims.confirm(changed)
        with pytest.raises(Rejected, match="changed work"):
            await adapter.send(changed)
        await adapter.close()
        assert (await adapter.health())["ready"] is False
    asyncio.run(run())


def test_artifact_integrity_failure_is_a_failed_result_without_output():
    async def run():
        ports = fixture_ports()
        adapter = ReviewAdapter("review-fixture", {"effects": "disabled", "route": "local"}, ports=ports, environment="test")
        await adapter.connect()
        audio = await ports.artifacts.write(b"audio", "text/plain")
        ports.artifacts.contents[audio["content_hash"]] = b"tampered"
        packet = work("review.transcribe", {"audio_asset": audio, "events": []}, REVIEW["steps"][1]["outputs"])
        ports.claims.confirm(packet)
        result = await adapter.send(packet)
        assert result["outcome"] == "failed" and result["outputs"] == {}
        assert ports.stt.calls == 0 and adapter.decisions[0]["code"] == "artifact_integrity_mismatch"
    asyncio.run(run())


@pytest.mark.parametrize("content", [b"{malformed", b'{"schema":"one","schema":"two"}',
    b'{"schema":"review.independent-packet.v1","transcript":"speech","observations":[],"codebase_context":[],"negative_evidence":{"silent_annotations":[],"filtered_points":[],"discarded_events":[]},"review":{"review_id":"r"},"quality":"review_packet_ready"}'])
def test_malformed_or_degraded_packet_fails_before_any_status_intent(content):
    async def run():
        ports = fixture_ports()
        adapter = ReviewAdapter("review-fixture", {"effects": "disabled", "route": "local"}, ports=ports, environment="test")
        await adapter.connect()
        artifact = await ports.artifacts.write(content, "application/json")
        note = await ports.artifacts.write(b"review note", "text/markdown")
        packet = work("review.write_status", {"review_id": "r", "review_packet": artifact, "review_note": note,
                     "review_packet_status": "review_packet_ready"}, REVIEW["steps"][7]["outputs"])
        ports.claims.confirm(packet)
        result = await adapter.send(packet)
        assert result["outcome"] == "failed" and result["outputs"] == {}
        assert not ports.intents.intents
        assert adapter.decisions[0]["code"] in {"malformed_packet", "review_packet_degraded"}
    asyncio.run(run())


@pytest.mark.parametrize("mutation", ["degraded", "transcript_only", "silent_repeat", "missing_timing"])
def test_public_runtime_review_failure_and_negative_evidence(provider, tmp_path, mutation):
    source = deepcopy(INPUTS)
    if mutation == "degraded":
        source["source_snapshot"] = {}
    if mutation == "transcript_only":
        source["stt_response"] = {"transcript": "Just looking around.", "audio_offset_ms": 0, "words": []}
    if mutation == "silent_repeat":
        source["events"].append({"id": 2, "type": "stroke", "target": "button.review-dismiss", "elapsedMs": 5000, "bounds": {"x": 10, "y": 20}})
    if mutation == "missing_timing":
        source["stt_response"]["words"] = []
    report = asyncio.run(execute_case(provider[0], REVIEW, source, source, tmp_path, scenario=mutation))
    expected = "succeeded" if mutation == "silent_repeat" else "failed"
    assert report["run_state"] == expected
    assert report["external_send_count"] == 0
    assert report["runnable_batches"][1] == ["step_2", "step_3"]
    final = next(row for row in report["steps"] if row["step_id"] == "step_7")["outputs"]
    initial = next(row for row in report["steps"] if row["step_id"] == "step_5")["outputs"]
    assert final["review_packet"] != initial["review_packet"]
    packet = json.loads(base64.b64decode(report["artifacts"][final["review_packet"]["content_hash"]]["content_base64"]))
    assert packet["transcript"] == source["stt_response"]["transcript"]
    assert packet_quality(packet) == final["review_packet_status"]
    if mutation == "silent_repeat":
        assert len(packet["observations"]) == 1
        assert len(packet["negative_evidence"]["silent_annotations"]) == 1
        assert json.loads(packet["negative_evidence"]["silent_annotations"][0])["event"]["start_ms"] == 5000
        assert len(report["simulated_intents"]) == 2
    else:
        assert report["step_states"]["step_9"] == "waiting"
        assert all(row["step_id"] != "step_9" for row in report["steps"])
        assert report["runnable_batches"][-1] == []
        assert report["steps"][-1]["step_id"] == "step_8" and report["steps"][-1]["outcome"] == "failed"
        assert not report["simulated_intents"]


def test_all_nine_handlers_and_receipts_use_public_contracts(provider, tmp_path):
    report = asyncio.run(execute_case(provider[0], REVIEW, INPUTS, INPUTS, tmp_path, scenario="ready"))
    assert report["run_state"] == "succeeded"
    assert len(report["steps"]) == 9
    assert all(row["delivery_state"] == "committed" and row["receipt_digest"] == digest(row["receipt"]) for row in report["steps"])
    assert report["steps"][7]["outputs"]["review_status_updated"]["status"] == "simulated_processed"
    assert report["external_send_count"] == 0 and report["stt_calls"] == 1
    assert [intent["operation"] for intent in report["simulated_intents"]] == ["review.status", "vault.daily-note"]
    assert all(intent["simulation"] and not intent["native_authority"] for intent in report["simulated_intents"])


def test_non_service_sop_executes_through_same_registry_and_executor(provider, tmp_path):
    report = asyncio.run(execute_case(provider[0], DEVELOPMENT, {}, {}, tmp_path, scenario="development", development=True))
    assert report["run_state"] == "succeeded" and len(report["steps"]) == 6
    assert report["runnable_batches"][2] == ["contract-tests", "unit-tests"]
    assert {row["operation"] for row in report["steps"]} == {step["capabilities"][0] for step in DEVELOPMENT["steps"]}
    assert "case_id" not in report and "service_request_id" not in report
    assert report["stt_calls"] == 0 and report["simulated_intents"] == []
    assert report["external_send_count"] == 0


@pytest.mark.parametrize("field", ["transcript", "quote"])
def test_comparison_never_classifies_changed_speech_as_equivalent(field):
    from frank_review_adapter.comparison import compare_computed, expected_values

    golden = json.loads((FIXTURES / "legacy-comparison.json").read_text())["scenarios"][0]
    expected = expected_values(golden["retained_replay_fixture"])
    rows = [{"step_id": step, **deepcopy(value)} for step, value in expected.items()]
    if field == "transcript":
        next(row for row in rows if row["step_id"] == "step_2")["outputs"]["transcript"] = "invented speech"
    else:
        next(row for row in rows if row["step_id"] == "step_5")["outputs"]["observations"][0]["what_they_said"] = "invented speech"
    comparison = compare_computed({"steps": rows, "run_state": "succeeded"}, golden)
    assert comparison["unclassified_divergences"]
    assert any(item["actual"] == "invented speech" for item in comparison["unclassified_divergences"])


def test_verification_refuses_an_existing_store_before_starting_a_provider(tmp_path):
    from frank_review_adapter.verify_main import verify

    sentinel = tmp_path / "runtime.db"
    sentinel.write_bytes(b"foreign store sentinel")
    with pytest.raises(Rejected, match="fresh empty"):
        verify(FIXTURES, tmp_path)
    assert sentinel.read_bytes() == b"foreign store sentinel"


def test_plugin_never_imports_legacy_handlers_or_runtime_storage():
    import ast
    import frank_review_adapter

    forbidden = ("services", "process_runtime.application", "process_runtime.sqlite_store", "process_runtime.shadow")
    for path in Path(frank_review_adapter.__file__).parent.glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Import):
                names = [item.name for item in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            else:
                continue
            assert not any(name == prefix or name.startswith(prefix + ".") for name in names for prefix in forbidden)


# SOP preservation controls use only the normal adapter and existing in-memory
# ports. They do not start a runtime/provider or qualify extraction semantics.
REQUIRED_REVIEW_CONSTRAINTS = {
    "Do not create ISS notes in the review-processing pipeline.",
    "Do not implement fixes in the review-processing pipeline.",
    "Do not infer a redesign beyond what the reviewer actually said.",
    "No design requirements, acceptance criteria or silent-gesture issues are inferred.",
}


async def preservation_send(adapter, ports, index, state):
    step = REVIEW["steps"][index]
    packet = work(step["capabilities"][0], {key: state[key] for key in step["inputs"]}, step["outputs"], step_id=step["step_id"])
    packet["effect_id"] = f"preservation-{index}"
    ports.claims.confirm(packet)
    return await adapter.send(packet)


async def preservation_case(mode, *, untrusted=None):
    source = deepcopy(INPUTS)
    if mode == "deferred":
        source["source_snapshot"] = {}
    if mode == "multiple_locations":
        # The supplied component claim is resolved; two current source locations
        # still must not imply semantic eligibility. This is not resolver proof.
        source["source_snapshot"][source["subject_id"]]["other.tsx"] = '<button className="review-dismiss" />'
    if untrusted is not None:
        source["source_snapshot"] = {source["subject_id"]: {untrusted + ".tsx": '<button className="review-dismiss" />'}}
    ports = fixture_ports(source)
    adapter = ReviewAdapter("review-fixture", {"effects": "disabled", "route": "local"}, ports=ports, environment="test")
    await adapter.connect()
    text = ("The spacing needs attention." if mode == "general_verbal" else
            "This button is not centered. This button needs contrast.")
    if untrusted is not None:
        text = "This button needs " + untrusted
    words = [{"text": word, "start_ms": index * 50, "end_ms": index * 50 + 40}
             for index, word in enumerate(text.split())]
    component = {"component": untrusted or "button.review-dismiss", "selectors": ["button.review-dismiss"],
                 "aliases": [], "source": "view.tsx:1", "spatial_hint": "", "resolution_status": "resolved"}
    events = [{"event_index": 0, "start_ms": 0, "end_ms": words[-1]["end_ms"], "kind": "click", "target": "button.review-dismiss"}]
    if mode == "blocked":
        component.update(resolution_status="unresolved", source="")
    if mode == "general_verbal":
        events, components = [], []
    else:
        components = [component]
    if mode == "mixed":
        events = [{"event_index": 0, "start_ms": 0, "end_ms": words[4]["end_ms"], "kind": "click", "target": "button.review-dismiss"}]
    state = {key: source[key] for key in ("review_id", "subject_id", "submitted_by", "reviewed_at", "duration_ms")}
    if untrusted is not None:
        state["review_id"] = untrusted
    state.update(resolved_transcript=text, words=words, events=events, component_names=components,
                 transcript_note=await ports.artifacts.write(b"unit annotation", "text/plain"))
    initial = None
    for index in (4, 5, 6):
        result = await preservation_send(adapter, ports, index, state)
        assert result["outcome"] == "succeeded"
        state.update(result["outputs"])
        if index == 4:
            initial_bytes = await ports.artifacts.read(state["review_packet"])
            initial = json.loads(initial_bytes)
            initial_reference = deepcopy(state["review_packet"])
    final = json.loads(await ports.artifacts.read(state["review_packet"]))
    assert state["review_packet"] != initial_reference
    assert await ports.artifacts.read(initial_reference) == initial_bytes
    assert ports.stt.calls == 0 and not ports.intents.intents
    return adapter, ports, state, initial, final


@pytest.mark.parametrize("mode", ["verified", "deferred", "blocked", "multiple_locations", "general_verbal", "mixed"])
def test_sop_handoff_preserves_binding_reasons_without_source_only_actionability(mode):
    async def run():
        adapter, ports, state, initial, final = await preservation_case(mode)
        identities = [item["observation_id"] for item in final["observations"]]
        assert final["transcript"] == initial["transcript"] == state["resolved_transcript"]
        assert final["observations"] == initial["observations"] == state["observations"]
        assert final["negative_evidence"] == initial["negative_evidence"]
        for packet in (initial, final):
            handoff = packet["implementation_handoff"]
            assert REQUIRED_REVIEW_CONSTRAINTS <= set(handoff["non_goals"])
            assert handoff["implementation_tasks"] == []
            eligible = identities[:1] if packet is final and mode in {"verified", "mixed"} else []
            assert packet["schema"] == "review.independent-packet.v2"
            assert packet["actionability"]["actionable_now"] == eligible
            assert packet["actionability"]["needs_human_clarification"] == [oid for oid in identities if oid not in eligible]
            assert all(not any(question.startswith(oid + ": ") for question in handoff["open_questions"]) for oid in eligible)
            assert all(any(question.startswith(oid + ": ") for question in handoff["open_questions"])
                       for oid in identities if oid not in eligible)
            assert handoff["verification_notes"][0] == "Effect-disabled deterministic evidence; no model/provider qualification."
        assert all(any(identity in note and "Source binding pending." in note for note in initial["implementation_handoff"]["verification_notes"])
                   for identity in identities)
        final_notes = final["implementation_handoff"]["verification_notes"]
        assert not any("Source binding pending." in note for note in final_notes)
        assert all(any(identity in note and "Implementation cause remains unassessed." in note for note in final_notes) for identity in identities)
        statuses = [row["resolution_status"] for row in final["codebase_context"]]
        expected_statuses = {"verified": ["verified", "verified"], "deferred": ["deferred", "deferred"],
                             "blocked": ["blocked", "blocked"], "multiple_locations": ["verified", "verified"],
                             "general_verbal": ["blocked"], "mixed": ["verified", "blocked"]}
        assert statuses == expected_statuses[mode]
        for row in final["codebase_context"]:
            label = "Verified source-location evidence only:" if row["resolution_status"] == "verified" else "Source binding " + row["resolution_status"] + ":"
            assert any(row["observation_id"] in note and label in note for note in final_notes)
            assert row["likely_cause"] == "unknown"
            assert row["confidence"] == ("source_match_only" if row["resolution_status"] == "verified" else "low")
        assert all(item["type"] == "feedback" for item in final["observations"])
        if mode == "multiple_locations":
            assert all(len(row["references"]) == 2 for row in final["codebase_context"])
        if mode in {"general_verbal", "mixed"}:
            general = final["observations"][-1]
            assert general["selectors"] == [] and general["match_type"] == "unresolved"
            assert general["what_they_said"] == ("The spacing needs attention." if mode == "general_verbal" else "This button needs contrast.")
            assert final["codebase_context"][-1]["references"] == []
        note = (await ports.artifacts.read(state["review_note"])).decode()
        assert all(text in note for text in REQUIRED_REVIEW_CONSTRAINTS)
        assert all(text in note for text in final_notes)
        status = await preservation_send(adapter, ports, 7, state)
        if mode in {"verified", "multiple_locations"}:
            assert packet_quality(final) == state["review_packet_status"] == "review_packet_ready"
            assert status["outcome"] == "succeeded"
            state.update(status["outputs"])
            assert state["review_status_updated"]["status"] == "simulated_processed"
            state["review_id_short"] = state["review_id"][:8]
            daily = await preservation_send(adapter, ports, 8, state)
            assert daily["outcome"] == "succeeded" and daily["outputs"] == {}
            assert [row["operation"] for row in ports.intents.intents] == ["review.status", "vault.daily-note"]
            assert all(row["simulation"] and not row["native_authority"] for row in ports.intents.intents)
        else:
            assert status["outcome"] == "failed" and status["outputs"] == {}
            assert adapter.decisions[-1]["code"] == "review_packet_degraded"
            assert not ports.intents.intents
        await adapter.close()
    asyncio.run(run())


@pytest.mark.parametrize("backticks", ["```", "````````````"])
def test_human_note_renders_untrusted_speech_and_references_as_text(backticks):
    async def run():
        payload = '<script>alert(1)</script> [fix](javascript:alert(1))\n' + backticks + '\n# injected'
        adapter, ports, state, initial, final = await preservation_case("verified", untrusted=payload)
        quote = "This button needs " + payload
        assert final["transcript"] == initial["transcript"] == quote
        item = final["observations"][0]
        assert item["what_they_said"] == item["issue"] == quote
        assert json.loads(item["evidence"])["quote"] == quote
        assert item["component"] == final["review"]["review_id"] == payload
        assert json.loads(final["codebase_context"][0]["references"][0])["path"] == payload + ".tsx"
        note = (await ports.artifacts.read(state["review_note"])).decode()
        # Inspect the emitted fenced-text grammar without claiming a renderer run.
        blocks, outside, body, fence = [], [], [], None
        for line in note.splitlines():
            if fence is None and line.endswith("text") and set(line[:-4]) == {"`"} and len(line[:-4]) >= 3:
                fence, body = line[:-4], []
            elif fence is not None and line == fence:
                blocks.append("\n".join(body))
                fence = None
            elif fence is not None:
                body.append(line)
            else:
                outside.append(line)
        assert fence is None
        assert quote in blocks and payload in blocks
        assert all(token not in "\n".join(outside) for token in ("<script>", "javascript:", "[fix]", "# injected"))
        assert all(constraint in "\n".join(blocks) for constraint in REQUIRED_REVIEW_CONSTRAINTS)
        assert final["actionability"]["actionable_now"] == []
        await adapter.close()
    asyncio.run(run())
