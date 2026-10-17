"""Review capability functions; no scheduling, runtime writes or legacy imports."""
from __future__ import annotations

import hashlib
import json
import re

from frank_executor.model import Rejected, canonical, decode_json

from .ports import ReviewFailure
from .quality import packet_quality
from .semantic import PACKET_FORMAT_V2, NON_GOALS, QUALIFICATION_NOTE, binding_notes, speech, fragment, apply_semantics, ACTION_SUBJECT


def encoded(value):
    return canonical(value).decode()


SEMANTIC_REVIEW = "Semantic review remains needed before planning; source location alone does not establish actionability."

def text_block(text):
    # A fence longer than every run in the data keeps speech/references inert.
    longest = max((len(match[0]) for match in re.finditer(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return [fence + "text", text, fence]


class Handlers:
    def __init__(self, ports):
        self.ports = ports
        names = ("load_review", "transcribe", "resolve_components", "annotate", "extract",
                 "bind_source", "write_review", "write_status", "daily_note")
        self.operations = {"review." + name: getattr(self, name) for name in names}
        for alias, name in {"transcribe-review-audio": "transcribe", "annotate-review-transcript": "annotate",
                            "extract-review-observations": "extract", "update_review_status": "write_status"}.items():
            self.operations[alias] = getattr(self, name)

    async def execute(self, work):
        return await self.operations[work["operation"]](work["inputs"], work["binding"])

    async def read(self, reference):
        if (not isinstance(reference, dict) or set(reference) != {"content_hash", "byte_length", "media_type"}
                or type(reference["byte_length"]) is not int):
            raise ReviewFailure("malformed_artifact")
        content = await self.ports.artifacts.read(reference)
        if (not isinstance(content, bytes) or len(content) != reference["byte_length"]
                or hashlib.sha256(content).hexdigest() != reference["content_hash"]):
            raise ReviewFailure("artifact_integrity_mismatch")
        return content

    async def write(self, content, media_type="application/json"):
        payload = canonical(content) if not isinstance(content, bytes) else content
        expected = {"content_hash": hashlib.sha256(payload).hexdigest(), "byte_length": len(payload), "media_type": media_type}
        reference = await self.ports.artifacts.write(payload, media_type)
        if reference != expected:
            raise ReviewFailure("artifact_write_integrity_mismatch")
        return reference

    async def json_artifact(self, reference, failure_code):
        content = await self.read(reference)
        try:
            return decode_json(content)
        except Rejected as exc:
            # Invalid retained bytes are a known semantic failure. Transport/port
            # exceptions remain unknown; neither class may become success.
            raise ReviewFailure(failure_code) from exc

    async def load_review(self, inputs, binding):
        await self.read(inputs["audio_asset"])
        raw = await self.json_artifact(inputs["events_asset"], "malformed_review_events")
        if not isinstance(raw, list) or any(not isinstance(event, dict) for event in raw):
            raise ReviewFailure("malformed_review_events")
        events = []
        for index, event in enumerate(raw):
            start = event.get("start_ms", event.get("elapsedMs", event.get("elapsed_ms")))
            end = event.get("end_ms", start)
            if type(start) is not int or type(end) is not int or start < 0 or end < start:
                raise ReviewFailure("unresolved_event_timing")
            target = event.get("target")
            kind = event.get("type", event.get("kind", "unknown"))
            if not isinstance(kind, str) or (target is not None and not isinstance(target, str)):
                raise ReviewFailure("malformed_review_events")
            events.append({"event_index": index, "start_ms": start, "end_ms": end,
                           "target": target or "", "kind": kind})
        return {"review_id_short": inputs["review_id"][:8], "audio_asset": inputs["audio_asset"], "events": events}

    async def transcribe(self, inputs, binding):
        response = await self.ports.stt.transcribe(await self.read(inputs["audio_asset"]), inputs["audio_asset"])
        if not isinstance(response, dict) or not isinstance(response.get("transcript"), str):
            raise ReviewFailure("malformed_transcription")
        offset = response.get("audio_offset_ms", 0)
        if type(offset) is not int or offset < 0 or not isinstance(response.get("words"), list):
            raise ReviewFailure("malformed_transcription")
        words, previous = [], -1
        for word in response["words"]:
            if not isinstance(word, dict) or not isinstance(word.get("text"), str) or not word["text"].strip():
                raise ReviewFailure("malformed_transcription")
            start, end = word.get("start_ms"), word.get("end_ms")
            if start is None and type(word.get("start")) in {float, int}:
                start = round(word["start"] * 1000)
            if end is None and type(word.get("end")) in {float, int}:
                end = round(word["end"] * 1000)
            if type(start) is not int or type(end) is not int or start < previous or end < start or start < 0:
                raise ReviewFailure("malformed_transcription_timing")
            previous = start
            words.append({"text": word["text"], "start_ms": start + offset, "end_ms": end + offset})
        return {"transcript": response["transcript"], "audio_offset_ms": offset, "words": words}

    async def resolve_components(self, inputs, binding):
        resolved = await self.ports.components.resolve(inputs["subject_id"], inputs["events"])
        if not isinstance(resolved, list):
            raise ReviewFailure("malformed_component_evidence")
        rows = []
        for event in inputs["events"]:
            target = event["target"]
            candidates = [item for item in resolved if target and target in item.get("selectors", [])]
            if len(candidates) == 1:
                item = candidates[0]
                if item.get("resolution_status") == "resolved" and item.get("source"):
                    rows.append(item)
                    continue
            descriptor = target or f"unresolved spatial event {event['event_index']}"
            rows.append({"component": descriptor, "selectors": [target] if target else [], "aliases": [],
                         "source": "", "spatial_hint": "geometry unavailable in normalized event contract",
                         "resolution_status": "unresolved"})
        unique = {encoded(item): item for item in rows}
        return {"component_names": list(unique.values())}

    async def annotate(self, inputs, binding):
        note = {"schema": "review.transcript-annotation.v1", "transcript": inputs["transcript"],
                "words": inputs["words"], "audio_offset_ms": inputs["audio_offset_ms"],
                "events": inputs["events"], "component_names": inputs["component_names"],
                "review_id": inputs["review_id"], "speech_policy": "verbatim; target evidence is separate",
                "uncertainties": ["Normalized events retain no raw gesture geometry; inspect the root events artifact."]}
        return {"resolved_transcript": inputs["transcript"], "transcript_note": await self.write(note)}

    async def extract(self, inputs, binding):
        text, words, events = inputs["resolved_transcript"], inputs["words"], inputs["events"]
        sentences = re.split(r"(?<=[.!?])\s+", text.strip()) if text.strip() else []
        # Never manufacture word alignment when provider text differs or timing is absent.
        aligned = bool(words) and text.split() == [word["text"] for word in words]
        position, observations, filtered, used = 0, [], [], set()
        for index, quote in enumerate(sentences):
            count = len(quote.split())
            segment = words[position:position + count] if aligned else []
            position += count
            timing = {"start_ms": segment[0]["start_ms"], "end_ms": segment[-1]["end_ms"]} if segment else None
            matches = [event for event in events if timing and event["start_ms"] <= timing["end_ms"]
                       and event["end_ms"] >= timing["start_ms"]]
            feedback_cue = (re.search(r"\b(not|need|needs|too|move|wrong|want|should|contrast|centered|can't|don't)\b", quote, re.I)
                            or ACTION_SUBJECT.search(quote))
            intent = speech(quote)["intent"]
            if fragment(quote) or not (feedback_cue or intent in {"layout_directive", "refusal", "preference", "non_issue"}):
                reason = ("Incomplete fragment retained as negative evidence; never an implementation issue." if fragment(quote)
                          else "No bounded coherent feedback cue; preserve for human review.")
                filtered.append(encoded({"quote": quote, "reason": reason, "timing": timing}))
                continue
            targets = sorted({event["target"] for event in matches if event["target"]})
            components = [item for item in inputs["component_names"] if any(ref in item["selectors"] for ref in targets)]
            resolved = len(targets) == 1 and len(components) == 1 and components[0]["resolution_status"] == "resolved"
            component = components[0]["component"] if len(components) == 1 else "unresolved general review context"
            identity = "observation-" + hashlib.sha256(quote.encode()).hexdigest()[:16] + f"-{index}"
            evidence = {"quote": quote, "timing": timing, "event_indices": [e["event_index"] for e in matches],
                        "component_resolution": "resolved" if resolved else "unresolved", "inference": "bounded lexical cue only"}
            observations.append({"observation_id": identity, "type": "feedback", "component": component,
                                 "selectors": targets, "what_they_said": quote, "issue": quote,
                                 "evidence": encoded(evidence), "match_type": "verbal_and_event" if resolved else "unresolved"})
            used.update(e["event_index"] for e in matches)
        silent = [encoded({"event": event, "reason": "No temporally matched reviewer speech; never an implementation issue."})
                  for event in events if event["event_index"] not in used and event["kind"] in {"stroke", "pointer", "gesture", "click"}]
        discarded = [encoded({"event": event, "reason": "Unmatched event evidence retained."}) for event in events
                     if event["event_index"] not in used and event["kind"] not in {"stroke", "pointer", "gesture", "click"}]
        negative = {"silent_annotations": silent, "filtered_points": filtered, "discarded_events": discarded}
        actionability = {key: [] for key in ("actionable_now", "design_preference", "discarded_or_filtered", "needs_human_clarification", "non_issue")}
        actionability["needs_human_clarification"] = [item["observation_id"] for item in observations]
        actionability["discarded_or_filtered"] = silent + filtered + discarded
        handoff = {"implementation_tasks": [], "files_to_inspect_first": [],
                   "open_questions": [f"{item['observation_id']}: {SEMANTIC_REVIEW}" for item in observations],
                   "non_goals": list(NON_GOALS), "verification_notes": binding_notes(observations)}
        packet = {"schema": PACKET_FORMAT_V2, "transcript": text, "observations": observations,
                  "events": events, "component_names": inputs["component_names"], "codebase_context": [],
                  "negative_evidence": negative, "actionability": actionability, "implementation_handoff": handoff,
                  "uncertainties": ["Raw geometry remains in root input artifact.", "Extraction uses bounded lexical cues, not a qualified model."],
                  "quality": "failed"}
        apply_semantics(packet, "initial")
        status = packet_quality(packet)
        packet["quality"] = status
        actionability, handoff = packet["actionability"], packet["implementation_handoff"]
        return {"observations": observations, "target_events": [{k: event[k] for k in ("event_index", "start_ms", "end_ms", "target")} for event in events],
                "silent_annotations": silent, "filtered_points": filtered, "negative_evidence": negative,
                "actionability": actionability, "implementation_handoff": handoff,
                "review_packet": await self.write(packet), "review_packet_status": status}

    async def bind_source(self, inputs, binding):
        contexts = []
        for observation in inputs["observations"]:
            references = await self.ports.sources.inspect(inputs["subject_id"], observation["selectors"])
            if not isinstance(references, list):
                raise ReviewFailure("malformed_source_evidence")
            verified = bool(references) and observation["match_type"] != "unresolved"
            blocked = observation["match_type"] == "unresolved"
            reasoning = ("Exact selectors matched inspected source." if verified else
                         "Observation target is unresolved; source-location binding is blocked." if blocked else
                         "Source/component binding is unavailable; inspect the subject-to-source mapping.")
            contexts.append({"observation_id": observation["observation_id"], "component": observation["component"],
                             "references": [encoded(reference) for reference in references], "likely_cause": "unknown",
                             "reasoning": reasoning, "confidence": "source_match_only" if verified else "low",
                             "caveats": ["Selector matching is evidence of location, not an inferred implementation cause."],
                             "resolution_status": "verified" if verified else "blocked" if blocked else "deferred"})
        return {"codebase_context": contexts}

    async def write_review(self, inputs, binding):
        packet = await self.json_artifact(inputs["review_packet"], "malformed_packet")
        # Preserve the entire Step5 negative ledger; never reconstruct it from a subset.
        packet_quality(packet)
        if packet["transcript"] != inputs["resolved_transcript"] or packet["observations"] != inputs["observations"]:
            raise ReviewFailure("packet_input_mismatch")
        packet["review"] = {key: inputs[key] for key in ("review_id", "subject_id", "submitted_by", "reviewed_at", "duration_ms")}
        packet["codebase_context"] = inputs["codebase_context"]
        handoff = packet["implementation_handoff"]
        handoff["files_to_inspect_first"] = sorted({reference for row in inputs["codebase_context"] for reference in row["references"]})
        handoff["verification_notes"] = binding_notes(inputs["observations"], inputs["codebase_context"])
        handoff["non_goals"] = list(dict.fromkeys([*handoff["non_goals"], *NON_GOALS]))
        if packet["schema"] == PACKET_FORMAT_V2:
            apply_semantics(packet, "final")
        else:
            # Supported historical v1 write: preserve its existing semantics;
            # never infer v2 category, confidence or planning eligibility.
            packet["actionability"]["actionable_now"] = []
            packet["actionability"]["needs_human_clarification"] = [item["observation_id"] for item in inputs["observations"]]
            handoff["open_questions"] = [f"{item['observation_id']}: {SEMANTIC_REVIEW}" for item in inputs["observations"]]
        status = packet_quality(packet)
        packet["quality"] = status
        final = await self.write(packet)
        lines = ["# Review", "", *text_block(inputs["review_id"]), f"Packet status: {status}", "", "## What I said",
                 *text_block(inputs["resolved_transcript"]), "", "## Feedback"]
        for index, item in enumerate(inputs["observations"], 1):
            lines += [f"### Feedback {index}", *text_block(item["what_they_said"]),
                      *text_block(encoded({key: item[key] for key in ("observation_id", "type", "component", "selectors", "issue", "evidence", "match_type")}))]
        if packet["schema"] == PACKET_FORMAT_V2:
            lines += ["", "## Semantic planning assessment (no execution authority)", *text_block(encoded(packet["semantic_metadata"]))]
        source_heading = ("Reported source-confidence and location evidence" if packet["schema"] == PACKET_FORMAT_V2
                          else "Source and uncertainty")
        for heading, text in ((source_heading, encoded(inputs["codebase_context"])),
                              ("Verification notes", "\n".join(handoff["verification_notes"])),
                              ("Open questions", "\n".join(handoff["open_questions"])),
                              ("Non-goals", "\n".join(handoff["non_goals"])),
                              ("Negative evidence", encoded(packet["negative_evidence"]))):
            lines += ["", "## " + heading, *text_block(text)]
        note = await self.write("\n".join(lines).encode(), "text/markdown")
        return {"review_note": note, "review_packet": final, "review_packet_status": status}

    async def write_status(self, inputs, binding):
        packet = await self.json_artifact(inputs["review_packet"], "malformed_packet")
        status = packet_quality(packet)
        if (packet.get("review", {}).get("review_id") != inputs["review_id"]
                or status != "review_packet_ready" or inputs["review_packet_status"] != status):
            raise ReviewFailure("review_packet_degraded")
        await self.read(inputs["review_note"])
        intent = await self.ports.intents.record(binding, "review.status", {"review_id": inputs["review_id"], "decision": "processed", "review_packet": inputs["review_packet"]})
        if intent.get("simulation") is not True or intent.get("recorded") is not True:
            raise ReviewFailure("status_simulation_unconfirmed")
        return {"review_status_updated": {"review_id": inputs["review_id"], "review_note": inputs["review_note"], "status": "simulated_processed"}}

    async def daily_note(self, inputs, binding):
        status = inputs["review_status_updated"]
        if status["status"] != "simulated_processed" or status["review_id"] != inputs["review_id"] or status["review_note"] != inputs["review_note"]:
            raise ReviewFailure("status_intent_required")
        await self.read(inputs["transcript_note"])
        await self.read(inputs["review_note"])
        intent = await self.ports.intents.record(binding, "vault.daily-note", {"review_id": inputs["review_id"], "subject_id": inputs["subject_id"],
                    "line": f"Simulated review {inputs['review_id_short']}: {len(inputs['observations'])} speech-derived feedback item(s).", "review_note": inputs["review_note"]})
        if intent.get("simulation") is not True or intent.get("recorded") is not True:
            raise ReviewFailure("daily_note_simulation_unconfirmed")
        return {}
