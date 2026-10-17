"""Closed artifact-only v2 semantics; finite speech rules, no authority or effects."""
from __future__ import annotations

import re

from frank_executor.model import ID, Rejected, canonical, decode_json
from .ports import ReviewFailure

PACKET_FORMAT_V2 = "review.independent-packet.v2"
POLICY_ID = "review.bounded-layout-planning.v1"
SEMANTIC_SCHEMA = "review.semantic-metadata.v1"
SCOPE = "planning_only_no_execution"

NON_GOALS = (
    "Do not create ISS notes in the review-processing pipeline.",
    "Do not implement fixes in the review-processing pipeline.",
    "Do not infer a redesign beyond what the reviewer actually said.",
    "No design requirements, acceptance criteria or silent-gesture issues are inferred.",
)
QUALIFICATION_NOTE = "Effect-disabled deterministic evidence; no model/provider qualification."


def binding_notes(observations, contexts=None):
    by_id = {row["observation_id"]: row for row in contexts or []}
    notes = [QUALIFICATION_NOTE]
    for item in observations:
        context = by_id.get(item["observation_id"])
        if contexts is None:
            state = "Source binding pending."
        elif item["match_type"] == "unresolved":
            state = "Source binding blocked: the observation target remains unresolved."
        elif context is None:
            state = "Source binding deferred: no per-observation source context was supplied."
        elif context["resolution_status"] == "verified" and context["references"]:
            state = "Verified source-location evidence only: " + context["reasoning"]
        else:
            label = "blocked" if context["resolution_status"] == "blocked" else "deferred"
            state = "Source binding " + label + ": " + context["reasoning"]
        notes.append(f"{item['observation_id']}: {state} Implementation cause remains unassessed.")
    return notes


# Full utterance rules, not substring promotion. Explicit negative intent wins.
SUBJECT = r"(?:this|the) (?:button|element|control|label|panel|dialog|text|icon)"
# Retention only: a known action and bounded subject do not establish eligibility.
ACTION_SUBJECT = re.compile(r"\b(?:center|centre|align) " + SUBJECT + r"\b", re.I)
CONCERN = re.compile(SUBJECT + r" is (?P<state>not centered|not centred|not aligned|off-center|off-centre|misaligned)", re.I)
DIRECTION = r"(?:to the )?(?:left|right|center|centre)"
DIRECTIVE = re.compile(r"(?:please )?(?P<verb>center|centre|align) " + SUBJECT + r"(?: (?P<goal>" + DIRECTION + r"))?", re.I)
REFUSAL = re.compile(r"(?:please )?(?:do not|don't|never) (?P<verb>center|centre|align) " + SUBJECT + r"(?: (?P<goal>" + DIRECTION + r"))?", re.I)
SATISFIED = re.compile(r"(?:" + SUBJECT + r"|this|it) is (?P<state>centered correctly|centred correctly|aligned correctly)", re.I)
LAYOUT = re.compile(r"\b(?:center(?:ed)?|centre(?:d)?|align(?:ed|ment)?|misaligned|spacing|layout|off-center|off-centre)\b", re.I)
PREFERENCE = re.compile(r"(?:(?:i (?:would )?prefer|i'd prefer|my preference is) " + SUBJECT +
                        r" (?:to be )?(?:centered|centred|aligned)(?: " + DIRECTION + r")?|(?:i would rather|i'd rather) " +
                        SUBJECT + r" (?:be )?(?:centered|centred|aligned)(?: " + DIRECTION + r")?)", re.I)
PRAISE = re.compile(r"(?:(?:" + SUBJECT + r"|this|it) (?:looks? (?:good|great|nice|fine)|works? (?:well|great))|i (?:like|love) (?:this|it)|(?:there is )?no (?:issue|problem)(?: with " + SUBJECT + r")?|approved)", re.I)
NEGATION = re.compile(r"\b(?:do not|don't|never|not sure|maybe|perhaps|but|however|although|unless)\b", re.I)
CONFIDENCE_BASIS = "No semantic confidence assessment is made by this finite speech/location policy."
REASONS = {
    "explicit_preference": "Explicit preference is retained; it is not an implementation defect or planning grant.",
    "explicit_non_issue": "Explicit praise, approval or no-concern is retained without creating an issue.",
    "unsupported_intent": "The finite policy does not establish a coherent affirmative layout concern/directive; semantic intent remains unassessed.",
    "explicit_refusal": "An explicit alignment refusal is retained as negative intent; it creates no issue or planning grant.",
    "conflicting_intent": "Retained utterances contain incompatible alignment goals or an opposing refusal/correct-state claim for the same target; this finite policy does not resolve the conflict.",
    "target_unresolved": "The spoken concern is retained, but one unambiguous temporally matched target is not resolved.",
    "source_pending": "Source binding is pending; the recognized concern is not yet planning-eligible.",
    "source_deferred": "The target is resolved but an exact verified source binding is unavailable.",
    "source_conflicting": "Retained source candidates or component/reference locations conflict; this policy does not resolve their contradiction.",
    "source_blocked": "Source binding is blocked; retained evidence cannot establish the required location.",
    "supported_layout_and_binding": "A coherent layout concern/directive and one consistent verified source location support planning only; no issue creation, fix, effect or authority is granted.",
}


def require(condition):
    if not condition:
        raise ReviewFailure("malformed_semantic_packet")


def keys(value, expected):
    require(isinstance(value, dict) and set(value) == set(expected))


def texts(value):
    require(isinstance(value, list) and all(isinstance(x, str) for x in value))


def layout_action(plain):
    """Finite structured goals only; supplied text is never interpreted as code."""
    for pattern, kind in ((REFUSAL, "refusal"), (DIRECTIVE, "request")):
        match = pattern.fullmatch(plain)
        if match:
            verb, goal = match["verb"].lower(), match["goal"]
            if verb in {"center", "centre"}:
                return {"kind": kind, "goal": "center"} if goal is None else None
            if goal is None:
                return {"kind": "refusal", "goal": "alignment"} if kind == "refusal" else None
            return {"kind": kind, "goal": goal.lower().removeprefix("to the ").replace("centre", "center")}
    match = CONCERN.fullmatch(plain)
    if match:
        return {"kind": "concern", "goal": "alignment" if match["state"].lower() in {"not aligned", "misaligned"} else "center"}
    match = SATISFIED.fullmatch(plain)
    if match:
        return {"kind": "satisfied", "goal": "alignment" if match["state"].lower() == "aligned correctly" else "center"}
    return None


def speech(quote):
    """Complete praise/action forms and negative precedence; unknown stays honest."""
    plain = quote.strip().rstrip(".! ").strip()
    category = "layout" if LAYOUT.search(plain) else "unknown"
    basis = "explicit_layout_vocabulary" if category == "layout" else "no_supported_category_rule"
    action = layout_action(plain)
    clear = action is not None and action["kind"] in {"concern", "request"}
    if action is not None and action["kind"] == "refusal" and "?" not in plain:
        intent = "refusal"
    elif "?" in plain or NEGATION.search(plain) or re.search(r"\bnot\b", plain, re.I) and not clear:
        intent = "unsupported"
    elif PREFERENCE.fullmatch(plain):
        intent = "preference"
    elif PRAISE.fullmatch(plain) or action is not None and action["kind"] == "satisfied":
        intent = "non_issue"
    elif clear:
        intent = "layout_directive"
    else:
        intent = "unsupported"
    return {"category": category, "basis": basis, "intent": intent, "action": action}


def intent_conflict(item, claim, observations):
    action = claim["action"]
    if action is None or not item["selectors"]:
        return False
    for other in observations:
        if other["observation_id"] == item["observation_id"] or other["selectors"] != item["selectors"]:
            continue
        other_claim = speech(other["what_they_said"])
        other_action = other_claim["action"]
        if other_action is None:
            continue  # Generic praise is not an opposing correct-state assertion.
        kind, goal = other_action["kind"], other_action["goal"]
        if kind == "refusal" and (goal == "alignment" or goal == action["goal"]):
            return True
        if kind in {"request", "concern"} and other_claim["intent"] == "layout_directive":
            if goal in {"left", "right", "center"} and action["goal"] in {"left", "right", "center"} and goal != action["goal"]:
                return True
        if kind == "satisfied" and action["kind"] == "concern" and goal == action["goal"]:
            return True
    return False


def consistent_location(item, packet, reference):
    matches = [c for c in packet["component_names"] if c["component"] == item["component"]
               and c["resolution_status"] == "resolved" and item["selectors"] == [reference["selector"]]
               and reference["selector"] in c["selectors"]]
    # Compare only supplied inert location data. No path opens or provenance claim.
    return len(matches) == 1 and matches[0]["source"] == f"{reference['path']}:{reference['line']}"


def fragment(quote):
    plain = quote.strip().rstrip(".!? ")
    return (len(plain.split()) < 2
            or re.search(r"\b(?:needs?|should|want|is|not|to|the|this)$", plain, re.I) is not None
            or re.fullmatch(r"(?:not )?(?:centered|centred|aligned)", plain, re.I) is not None)


def source_reference(raw):
    ref = decode_json(raw)
    keys(ref, {"path", "line", "content_hash", "selector", "text"})
    require(isinstance(ref["path"], str) and bool(ref["path"]))
    require(type(ref["line"]) is int and ref["line"] > 0)
    require(isinstance(ref["content_hash"], str) and re.fullmatch(r"[0-9a-f]{64}", ref["content_hash"]) is not None)
    require(isinstance(ref["selector"], str) and isinstance(ref["text"], str))
    return ref


def metadata(packet, stage):
    by_id = {row["observation_id"]: row for row in packet["codebase_context"]}
    assessments = {}
    for item in packet["observations"]:
        oid = item["observation_id"]
        claim = speech(item["what_they_said"])
        context = by_id.get(oid)
        refs = [source_reference(raw) for raw in context["references"]] if context else []
        if stage == "initial":
            state = "pending"
        elif len(refs) > 1 or (len(refs) == 1 and context["resolution_status"] == "verified"
                               and not consistent_location(item, packet, refs[0])):
            state = "conflicting"
        else:
            state = context["resolution_status"] if context else "deferred"
        target = (item["match_type"] == "verbal_and_event" and len(item["selectors"]) == 1)
        if claim["intent"] == "refusal":
            decision, reason = "not_eligible", "explicit_refusal"
        elif claim["intent"] == "preference":
            decision, reason = "design_preference", "explicit_preference"
        elif claim["intent"] == "non_issue":
            decision, reason = "non_issue", "explicit_non_issue"
        elif claim["intent"] != "layout_directive" or claim["category"] != "layout":
            decision, reason = "not_eligible", "unsupported_intent"
        elif intent_conflict(item, claim, packet["observations"]):
            decision, reason = "not_eligible", "conflicting_intent"
        elif not target:
            decision, reason = "not_eligible", "target_unresolved"
        elif stage == "initial":
            decision, reason = "not_eligible", "source_pending"
        elif state == "conflicting":
            decision, reason = "not_eligible", "source_conflicting"
        elif context and context["resolution_status"] == "verified" and len(refs) == 1:
            decision, reason = "planning_eligible", "supported_layout_and_binding"
        else:
            decision, reason = "not_eligible", "source_blocked" if state == "blocked" else "source_deferred"
        assessments[oid] = {
            "record_kind": "feedback", "issue_category": claim["category"], "category_basis": claim["basis"], "layout_action": claim["action"],
            "semantic_confidence": {"state": "unassessed", "basis": CONFIDENCE_BASIS},
            "source_evidence": {"binding_state": state, "scope": "location_only" if refs else "none",
                                "reference_count": len(refs), "reported_source_confidence": context["confidence"] if context else None},
            "triage": {"decision": decision, "reason": reason, "detail": REASONS[reason]},
        }
    return {"schema": SEMANTIC_SCHEMA, "policy_id": POLICY_ID, "scope": SCOPE,
            "stage": stage, "observations": assessments}


def projection(packet, assessment):
    buckets = {name: [] for name in ("actionable_now", "design_preference", "discarded_or_filtered", "needs_human_clarification", "non_issue")}
    questions = []
    for oid, row in assessment["observations"].items():
        decision = row["triage"]["decision"]
        bucket = {"planning_eligible": "actionable_now", "design_preference": "design_preference", "non_issue": "non_issue"}.get(decision, "needs_human_clarification")
        buckets[bucket].append(oid)
        if decision == "not_eligible":
            questions.append(oid + ": " + row["triage"]["detail"])
    negative = packet["negative_evidence"]
    buckets["discarded_or_filtered"] = negative["silent_annotations"] + negative["filtered_points"] + negative["discarded_events"]
    return buckets, questions


def apply_semantics(packet, stage):
    try:
        assessment = metadata(packet, stage)
        packet["semantic_metadata"] = assessment
        packet["actionability"], packet["implementation_handoff"]["open_questions"] = projection(packet, assessment)
    except (KeyError, TypeError, ValueError, AttributeError, Rejected) as exc:
        raise ReviewFailure("malformed_semantic_packet") from exc


def validate_v2_packet(packet):
    """Validate actual correlations, then recompute metadata; supplied flags do not win."""
    try:
        required = {"schema", "transcript", "observations", "events", "component_names", "codebase_context",
                    "negative_evidence", "actionability", "implementation_handoff", "uncertainties", "quality", "semantic_metadata"}
        require(isinstance(packet, dict) and set(packet) in (required, required | {"review"}))
        require(packet["schema"] == PACKET_FORMAT_V2 and isinstance(packet["transcript"], str) and isinstance(packet["quality"], str))
        texts(packet["uncertainties"])
        sem = packet["semantic_metadata"]
        keys(sem, {"schema", "policy_id", "scope", "stage", "observations"})
        require(sem["schema"] == SEMANTIC_SCHEMA and sem["policy_id"] == POLICY_ID and sem["scope"] == SCOPE and sem["stage"] in {"initial", "final"})
        require((sem["stage"] == "final") == ("review" in packet))
        if "review" in packet:
            keys(packet["review"], {"review_id", "subject_id", "submitted_by", "reviewed_at", "duration_ms"})
            require(all(isinstance(packet["review"][k], str) for k in ("review_id", "subject_id", "submitted_by", "reviewed_at")))
            require(type(packet["review"]["duration_ms"]) is int and packet["review"]["duration_ms"] >= 0)
        events = {}
        require(isinstance(packet["events"], list))
        for event in packet["events"]:
            keys(event, {"event_index", "start_ms", "end_ms", "kind", "target"})
            require(type(event["event_index"]) is int and event["event_index"] >= 0 and event["event_index"] not in events)
            require(type(event["start_ms"]) is int and type(event["end_ms"]) is int and 0 <= event["start_ms"] <= event["end_ms"])
            require(isinstance(event["kind"], str) and isinstance(event["target"], str))
            events[event["event_index"]] = event
        require(isinstance(packet["component_names"], list))
        for comp in packet["component_names"]:
            keys(comp, {"component", "selectors", "aliases", "source", "spatial_hint", "resolution_status"})
            require(all(isinstance(comp[k], str) for k in ("component", "source", "spatial_hint")))
            texts(comp["selectors"]); texts(comp["aliases"])
            require(comp["resolution_status"] in {"resolved", "unresolved"})
        observations, evidence = {}, {}
        require(isinstance(packet["observations"], list))
        for item in packet["observations"]:
            keys(item, {"observation_id", "type", "component", "selectors", "what_they_said", "issue", "evidence", "match_type"})
            oid = item["observation_id"]
            require(isinstance(oid, str) and ID.fullmatch(oid) is not None and oid not in observations)
            require(item["type"] == "feedback" and item["match_type"] in {"verbal_and_event", "unresolved"})
            require(all(isinstance(item[k], str) for k in ("component", "what_they_said", "issue")) and bool(item["what_they_said"]))
            texts(item["selectors"]); require(all(item["selectors"]) and len(set(item["selectors"])) == len(item["selectors"]))
            ev = decode_json(item["evidence"])
            keys(ev, {"quote", "timing", "event_indices", "component_resolution", "inference"})
            require(ev["quote"] == item["what_they_said"] and item["issue"] == item["what_they_said"] and item["what_they_said"] in packet["transcript"] and isinstance(ev["inference"], str))
            require(ev["component_resolution"] in {"resolved", "unresolved"})
            if ev["timing"] is not None:
                keys(ev["timing"], {"start_ms", "end_ms"})
                require(all(type(ev["timing"][k]) is int for k in ("start_ms", "end_ms")) and 0 <= ev["timing"]["start_ms"] <= ev["timing"]["end_ms"])
            require(isinstance(ev["event_indices"], list) and all(type(n) is int and n in events for n in ev["event_indices"]))
            require(len(set(ev["event_indices"])) == len(ev["event_indices"]))
            linked = [events[n] for n in ev["event_indices"]]
            require(item["selectors"] == sorted({event["target"] for event in linked if event["target"]}))
            require(not linked or ev["timing"] is not None and all(e["start_ms"] <= ev["timing"]["end_ms"] and e["end_ms"] >= ev["timing"]["start_ms"] for e in linked))
            if item["match_type"] == "verbal_and_event":
                matches = [c for c in packet["component_names"] if any(s in c["selectors"] for s in item["selectors"])]
                require(len(item["selectors"]) == 1 and bool(linked) and len(matches) == 1 and matches[0]["resolution_status"] == "resolved" and matches[0]["component"] == item["component"] and ev["component_resolution"] == "resolved")
            else:
                require(ev["component_resolution"] == "unresolved")
            observations[oid], evidence[oid] = item, ev
        contexts, refs = {}, {}
        require(isinstance(packet["codebase_context"], list))
        for context in packet["codebase_context"]:
            keys(context, {"observation_id", "component", "references", "likely_cause", "reasoning", "confidence", "caveats", "resolution_status"})
            oid = context["observation_id"]
            require(oid in observations and oid not in contexts and context["component"] == observations[oid]["component"])
            require(context["confidence"] in {"source_match_only", "low"} and context["resolution_status"] in {"verified", "deferred", "blocked"})
            require(context["likely_cause"] == "unknown" and isinstance(context["reasoning"], str))
            texts(context["references"]); texts(context["caveats"])
            refs[oid] = [source_reference(raw) for raw in context["references"]]
            require(all(r["selector"] in observations[oid]["selectors"] for r in refs[oid]))
            require(context["resolution_status"] != "verified" or bool(refs[oid]))
            contexts[oid] = context
        require(set(contexts) == (set(observations) if sem["stage"] == "final" else set()))
        keys(packet["negative_evidence"], {"silent_annotations", "filtered_points", "discarded_events"})
        for value in packet["negative_evidence"].values(): texts(value)
        expected = metadata(packet, sem["stage"])
        require(canonical(sem) == canonical(expected))
        buckets, questions = projection(packet, expected)
        require(canonical(packet["actionability"]) == canonical(buckets))
        handoff = packet["implementation_handoff"]
        keys(handoff, {"implementation_tasks", "files_to_inspect_first", "open_questions", "non_goals", "verification_notes"})
        for value in handoff.values(): texts(value)
        require(handoff["implementation_tasks"] == [] and handoff["non_goals"] == list(NON_GOALS) and handoff["open_questions"] == questions)
        require(handoff["verification_notes"] == binding_notes(packet["observations"], packet["codebase_context"] if sem["stage"] == "final" else None))
        require(handoff["files_to_inspect_first"] == sorted({ref for c in packet["codebase_context"] for ref in c["references"]}))
        return evidence, refs
    except (KeyError, TypeError, ValueError, AttributeError, Rejected) as exc:
        raise ReviewFailure("malformed_semantic_packet") from exc
