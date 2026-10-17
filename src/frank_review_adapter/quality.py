from __future__ import annotations

from .ports import ReviewFailure
from .semantic import PACKET_FORMAT_V2, validate_v2_packet


def packet_quality(packet: dict) -> str:
    """Recompute the decision from evidence; stored labels have no authority."""
    if not isinstance(packet, dict) or packet.get("schema") not in ("review.independent-packet.v1", PACKET_FORMAT_V2):
        raise ReviewFailure("malformed_packet")
    if not isinstance(packet.get("transcript"), str) or not isinstance(packet.get("observations"), list):
        raise ReviewFailure("malformed_packet")
    identities = set()
    for item in packet["observations"]:
        if (not isinstance(item, dict) or not isinstance(item.get("observation_id"), str)
                or not item["observation_id"] or item["observation_id"] in identities
                or not isinstance(item.get("what_they_said"), str) or not item["what_they_said"]
                or not isinstance(item.get("selectors"), list)
                or any(not isinstance(ref, str) or not ref for ref in item["selectors"])):
            raise ReviewFailure("malformed_packet")
        identities.add(item["observation_id"])
    if not isinstance(packet.get("codebase_context"), list):
        raise ReviewFailure("malformed_packet")
    contexts = {}
    for context in packet["codebase_context"]:
        if (not isinstance(context, dict) or context.get("observation_id") not in identities
                or context["observation_id"] in contexts
                or context.get("resolution_status") not in {"verified", "deferred", "blocked"}
                or not isinstance(context.get("references"), list)):
            raise ReviewFailure("malformed_packet")
        contexts[context["observation_id"]] = context
    negative = packet.get("negative_evidence")
    if (not isinstance(negative, dict) or set(negative) != {"silent_annotations", "filtered_points", "discarded_events"}
            or any(not isinstance(value, list) or any(not isinstance(x, str) for x in value) for value in negative.values())):
        raise ReviewFailure("malformed_packet")
    if packet["schema"] == PACKET_FORMAT_V2:
        validate_v2_packet(packet)
    if not packet["transcript"].strip():
        return "failed"
    if not packet["observations"]:
        return "transcript_only"
    if any(not item["selectors"] or item.get("match_type") == "unresolved" for item in packet["observations"]):
        return "needs_human_review"
    for item in packet["observations"]:
        context = contexts.get(item["observation_id"])
        if not context or context["resolution_status"] != "verified" or not context["references"]:
            return "needs_source_binding"
    return "review_packet_ready"
