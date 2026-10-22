"""Hermes-side worker; executed by the pinned Hermes interpreter."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import sys


def main():
    if len(sys.argv) != 2:
        return 2
    root = Path(sys.argv[1])
    if not root.is_absolute() or not (root / "run_agent.py").is_file():
        return 2
    raw = sys.stdin.buffer.read(1024 * 1024 + 2049)
    if not raw or len(raw) > 1024 * 1024 + 2048:
        return 2
    value = json.loads(raw)
    required = {"model", "enabled_toolsets", "max_iterations", "session_id", "quiet_mode",
                "skip_context_files", "skip_memory", "prompt", "task_id", "attachments"}
    if set(value) != required or value["task_id"] != value["session_id"]:
        return 2
    sys.path.insert(0, str(root))
    from run_agent import AIAgent
    configuration = {key: value[key] for key in required - {"prompt", "task_id", "attachments"}}
    if configuration["model"] != "openai-codex/gpt-5.6-sol":
        return 2
    configuration["provider"] = "openai-codex"
    configuration["model"] = "gpt-5.6-sol"
    agent = AIAgent(**configuration)
    attachments = value["attachments"]
    if not isinstance(attachments, list) or len(attachments) > 1:
        return 2
    parts = [{"type": "text", "text": value["prompt"]}]
    for item in attachments:
        if (not isinstance(item, dict)
                or set(item) != {"artifact_id", "content_hash", "media_type", "content_base64"}
                or item["media_type"] not in {"image/jpeg", "image/png"}
                or not isinstance(item["content_base64"], str)
                or len(item["content_base64"]) > 699052):
            return 2
        try:
            content = base64.b64decode(item["content_base64"], validate=True)
        except (ValueError, TypeError):
            return 2
        if (not 0 < len(content) <= 524288
                or hashlib.sha256(content).hexdigest() != item["content_hash"]):
            return 2
        parts.append({"type": "image_url", "image_url": {
            "url": f"data:{item['media_type']};base64,{item['content_base64']}"}})
    if attachments:
        result = agent.run_conversation(parts, task_id=value["task_id"],
                                        persist_user_message=value["prompt"])
    else:
        result = agent.run_conversation(value["prompt"], task_id=value["task_id"])
    final = result.get("final_response") if type(result) is dict else None
    if type(final) is not str or len(final.encode()) > 1024 * 1024:
        return 2
    sys.stdout.write(json.dumps({"final_response": final}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        raise SystemExit(2)
