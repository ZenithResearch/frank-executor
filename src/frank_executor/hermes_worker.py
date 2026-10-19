"""Hermes-side worker; executed by the pinned Hermes interpreter."""
from __future__ import annotations

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
                "skip_context_files", "skip_memory", "prompt", "task_id"}
    if set(value) != required or value["task_id"] != value["session_id"]:
        return 2
    sys.path.insert(0, str(root))
    from run_agent import AIAgent
    agent = AIAgent(**{key: value[key] for key in required - {"prompt", "task_id"}})
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
