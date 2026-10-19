import hashlib
import json
import os
from pathlib import Path

import pytest

from frank_executor.hermes_subprocess import HermesSubprocessFactory
from frank_executor.model import Rejected


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def fixture(tmp_path):
    tmp_path.mkdir(parents=True, exist_ok=True)
    home = tmp_path / "home"; home.mkdir(mode=0o700)
    root = tmp_path / "hermes"; root.mkdir()
    (root / "run_agent.py").write_text('''class AIAgent:\n    def __init__(self, **kwargs): self.kwargs=kwargs\n    def run_conversation(self, prompt, task_id=None): return {"final_response":"{\\"answer\\":14}"}\n''')
    python = Path(os.environ.get("PYTHON", os.sys.executable)).resolve()
    return HermesSubprocessFactory(python=str(python), python_sha256=sha(python),
        source_root=str(root), run_agent_sha256=sha(root / "run_agent.py"),
        hermes_home=str(home), version="0.20.0", timeout_seconds=30)


def selected(factory):
    return factory(model="openai-codex/gpt-5.6-sol", enabled_toolsets=[], max_iterations=4,
        session_id="effect-1", quiet_mode=True, skip_context_files=True, skip_memory=True)


def test_pinned_subprocess_returns_only_final_response(tmp_path):
    assert selected(fixture(tmp_path)).run_conversation("work", task_id="effect-1") == {
        "final_response": '{"answer":14}'}


def test_profile_drift_and_invocation_drift_are_denied(tmp_path):
    factory = fixture(tmp_path)
    (factory.source_root / "run_agent.py").write_text("changed")
    with pytest.raises(Rejected, match="artifact"):
        factory.check_available()
    factory = fixture(tmp_path / "next")
    with pytest.raises(Rejected, match="differs"):
        factory(model="other", enabled_toolsets=[], max_iterations=4, session_id="effect-1",
            quiet_mode=True, skip_context_files=True, skip_memory=True)
