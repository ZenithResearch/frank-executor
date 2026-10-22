import hashlib
import json
import os
from pathlib import Path
import shutil

import pytest

from frank_executor.hermes_subprocess import HermesSubprocessFactory
from frank_executor.model import Rejected


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def fixture(tmp_path, source=None):
    tmp_path.mkdir(parents=True, exist_ok=True)
    home = tmp_path / "home"; home.mkdir(mode=0o700)
    root = tmp_path / "hermes"; root.mkdir()
    (root / "run_agent.py").write_text(source or '''class AIAgent:\n    def __init__(self, **kwargs): self.kwargs=kwargs\n    def run_conversation(self, prompt, task_id=None): return {"final_response":"{\\"answer\\":14}"}\n''')
    source_python = Path(os.environ.get("PYTHON", os.sys.executable)).resolve()
    python = tmp_path / "python3.12"
    shutil.copyfile(source_python, python)
    python.chmod(0o700)
    return HermesSubprocessFactory(python=str(python), python_sha256=sha(python),
        source_root=str(root), run_agent_sha256=sha(root / "run_agent.py"),
        hermes_home=str(home), version="0.20.0", timeout_seconds=30)


def selected(factory):
    return factory(model="openai-codex/gpt-5.6-sol", enabled_toolsets=[], max_iterations=4,
        session_id="effect-1", quiet_mode=True, skip_context_files=True, skip_memory=True)


def test_pinned_subprocess_returns_only_final_response(tmp_path):
    assert selected(fixture(tmp_path)).run_conversation("work", task_id="effect-1") == {
        "final_response": '{"answer":14}'}


def test_subprocess_selects_codex_provider_and_carries_bounded_stale_timeout(tmp_path):
    source = '''import json\nimport os\nclass AIAgent:\n    def __init__(self, **kwargs): self.kwargs=kwargs\n    def run_conversation(self, prompt, task_id=None):\n        return {"final_response": json.dumps({"provider": self.kwargs.get("provider"), "model": self.kwargs.get("model"), "stale_timeout": os.environ.get("HERMES_API_CALL_STALE_TIMEOUT")}, sort_keys=True)}\n'''
    response = selected(fixture(tmp_path, source)).run_conversation("work", task_id="effect-1")
    assert json.loads(response["final_response"]) == {
        "model": "gpt-5.6-sol",
        "provider": "openai-codex",
        "stale_timeout": "300",
    }


def test_subprocess_supplies_verified_image_in_same_model_turn(tmp_path):
    source = '''import json
class AIAgent:
    def __init__(self, **kwargs): pass
    def run_conversation(self, prompt, task_id=None, persist_user_message=None):
        return {"final_response": json.dumps({"parts": len(prompt), "persisted": persist_user_message, "kind": prompt[1]["type"]}, sort_keys=True)}
'''
    content = b"image-content"
    attachment = {"artifact_id": "reference-1", "content_hash": hashlib.sha256(content).hexdigest(),
                  "media_type": "image/png", "content_base64": __import__("base64").b64encode(content).decode()}
    response = selected(fixture(tmp_path, source)).run_conversation(
        "captured prompt", task_id="effect-1", attachments=(attachment,))
    assert json.loads(response["final_response"]) == {
        "kind": "image_url", "parts": 2, "persisted": "captured prompt"}


def test_profile_drift_and_invocation_drift_are_denied(tmp_path):
    factory = fixture(tmp_path)
    (factory.source_root / "run_agent.py").write_text("changed")
    with pytest.raises(Rejected, match="artifact"):
        factory.check_available()
    factory = fixture(tmp_path / "next")
    with pytest.raises(Rejected, match="differs"):
        factory(model="other", enabled_toolsets=[], max_iterations=4, session_id="effect-1",
            quiet_mode=True, skip_context_files=True, skip_memory=True)
