"""Pinned process boundary for an isolated Hermes installation."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import threading

from .model import Rejected, decode_json


def _pin(value):
    if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise Rejected("Exact Hermes SHA256 required")
    return value


def _path(value):
    result = Path(value)
    if type(value) is not str or not result.is_absolute() or ".." in result.parts:
        raise Rejected("Absolute Hermes path required")
    return result


def _sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _regular(path, expected, *, executable=False):
    path = _path(str(path))
    selected = path.resolve(strict=True) if executable else path
    link = path.lstat()
    info = selected.stat(follow_symlinks=False)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.getuid())
            or info.st_mode & 0o022 or info.st_nlink != 1
            or executable and not info.st_mode & 0o100
            or stat.S_ISLNK(link.st_mode) and link.st_uid != os.getuid()
            or not stat.S_ISLNK(link.st_mode) and selected != path
            or _sha(selected) != expected):
        raise Rejected("Pinned Hermes artifact unavailable")
    return path


class HermesSubprocessFactory:
    """Factory compatible with HermesAdapter without importing Hermes into Frank."""

    def __init__(self, *, python, python_sha256, source_root, run_agent_sha256,
                 hermes_home, version, timeout_seconds=600):
        self.python = _path(python)
        self.python_sha256 = _pin(python_sha256)
        self.source_root = _path(source_root)
        self.run_agent_sha256 = _pin(run_agent_sha256)
        self.hermes_home = _path(hermes_home)
        if version != "0.20.0" or type(timeout_seconds) is not int or not 30 <= timeout_seconds <= 900:
            raise Rejected("Unsupported Hermes subprocess profile")
        self.version, self.timeout_seconds = version, timeout_seconds
        self.check_available()

    def check_available(self):
        _regular(self.python, self.python_sha256, executable=True)
        _regular(self.source_root / "run_agent.py", self.run_agent_sha256)
        info = self.hermes_home.stat(follow_symlinks=False)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077):
            raise Rejected("Owner-private Hermes profile required")

    def __call__(self, **kwargs):
        expected = {"model", "enabled_toolsets", "max_iterations", "session_id",
                    "quiet_mode", "skip_context_files", "skip_memory"}
        if (set(kwargs) != expected or kwargs["quiet_mode"] is not True
                or kwargs["skip_context_files"] is not True or kwargs["skip_memory"] is not True
                or kwargs["enabled_toolsets"] != [] or kwargs["max_iterations"] != 4
                or kwargs["model"] != "openai-codex/gpt-5.6-sol"):
            raise Rejected("Hermes invocation differs from selected provider profile")
        self.check_available()
        return _HermesProcess(self, kwargs)


class _HermesProcess:
    def __init__(self, factory, configuration):
        self.factory, self.configuration = factory, configuration
        self._lock, self._child = threading.Lock(), None

    def run_conversation(self, prompt, *, task_id):
        if type(prompt) is not str or not prompt or len(prompt.encode()) > 1024 * 1024:
            raise Rejected("Bounded Hermes prompt required")
        if task_id != self.configuration["session_id"]:
            raise Rejected("Hermes task identity changed")
        request = json.dumps({**self.configuration, "prompt": prompt, "task_id": task_id},
                             sort_keys=True, separators=(",", ":")).encode()
        worker = Path(__file__).with_name("hermes_worker.py")
        environment = {"HOME": str(Path.home()), "HERMES_HOME": str(self.factory.hermes_home),
                       "HERMES_API_CALL_STALE_TIMEOUT": "300",
                       "LANG": "C.UTF-8", "PATH": os.defpath, "PYTHONNOUSERSITE": "1",
                       "PYTHONDONTWRITEBYTECODE": "1"}
        child = subprocess.Popen(
            [str(self.factory.python), "-I", "-B", str(worker), str(self.factory.source_root)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=self.factory.hermes_home, env=environment, start_new_session=True,
        )
        with self._lock:
            if self._child is not None:
                child.kill(); child.wait()
                raise Rejected("Hermes process already active")
            self._child = child
        try:
            output, diagnostic = child.communicate(request, timeout=self.factory.timeout_seconds)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGTERM)
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL); child.wait()
            raise Rejected("Hermes provider timed out") from None
        finally:
            with self._lock:
                self._child = None
        if child.returncode != 0 or len(output) > 1024 * 1024 or len(diagnostic) > 262144:
            raise Rejected("Hermes provider outcome unavailable")
        result = decode_json(output)
        if type(result) is not dict or set(result) != {"final_response"}:
            raise Rejected("Hermes provider returned an unsupported response")
        return result

    def interrupt(self, _reason):
        with self._lock:
            child = self._child
        if child is not None and child.poll() is None:
            os.killpg(child.pid, signal.SIGTERM)
