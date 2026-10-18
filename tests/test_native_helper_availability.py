"""Real filesystem helper-admission controls; no helper process is launched."""
import hashlib
import os

import pytest

from frank_executor.model import Rejected
from frank_executor.native_results import NativeSecSHelper


def tracked_opener(monkeypatch):
    real_open = os.open
    opened = []
    def checked(path, flags, *args, **kwargs):
        # Fail before an old blocking FIFO opener can hang the RED control.
        assert flags == os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        fd = real_open(path, flags, *args, **kwargs)
        opened.append(fd)
        return fd
    monkeypatch.setattr("frank_executor.native_results.os.open", checked)
    return opened


def test_helper_regular_artifact_uses_nonblocking_exact_flags_and_closes(tmp_path, monkeypatch):
    path = tmp_path / "helper"
    raw = b"never executed qualified-artifact substitute for file admission only\n"
    path.write_bytes(raw)
    path.chmod(0o700)
    opened = tracked_opener(monkeypatch)
    NativeSecSHelper(str(path), hashlib.sha256(raw).hexdigest()).check_available()
    assert len(opened) == 1
    with pytest.raises(OSError):
        os.fstat(opened[0])


def test_helper_substituted_fifo_is_opened_nonblocking_then_denied_and_closed(tmp_path, monkeypatch):
    path = tmp_path / "helper"
    os.mkfifo(path, 0o700)
    opened = tracked_opener(monkeypatch)
    with pytest.raises(Rejected):
        NativeSecSHelper(str(path), "a" * 64).check_available()
    assert len(opened) == 1  # Actual FIFO descriptor reached regular-file classification.
    with pytest.raises(OSError):
        os.fstat(opened[0])
