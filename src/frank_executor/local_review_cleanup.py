"""CLI crash/cleanup observation only. Persisted data never authorizes a signal."""
from __future__ import annotations

import os
import stat
import uuid
from pathlib import Path

from .model import Rejected, canonical, decode_json
from frank_review_adapter.local_capture import private_directory, read_private

NAME = "frank-local-review-cleanup.json"


class CleanupUnresolved(Rejected):
    pass


def marker_path(profile):
    return Path(profile.composition["journal"]).parent / NAME


def marker_status(profile):
    path = marker_path(profile)
    try:
        path.lstat()
    except FileNotFoundError:
        return "clear"
    try:
        value = decode_json(read_private(path, 4096))
        if (type(value) is dict and value.get("schema") == "frank.local-review.cleanup.v1"
                and value.get("state") in {"running", "cleanup_unresolved"}):
            return value["state"]
    except (OSError, Rejected):
        pass
    return "invalid-retained"


def unresolved(transport):
    if transport is None:
        return False
    lock = getattr(transport, "_operation", None)
    return bool(getattr(transport, "_owned", None) is not None
                or getattr(transport, "_census", None) is not None
                or getattr(transport, "_loose_fds", ())
                or getattr(transport, "_loose_observers", ())
                or lock is not None and lock.locked())


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class Operation:
    def __init__(self, profile, action):
        self.path = marker_path(profile)
        private_directory(self.path.parent)
        self.value = {"schema":"frank.local-review.cleanup.v1", "operation_id":uuid.uuid4().hex,
            "profile_sha256":profile.config_sha256, "action":action, "state":"running",
            "unresolved":{"wallet":False,"result":False,"verifier":False}}
        try:
            self.fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            raise CleanupUnresolved("Retained local-review cleanup state requires owner inspection") from None
        self.identity = os.fstat(self.fd)
        try:
            self._write()
            sync_directory(self.path.parent)
        except BaseException:
            os.close(self.fd)
            self.fd = None
            # An incomplete marker remains blocked; never erase ambiguous state.
            raise CleanupUnresolved("Local-review cleanup record could not be retained") from None

    def _same(self):
        current = self.path.lstat()
        if (not stat.S_ISREG(current.st_mode) or current.st_uid != os.getuid()
                or current.st_nlink != 1 or current.st_mode & 0o077
                or (current.st_dev,current.st_ino) != (self.identity.st_dev,self.identity.st_ino)):
            raise CleanupUnresolved("Local-review cleanup owner changed")

    def _write(self):
        raw = canonical(self.value)
        os.lseek(self.fd,0,os.SEEK_SET)
        os.ftruncate(self.fd,0)
        while raw:
            n = os.write(self.fd,raw)
            if n <= 0:
                raise OSError("cleanup record short write")
            raw = raw[n:]
        os.fsync(self.fd)

    def finish(self, *, wallet=None, result=None, verifier=None):
        states = {"wallet":unresolved(wallet),"result":unresolved(result),
                  "verifier":bool(getattr(verifier,"cleanup_pending",False))}
        try:
            self._same()
            retained = decode_json(read_private(self.path,4096))
            if retained != self.value:
                raise CleanupUnresolved("Local-review cleanup record changed")
            if any(states.values()):
                self.value.update(state="cleanup_unresolved",unresolved=states)
                self._write()
                sync_directory(self.path.parent)
                raise CleanupUnresolved("Native local-review cleanup remains unresolved")
            self._same()
            os.unlink(self.path)
            sync_directory(self.path.parent)
        except (OSError, Rejected):
            raise CleanupUnresolved("Native local-review cleanup remains unresolved") from None
        finally:
            if self.fd is not None:
                os.close(self.fd)
                self.fd = None
