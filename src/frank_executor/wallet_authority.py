"""Owner-injected, pinned Wallet command transport; installed admission is separate."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
import hashlib
from importlib.resources import files
import json
import math
import os
from pathlib import Path
import select
import selectors
import signal
import stat
import subprocess
import sys
import threading
import time

from .model import Rejected, canonical, decode_json
from .runtime import ContractValidator

QUERY_OPERATIONS = frozenset({
    "process.get", "work.list", "events.list", "attempt.get", "output.get", "run.get",
    "artifact.get", "version.get", "receipt.get",
})
MAX_EXECUTABLE_BYTES = 64 * 1024 * 1024
MAX_CONFIGURATION_BYTES = 65_536
MAX_AUTHORITY_BYTES = 4_400_000
MAX_PACKET_BYTES = 2_097_152 + 16_384 + 69
MAX_CONTEXT_BYTES = 65_536
MAX_STDERR_BYTES = 4096
_PS = "/bin/ps"
MAX_CENSUS_BYTES = 65_536
CENSUS_TIMEOUT = 0.5
DENIAL = "Native Wallet call authority unavailable"


def _deny():
    return Rejected(DENIAL)


def _hex(value, size):
    return type(value) is str and len(value) == size and all(c in "0123456789abcdef" for c in value)


@dataclass(frozen=True)
class _Profile:
    executable: Path
    executable_sha256: str
    configuration: Path
    configuration_sha256: str
    timeout: float


def _pinned_file(path, expected, maximum, *, executable=False):
    """Reuse the verifier's owner/no-follow/hash admission convention.

    These artifact checks assume an owner-controlled immutable deployment. The
    command's own pinned read, not these surrounding reads, binds config bytes.
    """
    fd = None
    try:
        for current in (path, *path.parents):
            info = current.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise _deny()
            if current != path:
                sticky = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
                if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.getuid())
                        or (info.st_mode & 0o022 and not sticky)):
                    raise _deny()
        if not executable:
            parent = path.parent.lstat()
            if parent.st_uid != os.getuid() or parent.st_mode & 0o077:
                raise _deny()
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or not 0 < info.st_size <= maximum
                or info.st_uid not in ((0, os.getuid()) if executable else (os.getuid(),))
                or info.st_mode & (0o022 if executable else 0o077)
                or (executable and not info.st_mode & 0o111)):
            raise _deny()
        digest = hashlib.sha256()
        body = bytearray()
        count = 0
        while block := os.read(fd, 65_536):
            count += len(block)
            if count > maximum:
                raise _deny()
            digest.update(block)
            if not executable:
                body.extend(block)
        after = os.fstat(fd)
        if (count != info.st_size or digest.hexdigest() != expected
                or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                != (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)):
            raise _deny()
        return bytes(body)
    except (OSError, ValueError):
        raise _deny() from None
    finally:
        if fd is not None:
            os.close(fd)


def _envelope(raw):
    if not 0 < len(raw) <= MAX_AUTHORITY_BYTES:
        raise _deny()

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError()
            result[key] = value
        return result

    def constant(_):
        raise ValueError()

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
        if (type(value) is not dict or set(value) != {"schema", "packet_hex", "signed_context_hex"}
                or value["schema"] != "runtime.secs-envelope.v1"):
            raise ValueError()
        for name, maximum in (("packet_hex", MAX_PACKET_BYTES), ("signed_context_hex", MAX_CONTEXT_BYTES)):
            field = value[name]
            if (type(field) is not str or not 0 < len(field) <= 2 * maximum
                    or len(field) % 2 or not _hex(field, len(field))):
                raise ValueError()
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise _deny() from None
    return raw  # Preserve the producer's bytes; receiver verifies the bincode/signatures.


# The wrapper performs no Wallet action until the parent has attached NOTE_EXIT.
# Its private FD is closed before exec; Wallet keeps the same owned PID/PGID.
_GATE = """import os,sys
fd=int(sys.argv[1])
try:
    token=os.read(fd,1)
finally:
    os.close(fd)
if token != b'G':
    os._exit(125)
os.execve(sys.argv[2],sys.argv[2:],{})
"""


@dataclass
class _Owned:
    process: subprocess.Popen
    observer: object
    streams: tuple
    gate_read: int | None
    gate_write: int | None
    exit_seen: bool = False
    reaped: bool = False
    returncode: int | None = None


def _observe(owned, changes=None):
    for event in owned.observer.control(changes, 1, 0):
        if (event.flags & select.KQ_EV_ERROR or event.ident != owned.process.pid
                or event.filter != select.KQ_FILTER_PROC
                or not event.fflags & select.KQ_NOTE_EXIT):
            raise _deny()
        owned.exit_seen = True


class _PinnedCommand:
    """Trusted composition admits the immutable executable/config tuple first.

    The host also owns this child's reaping exclusively: default SIGCHLD, no
    outside waitpid(-1), process.poll/wait, or other child-reaper thread. The
    class cannot prove that host prerequisite. Runtime still verifies evidence.
    """

    def __init__(self, *, executable, executable_sha256, configuration, configuration_sha256, timeout=5):
        self._profile = _Profile(Path(executable), executable_sha256, Path(configuration), configuration_sha256, timeout)
        p = self._profile
        if (not p.executable.is_absolute() or not p.configuration.is_absolute()
                or not _hex(p.executable_sha256, 64) or not _hex(p.configuration_sha256, 64)
                or type(timeout) not in (int, float) or not math.isfinite(timeout)
                or not 0.05 <= timeout <= 30):
            raise _deny()
        # This is the already trusted running host interpreter, not a new
        # caller-selected executable or an environment-selected launcher.
        self._python = sys.executable
        if not self._python or not Path(self._python).is_absolute():
            raise _deny()
        self._operation = threading.Lock()
        self._owned = None
        self._census = None
        self._loose_fds = []
        self._loose_observers = []
        self._first_failure = None
        self._cleanup_failures = ()

    def _remember(self, category):
        if self._first_failure is None:
            self._first_failure = category

    def _cleanup_error(self, category):
        self._remember("cleanup:" + category)
        if category not in self._cleanup_failures:
            self._cleanup_failures += (category,)

    def _check_profile(self):
        p = self._profile
        _pinned_file(p.executable, p.executable_sha256, MAX_EXECUTABLE_BYTES, executable=True)
        return _pinned_file(p.configuration, p.configuration_sha256, MAX_CONFIGURATION_BYTES)

    def _decode_output(self, raw):
        raise _deny()

    def check_available(self):
        """No process/store access; unresolved ownership keeps admission closed."""
        if self._owned is not None or self._census is not None or self._loose_fds or self._loose_observers:
            raise _deny()
        if (signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL
                or not all(hasattr(select, name) for name in (
                    "kqueue", "kevent", "KQ_FILTER_PROC", "KQ_NOTE_EXIT", "KQ_EV_ADD",
                    "KQ_EV_ENABLE", "KQ_EV_ONESHOT", "KQ_EV_ERROR"))):
            raise _deny()
        self._check_profile()

    async def _worker(self, function, *args):
        stop = threading.Event()
        worker = asyncio.create_task(asyncio.to_thread(function, *args, stop))
        cancelled = False
        while True:
            try:
                result = await asyncio.shield(worker)
                if cancelled:
                    raise asyncio.CancelledError()
                return result
            except asyncio.CancelledError:
                cancelled = True
                stop.set()
                if worker.done():
                    try:
                        worker.result()
                    except Exception:
                        pass
                    raise
            except Exception:
                if cancelled:
                    raise asyncio.CancelledError() from None
                raise _deny() from None

    def _close_owned_fds(self, owned):
        good = True
        for name in ("gate_read", "gate_write"):
            fd = getattr(owned, name)
            if fd is not None:
                try:
                    os.close(fd)
                    setattr(owned, name, None)
                except Exception:
                    self._cleanup_error("gate-close")
                    good = False
        for stream in owned.streams:
            try:
                if not stream.closed:
                    stream.close()
            except Exception:
                self._cleanup_error("pipe-close")
                good = False
        try:
            if owned.observer is not None:
                owned.observer.close()
                owned.observer = None
        except Exception:
            self._cleanup_error("observer-close")
            good = False
        return good

    def _cleanup_loose(self):
        good = True
        for fd in tuple(self._loose_fds):
            try:
                os.close(fd)
                self._loose_fds.remove(fd)
            except Exception:
                self._cleanup_error("gate-close")
                good = False
        for observer in tuple(self._loose_observers):
            try:
                observer.close()
                self._loose_observers.remove(observer)
            except Exception:
                self._cleanup_error("observer-close")
                good = False
        return good

    def _cleanup_census(self):
        process = self._census
        if process is None:
            return True
        good = True
        # Fixed trusted ps never forks. This is a direct-child cleanup, not a
        # signal to the Wallet group. Popen.kill safely handles an exited ps.
        if process.returncode is None:
            try:
                process.kill()
            except Exception:
                self._cleanup_error("census-kill")
                good = False
            try:
                process.wait(timeout=0.25)
            except Exception:
                self._cleanup_error("census-reap")
                good = False
        for stream in (process.stdout, process.stderr):
            try:
                if not stream.closed:
                    stream.close()
            except Exception:
                self._cleanup_error("census-close")
                good = False
        if process.returncode is not None and process.stdout.closed and process.stderr.closed:
            self._census = None
        return good and self._census is None

    def _snapshot_bytes(self, pid):
        """Fixed, bounded OS census of this group only; never retain process argv."""
        if self._census is not None:
            raise _deny()
        deadline = time.monotonic() + CENSUS_TIMEOUT
        process = subprocess.Popen(
            [_PS, "-x", "-g", str(pid), "-o", "pid=,ppid=,pgid=,uid=,stat="],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={"LC_ALL": "C"}, cwd="/", bufsize=0, shell=False, close_fds=True,
        )
        self._census = process
        output, errors = bytearray(), bytearray()
        good = False
        try:
            with selectors.DefaultSelector() as selector:
                for stream in (process.stdout, process.stderr):
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise _deny()
                    for event, _ in selector.select(min(remaining, 0.05)):
                        stream = event.fileobj
                        block = os.read(stream.fileno(), 4096)
                        if not block:
                            selector.unregister(stream)
                            stream.close()
                        else:
                            target = output if stream is process.stdout else errors
                            target.extend(block)
                            if len(output) > MAX_CENSUS_BYTES or len(errors) > 1024:
                                raise _deny()
            remaining = deadline - time.monotonic()
            if remaining <= 0 or process.wait(timeout=remaining) != 0 or errors:
                raise _deny()
            good = True
        except Exception:
            self._cleanup_error("census")
            raise
        finally:
            if not self._cleanup_census():
                good = False
        if not good:
            raise _deny()
        return bytes(output)

    def _sole_zombie(self, owned):
        # The leader stays unreaped, so the PID cannot be reused under the
        # exclusive-reaper prerequisite. A sole Z cannot fork new descendants.
        rows = []
        seen = set()
        for line in self._snapshot_bytes(owned.process.pid).decode("ascii").splitlines():
            fields = line.split()
            if (len(fields) != 5 or any(not field.isdecimal() or len(field) > 10
                    for field in fields[:4]) or not 1 <= len(fields[4]) <= 16
                    or fields[4][0] not in "IRSTUZ"
                    or any(flag not in "+<>AELNSsVWX" for flag in fields[4][1:])):
                raise _deny()
            pid, ppid, pgid, uid = map(int, fields[:4])
            if pid <= 0 or ppid <= 0 or pgid != owned.process.pid or pid in seen:
                raise _deny()
            seen.add(pid)
            rows.append((pid, ppid, pgid, uid, fields[4]))
        if not rows:
            raise _deny()
        if len(rows) != 1:
            return False
        pid, ppid, pgid, uid, status = rows[0]
        return (pid == pgid == owned.process.pid and ppid == os.getpid()
                and uid == os.getuid() and status[0] == "Z")

    def _zombie_proof(self, owned):
        try:
            return self._sole_zombie(owned), True
        except Exception:
            self._cleanup_error("census")
            return False, False

    def _cleanup_owned(self):
        """Complete remaining safe steps, retain unresolved state, never retry work."""
        loose_good = self._cleanup_loose()
        census_good = self._cleanup_census()
        owned = self._owned
        if owned is None:
            return loose_good and census_good
        good = self._close_owned_fds(owned) and loose_good and census_good
        if not owned.reaped:
            # Darwin rejects group signals to an all-zombie group with EPERM.
            # Only an exact sole-owned-Z census permits the no-signal reap path.
            stopped = False
            if owned.exit_seen:
                stopped, census_good = self._zombie_proof(owned)
                good = good and census_good
            if not stopped:
                try:
                    os.killpg(owned.process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    stopped = True
                except Exception:
                    stopped, census_good = self._zombie_proof(owned)
                    good = good and census_good
                    if not stopped:
                        self._cleanup_error("term")
                        good = False
            if not stopped:
                if not owned.exit_seen:
                    time.sleep(0.25)
                try:
                    os.killpg(owned.process.pid, signal.SIGKILL)
                    stopped = True
                except ProcessLookupError:
                    stopped = True
                except Exception:
                    stopped, census_good = self._zombie_proof(owned)
                    good = good and census_good
                    if not stopped:
                        self._cleanup_error("kill")
                        good = False
            if stopped:
                try:
                    owned.returncode = owned.process.wait(timeout=1)
                    owned.reaped = True
                except Exception:
                    self._cleanup_error("reap")
                    good = False
        absent = False
        if owned.reaped:
            # After reaping, ONLY observe absence: no later signal can target a
            # potentially reused numeric group. A remaining group quarantines.
            deadline = time.monotonic() + 0.25
            while True:
                try:
                    os.killpg(owned.process.pid, 0)
                except ProcessLookupError:
                    absent = True
                    break
                except Exception:
                    self._cleanup_error("group-probe")
                    good = False
                    break
                if time.monotonic() >= deadline:
                    self._cleanup_error("group-present")
                    good = False
                    break
                time.sleep(0.01)
        if (owned.reaped and absent and owned.gate_read is None and owned.gate_write is None
                and owned.observer is None and all(stream.closed for stream in owned.streams)):
            self._owned = None
        return good and self._owned is None and self._census is None

    async def aclose(self):
        """Explicit bounded cleanup of retained ownership; never acquires evidence."""
        await self._worker(self._close_worker)

    def _close_worker(self, stop):
        if not self._operation.acquire(blocking=False):
            raise _deny()
        try:
            if not self._cleanup_owned():
                raise _deny()
        finally:
            self._operation.release()

    def _invoke(self, mode, data, stop):
        if not self._operation.acquire(blocking=False):
            raise _deny()
        observer = None
        read_fd = write_fd = None
        owned = None
        failed = False
        phase = "profile"
        output = bytearray()
        try:
            self.check_available()
            if stop.is_set():
                phase = "cancelled"
                raise _deny()
            phase = "launch"
            observer = select.kqueue()
            read_fd, write_fd = os.pipe()
            p = self._profile
            wallet_argv = [str(p.executable), mode, "--config", str(p.configuration),
                           "--config-sha256", p.configuration_sha256]
            process = subprocess.Popen(
                [self._python, "-I", "-S", "-B", "-c", _GATE, str(read_fd), *wallet_argv],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                pass_fds=(read_fd,), env={}, cwd=str(p.configuration.parent), bufsize=0,
                shell=False, close_fds=True, start_new_session=True,
            )
            owned = _Owned(process, observer, (process.stdin, process.stdout, process.stderr), read_fd, write_fd)
            self._owned = owned
            observer = read_fd = write_fd = None  # Ownership transferred even if attach fails.
            deadline = time.monotonic() + p.timeout
            phase = "attach"
            os.close(owned.gate_read)
            owned.gate_read = None
            _observe(owned, [select.kevent(process.pid, filter=select.KQ_FILTER_PROC,
                flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE | select.KQ_EV_ONESHOT,
                fflags=select.KQ_NOTE_EXIT)])
            if owned.exit_seen or stop.is_set():
                raise _deny()
            phase = "gate-release"
            if os.write(owned.gate_write, b"G") != 1:
                raise _deny()
            os.close(owned.gate_write)
            owned.gate_write = None
            sent, errors = 0, bytearray()
            phase = "transport"
            with selectors.DefaultSelector() as selector:
                for stream, event in ((process.stdin, selectors.EVENT_WRITE),
                                      (process.stdout, selectors.EVENT_READ),
                                      (process.stderr, selectors.EVENT_READ)):
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, event)
                while selector.get_map() or not owned.exit_seen:
                    remaining = deadline - time.monotonic()
                    if stop.is_set() or remaining <= 0:
                        phase = "cancelled" if stop.is_set() else "timeout"
                        raise _deny()
                    _observe(owned)
                    for event, _ in selector.select(min(remaining, 0.05)):
                        stream = event.fileobj
                        if stream is process.stdin:
                            sent += os.write(stream.fileno(), data[sent:sent + 8192])
                            if sent == len(data):
                                selector.unregister(stream)
                                stream.close()
                        else:
                            block = os.read(stream.fileno(), 8192)
                            if not block:
                                selector.unregister(stream)
                                stream.close()
                            else:
                                target = output if stream is process.stdout else errors
                                target.extend(block)
                                if len(output) > MAX_AUTHORITY_BYTES or len(errors) > MAX_STDERR_BYTES:
                                    raise _deny()
            phase = "output"
            if errors:
                raise _deny()
            self._decode_output(bytes(output))
            phase = "post-profile"
            self._check_profile()
        except Exception:
            failed = True
            self._remember(phase)
        finally:
            if owned is not None:
                try:
                    if not self._cleanup_owned():
                        failed = True
                except Exception:
                    self._cleanup_error("unexpected")
                    failed = True
                if owned.returncode != 0:
                    self._remember("exit")
                    failed = True
            # Only launch-before-transfer paths can leave these local handles.
            for fd in (read_fd, write_fd):
                if fd is not None:
                    try:
                        os.close(fd)
                    except Exception:
                        self._cleanup_error("gate-close")
                        self._loose_fds.append(fd)
                        failed = True
            if observer is not None:
                try:
                    observer.close()
                except Exception:
                    self._cleanup_error("observer-close")
                    self._loose_observers.append(observer)
                    failed = True
            self._operation.release()
        if failed or stop.is_set():
            raise _deny() from None
        return bytes(output)


class WalletCallAuthority(_PinnedCommand):
    """Pinned Wallet request authority; shares only owned-process mechanics."""
    mode = "secs_verified"

    def __init__(self, *, executable, executable_sha256, configuration, configuration_sha256, timeout=5):
        super().__init__(executable=executable, executable_sha256=executable_sha256,
                         configuration=configuration, configuration_sha256=configuration_sha256, timeout=timeout)
        bundle = json.loads(files("process_runtime_client").joinpath("runtime-v1.schema.json").read_text())
        self._validate = ContractValidator(bundle)

    def _check_profile(self):
        raw = super()._check_profile()
        try:
            value = decode_json(raw)
            if (type(value) is not dict or set(value) != {
                    "schema", "native_configuration", "native_configuration_sha256", "wallet_root",
                    "application", "store_binding", "expected_state"}
                    or value["schema"] != "castalia.wallet-service-command.v1"
                    or value["application"] != "runtime"):
                raise _deny()
        except (ValueError, KeyError, TypeError):
            raise _deny() from None

    def _decode_output(self, raw):
        return _envelope(raw)

    async def evidence(self, envelope: bytes) -> bytes:
        return await self._acquire(envelope, resume=False)

    async def resume_evidence(self, envelope: bytes) -> bytes:
        """Explicit saved-command recovery; no creation, query or fallback."""
        return await self._acquire(envelope, resume=True)

    async def _acquire(self, envelope, *, resume):
        try:
            if type(envelope) is not bytes:
                raise _deny()
            body = decode_json(envelope)
            if canonical(body) != envelope or type(body) is not dict:
                raise _deny()
            if body.get("schema") == "runtime.command.v1":
                self._validate(body, "command")
                mode = "resume" if resume else "issue"
            elif (not resume and body.get("schema") == "runtime.query.v1"
                    and body.get("operation") in QUERY_OPERATIONS):
                self._validate(body, "query")
                mode = "query"
            else:
                raise _deny()
        except (ValueError, KeyError, TypeError):
            raise _deny() from None
        return await self._worker(self._invoke, mode, envelope)
