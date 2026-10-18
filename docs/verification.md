# Public source and installed verification

Run the full suite on macOS with Python3.12. Native Wallet transport controls use
actual kqueue/NOTE_EXIT, owned process groups and OS census; Linux is not an
alternate qualification target for that path. The public workflow selects
`macos-latest`. A workflow source file is not evidence that hosted CI ran.

Native result compatibility tests require an actual verification-only helper and
never silently skip. Set `FRANK_NATIVE_VERIFIER` to that artifact and
`FRANK_NATIVE_VERIFIER_SHA256` to its independently recorded digest. The historical
macOS artifact digest remains the test fallback. Retain source revision, locked
Native dependency closure and build/artifact hashes separately. Environment input
selects a test artifact, not production authority configuration.

```sh
.venv/bin/python -m pytest -q --basetemp="${TMPDIR:-/tmp}/frank-owned-tests"
.venv/bin/python -m ruff check --select F src tests
git diff --check
```

Tests use disposable private files/SQLite, loopback Runtime, fake providers and
synthetic protocol processes. Actual native signature tests remain distinguishable
from synthetic lifecycle/port controls. Private logs, workstation locations and
work-tracking records are not public evidence. De-identified demonstration fixtures
have explicit recomputed content references; assertions and comparison categories
are preserved. New public source/full-suite and installed results must be recorded
for the exact public tuple rather than inherited from private-source results.

The public `resource_origin.py` retains two existing public resource hashes for
de-identified `personal-review-legacy.md` and `personal-review-v1.migration.json`.
Those hashes must match the corresponding public Runtime bundle and Frank fixtures.
No fallback accepts a private or mismatched resource. This is an explicit source
exception from the private component revision, not byte-identical qualification.

For wheel verification, build offline with the reviewed Python3.12/setuptools84
builder, check every ZIP member/RECORD hash and size, and compare all package/data
bytes against the admitted source. Tests, fixture generators and operator evidence
must not enter the wheel. Install Frank and the matched public Runtime wheel into
a fresh environment; verify distribution origins/RECORD and run the existing
installed-mode suite without source-path overrides. Native component artifacts and
current receiver policy remain separate required inputs.

The historical cfg(test) fixture generator is not a package or production
dependency. Its retained Cargo.lock still records an old private Wallet Git URL;
that URL is not a credential, but anonymous regeneration of this historical lock
is not established. The lock is preserved rather than silently repinned. Current
public signature vectors can be consumed by the pinned verification-only helper;
regenerating them requires separately qualified dependency/lock work. No signing
executable or disposable fixture seed is included in the Frank wheel.
