# Frank executor

Frank executes work offered by the public process-runtime v1 API. Runtime owns
published definitions, DAG readiness, Attempts, fences, leases, retries, outputs
and receipts. Frank has its own delivery/capture journal and uses the public Runtime client
for canonical data. Workspace validation delegates to Runtime's pure compiler;
Frank never opens the Runtime database.

The original `frank-executor` CLI defaults to denied production authority. The
separate `frank-local-review` entrypoint supports a closed, owner-pinned native
composition on macOS Python3.12. Source publication does not provision an identity,
grant permission, select review input, enable providers or qualify an installation.

The additive [generic workspace client](docs/workspace.md), `frank-workspace`,
supports an initially empty native-configured workspace: generic draft validation,
creation/editing, publication and current process reads. It requires no review,
audio, capture, result party, actor or Run. Runtime owns the canonical records;
Frank retains only exact client intent and acknowledgements. Validation delegates
to Runtime's installed pure compiler. Optional workflow selection stays separate.

## Install and verify

Use Python3.12 and the matching public `process-runtime==0.1.0` distribution, which
includes `process_runtime_client`. For reviewed sibling source checkouts:

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install -e ../process-runtime -e '.[test]'
.venv/bin/python -m pytest -q --basetemp="${TMPDIR:-/tmp}/frank-owned-tests"
```

The full suite requires macOS kqueue/NOTE_EXIT and an actual verification-only
Native helper with a recorded source/artifact digest. See
[verification](docs/verification.md). Tests use disposable stores, loopback Runtime
and fake providers. Synthetic process output is not Native signature evidence.
Private qualification logs are not part of this public repository.

## Execution and recovery

The default development configuration requires explicit untrusted opt-in in both
Frank and Runtime. It cannot be used as production authority:

```sh
frank-executor check-config --config ./frank.json
frank-executor health --config ./frank.json
frank-executor register --config ./frank.json --actor frank-local
frank-executor work --config ./frank.json --actor frank-local
```

The [native local-review profile](docs/local-review-installed-profile.md) binds
exact Wallet command, result-attester and verification helper artifacts, same-read
configuration hashes and current receiver policy. No generic signer, raw-key flag,
qualification token or local-development fallback is accepted. It supports fixed
`initialize`, `next`, `inspect`, `resume`, `renew` and `export` actions. `next` selects
only actual Runtime-offered work. Export requires the committed output, receipt and
artifact bytes to correlate. The retained cleanup marker blocks reentry until all
owned native workers, children and pipes resolve; it grants no future kill authority.

[Wallet call authority](docs/wallet-call-authority.md) separates new commands from
explicit no-create saved-command recovery and fresh queries.
[Local result production](docs/local-review-result-producer.md) retains computation
and port evidence before attest/resume/renew; proof renewal never reruns the handler.
The independent [result verifier](docs/native-result-authority-v1.md) checks native
proofs and current policy again before admission and terminal dispatch.

Read [operation and recovery](docs/operations.md), [adapter contracts](docs/integration-adapter-v1.md)
and [ownership](docs/architecture.md) for the limits. The Dockerfile remains a generic
offline packaging example; it does not provide macOS native-process qualification.

## Public deployment

The [Zenith Hub lightweight deployer](https://github.com/ZenithResearch/zenith-hub-lightweight)
owns the shared Mac installer/operator UI. Its installation and native activation
are separate. See [publication scope](NOTICE.public-baseline.md): private histories,
credentials, work records and live data are not imported, and public availability
does not grant a new project reuse license.
