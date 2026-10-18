# Native local-review composition

`frank-local-review` is a separate, explicitly selected entrypoint. The original
`frank-executor`, `frank.config.v1`, installation-only configuration and default
deny behavior are unchanged. This public source includes the closed profile,
workflow actions and durable cleanup handling. Public source tests, an installed
artifact tuple and actual current Native authority must be validated separately;
source availability alone does not select real owner pins, identities or inputs.

There is no `qualified` flag, token, subclass, test-mode downgrade or mode-string
activation. Production admission inspects the exact `WalletCallAuthority`,
`NativeSecSHelper`, `FileReceiverPolicy` and actual system clock. The pinned
executables/configurations must be available; current verifier keys and subject rules
are read again. Subject rules are correlated with the selected actor, integration
and route; signer keys and subject keys retain their distinct existing roles. Exact per-result signature, descriptor, route, resource,
revocation, expiry, replay and terminal-dispatch checks remain authoritative.
The historical `native_unqualified` library label is retained for compatibility
with synthetic construction; setting or reading that label does not grant
admission. Synthetic helper, custom clock or callable policy is still denied
in production. Host deployment must keep admitted code/artifacts immutable;
reading their metadata alone does not prove native qualification or a live grant.

## Closed owner files

Both JSON documents reject additional and duplicate fields. The master and
composition are bounded to 65,536 bytes and read from owner-private regular files
under private owner directories, without symlink traversal. The command line
must provide the SHA256 of the exact master bytes. The loader checks each hash
over the same bytes it parses. No environment variable supplies native paths,
policy, identity or an alternative signer.

Master fields, exactly:

| Field | Value |
| --- | --- |
| `schema` | `frank.local-review.config.v1` |
| `composition` | `{path, sha256}` of the producer-composition document |
| `source_manifest_sha256` | Exact capture source-manifest hash |
| `wallet` | `{executable, executable_sha256, configuration, configuration_sha256}` |
| `result` | The same four fields for `secs-frank-result` |
| `verifier` | `{executable, sha256, policy}` for the verification-only helper and current public receiver policy |

The Wallet/result executables retain their own same-read configuration pins.
The receiver policy path is fixed owner composition; its current public bytes
are deliberately reloaded so revocations need no stale startup-policy cache.
It is a public-policy file, never a key or seed input.

Producer composition fields, exactly:

| Field | Value |
| --- | --- |
| `schema` | `frank.local-review.composition.v1` |
| `runtime_endpoint` | Explicit HTTP(S) endpoint without credentials, query or fragment |
| `journal` | Absolute Frank-owned journal filename under an existing private directory |
| `capture_root` | Existing private root containing `source-manifest.json` and `blobs/` |
| `actor` | `{actor_id, integration_id, route, capabilities, resources}` |
| `run_ids` | 1–64 unique explicit run IDs |
| `producer_artifact_sha256`, `normalizer_sha256` | Content-addressed source-manifest blobs selected by the admitted installation |
| `transcript` | `{audio_sha256, artifact}` for explicit supplied transcript evidence |
| `snapshots` | At most 64 subject IDs, each with at most 128 `{path, artifact}` logical source references |

An artifact is exactly `{content_hash, byte_length, media_type}`, at most 1 MiB.
Selected transcript content must already conform to
`frank.supplied-audio-transcript.v1` and match the actual supplied audio hash.
This is supplied transcript evidence, never a claim that live STT ran. Source
paths are logical labels; source content is fetched by its Runtime artifact
reference, never from model-selected filesystem paths or URLs.

The actor may declare only the nine canonical review capabilities and four
published aliases (`transcribe-review-audio`, `annotate-review-transcript`,
`extract-review-observations`, `update_review_status`). This preserves eligibility
for the existing personal-review-v1 ProcessVersion. Execution selection remains
one of the nine canonical operations. Up to 128 unique resources are explicit
owner declarations. No process resource, closed port or stored packet shape changes.

The capture manifest retains the exact composition bytes plus selected producer
and normalizer blobs. Its `configuration_sha256` is the composition hash. The
source-manifest hash belongs only in the master, so the composition and manifest
do not form a hash cycle. Native result assignment separately pins that manifest.
The owner/setup process provides these immutable files; this CLI does not create
keys, assignments, grants, input artifacts or a new source manifest.

## Operations

Every invocation uses `--config PATH --config-sha256 HEX`. The entrypoint supports:

- `check-config` and `health`: bounded local file/policy admission only. They do
  not create a Journal/capture, open SQLite, launch native processes or contact
  Runtime. They report artifact availability/current-policy validity and
  `runtime_checked: false`; they do not report a live end-to-end grant.
- `register` and `work`: use the fixed actor and actual authenticated Runtime API.
  Work listings are filtered to the configured run IDs.
- `execute --run-id ID --step-id ID --operation NAME --scope ID`: require that
  exact step in Runtime's eligible work listing before claiming it. Existing
  `Executor.run` supervises one Attempt, including heartbeat and final guarded
  completion/failure; it never calculates DAG readiness.
- `resume --effect-key ID`: recover the exact retained delivery, explicit
  saved terminal command or original Native selector. Unknown work is not sent
  again and completed captures are not recomputed.
- `renew --effect-key ID`: explicitly renew the original immutable result tip,
  subject to current Runtime claim and Native parent/body checks. There is no
  expired-proof fallback or provider rerun. Unknown lost output must be resumed
  before a tip exists to renew.
- `reconcile-command --request-id ID`: exact no-create Wallet resume for retained
  nonterminal commands. Terminal completion/failure/effect observation is rejected
  here and must use guarded effect recovery.

`--lease-ms` is 1,000–3,600,000 (default 120,000), and `--wait-seconds` is greater
than 0 and at most 3,600 (default 60). One invocation supervises one selected step;
it does not start an unbounded service or poll for arbitrary new work. Unknown
outcomes exit 3 and require explicit recovery; fixed configuration/current-authority
denials exit 2. Normal cleanup closes the adapter and Wallet transport, including
its retained owned-process cleanup state. Status/daily-note intents remain durable
local simulations with no external delivery. There is no Matrix/Hermes dependency.

Current policy/result expiry and retired Attempt limits still apply to recovery.
The CLI does not renew a command's original authority window or revive an expired
Attempt. Selecting a profile does not bypass Native or Runtime's current policy.

## Initial source validation plan (historical)

The initial test-first packet proposed 27 cells; one bounded policy-file-open
control and three current-policy correlation negatives made 31 in that candidate. They cover closed/private exact bytes,
the actual retained published 13-capability union, unchanged defaults, no-store
health, exact native types/system clock/current policy, concrete public Runtime
ports, canonical operation selection and bounded Runtime eligibility/no-retry
orchestration. Dummy pinned artifact bytes in these tests are explicitly never
executed. Actual native signatures, full result chain, native stdout/helper
compatibility, installed console script/origins and useful real input remain
separate qualification evidence. No live profile, role, input or grant is assigned
by this source packet.


## Owner-pinned workflow and CLI cleanup successor

The additional workflow actions below are source-only until their separate
validation and installed composition are accepted. The prior 31 profile controls
and two FIFO controls do not prove this successor.

Hub invokes fixed actions with `--config PATH --config-sha256 HEX --workflow PATH
--workflow-sha256 HEX`. The workflow document is selected only after create-only
setup has emitted the exact master bytes. `profile_sha256` hashes those master
bytes; no guessed hash, cycle or automatic trust rewrite is permitted. Both
workflow flags are required together. The master and composition schemas remain
unchanged.

`frank.local-review.workflow.v1` has exactly these seven fields:

| Field | Meaning |
| --- | --- |
| `schema` | `frank.local-review.workflow.v1` |
| `profile_sha256` | Exact selected master SHA256 |
| `run_id` | One run explicitly permitted by the composition |
| `process` | `{draft:{path,sha256}, compiled:{path,sha256}, process_version}` for selected personal-review-v1 source and compiled bytes |
| `inputs` | Exact initial Runtime run input values |
| `artifacts` | 1–16 unique nonempty `{path,artifact}` owner-selected files; artifact is the existing three-field reference |
| `export` | `{root,step_id,output}` selecting the published review.write_review step's review_note artifact and the existing private Pilot/exports directory |

The workflow is at most 65,536 bytes. Process files and each artifact are at most
1 MiB; existing canonical Runtime command limits still apply to base64 ingress,
so a raw file within that ceiling can still be too large for its command. Such
input is rejected without enlarging any protocol limit. The workflow must retain
every composition-selected audio, event, supplied transcript and source artifact.
These are owner-selected actual bytes; initialization does not synthesize speech,
source data, expected notes or a provider transcript.

- `initialize` uploads selected content-addressed inputs and reads them back,
  puts the pinned draft, publishes the exact version, verifies actual version
  bytes, registers the fixed actor, creates the exact run and reads it back.
  Stable command IDs bind the workflow hash. Observed exact responses are reused;
  a saved pending command stops initialization and requires explicit `resume`.
  There is no retry with a fresh ID or fallback after authority denial.
- `next` checks for unresolved local commands/effects and a running Attempt, then
  uses actual Runtime work.list and version.get. It takes one offered step with
  exactly one canonical review capability, preserving all required published
  aliases. It never calculates dependencies or schedules an unoffered step.
- `inspect` reads the real run and every succeeded step's actual output and receipt.
  Its bounded `frank.local-review.inspection.v1` result contains run_id, run_state,
  recoverable, export_available, step identity/state/receipt/digest rows, pending
  command summaries and unresolved effect summaries. It contains no note bodies,
  credentials or policies. Recoverable means one supported retained selection,
  not a promise that its lease or authority remains valid. Export availability requires matching committed
  evidence, never an expected fixture output.
- `export` additionally reads and verifies the actual Markdown artifact, then
  creates `<content_hash>.md` under the selected private export root. Existing
  exact bytes may be read back; a conflicting file is denied and never overwritten.
- `resume` with a workflow selects one exact retained effect, or (when no effect
  exists) one saved nonterminal command for explicit no-create Wallet recovery.
  `renew` requires one original effect. Ambiguous state, an orphan claimed Attempt,
  expired command authority and retired Attempts remain blocked. This successor
  does not claim to reconstruct missing provenance or rerun a handler after loss.

Hub may call inspect after a successful action to refresh its status; CLI action
responses do not themselves imply the next step or overall completion. All CLI
work has an overall wait budget in addition to existing native/SDK deadlines.
Cancellation drains existing transport cleanup before returning; it cannot prove
that an external authority operation never committed.

Before any native action the CLI exclusively creates
`<journal-parent>/frank-local-review-cleanup.json` with schema
`frank.local-review.cleanup.v1`, operation_id, profile_sha256, action, state and
`unresolved:{wallet,result,verifier}`. The state starts running. Only its matching owner
removes the record after bounded cleanup leaves no owned leader, census process,
loose descriptor/observer or active transport worker. Unresolved cleanup persists
state cleanup_unresolved and exits 4; retained/malformed markers block future
native actions. Neither this file nor Hub's separate pilot-operation.json grants
future signal authority: no PID/PGID is recorded or reused. Hard termination may
leave running or malformed state and requires owner inspection. Health remains
read-only and reports cleanup_state. Exits 2/3 retain their denial/unknown meanings
only when cleanup ownership has resolved. A host must keep these owner-private
records and admitted inputs protected from concurrent owner mutation.

The source tests use real private files and the Frank journal with a public-schema
Runtime double, plus cleanup-state objects and cancellation. They exercise exact
command replay selection, published-source mismatch, eligible/foreign/unknown
work, committed output/receipt/artifact correlation and create-only export. They
do not launch a native executable or claim crypto/installed/pilot qualification.
The admitted native tuple must include the separately qualified finite-capacity
Wallet command implementation; old binary bytes with unsupported configuration
must deny and are never used as a fallback.


### Cancellation and verifier ownership

The action marker includes a `verifier` unresolved observation alongside Wallet
and result-command observations. Existing retained markers remain blocking;
absence of the new field never permits reopening one. Both the producer and
Executor share the same concrete verifier. Cancellation stops result delivery,
while its shielded thread remains retained until explicit close drains it.
The fixed verifier helper retains its direct child, selector and all pipe handles;
a failed reap or close denies another verification. Helper I/O keeps its existing
five-second maximum and output bounds. Cleanup has a one-second child wait;
verifier close has a seven-second total asynchronous drain budget. Timeout or
repeated cancellation leaves unfinished work visible to the CLI marker. A future
CLI does not use persisted data to signal or retry any old process.

Composition runs synchronously before the first native action: it performs only
metadata/configuration/SQLite composition and cannot leave a newly created
executor hidden in a cancelled worker. Existing public SDK unknown-command
recovery and per-request authority remain unchanged.

Hub automatic inspection uses the separately coordinated fixed CLI
`--wait-seconds 15` and a 30-second wrapper budget; manual actions retain the
60-second CLI default and 90-second wrapper budget. Node's pilot envelope stays
240 seconds. Inspection never invokes the result producer/verifier helper; its
remaining reserve is for the existing Wallet query transport and cleanup. These
are application deadlines and cleanup reserves, not a guarantee that the OS can
terminate pathological blocked syscalls. A hard termination or unresolved drain
retains CLI/Hub ownership observations and requires owner inspection.
