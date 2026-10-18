# Generic native workspace client

`frank-workspace` is an additive client for an initially empty environment. It
does not initialize a process, Run, Actor, review, audio input, result party,
capture, provider or external effect. Runtime remains the sole owner of process
definitions, revisions and immutable publications. Frank's journal records client
intent and acknowledgements, never canonical Runtime data. Validation calls the
installed Runtime package's pure compiler; it does not open Runtime storage, and
Runtime independently compiles the current source again on publication.

The closed owner-private configuration has exactly these four fields:

```json
{
  "schema": "frank.workspace.v1",
  "runtime_endpoint": "http://127.0.0.1:8292",
  "journal": "/absolute/private/workspace/data/frank-workspace.db",
  "wallet": {
    "executable": "/absolute/private/workspace/native/castalia-wallet-service",
    "executable_sha256": "<exact admitted artifact SHA256>",
    "configuration": "/absolute/private/workspace/authority/config/wallet-command.json",
    "configuration_sha256": "<exact setup output SHA256>"
  }
}
```

The angle-bracket examples are not executable configuration or admitted hashes.
Use actual current setup outputs. The endpoint is an explicit HTTP numeric
loopback origin with a port1024–65535. Master, input and Wallet configuration
reads require bounded private regular files, exact lower-case SHA256 and safe
ancestors. Journal parent must already be owner-private; an existing journal must
be a private single-link regular file and belong to Frank. No directory or key
is created by `check-config` or `validate`. The command does not provision a
holder, change permissions, renew roles or turn an artifact hash into authority.

Every call uses:

```text
python -I -B -m frank_executor.workspace_cli ACTION
  --config ABS --config-sha256 LOWER64
  [--input ABS --input-sha256 LOWER64] [--wait-seconds 60]
```

All actions except `check-config` require an input file of at most64KiB, read and
hashed before its strict duplicate-rejecting JSON parse. Output is bounded by
Frank's existing1MiB JSON ceiling. The whole action deadline is greater than0 and
at most120seconds. Inputs never choose a host command, executable, provider,
policy, authority evidence or environment variable.

| Action | Exact input | Output |
| --- | --- | --- |
| `check-config` | none | `frank.workspace.status.v1`; `runtime_checked:false` and cleanup observation |
| `catalog` | `{after,limit,max_pages}`; cursor≥0, limit1–100, pages1–20 | `frank.workspace.catalog.v1`: `process_ids`, original `after`, `next_cursor`, `high_watermark`, `cursor_exhausted`, `complete` |
| `get` | `{process_id}` | `frank.workspace.process.v1` with exact canonical `process` read |
| `validate` | exact generic `process.draft.v1` document | `frank.workspace.validation.v1`; `valid:true`, Runtime compiled snapshot/hash; or `valid:false` with bounded code/detail |
| `draft-put` | exact public `runtime.command.v1` for `process.draft.put` | actual unchanged Runtime result |
| `publish` | exact public `runtime.command.v1` for `process.publish` | actual unchanged Runtime result |
| `resume-command` | `{request_id}` | exact retained acknowledgement or actual Runtime result for the original saved authoring command |

A new empty workspace is valid with zero processes. A new unsaved editor buffer
can be incomplete; saving still obeys Runtime's existing draft schema (including
at least one explicitly selected step). No example is inserted automatically.
Empty capabilities do not create a worker or prove a process is executable.

For new draft creation use `expected_version:null`; for an edit use the exact
current `process.get.version`. Preserve the draft's explicit source provenance.
Publication names the current `draft_revision`, current record version and a new
immutable `version_id`. Public SDK resource derivation must exactly equal the
command's `resource` (`processes/<id>`). A stale version is returned as denial,
never auto-rebased. Validation success does not publish or imply capability,
worker, provider or execution readiness.

The controller allocates a unique request ID once, retains the exact reviewed
command and reuses it for retries. Before native acquisition RuntimeGateway
durably saves that intent. A repeated pending identity returns unknown and
requires explicit `resume-command`; it never selects `issue` as a fallback.
An observed identity returns its exact retained acknowledgement (an observation,
not a new current state read). Changed bytes under that identity deny. Resume is
limited to draft/publication commands; it cannot replay execution/effect calls.
No new proof, key, window or command identity is inferred from a denial or expiry.

The own journal has one `workspace_binding` metadata row for the exact master
SHA256. A changed endpoint, Wallet tuple or other master bytes cannot adopt a
previous workspace's acknowledgements. A nonempty unbound Frank journal is also
rejected without adopting or deleting its records. This is receipt consistency,
not authority or canonical process state. Later owner policy/configuration
updates require an explicit identity-preserving owner migration decision; this
CLI never resets a journal or silently rebinds it to a new composition.

Catalog uses the existing retained unfiltered `events.list` stream, with SDK
event/schema and strict contiguous-cursor checks. Process creation/publication
events discover IDs; selected drafts are read from `process.get`, not reconstructed
from event summaries. `cursor_exhausted:true` means this event suffix caught up to its returned
high-water mark. `complete:true` additionally requires `after:0`, so a suffix
never represents a complete catalog. Neither is an atomic future view. When
`after>0`, `process_ids` are changed IDs in that suffix; the UI may merge them into a rebuildable observation. If a page bound
is reached, continue explicitly from `next_cursor`; never call a partial page a
complete catalog. Missing/gapped/malformed streams deny, rather than assert empty.
There is no new canonical index or Runtime process-list schema.

Every query, including identical repeated `process.get` bytes, uses an explicitly
fresh Native query exchange identity retained by Native's journal. Query JSON
does not gain an invented request ID. Native, Wallet command and Frank each
explicitly admit `process.get`; that addition is not permission. The owner setup
and receiver policy still must allow each exact operation/resource. This source
does not widen a retained review role or claim its installed binary supports the
new query until the matching composition is qualified.

Native actions hold `journal.parent/frank-workspace-cleanup.json`, schema
`frank.workspace.cleanup.v1`, with operation/profile/action/state and boolean
unresolved Wallet/Runtime ownership. The marker is create-only and checked against
the held inode and exact content before removal. Wallet process ownership uses
the existing qualified engine. HTTP workers are shielded from caller cancellation
and drained before release; an unresolved worker/child/FD retains the marker.
The ordinary5-second local HTTP timeout and10-second drain are bounded policies,
not a guarantee that an arbitrary OS thread can be killed. No retained PID/PGID
authorizes a later signal. Exit0 is a normal result (including valid:false),2 is
denial,3 is unknown outcome,4 means retained/unresolved ownership. Only0/2/3 with
resolved cleanup permit an outer controller to remove its own matching hold.

The default `frank-executor` and optional `frank-local-review` entrypoints retain
their existing behavior. This authoring path composes no Executor or review/result
or provider configuration. Installed native authority, Service scope, worker/run
activation and useful user workflows remain separate explicit selections.
