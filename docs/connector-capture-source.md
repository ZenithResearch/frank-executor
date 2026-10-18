# Unsigned connector capture candidate

This library retains original unsigned connector observations while withholding
terminal output until an appropriate result issuer is available. Public tests
exercise its source behavior; private review receipts are not public qualification.
No identity, opcode, grant or live native role is created by this module.

The trusted host may pass a `ConnectorCapture` to one Matrix or Hermes adapter,
or supply the same dependency by integration ID to `configured_registry` during
execution composition. The dependency binds one actor, integration and route to
explicit configuration, connector artifact and normalization hashes. Other
routes retain the existing proof-verification path. These private source APIs
describe connector observations; they are not signing APIs or trust evidence.
External `frank.config.v1` and integration configurations remain unchanged. The
shipped CLI does not select this dependency. Its check-config and health paths do
not create a Journal or a capture store.

An enabled capture route accepts unsigned input only. An unexpected `proof` key,
including an invalid proof, is retained once as bounded rejected ingress for its
unique retained delivery, then rejected. It is never stripped and promoted. A
verify-only route never falls back to capture after a verifier denial.

## Durable records and bounds

Three additive tables in the existing Frank Journal retain evidence separately
from deliveries, events, cursors, commands and all native admission tables:

| Table | Bound and meaning |
| --- | --- |
| `connector_dispatch` | One immutable Hermes reservation per existing delivery. Exact work digest, host policy bytes and exact work-derived prompt digest. It commits before agent construction or execution. |
| `connector_captures` | One immutable eligible unsigned observation per existing delivery, with a unique integration/event pair. It retains the complete final result, work digest, exact native payload digest/resource, host policy, bounded provenance and original ingress bytes plus their digests. |
| `connector_rejected_ingress` | At most one immutable unexpected-proof observation per existing delivery. It records original ingress and normalized body separately and never grants capture/renewal eligibility. Exact repeats are idempotent; changed repeats reject. |

Canonical work and result limits remain one MiB. `payload_for` retains its
256-KiB bound and binds the exact retained work digest plus every final result
field except proof. Original ingress is separately limited by the existing
one-MiB canonical encoder. Policy/configuration and provenance objects each have
a 16-KiB canonical limit; source references each have a 4-KiB UTF-8 limit. Metadata
has fixed connector-selected fields, not arbitrary extension properties. The
Hermes prompt is bounded by the one-MiB work plus a 512-byte fixed instruction
allowance. No values are coerced or summarized to fit a limit.

These limits bound each selected delivery's evidence without adding another
unbounded append log. They do not impose a new global journal retention policy;
the existing delivery store still needs separately reviewed operational capacity
management. Original evidence is inline in the existing mode-0600 Journal, never
an arbitrary caller-selected file path. Resolved credentials and authorization
headers are not captured. Original connector content is sensitive evidence and
must be protected like the existing work/result journal; it is not diagnostic
output.

Matrix capture pages are bounded to 100 joined rooms, 1,000 raw events and 100
normalized results. Cursor, container types, all timeline gap flags and counts
are checked before preparing any eligible capture. All result/work/provenance
bytes are frozen before plain-room reads; encryption must still be absent on
receive/reconcile. Configuration pins are checked again afterward. A single
transaction admits the prepared capture batch, so an event or body conflict
rolls it all back. Original room, sender and raw event ID are retained alongside
the source path and normalization pin. The final result event/provider fields
come from actual event metadata. This does not qualify a live Matrix TLS/account
or timeline provenance chain.

Hermes's durable reservation wins once across instances and restart. A crash
before or inside agent execution leaves an unknown effect with a reservation;
it does not permit another factory/run invocation. On a valid SDK return, the
complete normalized body, final-response and output digests, session/task and
prompt bindings are captured before control could reach a future issuer. A
crash before durable capture honestly loses the return and remains unknown.
Reconciliation only reads retained capture and never reruns Hermes. SDK artifact
and configuration pins are source assertions for later independent qualification,
not model correctness or native result authority.

## Withheld terminal output

No issuer is implemented or stubbed. A captured terminal result raises
`CapturePending`; Matrix returns neither its terminal page nor its next cursor,
and Hermes never returns or caches the unsigned terminal body. Existing Executor
paths therefore cannot admit it through local development result verification.
Nonterminal acknowledgements and unknown observations are never eligible
captures. Hermes marker-without-capture reconciliation returns no result.

`ConnectorCapture.retained` is an internal evidence read. It rechecks work,
body, policy and provenance digests and returns original eligible capture data.
An admitted native or legacy result without this record has no connector-role
renewal eligibility. No issuance, retry or renewal operation is implemented.
Those contracts, fresh native nonce/context production and current authority
requirements remain with NS-04 and the later NS-07 acceptance review.

`Executor`, `ResultVerifier`, `NativeResultAdmission` and the existing guarded
Runtime dispatch paths remain unchanged. Only the independent verifier may
create native admission. Capture neither consumes a native nonce nor changes
first result/event bytes, command identities, completion/failure recovery or the
final shared-time cursor checks. No SOP handler or comparison implementation is
part of this candidate.

## Validation scope

The public capture tests are separate from installed authority qualification. The capture cases cover complete
normalized payload equality, field/correlation and size rejection, whole-page
framing before capture, plain-room changes, mutation across awaits, proof-mode
separation, idempotent/concurrent/conflicting records, batch rollback, retained
digest checks, no local-dev/Runtime/cursor/native replay escape, Hermes cross-
instance reservation, malformed/cancelled outcomes and two fixed synthetic
child-process deaths before factory completion and after capture commit.

These source tests do not by themselves establish a full adapter, journal, native-result
or SOP/comparison suite result. Broader source and installed validation require
their own release and evidence. No native signing positive is claimed.
