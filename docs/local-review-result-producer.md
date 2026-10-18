# Fixed local-review result producer

This module retains accountable local computation and obtains fixed Native result
attestation through explicit attest/resume/renew modes. Tests include synthetic
protocol controls; those do not qualify Native signatures or an installed tuple.
Wire schemas and existing fixture goldens retain their compatibility boundaries.
See the [closed local-review composition](local-review-installed-profile.md) for
actual concrete helper/current-policy admission and unchanged default denial.

## Trusted construction and accountability

The host constructs `LocalReviewCapture`, current `RuntimeClaims`, selected
public-input ports and `NativeResultProducer`, then calls
`ReviewAdapter.local_native(..., environment="test" or "development")`.
Generic ReviewAdapter construction remains denied in production. Explicit
local_native production composition requires the exact concrete Runtime ports,
pinned Wallet authority and genuine Native helper/current private-file policy/
system clock. Synthetic dependencies remain denied. No token or mode relabeling
turns test construction into production admission.
No dependency is restored from model/work JSON, a receipt or a previous result.

The selected local result party accepts responsibility for the exact retained
computation record and declared evidence. Hashes bind selected bytes; they do
not independently prove that software ran. `configuration_sha256` is the
producer-composition configuration, not the Native startup configuration: the
latter already contains the assignment hash and would make a circular preimage.
The actual Native startup file has its separate same-read CLI pin.

The owner creates the private capture root, its source manifest and selected
source blobs. Source manifest fields are closed: schema
`frank.local-review.source-manifest.v1`, `producer_artifact_sha256`,
`normalizer_sha256`, `configuration_sha256`, `entries`. Each entry is exactly
`{sha256, byte_length}`. It includes the three actual composition blobs and any
selected original input/source snapshots. The injected ports must implement
that owner-selected composition. This writer cannot isolate a hostile owning
UID or turn JSON declarations into execution attestation.

## Durable computation and publication

`reserve(work)` commits a unique row before any handler/provider operation. Its
identity includes complete binding, actor/integration/route and effect; the row
also binds complete original work and selected profile bytes. Changed work for
the same identity denies. A second process cannot receive permission to compute
again. A reserved-only row means unknown, including cancellation or crash.
Only explicit domain recovery/new Attempt can address that uncertainty.

Successful port returns are recorded at call time with exact input/output
bytes, content hashes, lengths and one of the seven accepted observation kinds.
Native checks these retained bytes, not an invented retrospective trace. Pure
transformation has no fictional provider call: the immutable payload and receipt
are its completion record. A real final claim check is always the last
observation. Recognized `ReviewFailure` codes produce a failed result with empty
outputs; other exceptions and uncertainty produce no terminal capture.

Frank first commits immutable payload/receipt BLOBs, then publishes the four
fixed files under the cooperative `capture.lock`. Publication uses a fresh
private pending directory, file fsync, directory fsync and atomic rename. A
publication failure leaves the completed database row; a later explicit
reconciliation can republish exactly those bytes without rerunning the handler.
Partial pending directories remain charged storage and are never adopted as a
complete capture or silently deleted by this API.

The on-disk protocol shared with Native is:

```
capture_root/source-manifest.json
capture_root/capture.lock
capture_root/blobs/<lowercase SHA256>
capture_root/<capture_id>/reservation.json
capture_root/<capture_id>/work.json
capture_root/<capture_id>/payload.json
capture_root/<capture_id>/receipt.json
```

`capture_id` is SHA256 of exact canonical reservation bytes. Reservation fields
are schema `frank.local-review.reservation.v1`, `reservation_id`, `work_sha256`
and `configuration_sha256`. The exact accepted capture receipt fields remain
unchanged. Each observation reference is its nonnull output hash, otherwise its
input hash; byte_length describes that referenced blob. Final claim input is
the complete original work and output is actual retained claim observation.

## Proof exchange and recovery

`NativeResultProducer.bind(result, work)` accepts only the original completed
capture body and reserves an `attest` selector before launching Native.
`resume(work)` is explicit no-create recovery of the saved selector.
`renew(work)` requires the exact previous envelope tip, a fresh current claim,
the same original body and an explicit new parent edge. A lost renewal reply is
recovered with resume of that selector. No denied issue/renew fallback exists.
`reconcile(work)` can select first attest only when a completed capture exists
and no Native invocation selector was ever reserved; otherwise it selects
resume. Expired or unavailable proof does not rerun a provider.

Fixed CLI form is `secs-frank-result <attest|resume|renew> --config PATH
--config-sha256 HASH`, with the closed selector on stdin. The transport reuses
the exact qualified Wallet owned-process monitor, gate, cancellation and cleanup
engine; only fixed routing/config/output decoding is specialized. Wallet public
methods, closed eight reads, no-create command resume, fault hooks, cleanup
bounds and exclusive-reaper prerequisite retain their behavior. The result
decoder accepts only `frank.secs-result-envelope.v1`. Native config must select
the same capture root. Native itself checks its entire closed same-read config,
assignment, custody, capture, original/tip state and final clock.

Received closed envelope bytes are retained as untrusted transport output so an
actually received expired tip can later select explicit renewal. They are not
an admission or provenance. Before returning a result the producer requires an
actual `NativeResultAdmission`, revalidates it, makes a fresh claim check after
all transport/storage waits and revalidates current result policy/window again.
It adds only proof; original work, result, event, provider reference and receipt
are immutable. Native renewal does not rewrite the original claim observation.

## Current ports and finite limits

`RuntimeArtifacts` uses public `artifact.get`/`artifact.put`, validates exact
bytes/reference and preserves uncertainty instead of retrying providers. Each
actual write invocation lets Gateway allocate a fresh command request ID;
identical content remains content-addressed without reissuing a Completed
Native command. Saved-command acknowledgment recovery is explicit Gateway replay.
`RuntimeClaims` first requires exact dispatched work in Frank's journal, then
uses public `attempt.get`/`run.get`/`version.get` to check current actor, fence,
inputs, outputs, exact pin/compiled hash, one published step, its selected
operation capability, declared input values, lease and run state. The claim
observation retains those actual public response data. Native does not independently query Runtime. Runtime
still enforces terminal mutation fencing; this is not globally atomic claim
revocation across processes.

`RuntimeSnapshotSources` reads only owner-selected content-addressed snapshots;
logical source paths are reported data, never fetched filesystem paths/URLs.
`SuppliedTranscript` is an explicit transcript artifact bound to a selected
actual audio hash, truthfully labelled supplied evidence. It does not synthesize
audio, word timing or an STT computation. No input is selected here; a real STT
provider remains a separate concrete dependency if chosen. Status and daily
note writes use actual durable local intent recording with `simulation:true`;
they do not deliver external updates.

Limits fail closed: 1 MiB per evidence/source blob; 4 MiB observation bytes per
computation; 128 observations and 16 KiB aggregate receipt/source manifest;
existing 1 MiB work and 256 KiB native payload; 700,000-byte result envelope;
four proof generations per capture. Store limits are 128 rows, 24 MiB charged
reservation per row and 512 MiB physical DB/WAL/publication/blob storage, with
8,192 storage entries. Thus the byte reservation ceiling can bind before the
row ceiling. No body/history identity is evicted to free authority. These are
application checks and quota charges, not OS preallocation or kernel quotas.

The component tests include storage/process reservation controls, explicit mocked
Native/helper orchestration, actual owned fake-process framing, public-client
port controls and unchanged default production denial. Synthetic helpers do
not sign and fixture audio/transcripts do not meet the user input requirement.
Actual Native result binary/helper composition, current role/claim negatives,
packaged artifacts and the genuine chosen input/provider workflow must still
be exercised. No result role, key, opcode, live service, grant or Gate credit is
created by these source checks.

Artifact writes use fresh Gateway request IDs while exact saved-command recovery
remains explicit. Current claim checks include published step capabilities, exact
pin/compiled hash, input/output types and values. Regression tests preserve these
boundaries; public source and installed validation must be recorded separately.
