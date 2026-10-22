# Hermes live-provider pilot

Status: the scalar-output canary has executed successfully. Artifact-output
materialization, immutable input hydration and the finite automated brand actor
are source-qualified but have not been released or installed.

The first live provider is the installed Hermes 0.20.0 `sophia` profile using
the `openai-codex` provider and `gpt-5.6-sol`. The pilot actor is
`frank-hermes-pilot`, its integration is `hermes-sophia-pilot`, and its only
route is `local`. The first canary enables no toolsets and has a maximum of four
agent iterations. It advertises exactly the automated capabilities in
`zenith.anima.brand-package` and the `brand.research`/`brand.workspace`
resources. It deliberately does not advertise `brand.review.human` or
`brand.human-review`; that step requires the separately selected operator actor.
Every invocation must return only the declared JSON outputs and perform no
external tool effect. The model inference itself is the only external send.

## Required chain

1. Runtime creates and owns the canary run and eligible work.
2. Frank's existing Wallet command authority registers, lists, claims,
   heartbeats and records the exact external-effect intent.
3. Frank resolves the claimed `reviewed_brief` and `reference_manifest` through
   Runtime before reserving a dispatch. It verifies both artifact references,
   the closed brief schema and value digest, and the reference manifest's exact
   embedded original. The first profile permits zero or one PNG/JPEG reference
   up to 524,288 bytes. Its hash-bound image is supplied in the same Hermes model
   turn; no path, URL, browser state or placeholder substitutes for missing bytes.
4. Hermes receives the exact retained work packet and verified provider input
   once. The captured prompt contains the closed brief and immutable reference
   manifest, so its digest binds the image supplied by the pinned subprocess.
   Frank durably retains
   the exact final response before any derived Runtime write. A restart can
   continue from those bytes without dispatching Hermes again.
5. For a declared artifact output, Hermes returns a closed UTF-8 descriptor
   containing `content_utf8` and an allowed media type. Frank writes those bytes
   through Runtime `artifact.put` with a deterministic request ID, verifies the
   returned content-addressed reference and replaces the descriptor with that
   canonical `ArtifactRef`. Scalar outputs retain their declared Runtime types.
6. Frank commits the normalized result and source provenance before any result
   can escape the adapter. Historical capture rows remain readable; new capture
   rows also bind the pre-materialization response record.
7. A pinned native connector-result producer reopens the owner-private Frank
   journal, validates the immutable selector, capture bytes and nested native
   authority configuration pin, and issues a short-lived
   `frank.result.attest.v1` envelope for the exact Attempt, fence, effect,
   actor, integration, route and normalized result.
8. Frank's independent native verifier admits that envelope. Runtime then
   independently authenticates each observe and complete command and commits
   the typed output.

The generic `frank-executor` production CLI remains denied. A dedicated
production composition must inject the pinned Wallet authority, native result
producer, verifier, connector capture, current-claim port and exact Hermes
profile. No configuration flag may reconstruct those capabilities.

## Additive connector-result contract

`frank.connector-result-selector.v1` identifies one immutable capture using:

- effect key and exact work digest;
- unsigned normalized result, payload, provenance and original-response digests;
- connector-policy digest, integration, event and Runtime effect resource;
- an optional exact parent-envelope digest for renewal.

Frank stores at most four exchanges per effect. `attest` creates the first
selector, `resume` can only reuse the latest selector, and `renew` requires the
exact completed parent envelope. The selector grants no authority. The native
helper must independently reopen and validate the selected journal row; the
independent verifier remains the only source of `NativeResultAdmission`.

## Canary acceptance

- Hermes SDK and configured model initialize without exposing credential
  values in output or logs.
- One eligible run produces exactly one durable Hermes dispatch reservation
  and one provider invocation.
- Missing, changed, malformed, oversized or unsupported Runtime input artifacts
  fail before Hermes dispatch. A selected image reaches Hermes in the same model
  turn, while the persisted user transcript contains only the captured prompt.
- The returned output matches the declared Runtime type and is committed only
  after native result admission.
- Artifact outputs accept only `text/markdown`, `text/plain` or
  `application/json`, are limited to one MiB each and become Runtime-owned
  `ArtifactRef` values before capture and native result admission.
- A lost `artifact.put` response is resumed with the same deterministic command;
  a process restart reuses the retained provider response and never redispatches
  Hermes.
- Process restart after capture does not resend to Hermes; it resumes the exact
  retained native selector.
- Wrong actor, route, Attempt, fence, effect, output, policy, helper, proof,
  expiry, revocation or replay denies before Runtime completion.
- Revoking the connector-result role or command grant closes readiness and
  leaves retained evidence inspectable.

## Remaining installation work

- Publish and install a Frank release containing artifact materialization and
  qualify it against the released Runtime artifact authority.
- Complete independent review and installed qualification of the implemented
  `frank.connector-result-producer.v1` journal reader and selector validation.
- Expand the existing Frank receiver grant through a new explicit owner plan;
  same-scope renewal cannot add executor operations.
- Add the dedicated production composition and exact pinned Hermes artifact
  selection to the macOS installer.
- Extend the actor and receiver grants only for the exact reviewed automated
  brand capabilities and Runtime artifact operations. Human approval remains a
  separate actor and operation.
- Publish the immutable brand-package ProcessVersion, run a real request with
  substantive artifact outputs and retain its Runtime, Frank, native and
  provider receipts.
