# Hermes live-provider pilot

Status: implementation started; no provider request has been sent.

The first live provider is the installed Hermes 0.20.0 `sophia` profile using
the `openai-codex` provider and `gpt-5.6-sol`. The pilot actor is
`frank-hermes-pilot`, its integration is `hermes-sophia-pilot`, and its only
route is `local`. The first canary enables no toolsets and has a maximum of four
agent iterations. It must return one declared JSON output and perform no
external tool effect. The model inference itself is the only external send.

## Required chain

1. Runtime creates and owns the canary run and eligible work.
2. Frank's existing Wallet command authority registers, lists, claims,
   heartbeats and records the exact external-effect intent.
3. Hermes receives the exact retained work packet once. Frank commits the
   prompt, final response, normalized result and source provenance before any
   result can escape the adapter.
4. A pinned native connector-result producer reopens the owner-private Frank
   journal, validates the immutable selector, capture bytes and nested native
   authority configuration pin, and issues a short-lived
   `frank.result.attest.v1` envelope for the exact Attempt, fence, effect,
   actor, integration, route and normalized result.
5. Frank's independent native verifier admits that envelope. Runtime then
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
- The returned output matches the declared Runtime type and is committed only
  after native result admission.
- Process restart after capture does not resend to Hermes; it resumes the exact
  retained native selector.
- Wrong actor, route, Attempt, fence, effect, output, policy, helper, proof,
  expiry, revocation or replay denies before Runtime completion.
- Revoking the connector-result role or command grant closes readiness and
  leaves retained evidence inspectable.

## Remaining installation work

- Complete independent review and installed qualification of the implemented
  `frank.connector-result-producer.v1` journal reader and selector validation.
- Expand the existing Frank receiver grant through a new explicit owner plan;
  same-scope renewal cannot add executor operations.
- Add the dedicated production composition and exact pinned Hermes artifact
  selection to the macOS installer.
- Enable new-run admission only for the reviewed composition digest, then run
  the no-tools canary and retain its Runtime, Frank, native and provider
  receipts.
