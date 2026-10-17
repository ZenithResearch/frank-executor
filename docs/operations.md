# Execution and recovery operations

Use one Frank-only journal per executor identity/deployment. Back up its database and WAL consistently before upgrades. The journal is private evidence, not an alternative process database. Keep runtime and Frank stores separate. Replaying a command requires the same request ID and canonical payload/expected version with fresh authority; changing bytes under an old key is rejected.

| Command | Required selectors | Behavior |
|---|---|---|
| check-config | --config | Static closed-shape validation, no connection |
| health | --config | Connect/qualify enabled adapter lifecycle, return transport health and authority mode, close |
| register / work | --actor | Public actor registration / eligible work query |
| execute | --actor --run-id --step-id --operation --scope | Claim exact runtime-returned work, supervise current lease and bounded dispatch |
| inspect | --config | Retained unresolved effect IDs/states and pending command IDs/operations |
| resume | --effect-key | Recover exact current live attempt and reconcile/poll; never resend |
| heartbeat | --effect-key | Query current binding and renew live attempt through runtime |
| release / fail | --effect-key --reason | Ask runtime for transition; unknown effects remain subject to runtime policy |
| receive | --integration | Normalize, correlate, verify and commit available replies before cursor checkpoint |
| reconcile-command | --request-id | Send exact retained command bytes with fresh authority |

All commands require `--config PATH`. `execute` and `resume` accept `--lease-ms` (default 120000) and `--wait-seconds` (default 60); CLI bounds the lease to 1000–3600000 ms and wait to 0–3600 seconds exclusive of zero. The runtime can impose tighter bounds. `execute --request-id` optionally fixes the initial claim's idempotency key. The library also provides exact binding recovery, effect reconciliation and completion reconciliation. Exit 0 returns JSON, exit 2 rejects configuration/authority/contract/state, exit 3 means an uncertain outcome needing inspection. No raw provider exception/body is logged by adapters.

The bounded command may stop with an acknowledged/unknown effect still retained. Keep polling or explicitly resume while the runtime lease remains live. After lease expiry or cancellation, delayed results cannot resurrect the old attempt. They require runtime/native reconciliation. The runtime decides whether an unknown effect permits another Attempt. A new process invocation does not automatically call send again or synthesize a replacement Attempt.

## Crash boundaries

| Retained boundary | Recovery |
|---|---|
| Runtime command pending, response absent | `reconcile-command` repeats the exact command; no version rebase |
| Intent exists, dispatch not locally admitted | Query runtime/effect evidence; explicit reconciliation, no blind send |
| Local unknown before provider call | External outcome is ambiguous, even if the crash may have preceded send |
| Provider acknowledgement | Continue receiving a correlated, authorized terminal result; acknowledgement cannot complete |
| Terminal result stored before runtime observation | `resume` submits/replays exact observation with current binding |
| Complete may have committed, response lost | `resume` replays exact completion then checks public immutable output digest/fence |
| Completion committed | Duplicate terminal receive is accepted only for identical evidence |
| Runtime failure response lost or cursor not checkpointed | Replay the stable failure command, verify public terminal Attempt, mark `failed_committed`; identical failed events can advance the cursor |
| Expired fence or unresolved failure | Retain history; runtime/native operator decides recovery |

`intent` is distinguishable from `unknown`; neither is permission to resend. A crash between a runtime intent response and local delivery insertion leaves a pending/observed command in `inspect`; recover its exact command and inspect runtime evidence before attempting any further effect. There is intentionally no unauthenticated “clear unknown” control. Reconciliation proves an outcome; it must not guess one.

On loss of heartbeat, delivery is cancelled locally and the adapter receives a bounded advisory cancel request. Noncooperative providers can continue; unknown evidence remains. Runtime mutation and receive checkpoint failures stop progress. Matrix receive gaps or unrelated result envelopes keep the cursor unchanged for investigation rather than silently losing results.

## Rollout and rollback

Hub must admit a compatible public runtime schema and Frank adapter schema digest before launch. Install the pinned public client and reviewed optional Hermes SDK wheel; perform static config and adapter health checks. For local tests explicitly enable untrusted mode on both sides. For production require qualified native identity and results ports; neither a successful health call nor a copied schema bypasses that gate.

The Dockerfile consumes reviewed offline wheels and runs as a non-root user. Supply a writable protected journal directory and read-only configuration; do not package credentials into the image. No container build, live adapter connection or native production call has been run in this implementation session.

Rollback must stop new dispatch, retain both stores and pending effects, and use a version that understands the same journal/contract. Do not delete a journal, restore only one side of an ambiguous operation, reset attempt fences, rewrite committed outputs or silently fall back to legacy Frank scheduling. If compatibility or unknown-effect reconciliation cannot be proved, keep execution stopped and inspection available.
