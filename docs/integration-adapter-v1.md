# Integration adapter v1

The separate [unsigned capture source candidate](connector-capture-source.md)
describes optional trusted execution injection, durable Hermes reservation and
withheld Matrix/Hermes terminal outputs. It adds no external configuration fields
or issuer API. Its code and tests are authored but not executed or qualified.

The machine-readable contract is `contracts/integration-adapter-v1.schema.json`; positive wire fixtures are in `contracts/fixtures`. `src/frank_executor/ports.py` defines the async lifecycle. Additive optional fields require consumer compatibility tests; required shape or semantics changes require a new version. Unknown schemas and envelope fields fail closed. JSON is finite, bounded to one MiB and 64 levels, with duplicate fields rejected at transport decoding. Integer fences exclude booleans.

Every adapter declares `contract_version=frank.integration.v1`, a configured unique integration ID, and whether its provider supports idempotency. It implements connect, close, capability discovery, health, send, receive(cursor), advisory cancellation, and read-only reconciliation. Registry startup rejects unknown enabled plugins, duplicate identities, missing actor routes/integrations, malformed declarations and incomplete protocol capabilities. Failed startup closes partial connections. A provider being reachable is distinct from native authority qualification.

A `frank.work.v1` packet carries exact run/step/attempt/fence binding, actor, integration, route, runtime effect ID, operation, declared scope, frozen inputs and output types. A `frank.result.v1` packet adds event identity, provider reference, outcome and outputs. Every correlation field must match retained work. Terminal success/failure also requires the injected result verifier. Transport/account identity is provenance only. Failed, unknown and acknowledged results cannot carry outputs. Runtime validates successful output types again before committing.

The local evidence key is SHA-256 of the versioned operation/scope and exact run/step/attempt/fence binding. The runtime chooses its effect ID/idempotency key after `executor.effect.intent`. Adapters must use that supplied effect ID, never invent another incompatible provider retry key. Intent and dispatch are distinct public commands. Frank commits its local `unknown` state before calling send; only one SQLite compare-and-set wins. No retry automatically invokes send again, even for providers advertising idempotency. Restart requires authoritative reconciliation.

## Matrix adapter

The existing Hub Matrix bridge uses Synapse room events, `m.room.message`, configured room identity and sender provenance (`services/matrix_bridge/main.py` in the inspected Hub base). The initial Frank adapter uses Matrix Client-Server v3 account/whoami, room send transaction IDs, sync cursors and event reads, with a configured account/room/sender allowlist. This is a direct integration, not the Hub queue bridge. The new Frank wire contract is carried in `org.zenith.frank.v1`; the normal message body is the bounded work packet. A Matrix bearer token authenticates Matrix transport only.

The runtime effect ID is the Matrix send transaction ID. A send event ID records acknowledgement, never completion. Inbound event ID/provider reference come from the actual Matrix event, not body-selected aliases. Wrong room/account/route/integration is rejected; identical replays are idempotent and changed replays are rejected. Sync cursors advance only after all results in the page are durably handled. A limited timeline is a reconciliation gap. No automatic send retry, sync-gap skip or cursor rewind discards evidence. Errors exclude response bodies and credentials.

This HTTP adapter supports unencrypted rooms only. It checks encryption state during connect and before send and fails closed when encryption is enabled. It is not an E2EE or device-verification implementation. Live server, account, TLS and encrypted-room adapters require separate qualification. Cancellation cannot prove a remote actor stopped. An acknowledgement event lookup cannot establish successful work; unknown outcome remains actionable.

## Hermes adapter

The inspected source is `hermes-agent` 0.18.0 at commit `4c3a388cba9608f8cda0cc604e6c557adb8b298c`. The adapter uses its existing `run_agent.AIAgent` constructor (`model`, `enabled_toolsets`, `max_iterations`, `session_id`, `quiet_mode`, `skip_context_files`, `skip_memory`) and `run_conversation(prompt, task_id=...)` returning `final_response`. It does not invent an HTTP endpoint or duplicate Hermes credential conventions. A deployment supplies the reviewed SDK installation and its existing credentials. SDK absence keeps readiness closed.

The runtime effect ID binds the Hermes session/task. Toolsets, model, route and iteration budget are explicit. The prompt contains the claimed packet and asks for one JSON output object. Context files and memory are disabled to keep execution scoped; terminal output still needs native result authority in production. Thread cancellation requests Hermes interruption and retains unknown evidence. The inspected SDK exposes no authoritative resume-by-ID outcome query in this adapter. In-memory results can reconcile within a process; after restart, retained Frank evidence and operator/native reconciliation are required. A session ID is not assumed to provide provider idempotency.
