# Ownership and boundaries

| Object or responsibility | Owner | Frank relationship |
|---|---|---|
| ProcessDefinition, immutable ProcessVersion and typed DAG | process-runtime | Public references and frozen claim snapshot only |
| ProcessRun, Step, Attempt, lease, fence, readiness, retry policy | process-runtime | Exact public lifecycle commands and queries |
| Immutable output commit and completion receipt | process-runtime | Supplies verified outputs; reconciles exact retained command |
| Service, Case, CasePlan and work intent | service-management | No copied aggregate or direct store access |
| Delivery evidence, transport cursor, pending command bytes | Frank | Private durable journal referencing runtime identities |
| Adapter configuration and actor route | Frank deployment configuration | Explicit plugin registry and capability/resource declarations |
| Runtime command authorization | Existing native secS/receiver policy | Injected proof callback; runtime verifies every call |
| Build pins, version admission, credentials and rollout | Hub | Frank supplies artifacts, health and CLI contract |
| Canonical implementation work graph | Devgraph | No runtime object storage or direct graph writes |

The async client boundary in `ports.py` is implemented by a wrapper around the generated synchronous public SDK using `asyncio.to_thread`. Public `command_envelope` generates resource identity; no prefix inference in Frank substitutes for runtime receiver descriptors. Local JSON schema checks catch wire skew before a malformed response becomes observed evidence. Public errors preserve code/retryability; uncertain results remain pending. Neither a stale version nor a timeout causes automatic rebase or a new idempotency key.

Actor capabilities/resources are declared and explainable through `Registry.match`. Runtime work eligibility is authoritative. The core executor imports no Matrix or Hermes implementation, has no process step ordinal branches, and cannot schedule a DAG. Built-ins are named only in the composition root; an injected factory plus an explicit configuration entry loads a conforming plugin without a dispatcher edit.

The journal stores command bytes and delivery evidence in a separate SQLite database tagged with a Frank application ID. It refuses an existing foreign database before changing its journal mode. WAL and full synchronous transactions make dispatch admission durable. File permissions are 0600; deployment must put the journal on appropriate protected storage because claimed inputs and outputs can contain sensitive application data. No signing keys, runtime proof bytes or Matrix access tokens are retained.
