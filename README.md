# Frank executor

Frank is an independently runnable executor for the public process-runtime v1 contract. It registers configured actors, asks the runtime for eligible work, claims an exact item, and sends a bounded work packet through a configured integration. The runtime owns published definitions, DAG readiness, Attempts, fences, leases, retries, recovery, outputs and receipts. Frank never opens a runtime database or imports runtime implementation modules.

This implementation is local preparation for review. **Production execution defaults to deny.** The dedicated Frank identity decision is approved, but no native subject/key has been provisioned or qualified. See [identity decision](docs/identity-provisioning.md). Local development requires explicit untrusted opt-in on both Frank and the runtime.

## Install and verify

Use Python 3.12 and a reviewed `process-runtime==0.1.0` distribution containing the public `process_runtime_client` package. The SDK is co-packaged in that distribution for this initial release; Frank imports only the public client package. For isolated sibling checkouts:

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install -e ../process-runtime -e '.[test]'
.venv/bin/python -m pytest -q --basetemp=/example/tmp/frank-owned-tests
```

Tests start a disposable runtime process on loopback and use the public HTTP client. They do not read its database. Matrix responses and the Hermes interface are deterministic fixtures; tests make no live provider calls. [Verification scope](docs/verification.md) separates tested behavior from deployment gates.

## Bounded command-line execution

Copy [the development example](examples/frank.local.json) to a local configuration, choose a Frank-only journal path, and configure installed adapters. Paths and secrets are deployment inputs. Matrix credentials are references resolved only inside its adapter; Hermes follows its existing native credential setup.

```sh
frank-executor check-config --config ./frank.json
frank-executor health --config ./frank.json
frank-executor register --config ./frank.json --actor frank-local
frank-executor work --config ./frank.json --actor frank-local
frank-executor execute --config ./frank.json --actor frank-local \
  --run-id RUN_ID --step-id STEP_ID --operation compute --scope answer \
  --lease-ms 120000 --wait-seconds 60
```

`execute` accepts one explicit runtime-returned work item. It does not infer dependencies, create another Attempt, republish definitions, or retry providers. It renews the current lease while delivery and result polling are active. A verified successful result goes through runtime output validation and atomic completion. A Matrix send acknowledgement remains pending. A timeout or failed heartbeat stops local processing and requests advisory adapter cancellation; this cannot prove an external effect stopped.

`check-config` performs static validation. `health` connects adapters, checks protocol capabilities and provider identity, reports liveness, configuration validity, adapter readiness and authority mode, then closes them. `authority: adapter_required` sets `ready: false` even when `adapter_ready: true`; it is a production admission failure. The shipped CLI has no native authority loader and therefore cannot execute production commands.

See [operation and recovery](docs/operations.md), [adapter contract](docs/integration-adapter-v1.md), and [ownership](docs/architecture.md). Hub owns deployment composition, credentials delivery, probes, version admission and rollout. The Dockerfile expects a reviewed offline wheel directory; no image build or deployment has been qualified here.

Native result verification, exact payload profile, durable replay/renewal and dispatch/cursor guards are described in [docs/native-result-authority-v1.md](docs/native-result-authority-v1.md). These implemented libraries remain production-unqualified; supported native issuer/provisioning and accountable normalized-result attestation still require installed qualification.

## Public deployment

Use the [Zenith Hub lightweight deployer](https://github.com/ZenithResearch/zenith-hub-lightweight)
for the shared Apple-silicon Mac installer and operator UI. Component source lives
under [ZenithResearch](https://github.com/ZenithResearch). Installation does not
provision native identities, grant command authority, or enable external effects.
See `NOTICE.public-baseline.md` for the scope of this clean publication.
