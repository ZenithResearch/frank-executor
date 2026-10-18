# Pinned Wallet call authority

`WalletCallAuthority` implements `CallAuthority.evidence(canonical_request_bytes)
-> bytes` using a fixed pinned subprocess. It supplies outbound evidence; it does
not verify normalized results or enable providers. Constructor inputs are trusted
owner deployment data. The fixed `secs_verified` mode names that composition,
not a substitute for Runtime signature/current-policy verification. Default CLI
admission remains denied; the separate [local-review entrypoint](local-review-installed-profile.md)
loads a closed owner profile. Native binaries and installed authority require
separate qualification. Tests exercise real disposable process lifecycle with
synthetic protocol output; they do not sign Native evidence.

A trusted local composition constructs the port with fixed absolute executable/configuration paths, their exact lowercase SHA256 pins and a finite timeout. These values must come from an independently admitted owner deployment, never a model, process input, work item, environment variable or provider result. No command factory, shell, arbitrary argv, signer, policy, key or clock callback is exposed. The existing `frank.config.v1` CLI remains unchanged and continues to default-deny native production execution. The separate local-review CLI defines its closed owner profile; the constructor does not treat a caller-supplied hash as qualification.

The only subprocess arguments are:

```text
<fixed executable> issue --config <fixed private configuration> --config-sha256 <fixed SHA256>
<fixed executable> query --config <fixed private configuration> --config-sha256 <fixed SHA256>
<fixed executable> resume --config <fixed private configuration> --config-sha256 <fixed SHA256>
```

Runtime command schema selects issue. Runtime query schema selects query only for this closed reader set: process.get, work.list, events.list, attempt.get, output.get, run.get, artifact.get, version.get, receipt.get. All other schemas/queries deny before spawn. The additive generic workspace client uses process.get to read current drafts; it requires the matching explicit Native/Wallet query admission. This is parsing support, not a permission grant: Native and the Runtime receiver independently apply their exact finite subject/descriptor/resource permissions. effect.get remains outside this selection.

The new Wallet query mode must use the separately reviewed `acquire_query(raw)`/`complete_query(raw, proof)` APIs to produce fresh evidence for each new read. No query body field, request ID or resource is added. Losing a query response leaves the caller's cursor unchanged; another explicit poll invokes query again. The adapter neither retries automatically nor falls back to issue/resume. New command sends use issue. Explicit RuntimeGateway.replay retrieves the exact saved command and selects the optional resume_evidence method; WalletCallAuthority maps that method only to resume. Native issue rejects an existing Completed row: it is not a recovery API. Resume reads the existing Pending/Completed row without creation or renewal. Missing, expired, changed or ambiguous recovery denies. Queries cannot select resume, and an issue denial never triggers resume or query. Generic authorities that lack resume_evidence retain their existing evidence method; an advertised non-callable recovery method denies. The original command body/request ID/version and authority window remain unchanged. Expired command recovery stays a domain decision.

## Exact bytes and public SDK boundary

RuntimeGateway validates and freezes commands, journals the exact canonical body, then calls evidence with UTF-8 compact sorted JSON (`ensure_ascii=False`, finite JSON). Queries use the same canonical codec. The adapter checks the public SDK contract resource and rejects noncanonical or mutable byte inputs; the exact accepted bytes become stdin, with no rewrite or added newline. Frank's existing one-MiB canonical envelope bound remains unchanged. The public Runtime/native profile may allow two MiB; this adapter does not widen Frank's separate limit.

GeneratedClientAdapter continues to use public SDK execute/query with explicit `evidence=` bytes. The SDK wraps the request and base64 evidence in runtime.transport.v1. Its outer JSON can escape Unicode differently; Runtime reconstructs the same canonical Snapshot before verifying native request_hex/digest. No private SDK send/opener override or Runtime implementation import is used by production code. Existing result dispatch guards remain after authority waits and in the actual SDK worker immediately before send.

Stdout must be a single UTF-8 JSON object with exactly schema, packet_hex and signed_context_hex. Schema must be runtime.secs-envelope.v1; hex must be nonempty, even-length lowercase and within existing Runtime bounds. Duplicate/unknown fields, extra output, wrong schema, stderr, nonzero exit, timeout, cancellation or pin change denies. The producer's exact stdout bytes are returned unchanged. Framing checks do not authenticate signatures; the Runtime receiver still performs native cryptographic/current-policy/replay admission.

## Bounded physical-Mac subprocess

The worker follows the existing NativeSecSHelper's selector-driven pipe transport and file-pin conventions, specialized for raw canonical stdin and authority-envelope stdout. It is not that verifier protocol: the verifier accepts a different JSON input/output. It uses shell=False, empty explicit environment, owner-config directory as cwd, close_fds, a new owned session/process group, concurrent bounded stdout/stderr reads, one monotonic subprocess deadline, and bounded TERM/KILL cleanup/reaping. It launches the already trusted running host Python with fixed -I -S -B -c wrapper source and one private pipe FD. The wrapper waits before any Wallet action. The parent attaches kqueue EVFILT_PROC/NOTE_EXIT, then releases one byte; the wrapper closes that FD and execs the fixed Wallet argv in the same owned PID/group. Wrapper startup, observer attachment or gate-release failure denies. This gate is necessary because Apple's NOTE_EXIT attachment observes only subsequent exit edges; simply registering after an ungated Popen can miss a fast exit. Cancellation signals the worker and waits for its cleanup; it never returns evidence after cancellation. No child is launched by check_available.

The inherited executable ceiling is 64 MiB. Configuration reads are at most 65,536 bytes; stdout 4,400,000 bytes; stderr 4096 bytes; packet 2,097,152 + 16,384 + 69 bytes; context 65,536 bytes. Timeout defaults to 5 seconds, with trusted finite range 0.05–30 seconds; cleanup uses a 0.25-second TERM grace, one-second direct-child reap wait and 0.25-second bounded group-absence observation. A stdlib-only inspection of the admitted Python 3.12.12 confirmed select.kqueue/kevent and the named PROC/NOTE_EXIT flags; os.waitid is absent despite the C build header. No waitid or guessed ABI is used. This is a Mac-host source plan, not a guest/OS-sandbox or continuous code-origin claim. Regular-file size bounds do not constitute a wall-clock bound on filesystem pin checks.

Executable and private configuration are hash/metadata checked before and after the subprocess. The Wallet command must use its same-read pinned entry point (the current source names it exchange_pinned) and hash the same bounded config bytes it actually parses. Pre/post Python reads are not proof of the bytes consumed under replacement. The nested Native same-read configuration hash remains required. Old commands lacking the pinned flag or query mode must fail; there is no compatibility fallback. Artifact path checking assumes the admitted owner-controlled immutable installation, as with the existing verifier; it does not claim protection from a hostile owning UID.

An adapter serializes its subprocess attempts and retains owned process/FD state until cleanup resolves. Cleanup attempts remaining safe TERM/KILL/reap/close steps even when an earlier step fails, and retains the first fixed failure category plus bounded secondary cleanup categories. The leader is not polled or reaped before group signals except when a bounded fixed OS census proves the leader is the sole owned zombie. The retained physical-Mac probe returns EPERM for signals to its already-exited, unreaped sole-leader group; EPERM alone never authorizes reaping. After reaping, subsequent cleanup only observes group absence; it never signals a possibly reused numeric group. Unresolved state denies all new launches. Explicit aclose performs bounded cleanup only, without acquiring evidence or retrying work. Retain the adapter instance and resolve cleanup before dropping it or exiting the embedding host. Quarantine is process-local, not a durable process manager.

For the zombie case, fixed `/bin/ps -x -g <owned PID> -o pid=,ppid=,pgid=,uid=,stat=` examines only the owned group. A successful snapshot must contain exactly one row with PID=PGID=the unreaped leader, PPID=this process, UID=this user and a Z state. The leader cannot fork, and the snapshot contains no other group member. The fixed trusted OS utility is read-only; no process arguments/environment/key data are requested or logged. Snapshot stdout is capped at 65,536 bytes, stderr at 1024, with a 0.5-second deadline and 0.25-second direct-child cleanup wait. Its separately tracked direct child uses no process-group signals and is expected not to fork. Malformed, missing, unreadable, oversized or timed-out snapshots deny this exemption. An unresolved census child also quarantines the adapter. There are at most three census attempts per cleanup (observed exit, failed TERM, failed KILL), adding at most 2.25 seconds of bounded census/cleanup time; resolving a previously retained census child can add another 0.25-second wait.

Live descendants still require group termination before leader reap. A group with additional zombies does not qualify for the sole-leader exemption; it remains quarantined if ordinary cleanup cannot establish termination and absence. No signal occurs after leader reaping. The snapshot is a bounded local OS observation under the immutable-host/exclusive-reaper prerequisites, not an adversarial process-containment or continuously atomic census claim.

Trusted composition must give this adapter exclusive child-reaping ownership: SIGCHLD must remain default, and no external waitpid(-1), process.poll/wait or other reaper may consume its leader. The class checks the signal disposition at admission but cannot prove arbitrary host behavior. The fixed admitted command must keep any descendants in its owned group; this is not daemon containment or an OS sandbox. The helper/interpreter/configuration tuple must remain immutable under the admitted owner deployment.

All failures expose only “Native Wallet call authority unavailable”. Raw requests, evidence, configuration paths/contents and child diagnostics are not logged. Native may have durably created/completed local journal state before a timeout; Runtime has not been sent the request by this authority port. The adapter does not misclassify that as a Runtime commit or invent a recovery operation.

## Integration dependencies and verification

The selected normal Wallet command must implement issue/query/resume and the
same-read `--config-sha256` contract. Exact binary/config pins, current finite
roles, native helper/receiver acceptance and installed startup remain required.
Commands lacking those interfaces deny without fallback. Finite command journal
capacity must be selected explicitly; this source does not expand it implicitly.

The tests cover actual owned fake-process stdin/argv and public SDK framing,
all nine selected query routes, input/pin/envelope rejection, timeout/cancellation,
stateful Completed-row recovery, Mac gate ordering, descendant/pipe handling,
cleanup faults, exact zombie census and reentry denial. Synthetic hex is not
Native evidence. Run these tests on macOS Python3.12; then exercise the actual
pinned Wallet command with disposable Native/Wallet fixtures and an independently
verifying Runtime. Installed/live-role qualification is separate from these tests.
