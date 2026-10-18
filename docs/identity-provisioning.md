# Dedicated Frank execution identity

Command authority and result-party authority are distinct native roles. An operator,
Matrix account or provider identity does not substitute for either. This repository
contains no live subject/key allocation, private key, grant or provisioning output.

`WalletCallAuthority` sends exact canonical Runtime command bytes through the fixed
normal Wallet command with pinned executable and same-read configuration hashes.
New commands use `issue`; explicit saved-command recovery uses `resume` without
creation or window extension. Eight closed Runtime read operations use fresh
`query` authority. Runtime independently validates native signatures, current
subject/key/descriptor permissions, time and replay.

`NativeResultVerifier` is a separate result boundary. It verifies the retained
work/body/context and current receiver policy. The separate closed local-review
profile requires concrete pinned native components and actual system time;
synthetic dependencies and the original CLI remain production-denied. A mode
label, receipt string or content hash is not proof that software ran.

The local-review result party takes responsibility for the exact captured
computation and evidence under its current assignment. Native owns leased key
custody and signing. Frank never receives seeds or generic signing APIs.

Before activation, qualify the exact installed command/result/helper/Runtime tuple,
select finite descriptors and resources, and exercise revocation, expiry, replay,
wrong bindings, original-window recovery and result renewal. Rotation must preserve
historical Attempt/effect evidence and retired fences. Real input is selected
explicitly: typed text is not audio and supplied transcript evidence is not a claim
that STT ran. Hub owns deployment composition without copying key material into
ordinary application configuration.
