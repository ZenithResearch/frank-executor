# Public native result vectors

Historical synthetic secS schema4/ZenithPacket v0 compatibility. The known disposable test seed is compiled only in `tests/native-fixture-generator` cfg(test); no real keys, private custody or original caller/model/provider authentication are represented. The existing verification-only helper checks native signature/packet binding. The Frank port independently checks result/body/work/policy/identity/namespace. Opcode200 is a synthetic receiver-local manifest binding, not a production allocation. No native issuer, producer, installed-chain or readiness qualification follows from these fixtures.

Regenerate create-only outside this directory using Cargo1.96.0, `--locked --offline`, the generator input.json and explicit FRANK_FIXTURE_INPUT/OUTPUT paths. Compare the generated public JSON byte for byte. No generated signing executable ships in Frank wheels.
