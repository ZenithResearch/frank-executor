# Public baseline verification

Run this repository’s tests from the public checkout. Historical private logs,
operator locations and captured production provenance are not public qualification
evidence. Public demonstration fixtures are de-identified and their hashes are
recomputed after transformation. Native tests explicitly skip when the documented
verification helper or fresh native vectors are unavailable. These skips do not
qualify native authority or provider operation.

Frank native compatibility tests require an actual helper and never silently skip.
Set FRANK_NATIVE_VERIFIER to the built verification-only helper and
FRANK_NATIVE_VERIFIER_SHA256 to its independently recorded artifact digest. The
existing reviewed macOS artifact digest remains the default. Build from the
Runtime repository’s pinned native/secs-verifier source; retain its source/lock
and artifact hashes. These are test inputs, not production authority configuration.
