# Property and stateful testing

The bounded default profile uses Hypothesis 6.160.0 with deterministic settings. Generated canonical values cover nested arrays/objects, empty structures, NFC Unicode, escaping, nulls, booleans, and interoperable integer boundaries. The suite checks canonical round trips, insertion-order independence, immutable request snapshots, and rejection of duplicate keys, floating representations, overflow, malformed UTF-8, trailing bytes, excessive nesting, oversized collections/strings, and unsupported types.

Every signed `CapabilityClaims` field is mutated individually. A mutation must either fail the strict schema or fail cryptographic/binding verification. The state machine repeatedly issues, verifies, consumes, replays, expires, mutates, and transfers capabilities while checking at-most-one commit.

`test-vectors/canonicalization/adversarial.json` is consumed by both Python and TypeScript. It covers NFC/NFD, exact and excessive UTF-8 string bounds, exact and excessive collection bounds, legal/excessive depth, zero and negative zero, finite and non-finite numbers, duplicate-key canonical input, safe integers, cycles, unusual Unicode, nested combinations, and Unicode code-point object-key ordering. `python scripts/verify_canonicalization_vectors.py` compares acceptance and, for protocol-equivalent values, exact canonical bytes and SHA-256 digests.

Run `make test-property`. Hypothesis reports and shrinks a reproducible failing example. The CI profile is bounded and does not replace fixed public vectors, fuzzing, review, or cross-language tests.
