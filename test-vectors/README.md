# Capability verification vectors

These eight fixed vectors exercise the public-key-only capability verifier. Every JSON file declares its expected validity and an expected failure-reason substring. The signing key is a deterministic, public test fixture with no external authority; only its public key appears in the vectors.

Run them independently from the repository root:

```bash
python scripts/verify_capability_vectors.py
```

Regeneration is deterministic except for JSON formatting and uses the explicitly labeled test-only fixture in `scripts/generate_capability_test_vectors.py`.

`canonicalization/adversarial.json` is a separate shared Python/TypeScript acceptance corpus for canonical input limits and normalization. Run it with:

```bash
python scripts/verify_canonicalization_vectors.py
```
