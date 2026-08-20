# Deterministic reference result

`expected-summary.txt` and `reference-result.json` are the normalized, deterministic result contract for the harmless scripted public demo. They accurately label the Executor Attestation provider as a simulator and are not a captured frontier-model or hardware-attestation result.

The live demo generates fresh nonces, capabilities, Ed25519 keys, evidence timestamps, and digests, so those values intentionally differ on every run. Its latest certificate is written to `.demo/latest-containment-certificate.json` and can be checked independently:

```bash
python scripts/verify_certificate.py .demo/latest-containment-certificate.json --trusted-key .demo/latest-certificate-signer-public.pem
```

The trusted key file is emitted separately from the certificate using the certificate signer's service identity. Never extract a key from the certificate and treat that extracted value as trusted configuration.

The committed `containment-certificate.json` and independently pinned `certificate-signer-public.pem` remain deterministic, zero-authority signature-verification fixtures for clean-install checks. They make no containment claim and commit no private key.
