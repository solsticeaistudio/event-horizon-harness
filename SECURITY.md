# Security policy

## Private reporting

Please report a suspected containment bypass through [GitHub private vulnerability reporting](https://github.com/Solasticeaistudio/event-horizon-harness/security/advisories/new). Do not open a public issue until the maintainer confirms that coordinated disclosure is appropriate. If GitHub does not offer the private form, email [solsticestudioai@gmail.com](mailto:solsticestudioai@gmail.com) with the subject `Event Horizon security report` and include only enough information to establish a secure follow-up channel.

Include the affected commit, environment, exact reproduction steps, the expected invariant, the observed result, and minimal synthetic evidence. Remove credentials, personal information, production identifiers, and unrelated data. Maintainers will acknowledge a usable report when practical; this research project does not promise a commercial response SLA or bounty.

## Valid security issues

A valid report demonstrates or plausibly identifies a failure of a documented security boundary, including:

- authority outside the deterministic static-policy ceiling;
- capability replay, scope widening, or transfer across a bound executor or session;
- unauthenticated, replayed, expired, wrong-audience, or mutated requests accepted by the capability signer, evidence recorder, or certificate signer;
- capability, recorder, certificate, or protected-client private material exposed through executor configuration or ordinary service metadata;
- accepted attestation without an issued one-use nonce or verified provider result;
- replay accepted after an ordinary verifier, signer, or executor process restart when the configured durable state remains intact;
- a forged client request, forged/swapped server response, stale service epoch, or checkpoint rollback accepted by the authenticated remote replay interface;
- a way for the hostile executor to read, mutate, delete, or roll back authoritative nonce or broker replay state in the documented topology;
- simulator evidence accepted as hardware trust;
- static-policy or required-guardian failure that permits execution;
- undetected alteration of the authoritative evidence chain or certificate;
- verified teardown that leaves reusable authority or declared persistence.

Availability failures without authority gain, behavior already listed in `KNOWN_LIMITATIONS.md`, unsupported deployment changes, and generic dependency scanner output without an exploitable path may be closed as non-security issues.

## Certificate trust anchors

Containment-certificate authenticity requires a signer public key or key ID supplied by trusted configuration outside the certificate. The normal library and CLI verification paths fail closed when that trust anchor is absent. Before this repair, the public verifier accepted the certificate's embedded key and therefore established only attacker-selectable self-consistency; that behavior must not be used as evidence of trusted issuance.

## Authorized testing only

Test only environments, accounts, data, and synthetic ranges you own or are explicitly authorized to use. Real-world targets and public infrastructure are out of scope. Destructive actions, denial of service, credential abuse, persistence on systems outside the synthetic fixture, unauthorized access, social engineering, and attempts to hide activity are prohibited.

The repository contains no authorization to test third parties. Use the bounded scripted adversary and declared `synthetic-range/...` fixtures for public reproductions.

## Supported versions

Security fixes target the current `main` branch and latest tagged public release. Historical research snapshots are retained for reproducibility but are not maintained security branches.
