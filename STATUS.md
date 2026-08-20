# Status

## Completed

- Audited the repository and recorded verified trust, capability, replay, evidence, and isolation paths in `docs/BASELINE_AUDIT.md`.
- Implemented typed adaptive task-policy proposals, deterministic trusted compilation, static/rule/model/shadow/evaluation modes, conservative fallback, and sizing metrics.
- Enforced provider-derived trust, exact capability bindings, durable one-use redemption, canary tripwires, signed denial certificates, persistent session-scoped behavioral subtract-only reduction, and per-capability redemption-time monotonic authority decay.
- Added Hypothesis/stateful protocol tests, concurrent redemption stress with a vulnerable positive control, deterministic chaos hooks, bounded adaptive-adversary integration, literature metadata feed, hardware-failsafe simulator, and a narrow TLA+ model.
- Added security reporting, public claim-boundary documentation, and reproducible extended-suite commands.

## Tests executed

- `python -m pytest tests/ -q`: 213 tests and 165 subtests passed.
- `python -m unittest discover -s tests -v`: 213 tests passed, including certificate trust-anchor, shared canonicalization-vector, and live per-capability decay coverage.
- `node --test attestation/tests/*.test.mjs`: 62 passed; the opt-in real Linux TPM test was skipped.
- `python scripts/verify_canonicalization_vectors.py`: 25 shared Python/TypeScript adversarial vectors passed with matching acceptance and protocol representations/digests.
- `python -m ruff check src tests scripts`: passed.
- `python scripts/lint_python.py`: passed.
- `python scripts/check_repository_policy.py`: passed.
- `python scripts/check_literature_feed.py --live`: passed with no source drift; six metadata campaigns remain pending human review.
- `python scripts/check_formal_model.py`: structural checks passed; TLC skipped because Java and a pinned TLA jar are unavailable on this host.
- `python scripts/generate_security_report.py`: deterministic available checks passed; report status is `PASS WITH UNAVAILABLE CHECKS` because TLC and physical hardware are unavailable.
- TypeScript `npm ci`, build, tests, canonicalization interoperability, and remote replay interoperability passed.
- A fresh-clone/clean-venv overlay of the repair passed install, build, `npm test`, demo, capability and canonical vectors, pinned certificate verification, and repository policy checks before commit.

## Known failures

- No portable test failure is known. Because the bundled clean-install script clones committed `HEAD`, an equivalent fresh-clone overlay was used to validate the repair before commit.
- GNU Make is not installed on this Windows host; the individual commands and `python scripts/generate_security_report.py` were run successfully.
- Physical hardware-in-the-loop, production TPM, Firecracker, and TLC execution are unavailable in this environment.

## Security limitations

- Adaptive and behavioral model outputs are untrusted proposals; only deterministic compilation and reductions enforce authority.
- The local replay/evidence stores and development keys remain under one host account; no consensus-backed multi-host or physically independent recorder is claimed.
- Live decay state is per fresh one-use capability, not session/lineage accumulating; optional behavioral decay counters are zero in the live broker path. Decay and external-effect reconciliation are fail-closed but not a distributed transaction across every possible effect system.
- Canary denial-certificate emission is available through the certificate infrastructure but is not automatically wired into every canary event path.
- The adaptive LLM endpoint is optional, bounded, and controller-side; no paid endpoint or model success claim is required.
- The hardware subsystem is a simulator only; no firmware target or physical switch was tested.
- The formal model is a narrow state-machine model and has not been TLC-checked on this host.
- Tests are project-authored and no external security audit has occurred. No frontier-model containment claim is made.

## Files changed

- Certificate verification now requires an external signer trust anchor across the library, CLI, demo, CI, and clean-install/reference paths.
- TypeScript canonicalization now matches Python bounds/normalization and uses shared adversarial vectors.
- Trust-decay tests and public documentation now distinguish live one-use per-capability decay from persistent session-scoped behavioral-guardian state.

## Commands to reproduce

```powershell
npm ci
npm run build
npm run typecheck
npm test
python -m pip install -e ".[test]"
python -m pytest tests/ -q
python -m unittest discover -s tests -v
python scripts/verify_canonicalization_vectors.py
python scripts/verify_remote_replay_interop.py
python scripts/verify_certificate.py examples/reference-run/containment-certificate.json --trusted-key examples/reference-run/certificate-signer-public.pem
python scripts/generate_security_report.py
```

## Next engineering milestone

Independently review this security repair, then deploy the authenticated replay and evidence interfaces under separate principals with rollback-resistant replicated storage.

## Exact next command

```powershell
python scripts/verify_certificate.py .demo/latest-containment-certificate.json --trusted-key .demo/latest-certificate-signer-public.pem
```
