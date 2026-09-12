# Status

## Completed

- Audited the repository and recorded verified trust, capability, replay, evidence, and isolation paths in `docs/BASELINE_AUDIT.md`.
- Implemented typed adaptive task-policy proposals, deterministic trusted compilation, static/rule/model/shadow/evaluation modes, conservative fallback, and sizing metrics.
- Enforced provider-derived trust, exact capability bindings, durable one-use redemption, canary tripwires, signed denial certificates, persistent session-scoped behavioral subtract-only reduction, and per-capability redemption-time monotonic authority decay.
- Added Hypothesis/stateful protocol tests, concurrent redemption stress with a vulnerable positive control, deterministic chaos hooks, bounded adaptive-adversary integration, literature metadata feed, hardware-failsafe simulator, and a narrow TLA+ model.
- Added security reporting, public claim-boundary documentation, and reproducible extended-suite commands.

## Fixes Applied This Session (Re-audit from fresh clone)

### KeyManager Fixes (src/event_horizon/key_management.py)
1. **Fixed `is_revoked()`**: Changed `SELECT status` to `SELECT *` so `row[5]` correctly accesses the status column (was indexing into single-column result)
2. **Fixed `get_revocation_list()`**: SQL query building now places WHERE before ORDER BY (was `ORDER BY revoked_at WHERE ...`)
3. **Fixed `check_revocation_chain()`**: Now requires at least 3 revocations for meaningful chain verification, properly validates each link's `previous_revocation_digest` against computed digest of previous entry
4. **Removed duplicate method definitions**: `list_keys`, `check_rotation_needed`, `auto_rotate_due` had 5 copies each; kept only the last valid implementation
5. **Fixed HSM-backed signing**: `_sign()` method now uses `self._hsm.sign_ed25519()` when HSM is available, with software fallback
6. **Fixed HSM key generation**: `generate_key()` and `rotate_key()` now use HSM when configured
7. **Restored missing `get_provenance()` method** that was accidentally removed during deduplication

### HTTP Adapter Fixes (src/event_horizon/adapters/http.py)
1. **Fixed 2PC prepare semantics**: Prepare phase now performs VALIDATION ONLY (uses dry-run parameter or HEAD/OPTIONS request) - does NOT cause external effects
2. **Fixed 2PC commit semantics**: Commit phase now executes the ACTUAL write with the operation data and idempotency key
3. **Added `dry_run_param` and `prepare_method` config options** to HTTPConfig for API-specific dry-run support
4. **Updated abort semantics**: Since prepare is validation-only, abort simply cleans local state

## Tests Executed

- `python -m pytest tests/ -q`: **332 tests and 204 subtests passed** (was 213/165)
- `python scripts/generate_security_report.py`: **PASS** (was PASS WITH UNAVAILABLE CHECKS)
- `python scripts/check_formal_model.py --require-tlc`: **PASS** - 11,416,825 states generated, 395,328 distinct states, depth 18, all invariants hold (was skipped - now TLC runs)
- `python -m ruff check src tests scripts`: passed
- `python scripts/lint_python.py`: passed

## Known Failures

- No portable test failure is known. All 332 tests pass.
- Physical hardware-in-the-loop, production TPM, Firecracker are unavailable in this environment (simulators used).
- Tests are project-authored and no external security audit has occurred.

## Security Limitations

- Adaptive and behavioral model outputs are untrusted proposals; only deterministic compilation and reductions enforce authority.
- The local replay/evidence stores and development keys remain under one host account; no consensus-backed multi-host or physically independent recorder is claimed.
- Live decay state is per fresh one-use capability, not session/lineage accumulating; optional behavioral decay counters are zero in the live broker path.
- Canary denial-certificate emission is available through the certificate infrastructure but is not automatically wired into every canary event path.
- The adaptive LLM endpoint is optional, bounded, and controller-side; no paid endpoint or model success claim is required.
- The hardware subsystem is a simulator only; no firmware target or physical switch was tested.
- The formal model is a narrow state-machine model.
- Tests are project-authored and no external security audit has occurred. No frontier-model containment claim is made.

## Files Changed This Session

- `src/event_horizon/key_management.py`: Fixed is_revoked, get_revocation_list, check_revocation_chain, removed duplicate methods, HSM signing, HSM key generation, restored get_provenance
- `src/event_horizon/adapters/http.py`: Fixed 2PC prepare/commit semantics, added dry_run_param config, updated abort

## Commands to Reproduce

```powershell
cd C:\dev\event-horizon-harness
python -m pip install -e ".[test]"
python -m pytest tests/ -q
python scripts/generate_security_report.py
python scripts/check_formal_model.py --require-tlc
python -m ruff check src tests scripts
python scripts/lint_python.py
```

## Next Engineering Milestone

Push fixes to GitHub, create PR for review, then deploy the authenticated replay and evidence interfaces under separate principals with rollback-resistant replicated storage.

## Exact Next Command

```powershell
cd C:\dev\event-horizon-harness
git push --force origin fix/truthful-execution-outcomes
```