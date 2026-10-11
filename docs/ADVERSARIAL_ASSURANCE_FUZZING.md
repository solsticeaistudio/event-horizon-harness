# EHH Adversarial Assurance: coverage fuzzing

This is a **rootless defensive test harness** for code already used by EHH
at its guest-facing security boundary. It does not start Firecracker,
Docker, external connectors, live etcd, or use real signing credentials.
It does not grant the fuzzed input permission to select an effect handler.

## Running the fuzz engine

On Linux x86_64 with Python 3.11 (Ubuntu/WSL2 supported as a development
environment):

```bash
cd ~/event-horizon-harness
python3 -m venv /var/tmp/ehh-fuzz-venv
/var/tmp/ehh-fuzz-venv/bin/python -m pip install -e ".[test,fuzz]"

# Reproducible assertions: not coverage-guided.
/var/tmp/ehh-fuzz-venv/bin/python scripts/run_ehh_fuzz.py \
  --target all --smoke --iterations 400

# Actual Atheris/libFuzzer instrumentation, separate worker per target.
/var/tmp/ehh-fuzz-venv/bin/python scripts/run_ehh_fuzz.py \
  --target frame --seconds 300
/var/tmp/ehh-fuzz-venv/bin/python scripts/run_ehh_fuzz.py \
  --target canonical --seconds 300
/var/tmp/ehh-fuzz-venv/bin/python scripts/run_ehh_fuzz.py \
  --target capability --seconds 300
/var/tmp/ehh-fuzz-venv/bin/python scripts/run_ehh_fuzz.py \
  --target gateway --seconds 300
```

The Atheris option is pinned to version 3.0.0, whose CPython 3.11 Linux
wheel is available. It instruments the imported Python targets with
coverage guidance, saves mutated corpus entries in
`artifacts/fuzz/<target>/corpus/`, and leaves crash-triggering inputs in
`artifacts/fuzz/<target>/crashes/`. Those directories must remain ignored
by Git until reviewed for secrets and redaction. The CLI never treats
the absence of a crash as evidence of unbreakability.

To replay an exact crash input as an independent one-off reproduction,
replace TARGET and PATH below:

```bash
python - <<'PY' TARGET PATH
import sys
from pathlib import Path
from scripts.ehh_fuzz_targets import run_case
print(run_case(sys.argv[1], Path(sys.argv[2]).read_bytes()))
PY
```

## Four targets and their invariants

| Target | Surface | Failure that Atheris must report |
|---|---|---|
| `frame` | Real `protocol.read_frame`, length-prefix and canonical re-encoding | Accepts a noncanonical or changed frame, or raises an uncaught unexpected exception |
| `canonical` | Real `canonical.strict_json_loads(..., require_canonical=True)` | Accepts ambiguous bytes or crashes on invalid JSON |
| `capability` | Real signed `IssuedCapability` decoding and `CapabilityVerifier.verify_and_consume` | A changed signed claim, public-key binding or signature authorizes |
| `gateway` | Real `DatasetEffectBoundary.execute` → `TrustedEffectGateway` with temporary SQLite authority | Unauthorized request/identity/mutation dispatches an effect, one-use capability dispatches twice, or rejection has an ambiguous effect |

The `capability` and `gateway` targets include a byte-selected *structured
mutation mode* (prefix `0xf0`). It starts from a legitimate signed
synthetic capability and changes one request/signature field at a time.
This reaches deeper verification paths than relying on random bytes to
accidentally form a well-typed signed capability.

A positive control exercises the correctly signed, exactly scoped
synthetic read once. Subsequent consumption must fail. The host callback
cannot access the filesystem or network; it only slices the hard-coded
string `hello-owned-only`. Disposable SQLite state stays under a temporary
directory, never in the deployed authority database.

The current targets use Python coverage instrumentation. They do **not**
provide native sanitizers for CPython, OpenSSL/cryptography, Firecracker or
the host kernel. This milestone does not fuzz the actual guest kernel,
the vsock transport daemon, peer networking, external-write adapters,
or coordinator/guardian cryptographic separation.

## CI and interpreting outcomes

The `EHH Adversarial Assurance Fuzz` workflow exercises deterministic
regression smoke cases followed by four **15-second** real coverage-guided
Atheris workers on relevant PRs, on `main`, weekly, and by manual
dispatch. The separate workers are intentional: Atheris/libFuzzer
coverage and crash state are process-local. CI uploads reproducible
corpus and crash inputs even if a worker fails. Reports include the
smoke sample count, rejection classes, seed, and duration. They are
**not independent containment certificates**.

A crash, unexpected acceptance, ambiguous-effect response or timeout is a
finding: keep the exact input SHA and process logs, minimize the case,
repair the defect and add it as a permanent regression fixture. Do not
delete an inconvenient failing seed to make the test pass. Do not publish
private credentials or arbitrary sensitive inputs; this runner's seeds
contain only synthetic signed test capabilities.

A clean short CI run is merely a build gate. For serious assurance,
schedule longer runs on dedicated hosts, record tested source revision,
Python/native dependency versions, corpus hashes, coverage evolution,
CPU-hours and crash deduplication, and commission a separate human
review. None of those external measurements have been performed yet.

## Safety and trust

This engine is for **owned synthetic fixtures only**. No package manager,
internet proxy, live agent, real target, shell executor or production
credential is invoked. The fuzz code runs in its own local Python
process; if you want an adversarial agent to control arbitrary payloads,
place that experiment in a separate containment layer and keep its
recording/authorization roots outside the agent's control.

The goal is evidence that our narrow attack surface behaves correctly,
not a claim that no AI will ever escape a sandbox.
