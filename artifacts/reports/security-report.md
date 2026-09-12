# Event Horizon security evaluation report

- Source revision: `0148b23d576757a4aa2ee0513c3b7c6f9b642600`
- Dirty tree at start: `true`
- Deterministic available checks: `PASS`
- Overall status: `PASS`
- TLC: `executed and passed`
- Hardware in the loop: `not run - no hardware available`

| Evaluation | Result | Tests | Milliseconds |
|---|---:|---:|---:|
| policy ceiling evaluation | PASS | 16 | 132 |
| trust tier | PASS | 8 | 175 |
| protocol property | PASS | 6 | 5247 |
| concurrent redemption | PASS | 3 | 1306 |
| chaos recovery | PASS | 6 | 327 |
| canary events | PASS | 11 | 359 |
| denial certificates | PASS | 11 | 308 |
| behavioral guardian | PASS | 10 | 154 |
| trust decay | PASS | 12 | 147 |
| adaptive adversary | PASS | 4 | 130 |
| positive controls | PASS | 2 | 139 |
| literature feed | PASS | 4 | 96 |
| hardware simulator | PASS | 10 | 133 |
| formal model structure | PASS | 1 | 84 |

## Policy sizing fixture

- Overprovisioned control SER: 500/1000
- Task-ceiling SER: 1000/1000
- Overprovisioned risk exposure: 101
- Task-ceiling risk exposure: 1
- Both synthetic fixture tasks completed; neither reported false denial.

Observed invocation is a proxy, not proof of minimum necessary authority. These results are project-authored synthetic tests, not an audit or frontier-model containment claim.
