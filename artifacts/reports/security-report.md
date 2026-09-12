# Event Horizon security evaluation report

- Source revision: `33ae8ffce563d77108f7b2741dcf04ffe6b7a00f`
- Dirty tree at start: `true`
- Deterministic available checks: `PASS`
- Overall status: `PASS`
- TLC: `executed and passed`
- Hardware in the loop: `not run - no hardware available`

| Evaluation | Result | Tests | Milliseconds |
|---|---:|---:|---:|
| policy ceiling evaluation | PASS | 16 | 134 |
| trust tier | PASS | 8 | 174 |
| protocol property | PASS | 6 | 5237 |
| concurrent redemption | PASS | 3 | 1334 |
| chaos recovery | PASS | 6 | 380 |
| canary events | PASS | 11 | 347 |
| denial certificates | PASS | 11 | 310 |
| behavioral guardian | PASS | 10 | 153 |
| trust decay | PASS | 12 | 147 |
| adaptive adversary | PASS | 4 | 129 |
| positive controls | PASS | 2 | 139 |
| literature feed | PASS | 4 | 99 |
| hardware simulator | PASS | 10 | 134 |
| formal model structure | PASS | 1 | 85 |

## Policy sizing fixture

- Overprovisioned control SER: 500/1000
- Task-ceiling SER: 1000/1000
- Overprovisioned risk exposure: 101
- Task-ceiling risk exposure: 1
- Both synthetic fixture tasks completed; neither reported false denial.

Observed invocation is a proxy, not proof of minimum necessary authority. These results are project-authored synthetic tests, not an audit or frontier-model containment claim.
