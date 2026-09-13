# Event Horizon security evaluation report

- Source revision: `65ed350f1e185e9c59ab1998fa118159de0b750e`
- Dirty tree at start: `true`
- Deterministic available checks: `PASS`
- Overall status: `PASS`
- TLC: `executed and passed`
- Hardware in the loop: `not run - no hardware available`

| Evaluation | Result | Tests | Milliseconds |
|---|---:|---:|---:|
| policy ceiling evaluation | PASS | 16 | 125 |
| trust tier | PASS | 8 | 176 |
| protocol property | PASS | 6 | 5266 |
| concurrent redemption | PASS | 3 | 1313 |
| chaos recovery | PASS | 6 | 334 |
| canary events | PASS | 11 | 345 |
| denial certificates | PASS | 11 | 288 |
| behavioral guardian | PASS | 10 | 156 |
| trust decay | PASS | 12 | 149 |
| adaptive adversary | PASS | 4 | 128 |
| positive controls | PASS | 2 | 143 |
| literature feed | PASS | 4 | 97 |
| hardware simulator | PASS | 10 | 132 |
| formal model structure | PASS | 1 | 87 |

## Policy sizing fixture

- Overprovisioned control SER: 500/1000
- Task-ceiling SER: 1000/1000
- Overprovisioned risk exposure: 101
- Task-ceiling risk exposure: 1
- Both synthetic fixture tasks completed; neither reported false denial.

Observed invocation is a proxy, not proof of minimum necessary authority. These results are project-authored synthetic tests, not an audit or frontier-model containment claim.
