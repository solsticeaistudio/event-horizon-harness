# Security Assurance Matrix (v0.6)

This matrix maps each deployment mode against the guarantees it actually
satisfies, and states which certificate claims are permitted in each mode.

**Language discipline.** Event Horizon proves *authenticated provenance*,
*mechanically derived semantics*, *independently corroborated evidence*, and
*mediated effect integrity*. It does **not** prove unrestricted semantic
truth: authenticated actors can still lie, and the architecture's job is to
make lies detectable, conflicting, or quarantined — never to launder them into
truth.

## Deployment modes

| Dimension | `development` | `local-hardened` | `witnessed` | `high-assurance` |
|---|---|---|---|---|
| Signed actors (typed statements) | yes | yes | yes | yes |
| Manifest role authorization | single manifest | manifest + rotation ready | manifest + rotation ready | enforced for every signer |
| Persistent replay state | SQLite local | SQLite local + remote capable | required durable | required durable/remote |
| Trusted recorder anchor | local file anchor | local file anchor | **external witness** | external witness (+ quorum-ready) |
| Effect Gateway mediation | optional library path | enabled for effectful ops | enabled | enforced (no ungoverned path) |
| Provider idempotency | simulated | adapter-supported | adapter-supported | required, reconciled |
| Independent key administration | same host (logical separation) | per-role key providers | per-role key providers | independently administered/HSM-ready |
| Multi-party certificate approval | none (policy hook present) | policy hook | policy hook | k-of-n approvers required |
| Hardware key protection | none | none | optional | required |

## Certificate assurance levels (machine-readable)

`local < authenticated < witnessed < mediated-effects < independent-trust`

A certificate records `assurance_level` plus `assurance_guarantees` — the
exact set of satisfied guarantees. Levels are **not** interchangeable:

- A certificate without an external witness can never present as `witnessed`.
- A certificate whose effects were not governed through the Effect Gateway
  keeps `effect_mediation_consistent = unknown` and never reaches
  `mediated-effects`; it does not claim external-effect containment.
- `independent-trust` additionally requires that every consumed statement was
  signed by a key manifest-authorized for its role.
- `status = conflicted` is first-class: when two authenticated sources
  disagree (for example an executor receipt versus a gateway reconciliation),
  the certificate preserves the conflict instead of choosing a side.

## Permitted claims by mode

| Claim | development | local-hardened | witnessed | high-assurance |
|---|---|---|---|---|
| "evidence is complete for this run" | yes | yes | yes | yes |
| "every actor was manifest-authorized" | no | partial | partial | yes |
| "history has not moved backward" | vs local anchor only | vs local anchor only | **vs witness** | vs witness |
| "all governed effects were mediated & reconciled" | n/a | yes (library path) | yes | yes |
| "certificate issuance had independent approval" | no | hook | hook | yes |

## Failure semantics

Claims are `satisfied`, `violated`, `unknown`, or `conflicted`. Certificates
are `complete`, `incomplete`, or `conflicted`, with explicit blocking reasons.
Disagreement between authenticated sources is preserved, never collapsed.
