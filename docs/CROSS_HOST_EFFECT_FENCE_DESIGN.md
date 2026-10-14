# Proposed cross-host effect-fence consensus architecture

**Status: DESIGN ONLY — not implemented, tested or accepted as cross-host failover.**
This note scopes work that is **not** included in PR #69's real mTLS
recipient or off-target, boot-separated powercut witness implementation.

## Why PR #69 is not multi-gateway failover

The current `DurableEffectJournal` is a local SQLite file owned by one
gateway host; the `fenced_tls_gateway_worker.py` also uses local SQLite
capability replay state. Remote TLS protects gateway-to-recipient transport,
but running a second gateway on a separate host with a different SQLite
journal can lose the original effect reservation provenance. The recipient
will still dedupe its own cooperating *atomic SQLite* row, but that alone is
not a consensus-backed gateway authorization or journal correctness proof.

Do not run two authoritative gateways with independent local journals, or
claim they form an HA gateway pair. Do not migrate a reservation by copying
a live SQLite database between hosts.

## Proposed authority and state contract

1. All gateway hosts pin one identical **etcd cluster ID**, namespace,
   tenant/environment and trust-policy epoch. Fail closed on mismatched
   identity, missing cluster head, or uncertain etcd outcome. Authenticate
   endpoints with distinct mTLS identities. Never bootstrap on failover.
2. Capability replay consumption is linearizable and globally one-use using
   the existing atomic etcd authority machinery; per-host replay SQLite is
   disallowed in genuine cross-host mode.
3. The logical effect key remains bound to the original
   `(tenant, environment, session_id, request_id)` domain. A new **separate**
   signed recovery capability does not replace the original capability ID.
4. **Before effect dispatch**, atomically compare `VERSION(effect_key)==0`
   and persist immutable fields: original capability ID, original claims
   digest, exact request digest, pinned recipient identity, protocol name,
   output digest and state `possibly-committed`. Never lease/delete this
   row or reinterpret an absent recipient read as clearance to dispatch a
   different effect. Recovery operations can only observe the original
   immutable reservation and its exact bindings.
5. The recipient independently enforces one persistent `effect_key` row
   and matches the same request/output digests in the **same durable SQLite
   transaction** as the synthetic business effect. A second gateway may
   safely issue the *identical* bound request after fresh signed approval;
   recipient returns the same immutable receipt, not a second effect.
6. Confirm `recipient-confirmed` only after an independent **positive**
   recipient read matches the original durable receipt. Use an etcd CAS
   against its observed `mod_revision`; if a concurrent writer won, re-read
   and verify bindings/receipt, rather than overwriting provenance. A lost
   quorum, ambiguous put response or failed observation means
   **indeterminate**, never an invented success or a fresh first dispatch.
7. Do not repurpose the existing `EtcdSignedReplayService` global head
   schema for effect keys without a separate transaction/version contract
   and its own test vector. Either extend the signed authority with a
   separate canonical effect-fence state machine plus pinned checkpoint
   continuity, or implement a distinct pinned namespace and independently
   verifiable signed change log. Operator rollback and unanchored bootstrap
   remain explicitly unsupported.

### Stale writer fencing

Recipient uniqueness is the only actual at-most-once business-effect
boundary of this prototype. A distributed gateway ownership epoch or lease
by itself is **not sufficient**: a paused prior gateway could resume after
lease expiry. Any epoch/leader fencing must be **enforced by the recipient**
and must not permit a different effect key/output under an old reservation.
For arbitrary external API effects, a cooperating idempotent recipient is
still mandatory; the same guarantee cannot be synthesized by wrapping HTTP.

### Infrastructure reality

Two laptops demonstrate a **real two-physical-host transport and network
partition** between one gateway and one recipient. Two hosts alone do
**not** establish a failure-independent three-voter etcd quorum. For
meaningful one-host-loss survivability, put at least three etcd voting
members in three separate failure domains (potentially MSI + HP + an
independent third machine/VM with documented placement); merely splitting
three containers across two laptops cannot survive either laptop loss
while preserving quorum.

Power loss is separately tested using a **disposable target** and an
off-target controller. Unplugging a battery-backed laptop or restarting WSL
is NOT electrical hard-off evidence.

## Portable and real acceptance matrix

| Fault window | Expected safe behavior |
|---|---|
| Two gateways concurrently reserve new key | Exactly one immutable original reservation; no rebinding |
| Gateway A loses ACK after recipient commit | Possibly committed; no original-capability replay |
| Gateway B with fresh signed recovery arrives | Same positive recipient receipt; exactly one durable effect |
| A resumes after B recovered | Same immutable binding; no new effect |
| Gateway local disk disappears | Distributed journal still pinned to same cluster; never rebootstrap |
| Loss of recipient network before/after commit | No negative clearance; eventual new signed recovery |
| Loss of etcd minority | Operations with quorum continue under pinned cluster |
| Loss of etcd majority | No newly accepted authority or fabricated completion |
| Stale/forged recipient receipt or changed result | Fail closed, original fence retained |
| Recipient powered off and recovered | Same original row/receipt or honest indeterminate, not fabricated durability |

## Evidence gate for a future PR

- CI: deterministic compare-and-swap/response-loss, malicious rebindings,
  stale gateway, recipient ambiguity and adversarial authority tests.
- Lab: independently supervised gateway A and gateway B with separate
  process/machine identity, receiver B, and consensus on distinct failure
  domains; capture competing requests, original receipts, signed authority
  state, cluster IDs, WAN/LAN partition events and independent controller
  observations.
- Originals: immutable JSON+SHA256, source and build manifest, verifier,
  signed events and independently checked bytes.
- **Not a claim** of independently trusted external payment/email effects,
  TPM attestation, physical disk electronics or arbitrary network partitions.

No implementation is merged or advertised as proven by this note.
