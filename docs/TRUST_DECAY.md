# Monotonic trust and authority decay

Capabilities bind a decay profile ID/version, complete profile digest, initial-authority digest, refresh-requirement digest, issuance/expiry, and one-use invocation limit. The verifier reconstructs the profile from the signed compiled ceiling and rejects any mismatch before redemption.

At redemption, the decay engine computes current authority before permitting an effect. The reusable engine can independently reduce lifetime, calls, read/write bytes, destinations, tools, actions, resources, integer argument ranges, parallelism, and effect severity. Its isolated API supports elapsed time, use/data counters, denials, risk, canary events, trust/policy age, environment changes, and workload restarts.

Each transition must satisfy:

```text
Authority(t + 1) subset-of Authority(t)
```

Within one decay-state identity, counters and maximum observed time are monotonic. Clock rollback uses the maximum previously observed time. Profile replacement, counter reset, expiration extension, state corruption, and storage unavailability fail closed. In-memory state is used for local unit tests; the process-separated signer and executor use SQLite transactions for restart continuity on one host.

## Live harness semantics

The live broker keys decay state by the signed `capability_id`. Every issued capability has a fresh random ID, an invocation limit of one, and is burned before effect dispatch. The broker and executor therefore each perform at most one decay authorization for that identity. They currently supply elapsed time and the implicit one-use count; denial, risk, canary, environment-change, and workload-restart counters are not accumulated by `DecayEngine` across later capabilities.

Session-scoped behavioral accumulation is a separate control implemented by the persistent Behavioral Transition Guardian. Its reductions affect later issuance through the guardian/compiler path; they are not `DecayEngine` history and must not be described as session- or lineage-wide decay. Session/lineage accumulation inside `DecayEngine` is not implemented.

Refresh creates a different capability identity and requires fresh attestation and authorization digests. It is a new authorization event, not an extension of an existing capability. A trust upgrade cannot enlarge an already issued capability, and a consumed capability is not revived.

The reference profile is deliberately narrow and operates alongside the independent one-use capability store. The live integration test proves that replay leaves the consumed capability's single decay transition unchanged, a denied pre-issuance request creates no decay identity, and a later authorization receives a separate fresh decay identity. SQLite does not claim distributed atomicity, consensus, rollback-resistant storage, or transactional atomicity with an external side effect.
