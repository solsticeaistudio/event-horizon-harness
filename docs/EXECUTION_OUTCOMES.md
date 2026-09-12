# Execution outcomes and external-effect contract

The executor consumes a one-use capability before dispatch. Consumption is durable authorization bookkeeping, not a transaction with the operation, evidence recorder, or response transport. A failed response does not establish rollback.

## Implemented outcome contract

`ExecutionResult.success` describes successful completion of the execution path as observed by the caller. `effect_state` records how far that path is known to have progressed:

| State | Meaning | Failure event |
|---|---|---|
| `not-started` | Validation or handler lookup failed, or execution stopped before dispatch. This attempt did not start the operation. | `execution.denied` |
| `possibly-committed` | Operation dispatch began, but output validation and completion recording have not all been acknowledged, or the coordinator lost the executor response. An effect may already exist. | `execution.indeterminate` |
| `completed` | The handler returned, output passed serialization/size checks, and the executor's recorder interface acknowledged completion. This does not establish transactional commit in a downstream service. | `execution.indeterminate` if response delivery or subsequent coordinator recording fails |

The state moves to `possibly-committed` immediately before invoking a compute callback or retrieving an object. Callback exceptions, oversized output, serialization failures, and recorder failures never move it back to `not-started`. Read-only operations are conservatively classified the same way; there is no operation-specific proof-of-no-effect interface yet.

A successful result has state `completed` and event `execution.completed`. A completed handler may still produce an unsuccessful result if the response path fails. Existing completion evidence is retained. Failure evidence is best effort when the recorder is unavailable; the absence of a record is not evidence that no effect occurred.

The process service uses a null local recorder and returns its outcome to the coordinator, which appends authoritative logical evidence. Therefore an executor `completed` response does not establish an authoritative recorder append. The coordinator preserves ambiguous outcomes and treats missing or invalid responses after dispatch conservatively. These messages still come from a trusted executor under the current process-demo assumptions; they are not independent evidence against guest root. A hard process crash may prevent any result; observers must treat a missing outcome after possible dispatch as unknown.

Replay denial describes the new attempt only. It says nothing about whether the original attempt committed an effect. Consumption is never refunded, and neither executor nor coordinator automatically retries or mints replacement authority for ambiguous operations. A consumed capability may have caused zero effects. A newly issued capability could cause a duplicate effect.

## Required contract before enabling external writes

External-write adapters are not implemented by this change. Each future adapter must satisfy these requirements before registration:

1. **Transaction boundary:** document the downstream commit point and whether consumption, mutation, and operation-journal persistence share an atomic transaction. If they do not, enumerate crash windows and classify unresolved windows as unknown. A returned error or rejected output is never rollback evidence.
2. **Operation identity and idempotency:** bind a trusted, tenant-scoped logical operation identity to the exact request and resource. The effect service must atomically reject mismatched reuse and durably deduplicate identical retries across concurrency and restarts. Specify retention and expiry. Client-selected keys or fresh capabilities must not silently bypass deduplication. This is additional to the existing capability ID, not a new implemented claim field.
3. **Reconciliation:** provide an authenticated, read-only lookup of authoritative downstream state by operation identity. Return confirmed committed, confirmed no effect, or unknown, with provenance. Only an operation-specific trusted observation may resolve ambiguity. An absent entry alone is insufficient if commit and journaling can diverge.
4. **Retry authority:** keep unknown operations stopped pending reconciliation. A confirmed no-effect result may support a separately authorized retry subject to current policy and expiry. Never restore the original one-use token. Compensation is a separate authorized effect, not rollback.
5. **Evidence and delivery:** correlate capability, request, logical operation, commit receipt, recorder acknowledgement, and delivery observation. Preserve unknown outcomes in reports; bound output and treat it as untrusted. Returning no output does not prove that no information escaped elsewhere.

No exactly-once execution, distributed transaction, automated reconciliation, or universal secret filtering is provided by this contract.

## Regression coverage and attack analysis

`tests/test_execution_outcomes.py` uses a synthetic append-only effect fixture checked directly by the test. It exercises callback failure, oversized output, circular-output serialization failure, recorder unavailability, response faults, malformed responses, successful execution, and failures before dispatch. Every post-effect case verifies that replay cannot append a second effect. Coordinator response loss is injected after a real callback executes; `tests/test_process_harness.py` additionally discards a real IPC response and checks durable executor consumption.

The vulnerable pre-fix executor reported callback exceptions, oversized output, and serialization failures as denials; these regression assertions fail against that implementation. The change closes a false-no-effect reporting path without increasing capabilities or adding retries. It does not prevent a malicious callback from causing an effect, make executor self-reports trustworthy after compromise, or cover all process-crash/storage-rollback/partition scenarios. Existing concurrent-redemption tests continue to cover atomic one-use consumption; broader independent fault observation remains roadmap work.
