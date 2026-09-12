# Deterministic chaos and recovery testing

The fault catalogue names 50 signer, synthesizer, compiler, executor, recorder, capability-store, guardian, attestation, and network points. Every point maps to one explicit disposition: deny, safe retry, reconcile, indeterminate, or halt. The injector is inert by default and refuses to enable outside `environment="test"`.

The real executor exposes test-only hooks before/after validation, before/after effect, around evidence recording, and before response. Any failure after operation dispatch is returned as `execution.indeterminate`, including callback exceptions, rejected output, serialization failure, recorder failure, and lost responses. The named `after-effect` hook is after output validation; the executor now marks possible effects before invoking the handler. The deterministic classifier likewise prohibits retry wherever an effect is committed or uncertain.

See [Execution outcomes](EXECUTION_OUTCOMES.md) for the three-state runtime contract and tests that independently observe a synthetic effect. The named-fault classifier remains a specification of dispositions, not evidence that every listed failure has been injected into a live service. Runtime state names and classifier state names are separate contracts.

Run `make test-chaos`. The catalogue currently tests state classification and executor hooks. Not every named point is yet wired as a live hook in every production component, and process-kill/filesystem fault campaigns remain future work.
