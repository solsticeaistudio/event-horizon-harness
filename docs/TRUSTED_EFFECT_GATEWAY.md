# Trusted effect gateway prototype

`trusted_effect_gateway.py` introduces an explicit authorization and
effect-dispatch boundary that consumes a capability **before** executing
a trusted handler and refuses to execute anything when replay authority or
pre-dispatch evidence is unavailable. A handler exception is recorded as a
possibly committed effect; the gateway never automatically retries it.

Backends use `select_consumption_store`:

- `backend="sqlite"` requires a durable database path.
- `backend="etcd"` requires `EtcdGatewayConfig` and a pinned cluster ID.
- Unknown backend and mixed-configuration options are rejected without fallback.

Only install this gateway in an independently trusted enforcement process:
**never provide etcd write credentials, SQLite authority paths, or external
effect credentials to the untrusted executor**. The callback mapping must
consist of trusted host-defined integrations, not attacker-supplied Python.

Regression tests show replay denied after SQLite restart, authority outage
fails closed, missing evidence denies dispatch, and effect ambiguity is not
silently retried. This is a *testable enforcement component*, not yet a
deployed separate-host service.

## Remaining mandatory work

- Authenticated and mutually secured transport connecting the seven-process
  harness to this trusted gateway with no database credentials in executor.
- Unified nonce and protected-request replay transitions with an atomically
  chained checkpoint in the chosen storage backend; the existing signed replay
  protocol's SQLite checkpoint cannot be bolted independently onto etcd.
- Real etcd quorum fault testing **through** the trusted gateway API, rather
  than only through direct isolated storage tests.
- Firecracker workload isolation and out-of-band host observations to establish
  that the hostile executor cannot bypass the gateway.

See [ADR-001](ADR-001-TRUSTED-REPLAY-TOPOLOGY.md).
