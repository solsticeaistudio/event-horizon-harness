# Seven-process signed replay authority integration (software laboratory)

This branch closes the key **wiring gap** between EHH's existing seven-role
process harness and its new atomic etcd-backed signed replay service.

The following are now *actually routed* through one signed HTTP replay
authority when `remote_authority` is configured:

| Trusted process | Replay operation | Scope |
| --- | --- | --- |
| Node attestation verifier (spawned by verifier) | nonce-create, nonce-consume, nonce-inspect | `attestation.nonces` |
| Capability signer | capability-consume | `capability.authority` |
| Signer protected request verifier | authorization-consume | `protected.signer` |
| Evidence recorder protected API | authorization-consume | `protected.recorder` |
| Certificate service protected API | authorization-consume | `protected.certificate` |

The parser and guardians **do not perform replay writes**. The executor
retains its own *local* secondary verification/replay store, but it does
not hold a signing client identity or a connection to the etcd authority.
The signer-side capability consume is still the required upstream gate
before the executor runs, and its signed commit is shared cluster-wide.

The actual `ProcessSeparatedHarness` previously defaulted all these
services to distinct local SQLite state. Its default remains backward
compatible. Passing `remote_authority=...` selects the remote path,
and an explicitly configured but unavailable remote service **must not
fall back to local SQLite or in-memory state**.

## Provision securely

Provision each scoped client identity out of band **before creating the
server's client allowlist**:

```python
from event_horizon.trusted_replay_client import provision_replay_client_policies

roles = provision_replay_client_policies(workdir, service_id="eh-distributed")
allowlist = {policy.key_id: policy for policy in roles.values()}
```

Only the trusted verifier/signer/recorder/certificate roles receive
client key files. Their grants are fixed in `ROLE_GRANTS`. The
`executor` role cannot receive a signed replay client key.

Configure the separately trusted authority server with these public
policies (see [atomic signed replay deployment](ATOMIC_SIGNED_ETCD_REPLAY.md)),
and provision only the **public** server PEM and URL to the harness:

```python
from event_horizon.process_harness import ProcessSeparatedHarness

with ProcessSeparatedHarness(
    workdir,
    ttl_seconds=30.0,
    remote_authority={
        "url": "https://replay.example:8443/v1/transition",
        "service_id": "eh-distributed",
        "epoch": 1,
        "server_public_key_pem": PINNED_SERVER_PUBLIC_KEY_PEM,
        "ca_cert_path": "/trusted/ca.pem",
        "client_cert_path": "/trusted/client.pem",
        "client_key_path": "/trusted/client.key",
    },
) as harness:
    request, capability, attestation = harness.request_capability(action_payload)
    result = harness.execute(request, capability, attestation)
```

Those client mTLS paths, private signing seeds, role configs and high-water
checkpoint witnesses **must be hosted outside an attacker-controlled
executor**. The example above is explanatory, not a production credential
bundle. The seven-process same-user development harness does not itself
establish host-user or VM filesystem isolation.

`role_remote_settings` provisioned each trusted client identity once
and stores its observed signed authority checkpoint persistently under
`trusted-control`. A process restart reloads the pinned signer, epoch and
last checkpoint. The Node verifier bridge uses the existing
`SignedReplayClient` and `RemoteNoncePersistence` from the attestation
package, writes its high-water mark before reporting attestation success,
and refuses to fall back to `SqliteNoncePersistence` in remote mode.
A missing/untrusted checkpoint file or an authority host compromise
requires separate operational handling and externally pinned continuity;
local checkpoint persistence alone is not rollback-resistant against a
malicious privileged host administrator.

Loopback-only plaintext is supported explicitly for disposable test hosts.
Remote endpoints require mTLS; redirects are forbidden. No TLS private key
may ever enter a Firecracker guest.

## Repeatable distributed seven-role test (no KVM)

`tests/test_etcd_signed_replay_live.py::LiveSignedReplayTests.
test_real_seven_process_harness_shares_signed_authority`:

1. Provisions unique role identities and an atomic signed replay server.
2. Starts seven real EHH process services and the Node attestation bridge.
3. Issues a capability with nonce creation/consumption through signed HTTP.
4. Consumes an authorized capability and records a genuine synthetic read.
5. Rejects the same capability on replay.
6. Verifies the executor config contains no remote authority settings.
7. Checks that the shared etcd checkpoint advanced from multi-role requests.
8. Restarts the signer, reloads its pinned high-water witness, and rejects
   the previously consumed capability again.

The disposable real three-node etcd workflow also tests signing and
authorization under a one-member failure, and refusal under quorum loss.
The process-harness scenario currently runs under healthy quorums (including
a two-node majority); the explicit minority test targets the signed replay
authority directly rather than a hardware-isolated seven-role experiment.

Run the relevant CI workflow on the branch:

`etcd authority quorum integration (disposable)`

The workflow provisions disposable local Docker etcd nodes, builds the
attestation Node bridge, and runs the new full-system integration. The
regular CI workflow still checks the existing SQLite-based baseline for
regression and exports the existing synthetic signed evidence bundle.

## What this does NOT demonstrate

- Real KVM/Firecracker isolation, guest-root compromise, or host-root
  containment (requires independently observed hardware execution).
- An authority process separated into another host's security boundary in
  this CI test: the signed HTTP server runs in the same runner as the seven
  service processes for end-to-end correctness.
- Protection against compromise of the authority signing key, etcd
  administrators, the host OS or witness files.
- Atomic consistency of the **separate executor-local decay engine and
  effect receipts** with the remote replay CAS. The remote replay checkpoint
  includes the authoritative authorization decision, not the external
  side effect or the local second-line decay store.
- Availability guarantees during partitions or claims about production
  throughput: the deliberately single global etcd head serializes all
  replay operations.

The next physical experiment is to place the executor in Firecracker,
run the trusted authority and effect gateway outside the guest, and capture
independent host-side effect oracles under malicious guest-root attempts.
