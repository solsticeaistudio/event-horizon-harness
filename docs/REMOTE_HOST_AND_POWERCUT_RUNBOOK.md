# EHH remote recipient / externally witnessed power-cut lab

**Status: draft protocol, portable CI testable; NO genuine two-physical-host
partition or externally power-cycled durability PASS is claimed.**

## Why this is a separate milestone

PRs #66–#68 proved six real Firecracker/KVM **single-host** recovery
scenarios, including recipient/gateway SIGKILL, lost ACK and racing recovery.
They do not establish cross-host failover or survival of a physical power cut.

The next proof requires an independent recipient host, a separate trusted
gateway host, an off-target witness/controller, TLS credentials, and an
owned *disposable* target host/VM with truly persisted storage. Running more
local Docker containers on WSL does not satisfy that requirement.

## Stage A: mTLS recipient on host B, EHH gateway on host A

Code: `event_horizon.fenced_recipient_tls` and these operator entrypoints:

- `scripts/serve_fenced_tls_recipient.py serve --config <PRIVATE-CONFIG>`
  on recipient host B, with private persistent SQLite database on **B's
  local, fsync-capable volume**.
- `scripts/serve_fenced_tls_recipient.py observe --config <PRIVATE-CONFIG>
  --effect-key <HEX64> --request-digest <HEX64>` on host A;
  this is a **read-only transport smoke probe**, not a signed effect.
- `scripts/fenced_tls_gateway_worker.py --config <PRIVATE-SIGNED-CONFIG>`
  on the trusted gateway host A, with EHH issuer-signed request and
  capability, pinned attestation/policy values, gateway-owned journal/replay
  files, remote TLS parameters and exact expected output. Keys stay on trusted
  hosts; none may be supplied by the untrusted guest.

Both ends require a trusted CA, TLS 1.2+, valid hostname verification, **mTLS
with individually pinned leaf certificate SHA-256** and a second, independent
256-bit HMAC key binding each bounded request and response. A failed TLS
handshake, certificate substitution, HMAC mismatch, network failure, timeout
or lost ACK NEVER releases an ambiguous first effect reservation.

Provision certificate authorities, leaf SAN identities, client/server
certificates, private HMAC key, and B's persistent storage **out of band**.
Generate and check each DER leaf digest with:

```bash
openssl x509 -in server.pem -outform DER | sha256sum
openssl x509 -in client.pem -outform DER | sha256sum
```

Use separate keys/certs for server and gateway; pin the server leaf hash in
A's private gateway config and the client leaf hash in B's server config.
Use a firewall restricted to A's trusted IP; never expose the port to the
internet. Config files must be owned by the service UID, mode 0600, and
stored under that UID's owned private directory. The certificate private
key files and IPC shared key must NEVER be committed to Git.

Exact **server** JSON config keys:

```json
{
  "listen_host": "10.10.0.2",
  "listen_port": 18443,
  "database": "/srv/ehh-recipient/recipient.sqlite",
  "recipient_id": "owned-remote-recipient-v1",
  "auth_key_hex": "EXACT_64_HEX_CHARACTERS",
  "ca_file": "/etc/ehh/private/ca.pem",
  "server_cert_file": "/etc/ehh/private/server.pem",
  "server_key_file": "/etc/ehh/private/server.key",
  "client_cert_sha256": "EXACT_64_HEX_CHARACTERS"
}
```

Private **observe** config keys: `host`, `port`, `server_name`,
`ca_file`, `client_cert_file`, `client_key_file`,
`server_cert_sha256`, `recipient_id`, `auth_key_hex`.
The signed-gateway config contains these as `tls_recipient`, plus the usual
`public_key_pem`, `key_id`, `request`, `capability`,
`verification_context`, `journal_path`, `replay_path`,
`recorder_path`, and `output`. All fields are exact allowlists.

**Cross-host acceptance, not met by portable CI:** Observe server and
gateway from separate physical hosts; capture verified leaf pins, network
routes, distinct actual host identities and separately persisted state;
inject a real network partition (on the **disposable recipient network
segment only**, not production connectivity); preserve the original
gateway journal across the outage; issue a fresh signed recovery capability;
verify exactly one immutable effect receipt on host B and the original
authorization binding on host A. Record independently signed observations.

**The existing effect-fence journal is not replicated across gateway hosts.**
Moving the *gateway* to a third host without shared trusted reservation
storage is prohibited; this PR does NOT claim two-gateway cross-host failover.
That requires a consensus-backed durable effect fence/epoch implementation
and its own multi-host experiment.

## Stage B: externally controlled hard power-off, boot-separated recovery

Code: `scripts/powercut_evidence.py`. It NEVER switches power or calls
`reboot`. All power control is performed OUTSIDE the target by an authorized
operator on a disposable virtual/physical host. Do not run on the personal
WSL laptop, active development machine, or a live production service.

1. On the disposable target B, on its **known persistent** Linux ext4/xfs
   volume, run `boot-id`, then `prepare` with a brand-new database path.
   The prepare step makes exactly one SQLite synchronous-FULL commit,
   performs explicit file/directory fsync, and writes an immutable canonical
   preflight. Preflight has no signed hardware attestation.
2. BEFORE power-off, copy the unchanged preflight to an independent
   controller A (and verify its SHA-256 on A). Ensure A has the Ed25519
   witness signing private key; **B never has that key**.
3. From controller A, use externally managed hypervisor/BMC power controls
   to hard-stop **only the dedicated disposable target** without a clean
   guest shutdown. Keep the target storage attached and persistent.
   Independently save controller power-off and power-on event logs.
   No such operation is automated or performed by EHH.
4. Power on B with the exact same persistent database volume, retrieve its
   new `boot-id`, and independently copy that value back to A.
5. On A (NOT on B), run `attest` with A's private Ed25519 key, the
   unchanged preflight, the real external controller event log, and the new
   boot ID. A signs a witness record binding all three. Return the original
   preflight, signed statement, event log and A's public key to B.
6. On recovered B, run `verify` with those four files and the original
   SQLite database. A passing report requires a different actual boot ID,
   valid external controller signature, matching preflight and event-log
   digests, the original durable effect receipt and exactly one row.

Examples (safe: these commands never cut power):

```bash
# On disposable target B, BEFORE the operator's out-of-band power cut:
python scripts/powercut_evidence.py prepare \
  --database /srv/ehh-test/recipient.sqlite \
  --preflight /srv/ehh-test/preflight.json \
  --recipient-id owned-powercut-test

# On B and A after B restarts:
python scripts/powercut_evidence.py boot-id

# On CONTROLLER A only, AFTER the power cycle:
python scripts/powercut_evidence.py attest \
  --preflight /secure-witness/preflight.json \
  --event-log /secure-witness/controller-power-events.log \
  --controller-id independent-power-controller-01 \
  --boot-id-after <NEW_BOOT_ID_FROM_B> \
  --private-key /secure-witness/off-target-ed25519.pem \
  --statement /secure-witness/attestation.json

# On recovered target B (all witness files returned read-only):
python scripts/powercut_evidence.py verify \
  --preflight /srv/ehh-test/preflight.json \
  --statement /srv/ehh-test/attestation.json \
  --event-log /srv/ehh-test/controller-power-events.log \
  --controller-public-key /srv/ehh-test/controller.pub \
  --database /srv/ehh-test/recipient.sqlite \
  --report /srv/ehh-test/powercut-result.json
```

An Ed25519 witness key can be generated **only on controller A**, not on B:
`openssl genpkey -algorithm Ed25519 -out off-target-ed25519.pem`,
then `openssl pkey -in off-target-ed25519.pem -pubout -out controller.pub`.

**Interpretation:** a PASS demonstrates a durable cooperating SQLite
recipient row across two observed Linux boot sessions, associated with a
cryptographically pinned **operator-attested** external power-control log.
It is not automated independent verification of electrical power removal.
The script cannot establish that a controller is honest or that a cloud
hypervisor truly removed power rather than rebooted. Honest hardware
power-off claims require review of the **external** controller provenance.
It does not prove survival of loss of the SQLite volume or two-copy quorum
durability.

## Current honest acceptance gates

- [ ] Portable TLS recipient tests pass, including wrong identity, dropped
      reply, network unavailability, original replay denial.
- [ ] Boot-separated witness verifier tests pass, including tampered log,
      forged signature, unchanged boot ID and corrupted recipient row.
- [ ] Explicit operators perform the above on at least two actual physical
      hosts (or separate physical hypervisors with honest host provenance).
- [ ] External power controller attestation and ORIGINAL JSON evidence
      are reviewed/published without secrets and with exact SHA-256.
- [ ] New source-specific, independent hardware/multi-host verifiers and
      original reports PASS before declaring real multi-host/powercut proof.

**Do not merge this draft as proven multi-host/power-loss recovery.** The
existing single-host KVM experiments remain untouched on `main`.
