# Two-physical-host evidence runner (operator-staged, non-destructive)

**Scope:** two distinctly identified **self-reporting** Linux machines, one
real network path, pinned mTLS recipient read-only observations, one unchanged
atomic SQLite effect row, and an original effect reservation. All six files
are individually Ed25519-signed on their own host; original JSON byte
hashes are checked against `.sha256` sidecars. The independent verifier
recalculates the exact hashes and checks both independently pinned host
public keys.

**Not proven by this runner alone:** why a TLS connection failed, physical
machine identity (no TPM), original/correct signed recovery token,
three physically independent etcd quorum voters, power-loss durability,
gateway relocation or arbitrary external-API exactly-once execution.
Its success value is deliberately narrower than PR #69/#70's overall
acceptance criteria. The source's `signed_fresh_recovery_verified` and
other unproven flags are explicitly `false`. **Both PRs remain drafts.**

### Required actual topology

- MSI: Linux via WSL2, trusted signed gateway, locally owned journal OR
  explicitly configured consensus effect journal, separate Ed25519 host
  evidence key, TLS client credentials, TLS recipient HMAC secret.
- HP: **native Ubuntu** on separate physical laptop, local persistent
  `FencedSqliteRecipient` SQLite database, trusted mTLS recipient server,
  distinct HP-only Ed25519 host evidence key.
- Verify baseline communication on an isolated LAN. Use a trusted
  firewall; do not expose recipient port to the public Internet.
- Both hosts must use the **identical pinned Git HEAD** for this run.
- Do not stop the HP's power or do a destructive network change through
  this script. The operator must use a reversible **lab-only** network
  disconnect that will not interrupt critical devices or other users.

The app deliberately does not run SSH commands or manipulate network
interfaces, host firewalls, or power control. HP can be managed through
SSH once Ubuntu is installed. There is no requirement to have a working
laptop screen after installing SSH.

### Before starting

First follow the mTLS provisioning, signed gateway configuration, and
initial signed `FencedTlsRecipientClient` integration steps in
[REMOTE_HOST_AND_POWERCUT_RUNBOOK.md](REMOTE_HOST_AND_POWERCUT_RUNBOOK.md).
For distributed gateway fencing and exact shared etcd config see
[CONSENSUS_EFFECT_FENCE_PROTO.md](CONSENSUS_EFFECT_FENCE_PROTO.md).
Do not start here if the actual signed gateway hasn't committed one owned
synthetic SQLite effect on HP and journaled the original authority.

Use a brand-new private directory on **each** host, owned by its
operator account, with file mode 0700. Each host generates its own key:
never copy either private key to the other machine.

```bash
umask 077
mkdir -m 700 -p ~/ehh-two-host-private

python scripts/two_host_campaign.py keygen \
  --private-key ~/ehh-two-host-private/host-witness.key \
  --public-key ~/ehh-two-host-private/host-witness.pub
```

Copy **public** key files to the offline verifier / controller via a trusted
path. Identify them out-of-band before pinning. Save the original
`gateway.host-witness.pub` and `recipient.host-witness.pub`; don't generate
replacement public keys after evidence capture.

On MSI, generate a single canonical UUID:
```bash
python scripts/two_host_campaign.py new-run-id
```
Record that run ID on both machines. Use one request and logical effect
throughout; derive inputs from the trusted **actual signed gateway request**
(not from an untrusted guest). Logical effect key is:
`digest({"session_id":request.session_id,"request_id":request.request_id})`.
The request digest is the matching `ActionRequest.request_digest`. These
are lowercase 64-digit SHA256-like EHH canonical digest hex strings.
The recipient ID must match the pinned ID on both hosts. Do **not** share
gateway signer private keys, HMAC keys, token secrets, or TLS private keys
through the public evidence directory.

### Three-phase operator campaign

For every phase, execute the matching `capture` on each machine. Output
filenames below are **required** by the offline verifier. Each `capture`
reads existing state and writes a new immutable original file and sidecar.
No existing evidence is overwritten.

On **HP** (recipient) after the initial properly signed effect commit, and
again at the two later checkpoints:

```bash
python scripts/two_host_campaign.py capture \
  --role recipient --phase before \
  --run-id RUN_UUID --effect-key EFFECT_SHA256 \
  --request-digest REQUEST_SHA256 \
  --recipient-id owned-hp-recipient \
  --database /srv/ehh-recipient/recipient.sqlite \
  --private-key ~/ehh-two-host-private/host-witness.key \
  --output ~/ehh-two-host-private/recipient.before.json
```

On **MSI** (gateway), same run/binding and checkpoint phase, with pinned
private mTLS observation config (see #69), plus **exactly one** journal
backend:

```bash
python scripts/two_host_campaign.py capture \
  --role gateway --phase before \
  --run-id RUN_UUID --effect-key EFFECT_SHA256 \
  --request-digest REQUEST_SHA256 \
  --recipient-id owned-hp-recipient \
  --tls-config ~/ehh-private/tls-observer.json \
  --journal-db ~/ehh-private/journal.sqlite \
  --private-key ~/ehh-two-host-private/host-witness.key \
  --output ~/ehh-two-host-private/gateway.before.json
```

For **consensus-only** operation, replace
`--journal-db PATH` with `--consensus-config PATH`, an operator-owned
0600 canonical/strict JSON file containing exactly
`etcd_gateway`, `etcd_cluster_id`, and `etcd_namespace`.
Use the exact same consensus cluster/domain as the signed gateway; the
observable effect journal is not a private fallback SQLite file.

The TLS observation config is a 0600 trusted JSON file containing exactly
`host`, `port`, `server_name`, `ca_file`, `client_cert_file`,
`client_key_file`, `server_cert_sha256`, `recipient_id`, `auth_key_hex`.
Treat its contents as **secrets**, never include it in public artifacts.

Next, **manually and reversibly** isolate the HP's lab network. Keep the
recipient process running, the HP powered up, and its SQLite volume intact.
Capture the gateway's `disconnected` observation **during** outage; it
must report `transport.status=indeterminate`. Independently capture HP's
local `recipient.disconnected.json` while network is isolated (this may
require HP console or a previously configured local operator).
No source modification, credential replacement, or database cleanup.

Restore networking and wait for pinned TLS reachability. Issue and execute a
**NEW separately signed recovery capability** using the actual EHH gateway
from PRs #69/#70. Preserve its **original gateway result and recorder
evidence** separately; this evidence runner will not claim it has verified
the fresh signing/consumption by itself. Capture the `recovered` phase on
both HP and MSI, with the same command flags and new phase/filename.

During all three phases, **do not power-cycle either host**. A boot-ID
change fails the network-only campaign; physical power-cut evidence is a
different experiment.

### Reassemble originals on the offline controller

Put all six original JSON+SHA256 pairs in ONE fresh private directory,
named `gateway.before.json`, `gateway.disconnected.json`,
`gateway.recovered.json`, `recipient.before.json`,
`recipient.disconnected.json`, `recipient.recovered.json`.
Transfer these together with the two original public keys over a protected
channel; do not edit the files and do not move private keys.

```bash
python scripts/two_host_campaign.py verify \
  --directory ~/ehh-two-host-bundle \
  --gateway-public-key ~/ehh-two-host-bundle/gateway.host-witness.pub \
  --recipient-public-key ~/ehh-two-host-bundle/recipient.host-witness.pub \
  --report ~/ehh-two-host-bundle/verification-result.json
```

A **PASS** means the six original signed stage observations, attached
checksums, distinct **self-reported** machine identities, original
gateway effect reservation, interrupted/restored TLS read, and unchanged
single recipient SQLite row all agree. Every successful result explicitly
sets these independent claims to `false`: signed fresh recovery verified,
physical reason for network outage verified, hardware machine identity
attested, physical power cut, cross-gateway host failover.

A malformed, absent, unpinned, substituted, incomplete or inconsistent
observation returns a **nonzero exit** with `INCOMPLETE/FAIL CLOSED`
and **does not create a successful verification-result.json**.

### Publication / safety

The six original reports contain hashed machine IDs, boot UUIDs, kernel
releases, effect digests and public-key fingerprints. They intentionally
exclude TLS/HMAC secrets and key material. Operator must still review every
artifact for host privacy and public publication safety. Check the
`git rev-parse HEAD` recorded in evidence before publication. Never edit
or regenerate originals after fault windows. Archive original byte hashes,
source revision and independently verified result in the PR, and publish
only when the claims are supported by separate witness material.

For real power-loss tests, use #69's **separate** external controller
proof; do not confuse a network-disconnect PASS with a hard power cut.
