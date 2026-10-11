# Coordinator-compromise isolation lab

This is an **owned synthetic experiment** based on EHH's already-merged
`signed_guardian_authority.py` signer contract. It deliberately assumes the
coordinator is hostile. It tests whether a coordinator with request/response
access but **no signing keys** can issue unauthorized authority.

## Rootless CI: real processes, not separate Unix identities

```bash
cd ~/event-horizon-harness
python scripts/run_isolated_authority_lab.py \
  --report artifacts/reports/coordinator-isolation-local.json
```

This launches **four guardian service processes, one capability signer
process, and nine distinct attack-client processes** over actual AF_UNIX
sockets. Every authority service checks `SO_PEERCRED` on accepted connections.
Every guardian creates its **own Ed25519 private key after process launch**;
the signer generates a separate capability key. The supervisor pins guardian
public keys in a signer-only configuration and observes an independent signed
positive-control capability.

The default mode runs under one Linux UID because GitHub Actions cannot
simply assume root. It proves process and cryptographic protocol behavior,
**not OS-enforced private-key isolation**. In same-UID mode the report MUST
label private-file and `/proc` isolation as `NOT-ASSESSED`; a same-UID
coordinator may be able to read same-UID files, debug other processes, or
inspect memory depending on system configuration.

## Linux privileged opt-in: separate UIDs

An operator can elect real OS role separation on an **owned, disposable Linux
test host**. Requires root only to spawn independent role processes with
unused numeric UIDs; does not install system users, change groups, create
Docker containers, contact the network, or modify any existing host keys.

```bash
cd ~/event-horizon-harness
sudo /var/tmp/event-horizon-isolation-venv/bin/python \
  scripts/run_isolated_authority_lab.py \
  --distinct-uids \
  --report artifacts/reports/coordinator-isolation-uids.json
```

The harness refuses if any intended test UID is already allocated. The
identities are `64001..64004` (four guardians), `64010` (signer), and `64020`
(adversarial coordinator). The signer pin file is `0600` owned by the signer.
Only intentionally public Python source is staged in a temporary
world-readable code directory, because role UIDs often cannot traverse the
operator's home directory. All stage files, temporary Unix socket paths and
pinned keys are removed by the supervisor afterwards. Guardian and signer
private keys are generated only within their corresponding child processes
and never serialized to disk or passed to the coordinator. The operator
root process and Linux kernel remain trusted.

In this mode the coordinator attempts to read the signer's pinned
configuration and the signer's `/proc/<pid>/mem`; **both must be denied** or
the experiment fails. Every authority RPC independently verifies the *real*
socket peer UID, which is assigned after the child drops privileges.

This is **not** a production multi-tenant isolation design. Linux privilege
separation alone is not kernel/hypervisor isolation, process role hardening,
memory-safety verification or protection against a hostile root operator.

## The actual negative controls

| Attempt | Expected property |
|---|---|
| Exact authorized request | Four signatures → signer checks policy → real verifiable capability |
| Reuse previously consumed challenge | Rejected by independent signer |
| Forge guardian signature | Invalid pinned Ed25519 signature cannot authorize |
| Omit guardian | Four independent approvals required |
| Duplicate guardian | Cannot claim unanimity twice |
| Widen arguments after getting signed approval | Request/challenge binding cannot be swapped |
| Modify claimed policy inside a signed envelope | Signature/policy binding rejects |
| Ask for prohibited network operation | Guardian veto and independent signer policy reject |
| Read signer pin configuration | Rejected in distinct-UID mode |
| Read signer process memory | Rejected in distinct-UID mode |

There are nine scenarios: the positive scenario includes challenge replay,
and the last two are assessed only in distinct-UID mode.

Every attempt runs from an untrusted **coordinator subprocess** that can
connect to guardian/signer services, submit malformed/forged replies, and
request capabilities but cannot use the private-key APIs. No coordinator
RPC accepts a compiled ceiling or private-key parameter; the signer
independently builds the synthetic ceiling from its own pinned fixture.

The experiment's report intentionally contains no private keys or raw
signed capability material. All outcomes are from the local supervisor
and must not be presented as externally witnessed proof of production
containment. This is the groundwork for a physically separated signer,
real attestation verifier, remote authenticated transport, and an
end-to-end malicious-agent KVM run.

`tests/test_isolated_authority_lab.py` runs the same **real subprocess**
campaign rootlessly on CI, and the Python CI job uploads its JSON report.
The CI workflow also explicitly runs the separate-UID mode with `sudo -n`
on its **ephemeral owned Ubuntu runner**, and uploads the distinct-UID
report separately. This is a real Linux UID isolation observation within
GitHub's temporary CI host, **not** an independently administered
production deployment or a KVM/guest-root result. An operator can repeat
the same run locally on a supported Linux machine.

## Security boundaries still missing

- No separate network hosts, independent administrators, HSM/KMS, or
  externally pinned attestation service
- Synthetic guardian attestation only (not a real TPM quote)
- No signed host observation outside the trusted supervisor
- No Firecracker guest; Docker/KVM integration remains a separate run
- The legacy in-process `GuardianQuorum` remains untouched and is NOT
  made compromise tolerant by simply adding this opt-in experiment

Success here proves resistance to the **specific simulated coordinator
attack choices** and validates OS identities in privileged mode. It does
not prove a general impossibility of coordinator or agent compromise.
