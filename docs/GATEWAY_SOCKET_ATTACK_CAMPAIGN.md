# Trusted host gateway: real Unix-socket adversarial campaign

Run `python scripts/run_gateway_socket_campaign.py --report artifacts/reports/gateway-socket-campaign.json`
on an owned Linux host with the EHH Python test dependencies installed.
No Docker, Firecracker, etcd, root or external target is required.

This campaign starts the **actual** `scripts/linux_effect_service.py` in
its own process with inherited Unix sockets, tests protocol framing and
`SO_PEERCRED`, uses genuine synthetic Ed25519 capabilities and observes
the durable SQLite consumption table independently after termination.
A separate supervisor responds to the real recorder protocol, including
a deliberate refusal of `execution.authorized`. Every experiment has a
fresh, unique temporary authority directory. Only the exact synthetic
`object.read` handler can run, over a non-sensitive static string.

| Scenario | Measured behavior |
|---|---|
| Valid authorization followed by replay | Exactly one completion, exactly one durable capability consumption |
| Changed request arguments | Denied without consuming; subsequent legitimate request succeeds |
| Damaged Ed25519 signature | Denied without consuming; legitimate request succeeds |
| Attempt to select trusted replay backend from guest frame | Denied; no change to host-owned backend |
| Duplicate JSON envelope key | No host effect; invalid transport rejected |
| Frame declares length above ceiling | No host effect or capability consumption |
| Payload ends before declared frame length | No host effect or capability consumption |
| Unix socket peer identity doesn't match trusted configuration | Refused before effect parsing or consumption |
| Evidence recorder refuses pre-effect authorization | No effect; capability burned and replay rejected |

The real process is launched under the same unprivileged test user. The
"wrong UID" case changes the pinned expected UID; it **does not** pretend
to exercise actual Linux privilege separation between two users.
Pre-authorized positive effects are **only in-memory string reads**;
completed event count and returned contents are checked against the
supervisor's fixture and independently inspected replay database.

This is not a Firecracker, vsock VMM, host-kernel, or model-agent exploit
test. The recorder still lives on the same test host, and these results
are not independently witnessed attestation. Passing these deterministic
attack cases cannot demonstrate that unknown bypasses do not exist.
For broader parser mutations run the real [Atheris coverage engine]
(ADVERSARIAL_ASSURANCE_FUZZING.md). Keep both forms of assurance:
the coverage engine explores inputs; this experiment measures real
process/socket/effect-state integration and fail-closed behavior.

CI runs the full campaign on the Python 3.11 runner and uploads a
machine-readable JSON report. If any scenario fails, the command and
unittest fail, leaving the PR blocked. No existing isolation mode or
runtime module is removed.
