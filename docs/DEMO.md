# Five-minute demonstration

1. Start a clean Event Horizon run and display the precomputed maximum authority graph.
2. Grant the attacker root-equivalent access inside the hostile cell.
3. Reveal a convincing honey cloud credential and an intentionally vulnerable local service.
4. Permit one exact `object.read` capability and show it succeed once.
5. Replay the capability: denied.
6. Change the arguments: denied.
7. Move it to another session/executor: denied.
8. Request network access or package installation: denied before execution.
9. Delete or rewrite the local audit copy: external chain remains valid; tampered copy fails verification.
10. Destroy the hostile environment and issue a signed Containment Certificate.

The demo obtains the certificate signer's public identity from the signer service and writes it as a separate trusted-key artifact before verification. Verification requires that external key (or an independently pinned key ID); it never promotes the public key embedded in the certificate into a trust root.

Closing line:

> The agent escaped every sandbox we gave it. It never escaped Event Horizon.
