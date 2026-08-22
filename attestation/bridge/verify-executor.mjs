#!/usr/bin/env node
// Development attestation bridge.
//
// The enrollment seed is delivered over STDIN, never via argv: process
// command lines are world-readable through the OS process listing while
// pipes are not. The payload is a single line: <seed>.
import { SimulatorProver } from '../packages/simulator/dist/index.js';
import { SqliteNoncePersistence, Verifier } from '../packages/core/dist/index.js';

const deviceId = process.argv[2];
const sessionId = process.argv[3];
const purpose = process.argv[4];
if (!deviceId || !sessionId || !purpose) {
  console.error('usage: verify-executor.mjs <device-id> <session-id> <purpose> (seed on stdin)');
  process.exit(2);
}

const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const seed = Buffer.concat(chunks).toString('utf8').trim();
if (!seed) {
  console.error('enrollment seed was not supplied on stdin');
  process.exit(2);
}

const prover = new SimulatorProver({ deviceId, seed });
const noncePersistence = process.env.EH_ATTESTATION_REPLAY_DB
  ? new SqliteNoncePersistence(
    process.env.EH_ATTESTATION_REPLAY_DB,
    process.env.EH_ATTESTATION_REPLAY_NAMESPACE ?? 'event-horizon',
  )
  : undefined;
const verifier = new Verifier({
  minTrustLevel: 'simulated',
  maxProofAgeSeconds: 30,
  deviceKeys: { [deviceId]: prover.publicKeyPem },
  pcrPolicy: { executor: { type: 'exact', value: prover.measurements.executor } },
  noncePersistence,
});
const context = { deviceId, executorId: deviceId, sessionId, purpose };
const nonce = await verifier.nonceAuthority.issue(context);
const bundle = await prover.prove({ nonce });
const result = await verifier.verify(bundle, { nonce, context });
console.log(JSON.stringify(result));
noncePersistence?.close();
if (!result.valid) process.exitCode = 1;
