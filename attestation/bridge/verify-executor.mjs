#!/usr/bin/env node
import { SimulatorProver } from '../packages/simulator/dist/index.js';
import { SqliteNoncePersistence, Verifier } from '../packages/core/dist/index.js';
import { configureRemoteNoncePersistence } from './remote-replay-http.mjs';

const deviceId = process.argv[2];
const seed = process.argv[3];
const sessionId = process.argv[4];
const purpose = process.argv[5];
if (!deviceId || !seed || !sessionId || !purpose) {
  console.error('usage: verify-executor.mjs <device-id> <seed> <session-id> <purpose>');
  process.exit(2);
}

const prover = new SimulatorProver({ deviceId, seed });
if (process.env.EH_ATTESTATION_REMOTE_REPLAY_CONFIG && process.env.EH_ATTESTATION_REPLAY_DB) {
  throw new Error('remote nonce authority cannot fall back to local SQLite');
}
const remoteAuthority = process.env.EH_ATTESTATION_REMOTE_REPLAY_CONFIG
  ? configureRemoteNoncePersistence(process.env.EH_ATTESTATION_REMOTE_REPLAY_CONFIG)
  : undefined;
const noncePersistence = remoteAuthority?.persistence ?? (process.env.EH_ATTESTATION_REPLAY_DB
  ? new SqliteNoncePersistence(
    process.env.EH_ATTESTATION_REPLAY_DB,
    process.env.EH_ATTESTATION_REPLAY_NAMESPACE ?? 'event-horizon',
  )
  : undefined);
const verifier = new Verifier({
  minTrustLevel: 'simulated',
  maxProofAgeSeconds: 30,
  deviceKeys: { [deviceId]: prover.publicKeyPem },
  pcrPolicy: { executor: { type: 'exact', value: prover.measurements.executor } },
  noncePersistence,
});
const context = { deviceId, executorId: deviceId, sessionId, purpose };
try {
  const nonce = await verifier.nonceAuthority.issue(context);
  const bundle = await prover.prove({ nonce });
  const result = await verifier.verify(bundle, { nonce, context });
  // Never hand verification success to the signer if a trusted checkpoint
  // could not be durably persisted.
  remoteAuthority?.persistCheckpoint();
  console.log(JSON.stringify(result));
  if (!result.valid) process.exitCode = 1;
} finally {
  if (noncePersistence?.close) noncePersistence.close();
}
