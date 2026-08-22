import test from 'node:test';
import assert from 'node:assert/strict';

import {
  canonicalBytes,
  ed25519KeyPairFromSeed,
  exportPrivateKeyPem,
  exportPublicKeyPem,
  keyIdFromPublicKey,
  sha256,
  signDetached,
  verifyDetached,
} from '../packages/crypto/dist/index.js';
import {
  RemoteNoncePersistence,
  RemoteReplayProtocolError,
  RemoteReplayUnavailableError,
  SignedReplayClient,
  Verifier,
  remoteReplayGenesisDigest,
} from '../packages/core/dist/index.js';
import { SimulatorProver } from '../packages/simulator/dist/index.js';

const fixedNow = Date.parse('2026-01-01T00:00:00.000Z');
const serviceId = 'event-horizon-replay';
const partition = 'attestation.nonces';

function signedMock() {
  const serverKeys = ed25519KeyPairFromSeed('remote-replay-server');
  const clientKeys = ed25519KeyPairFromSeed('remote-replay-client');
  const clientPublicKey = exportPublicKeyPem(clientKeys.publicKey);
  const serverKeyId = keyIdFromPublicKey(serverKeys.publicKey);
  let checkpoint = 0;
  let checkpointDigest = remoteReplayGenesisDigest(serviceId, 1);
  const records = new Map();

  const transport = async (request) => {
    const unsignedRequest = Object.fromEntries(Object.entries(request).filter(([key]) => key !== 'signature'));
    assert.equal(request.client_key_id, keyIdFromPublicKey(clientKeys.publicKey));
    assert.equal(verifyDetached(canonicalBytes(unsignedRequest), request.signature, clientPublicKey), true);
    assert.equal(request.minimum_checkpoint <= checkpoint, true);
    let accepted;
    let status;
    let result = {};
    if (request.operation === 'nonce-create') {
      const previous = records.get(request.payload.nonce);
      if (previous) {
        accepted = false;
        status = 'already-exists';
      } else {
        const record = {
          nonce: request.payload.nonce,
          context: request.payload.context,
          contextDigest: request.payload.context_digest,
          issuedAt: request.payload.issued_at,
          expiresAt: request.payload.expires_at,
          state: 'issued',
        };
        records.set(record.nonce, record);
        accepted = true;
        status = 'created';
      }
    } else if (request.operation === 'nonce-consume') {
      const record = records.get(request.payload.nonce);
      if (!record) {
        accepted = false;
        status = 'unknown';
      } else if (record.state === 'consumed') {
        accepted = false;
        status = 'consumed';
        result = { record };
      } else if (request.payload.now >= record.expiresAt) {
        record.state = 'expired';
        accepted = false;
        status = 'expired';
        result = { record };
      } else if (request.payload.context_digest !== record.contextDigest) {
        accepted = false;
        status = 'wrong-context';
        result = { record };
      } else {
        record.state = 'consumed';
        record.consumedAt = request.payload.now;
        accepted = true;
        status = 'consumed-now';
        result = { record };
      }
    } else {
      const record = records.get(request.payload.nonce);
      accepted = Boolean(record);
      status = record ? 'found' : 'unknown';
      result = record ? { record } : {};
    }
    checkpoint += 1;
    checkpointDigest = sha256(canonicalBytes({
      previous: checkpointDigest,
      checkpoint,
      request_digest: sha256(canonicalBytes(request)),
    }));
    const unsignedResponse = {
      schema: 'event-horizon.replay-response.v2',
      algorithm: 'Ed25519',
      service_id: serviceId,
      server_key_id: serverKeyId,
      epoch: 1,
      checkpoint,
      checkpoint_digest: checkpointDigest,
      request_id: request.request_id,
      request_digest: sha256(canonicalBytes(request)),
      accepted,
      status,
      result,
      responded_at: fixedNow,
    };
    return {
      ...unsignedResponse,
      signature: signDetached(canonicalBytes(unsignedResponse), serverKeys.privateKey),
    };
  };

  const client = new SignedReplayClient({
    serviceId,
    clientPrivateKeyPem: exportPrivateKeyPem(clientKeys.privateKey),
    serverPublicKeyPem: exportPublicKeyPem(serverKeys.publicKey),
    epoch: 1,
    transport,
    now: () => fixedNow,
  });
  return { client, serverKeys, transport };
}

test('remote nonce persistence drives end-to-end attestation verification', async () => {
  const remote = signedMock();
  const deviceId = 'remote-nonce-device';
  const prover = new SimulatorProver({
    deviceId,
    seed: 'remote-nonce-prover',
    now: () => new Date(fixedNow),
  });
  const verifier = new Verifier({
    deviceKeys: { [deviceId]: prover.publicKeyPem },
    noncePersistence: new RemoteNoncePersistence(remote.client, partition),
    now: () => new Date(fixedNow),
  });
  const context = {
    deviceId,
    executorId: 'remote-executor',
    sessionId: 'remote-session',
    purpose: 'executor-attestation',
  };
  const nonce = await verifier.nonceAuthority.issue(context);
  const bundle = await prover.prove({ nonce });
  assert.equal((await verifier.verify(bundle, { nonce, context })).valid, true);
  const replay = await verifier.verify(bundle, { nonce, context });
  assert.equal(replay.valid, false);
  assert.equal(!replay.valid && replay.failureCode, 'PROOF_REPLAY');
  assert.equal((await verifier.nonceAuthority.inspect(nonce))?.state, 'consumed');
});

test('remote response forgery fails closed before nonce authorization', async () => {
  const remote = signedMock();
  const forgedClient = new SignedReplayClient({
    serviceId,
    clientPrivateKeyPem: exportPrivateKeyPem(ed25519KeyPairFromSeed('remote-replay-client').privateKey),
    serverPublicKeyPem: exportPublicKeyPem(remote.serverKeys.publicKey),
    epoch: 1,
    now: () => fixedNow,
    transport: async (request) => {
      const response = await remote.transport(request);
      return { ...response, accepted: !response.accepted };
    },
  });
  const persistence = new RemoteNoncePersistence(forgedClient, partition);
  const record = {
    nonce: Buffer.alloc(32).toString('base64url'),
    context: {
      deviceId: 'device',
      executorId: 'executor',
      sessionId: 'session',
      purpose: 'purpose',
    },
    contextDigest: sha256(canonicalBytes({
      deviceId: 'device',
      executorId: 'executor',
      sessionId: 'session',
      purpose: 'purpose',
    })),
    issuedAt: fixedNow,
    expiresAt: fixedNow + 10_000,
    state: 'issued',
  };
  await assert.rejects(() => persistence.createIssued(record), RemoteReplayProtocolError);
});

test('remote replay outage and stale epoch fail closed', async () => {
  const keys = ed25519KeyPairFromSeed('outage-client');
  const server = ed25519KeyPairFromSeed('outage-server');
  const outage = new SignedReplayClient({
    serviceId,
    clientPrivateKeyPem: exportPrivateKeyPem(keys.privateKey),
    serverPublicKeyPem: exportPublicKeyPem(server.publicKey),
    epoch: 1,
    transport: async () => { throw new Error('offline'); },
    now: () => fixedNow,
  });
  await assert.rejects(
    () => outage.call('nonce-inspect', partition, { nonce: Buffer.alloc(32).toString('base64url'), now: fixedNow }),
    RemoteReplayUnavailableError,
  );

  const remote = signedMock();
  await remote.client.adoptEpoch(2, 0, remoteReplayGenesisDigest(serviceId, 2));
  await assert.rejects(
    () => remote.client.call('nonce-inspect', partition, {
      nonce: Buffer.alloc(32).toString('base64url'),
      now: fixedNow,
    }),
    /stale epoch/,
  );

  const fork = signedMock();
  const continuityClient = new SignedReplayClient({
    serviceId,
    clientPrivateKeyPem: exportPrivateKeyPem(ed25519KeyPairFromSeed('remote-replay-client').privateKey),
    serverPublicKeyPem: exportPublicKeyPem(fork.serverKeys.publicKey),
    epoch: 1,
    now: () => fixedNow,
    transport: async (request) => {
      const unsigned = {
        schema: 'event-horizon.replay-response.v2',
        algorithm: 'Ed25519',
        service_id: serviceId,
        server_key_id: keyIdFromPublicKey(fork.serverKeys.publicKey),
        epoch: 1,
        checkpoint: 5,
        checkpoint_digest: 'a'.repeat(64),
        request_id: request.request_id,
        request_digest: sha256(canonicalBytes(request)),
        accepted: false,
        status: 'checkpoint-mismatch',
        result: { reason: 'fork' },
        responded_at: fixedNow,
      };
      return {
        ...unsigned,
        signature: signDetached(canonicalBytes(unsigned), fork.serverKeys.privateKey),
      };
    },
  });
  await assert.rejects(
    () => continuityClient.call('nonce-inspect', partition, {
      nonce: Buffer.alloc(32).toString('base64url'),
      now: fixedNow,
    }),
    /continuity/,
  );
  assert.equal(continuityClient.checkpoint, 0);
});
