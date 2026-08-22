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
} from '../packages/crypto/dist/index.js';
import {
  RemoteReplayProtocolError,
  RemoteReplayUnavailableError,
  SignedReplayClient,
  remoteReplayGenesisDigest,
} from '../packages/core/dist/index.js';

const serviceId = 'event-horizon-replay';
const partition = 'attestation.nonces';
const fixedNow = Date.parse('2026-01-01T00:00:00.000Z');
const nonce = Buffer.alloc(32).toString('base64url');

function clientFixture(options = {}) {
  const clientKeys = ed25519KeyPairFromSeed('state-client');
  const serverKeys = options.serverKeys ?? ed25519KeyPairFromSeed('state-server-1');
  const client = new SignedReplayClient({
    serviceId,
    clientPrivateKeyPem: exportPrivateKeyPem(clientKeys.privateKey),
    serverPublicKeyPem: exportPublicKeyPem(serverKeys.publicKey),
    epoch: options.epoch ?? 1,
    transport: options.transport ?? (async () => { throw new Error('transport not configured'); }),
    checkpoint: options.checkpoint,
    checkpointDigest: options.checkpointDigest,
    now: () => fixedNow,
  });
  return { client, clientKeys, serverKeys };
}

function signedResponse(request, serverKeys, epoch, checkpoint, checkpointDigest) {
  const unsigned = {
    schema: 'event-horizon.replay-response.v2',
    algorithm: 'Ed25519',
    service_id: serviceId,
    server_key_id: keyIdFromPublicKey(serverKeys.publicKey),
    epoch,
    checkpoint,
    checkpoint_digest: checkpointDigest,
    request_id: request.request_id,
    request_digest: sha256(canonicalBytes(request)),
    accepted: false,
    status: 'unknown',
    result: {},
    responded_at: fixedNow,
  };
  return {
    ...unsigned,
    signature: signDetached(canonicalBytes(unsigned), serverKeys.privateKey),
  };
}

function inspect(client) {
  return client.call('nonce-inspect', partition, { nonce, now: fixedNow });
}

test('constructor normalizes only valid genesis and restored checkpoint combinations', () => {
  const genesis = remoteReplayGenesisDigest(serviceId, 1);
  assert.equal(clientFixture().client.checkpointDigest, genesis);
  assert.equal(clientFixture({ checkpoint: 0, checkpointDigest: genesis }).client.checkpoint, 0);
  assert.equal(clientFixture({ checkpoint: 7, checkpointDigest: 'a'.repeat(64) }).client.checkpoint, 7);

  const invalid = [
    { checkpoint: -1 },
    { checkpoint: 1.5 },
    { checkpoint: Number.MAX_SAFE_INTEGER + 1 },
    { checkpoint: 1 },
    { checkpoint: 1, checkpointDigest: 'short' },
    { checkpoint: 0, checkpointDigest: 'b'.repeat(64) },
  ];
  for (const options of invalid) {
    assert.throws(() => clientFixture(options), RemoteReplayProtocolError);
  }
});

test('epoch adoption waits for an in-flight operation and gates later calls', async () => {
  const oldServer = ed25519KeyPairFromSeed('state-server-1');
  const newServer = ed25519KeyPairFromSeed('state-server-2');
  let releaseOld;
  let oldRequest;
  let oldStarted;
  const started = new Promise((resolve) => { oldStarted = resolve; });
  const oldTransport = async (request) => {
    oldRequest = request;
    oldStarted();
    return await new Promise((resolve) => { releaseOld = resolve; });
  };
  const newRequests = [];
  const newTransport = async (request) => {
    newRequests.push(request);
    return signedResponse(request, newServer, 2, 2, 'b'.repeat(64));
  };
  const { client } = clientFixture({ serverKeys: oldServer, transport: oldTransport });
  const originalOperation = inspect(client);
  await started;
  const adoption = client.adoptEpoch(
    2,
    1,
    'a'.repeat(64),
    exportPublicKeyPem(newServer.publicKey),
    newTransport,
  );
  const laterOperation = inspect(client);
  await Promise.resolve();
  assert.equal(client.epoch, 1);
  assert.equal(newRequests.length, 0);

  releaseOld(signedResponse(oldRequest, oldServer, 1, 1, 'a'.repeat(64)));
  await originalOperation;
  await adoption;
  const laterResult = await laterOperation;
  assert.equal(laterResult.epoch, 2);
  assert.equal(newRequests.length, 1);
  assert.equal(newRequests[0].expected_epoch, 2);
  assert.equal(newRequests[0].minimum_checkpoint, 1);
  assert.equal(newRequests[0].minimum_checkpoint_digest, 'a'.repeat(64));
  assert.equal(client.serverKeyId, keyIdFromPublicKey(newServer.publicKey));
  assert.equal(client.checkpoint, 2);
});

test('failed adoption leaves epoch, key, checkpoint, digest, and transport unchanged', async () => {
  const requests = [];
  const fixture = clientFixture({
    transport: async (request) => {
      requests.push(request);
      return signedResponse(request, fixture.serverKeys, 1, 1, 'a'.repeat(64));
    },
  });
  const original = {
    epoch: fixture.client.epoch,
    checkpoint: fixture.client.checkpoint,
    digest: fixture.client.checkpointDigest,
    keyId: fixture.client.serverKeyId,
  };

  const assertOriginalState = () => {
    assert.deepEqual(
      {
        epoch: fixture.client.epoch,
        checkpoint: fixture.client.checkpoint,
        digest: fixture.client.checkpointDigest,
        keyId: fixture.client.serverKeyId,
      },
      original,
    );
  };

  await assert.rejects(
    () => fixture.client.adoptEpoch(2, 1, 'b'.repeat(64), 'not a public key'),
  );
  assertOriginalState();

  const replacementServer = ed25519KeyPairFromSeed('invalid-transport-server');
  await assert.rejects(
    () => fixture.client.adoptEpoch(
      2,
      1,
      'b'.repeat(64),
      exportPublicKeyPem(replacementServer.publicKey),
      42,
    ),
    TypeError,
  );
  assertOriginalState();

  await inspect(fixture.client);
  assert.equal(requests.length, 1);
});

test('rejected queued remote operation does not poison later queue entries', async () => {
  const serverKeys = ed25519KeyPairFromSeed('state-server-1');
  let calls = 0;
  const { client } = clientFixture({
    serverKeys,
    transport: async (request) => {
      calls += 1;
      if (calls === 1) throw new Error('temporary outage');
      return signedResponse(request, serverKeys, 1, 1, 'a'.repeat(64));
    },
  });
  const failed = inspect(client);
  const succeeding = inspect(client);
  await assert.rejects(() => failed, RemoteReplayUnavailableError);
  assert.equal((await succeeding).checkpoint, 1);
  assert.equal(calls, 2);
});

test('two adoptions execute in invocation order', async () => {
  const server2 = ed25519KeyPairFromSeed('state-server-2');
  const server3 = ed25519KeyPairFromSeed('state-server-3');
  const { client } = clientFixture();
  const second = client.adoptEpoch(
    2,
    0,
    remoteReplayGenesisDigest(serviceId, 2),
    exportPublicKeyPem(server2.publicKey),
  );
  const third = client.adoptEpoch(
    3,
    0,
    remoteReplayGenesisDigest(serviceId, 3),
    exportPublicKeyPem(server3.publicKey),
  );
  await Promise.all([second, third]);
  assert.equal(client.epoch, 3);
  assert.equal(client.checkpointDigest, remoteReplayGenesisDigest(serviceId, 3));
  assert.equal(client.serverKeyId, keyIdFromPublicKey(server3.publicKey));
});

test('adoption applies the same checkpoint-state validation as construction', async () => {
  const invalid = [
    [-1, undefined],
    [1.5, undefined],
    [Number.MAX_SAFE_INTEGER + 1, undefined],
    [1, undefined],
    [1, 'short'],
    [0, 'c'.repeat(64)],
  ];
  for (const [checkpoint, digest] of invalid) {
    const { client } = clientFixture();
    const originalDigest = client.checkpointDigest;
    await assert.rejects(
      () => client.adoptEpoch(2, checkpoint, digest),
      RemoteReplayProtocolError,
    );
    assert.equal(client.epoch, 1);
    assert.equal(client.checkpoint, 0);
    assert.equal(client.checkpointDigest, originalDigest);
  }

  const genesisClient = clientFixture().client;
  await genesisClient.adoptEpoch(2, 0);
  assert.equal(genesisClient.checkpointDigest, remoteReplayGenesisDigest(serviceId, 2));

  const restoredClient = clientFixture().client;
  await restoredClient.adoptEpoch(2, 4, 'd'.repeat(64));
  assert.equal(restoredClient.checkpoint, 4);
  assert.equal(restoredClient.checkpointDigest, 'd'.repeat(64));
});
