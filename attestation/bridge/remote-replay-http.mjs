// Trusted Node bridge to the existing signed replay HTTP authority.
// No etcd credentials and no local nonce fallback in remote mode.
import { readFileSync, writeFileSync, renameSync, unlinkSync, openSync, fsyncSync, closeSync, statSync } from 'node:fs';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { basename, dirname, join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { canonicalBytes } from '../packages/crypto/dist/index.js';
import { SignedReplayClient, RemoteNoncePersistence } from '../packages/core/dist/index.js';

const MAX_RESPONSE = 65_536;
const ROOT_FIELDS = [
  'url', 'service_id', 'epoch', 'server_public_key_pem',
  'client_seed_path', 'client_private_key_pem_path', 'checkpoint_state_path',
  'ca_cert_path', 'client_cert_path', 'client_key_path',
];

function exactKeys(obj, fields) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)
      || JSON.stringify(Object.keys(obj).sort()) !== JSON.stringify([...fields].sort())) {
    throw new Error('remote nonce client config fields are invalid');
  }
}
function strictFile(path) {
  const stat = statSync(path, { throwIfNoEntry: false });
  if (!stat || !stat.isFile() || stat.isSymbolicLink()) throw new Error('remote nonce file missing or unsafe');
  if (process.platform !== 'win32' && (stat.mode & 0o077) !== 0) {
    throw new Error('remote nonce key or checkpoint file permissions are unsafe');
  }
  return readFileSync(path, 'utf8');
}
function atomicState(path, data) {
  const temp = join(dirname(path), '.nonce-' + randomBytes(8).toString('hex'));
  try {
    writeFileSync(temp, canonicalBytes(data), { mode: 0o600, flag: 'wx' });
    const fd = openSync(temp, 'r');
    try { fsyncSync(fd); } finally { closeSync(fd); }
    renameSync(temp, path);
    if (process.platform !== 'win32') {
      const dir = openSync(dirname(path), 'r');
      try { fsyncSync(dir); } finally { closeSync(dir); }
    }
  } finally {
    try { unlinkSync(temp); } catch (err) { if (err.code !== 'ENOENT') throw err; }
  }
}

export function configureRemoteNoncePersistence(configPath) {
  const config = JSON.parse(strictFile(configPath));
  exactKeys(config, ROOT_FIELDS);
  const endpoint = new URL(config.url);
  if (endpoint.pathname !== '/v1/transition' || endpoint.search || endpoint.hash
      || endpoint.username || endpoint.password) {
    throw new Error('signed replay HTTP endpoint is invalid');
  }
  const localhost = ['127.0.0.1', '[::1]', 'localhost'].includes(endpoint.hostname);
  if (endpoint.protocol === 'http:') {
    if (!localhost || config.ca_cert_path || config.client_cert_path || config.client_key_path) {
      throw new Error('plaintext replay only permitted on loopback');
    }
  } else if (endpoint.protocol !== 'https:' || !config.ca_cert_path
      || !config.client_cert_path || !config.client_key_path) {
    throw new Error('remote replay requires mTLS');
  }
  const privateKey = strictFile(config.client_private_key_pem_path);
  const tls = endpoint.protocol === 'https:' ? {
    ca: readFileSync(config.ca_cert_path),
    cert: readFileSync(config.client_cert_path),
    key: readFileSync(config.client_key_path),
    rejectUnauthorized: true,
  } : {};
  const transport = (signedRequest) => new Promise((resolve, reject) => {
    const bytes = canonicalBytes(signedRequest);
    const sender = endpoint.protocol === 'https:' ? httpsRequest : httpRequest;
    const req = sender(endpoint, {
      method: 'POST', ...tls,
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Content-Length': String(bytes.length),
      },
      timeout: 4000,
    }, (response) => {
      if (response.statusCode !== 200) {
        response.resume();
        reject(new Error('replay authority HTTP status denied'));
        return;
      }
      const parts = [];
      let total = 0;
      response.on('data', (part) => {
        total += part.length;
        if (total > MAX_RESPONSE) {
          req.destroy(new Error('signed replay response exceeds size limit'));
          return;
        }
        parts.push(part);
      });
      response.on('end', () => {
        try { resolve(JSON.parse(Buffer.concat(parts).toString('utf8'))); }
        catch (err) { reject(err); }
      });
      response.on('error', reject);
    });
    req.on('timeout', () => req.destroy(new Error('signed replay request timeout')));
    req.on('error', reject);
    req.end(bytes);
  });
  const statePath = config.checkpoint_state_path;
  let checkpoint = 0;
  let checkpointDigest;
  let previous = null;
  try { previous = JSON.parse(strictFile(statePath)); }
  catch (err) { if (err.code !== 'ENOENT') throw err; }
  if (previous !== null) {
    exactKeys(previous, ['service_id', 'epoch', 'server_key_id', 'checkpoint', 'checkpoint_digest']);
    if (previous.service_id !== config.service_id || previous.epoch !== config.epoch) {
      throw new Error('remote nonce checkpoint identity mismatch');
    }
    checkpoint = previous.checkpoint;
    checkpointDigest = previous.checkpoint_digest;
  }
  const client = new SignedReplayClient({
    serviceId: config.service_id,
    clientPrivateKeyPem: privateKey,
    serverPublicKeyPem: config.server_public_key_pem,
    epoch: config.epoch,
    transport,
    checkpoint,
    checkpointDigest,
  });
  if (previous !== null && previous.server_key_id !== client.serverKeyId) {
    throw new Error('remote nonce server identity changed');
  }
  return {
    persistence: new RemoteNoncePersistence(client, 'attestation.nonces'),
    persistCheckpoint() {
      atomicState(statePath, {
        service_id: client.serviceId,
        epoch: client.epoch,
        server_key_id: client.serverKeyId,
        checkpoint: client.checkpoint,
        checkpoint_digest: client.checkpointDigest,
      });
    },
  };
}
