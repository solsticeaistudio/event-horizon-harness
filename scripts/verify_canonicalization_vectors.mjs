import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

import {
  canonicalBytes,
  canonicalize,
  sha256,
} from '../attestation/packages/crypto/dist/index.js';

const vectorPath = resolve(process.argv[2] ?? 'test-vectors/canonicalization/adversarial.json');
const jsonOutput = process.argv.includes('--json');
const fixture = JSON.parse(await readFile(vectorPath, 'utf8'));

function construct(specification) {
  switch (specification.kind) {
    case 'literal':
      return specification.value;
    case 'repeat-string':
      return specification.text.repeat(specification.count);
    case 'array':
      return Array(specification.count).fill(0);
    case 'object':
      return Object.fromEntries(
        Array.from({ length: specification.count }, (_, index) => [
          `key-${index.toString().padStart(3, '0')}`,
          index,
        ]),
      );
    case 'nested-array': {
      let value = 0;
      for (let index = 0; index < specification.levels; index += 1) value = [value];
      return value;
    }
    case 'float':
      return Number(specification.value);
    case 'non-finite':
      return { Infinity, '-Infinity': -Infinity, NaN }[specification.value];
    case 'integer':
      return Number(specification.value);
    case 'cycle': {
      const value = [];
      value.push(value);
      return value;
    }
    case 'strict-canonical-json': {
      const value = JSON.parse(specification.value);
      if (canonicalize(value) !== specification.value) {
        throw new TypeError('JSON input is not in canonical form');
      }
      return value;
    }
    default:
      throw new TypeError(`unknown vector construction: ${specification.kind}`);
  }
}

const results = {};
for (const vector of fixture.vectors) {
  let result;
  try {
    const value = construct(vector.construction);
    const encoded = canonicalBytes(value);
    result = {
      accepted: true,
      canonical: encoded.toString('utf8'),
      digest: sha256(encoded),
    };
  } catch {
    result = { accepted: false, canonical: null, digest: null };
  }
  const expected = vector.expected === 'ACCEPT';
  if (result.accepted !== expected) {
    throw new Error(
      `TypeScript ${vector.name} expected ${vector.expected} but observed ${result.accepted ? 'ACCEPT' : 'REJECT'}`,
    );
  }
  results[vector.name] = result;
}

if (jsonOutput) process.stdout.write(JSON.stringify(results));
else console.log(`TypeScript canonicalization vectors: VERIFIED (${Object.keys(results).length} vectors)`);
