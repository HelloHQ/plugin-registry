// ML-DSA-65 verification (scripts/ml-dsa.mjs) and the Node that CI runs it on.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import {
  ML_DSA_65_PUBLIC_KEY_BYTES,
  ML_DSA_65_SIG_BYTES,
  assertMlDsa65Available,
  verifyMlDsa65,
} from '../scripts/ml-dsa.mjs';

test('this Node verifies ML-DSA-65 (CI must not silently skip it)', () => {
  assert.doesNotThrow(assertMlDsa65Available);
});

test('good, bad and wrong-length signatures; a wrong-size key throws', () => {
  const { publicKey, privateKey } = generateKeyPairSync('ml-dsa-65');
  const raw = publicKey.export({ type: 'spki', format: 'der' }).subarray(-ML_DSA_65_PUBLIC_KEY_BYTES);
  const msg = Buffer.from('statement');
  const sig = sign(null, msg, privateKey);
  assert.equal(sig.length, ML_DSA_65_SIG_BYTES);
  assert.equal(verifyMlDsa65(msg, raw, sig), true);
  assert.equal(verifyMlDsa65(Buffer.from('statemenT'), raw, sig), false);
  const flipped = Buffer.from(sig);
  flipped[0] ^= 1;
  assert.equal(verifyMlDsa65(msg, raw, flipped), false);
  assert.equal(verifyMlDsa65(msg, raw, sig.subarray(1)), false);
  assert.equal(verifyMlDsa65(msg, raw, Buffer.alloc(0)), false);
  const other = generateKeyPairSync('ml-dsa-65').publicKey.export({ type: 'spki', format: 'der' }).subarray(-1952);
  assert.equal(verifyMlDsa65(msg, other, sig), false);
  assert.throws(() => verifyMlDsa65(msg, raw.subarray(1), sig), /1952 bytes/);
});

test('every workflow that runs the signature checks uses Node 24', () => {
  for (const wf of ['validate.yml', 'authors.yml']) {
    const text = readFileSync(new URL(`../.github/workflows/${wf}`, import.meta.url), 'utf8');
    const versions = [...text.matchAll(/node-version:\s*"?([0-9.]+)"?/g)].map((m) => m[1]);
    assert.ok(versions.length > 0, wf);
    for (const v of versions) assert.ok(Number(v.split('.')[0]) >= 24, `${wf} pins node ${v}`);
  }
});
