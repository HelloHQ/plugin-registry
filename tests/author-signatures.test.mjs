// Author-held artifact signatures: the side file, the prefix check, and the stamp.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { artifactStatement } from '../scripts/artifact-statement.mjs';
import { buildCert, enrollmentStatement } from '../scripts/author-cert.mjs';
import {
  ML_DSA_65_SIG_BYTES,
  authorArtifactTargets,
  authorSignatureProblems,
  stampAuthorArtifact,
} from '../scripts/author-signatures.mjs';
import { certFile } from '../scripts/stamp-author-cert.mjs';

const rawEd25519 = (publicKey) => publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
const HASH = 'ab'.repeat(32);
const NOW = '2026-10-05T10:00:00Z';

function enroll(slug, prefixes) {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const author = {
    slug,
    identity: { oidc_issuer: 'https://github.com', oidc_subject: '7' },
    id_prefixes: prefixes,
    public_keys: {
      ed25519: rawEd25519(publicKey).toString('base64'),
      'ml-dsa-65': randomBytes(1952).toString('base64'),
    },
    tier: 'author',
  };
  author.proof = { ed25519: sign(null, enrollmentStatement(author), privateKey).toString('base64') };
  return { author, privateKey };
}

function manifest(id, extra = {}) {
  return {
    id,
    name: 'Example',
    version: '1.0.0',
    trust_tier: 'verified',
    provenance: 'community',
    execution_mode: 'wasm',
    content_hash_sha256: HASH,
    wasm_url: 'https://example.com/plugin.wasm',
    ...extra,
  };
}

function sideFile(manifestObj, privateKey) {
  const pq = Buffer.alloc(ML_DSA_65_SIG_BYTES, 4);
  return {
    signatures: [
      { sig_alg: 'ed25519', signature: sign(null, artifactStatement(manifestObj), privateKey).toString('base64') },
      { sig_alg: 'ml-dsa-65', signature: pq.toString('base64') },
    ],
  };
}

function tree({ author, pluginId, manifestObj, side, cert = false }) {
  const dir = mkdtempSync(join(tmpdir(), 'author-sig-'));
  mkdirSync(join(dir, 'authors'));
  mkdirSync(join(dir, 'certs'));
  mkdirSync(join(dir, 'plugins', pluginId), { recursive: true });
  writeFileSync(join(dir, 'authors', `${author.slug}.json`), JSON.stringify(author));
  const manifestPath = join(dir, 'plugins', pluginId, 'manifest.json');
  writeFileSync(manifestPath, JSON.stringify(manifestObj));
  if (side) writeFileSync(join(dir, 'plugins', pluginId, 'author-signatures.json'), JSON.stringify(side));
  if (cert) {
    const bytes = buildCert(author, { now: NOW });
    const { cert_id, body } = certFile(bytes, [
      { sig_alg: 'ed25519', key_id: 'k1', bytes: Buffer.from('a') },
      { sig_alg: 'ml-dsa-65', key_id: 'k2', bytes: Buffer.from('b') },
    ]);
    writeFileSync(join(dir, 'certs', `${cert_id}.json`), JSON.stringify(body));
  }
  return dir;
}

test('a Verified plugin signed by the author who owns its prefix is sound', () => {
  const { author, privateKey } = enroll('acme', ['com.acme.']);
  const m = manifest('com.acme.widget');
  const dir = tree({ author, pluginId: m.id, manifestObj: m, side: sideFile(m, privateKey) });
  assert.deepEqual(authorSignatureProblems(dir), []);
});

test('the signature is refused when the prefix, the key or the tier does not match', () => {
  const owner = enroll('acme', ['com.acme.']);
  const other = enroll('other', ['com.other.']);
  const m = manifest('com.acme.widget');
  const wrongPrefix = tree({
    author: other.author,
    pluginId: m.id,
    manifestObj: m,
    side: sideFile(m, other.privateKey),
  });
  assert.match(authorSignatureProblems(wrongPrefix).join('\n'), /matched 0/);

  const wrongKey = tree({
    author: owner.author,
    pluginId: m.id,
    manifestObj: m,
    side: sideFile(m, other.privateKey),
  });
  assert.match(authorSignatureProblems(wrongKey).join('\n'), /matched 0/);

  const official = manifest('com.acme.widget', { trust_tier: 'official' });
  const officialDir = tree({
    author: owner.author,
    pluginId: official.id,
    manifestObj: official,
    side: sideFile(official, owner.privateKey),
  });
  assert.match(authorSignatureProblems(officialDir).join('\n'), /only a Verified plugin/);

  const missing = tree({ author: owner.author, pluginId: m.id, manifestObj: m, side: null });
  assert.match(authorSignatureProblems(missing).join('\n'), /needs author-signatures.json/);

  const placeholder = manifest('com.acme.widget', { content_hash_sha256: '0'.repeat(64) });
  const placeholderDir = tree({
    author: owner.author,
    pluginId: placeholder.id,
    manifestObj: placeholder,
    side: sideFile(placeholder, owner.privateKey),
  });
  assert.match(authorSignatureProblems(placeholderDir).join('\n'), /placeholder/);
});

test('an Official plugin without a side file is left alone', () => {
  const { author } = enroll('acme', ['com.acme.']);
  const m = manifest('com.hellohq.hello-world', { trust_tier: 'official', provenance: 'core' });
  const dir = tree({ author, pluginId: m.id, manifestObj: m, side: null });
  assert.deepEqual(authorSignatureProblems(dir), []);
  assert.deepEqual(authorArtifactTargets(dir, NOW), []);
});

test('the signer stamps the author signatures and the current certificate, once', () => {
  const { author, privateKey } = enroll('acme', ['com.acme.']);
  const m = manifest('com.acme.widget');
  const dir = tree({
    author,
    pluginId: m.id,
    manifestObj: m,
    side: sideFile(m, privateKey),
    cert: true,
  });
  const rel = 'plugins/com.acme.widget/manifest.json';
  assert.deepEqual(authorArtifactTargets(dir, NOW), [rel]);
  const stamped = stampAuthorArtifact(dir, rel, NOW);
  assert.deepEqual(stamped.signatures.map((s) => s.sig_alg), ['ed25519', 'ml-dsa-65']);
  assert.equal(stamped.signatures[0].key_id, 'author-acme-ed25519');
  const cert = JSON.parse(Buffer.from(stamped.author_cert, 'base64').toString('utf8'));
  assert.equal(cert.cert_id, 'author-acme-2026-10-05');
  assert.deepEqual(cert.id_prefixes, ['com.acme.']);
  assert.deepEqual(authorArtifactTargets(dir, NOW), [], 'a second plan finds nothing to do');
  const onDisk = JSON.parse(readFileSync(join(dir, rel), 'utf8'));
  assert.equal(onDisk.author_cert, stamped.author_cert);
});

test('without a certificate the manifest stays a stamp target', () => {
  const { author, privateKey } = enroll('acme', ['com.acme.']);
  const m = manifest('com.acme.widget');
  const dir = tree({ author, pluginId: m.id, manifestObj: m, side: sideFile(m, privateKey) });
  assert.deepEqual(authorArtifactTargets(dir, NOW), ['plugins/com.acme.widget/manifest.json']);
  assert.throws(() => stampAuthorArtifact(dir, 'plugins/com.acme.widget/manifest.json', NOW), /no current certificate/);
});
