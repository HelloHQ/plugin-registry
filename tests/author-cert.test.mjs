// Tests for author enrollment, certificate bytes, validity and stamping.
//   node --test tests/*.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  authorsNeedingCert,
  buildCert,
  certMatchesAuthor,
  enrollmentProblems,
  enrollmentStatement,
  validAuthorCertIds,
} from '../scripts/author-cert.mjs';
import { certFile } from '../scripts/stamp-author-cert.mjs';

const rawEd25519 = (publicKey) => publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);

/** A sound enrollment record, with a real Ed25519 proof. */
function enroll(slug = 'acme-labs', overrides = {}) {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const author = {
    slug,
    identity: { oidc_issuer: 'https://github.com', oidc_subject: '4242' },
    public_keys: {
      ed25519: rawEd25519(publicKey).toString('base64'),
      'ml-dsa-65': randomBytes(1952).toString('base64'),
    },
    tier: 'author',
    ...overrides,
  };
  author.proof = { ed25519: sign(null, enrollmentStatement(author), privateKey).toString('base64') };
  return { author, privateKey };
}

const NOW = '2026-10-05T10:00:00Z';
const DAY = 24 * 60 * 60 * 1000;
const plus = (days) => new Date(Date.parse(NOW) + days * DAY).toISOString();

/** A registry checkout with [authors] and certs issued at the given start times. */
function registry(authors, certs = []) {
  const dir = mkdtempSync(join(tmpdir(), 'registry-'));
  mkdirSync(join(dir, 'authors'));
  mkdirSync(join(dir, 'certs'));
  for (const a of authors) writeFileSync(join(dir, 'authors', `${a.slug}.json`), JSON.stringify(a));
  for (const { author, start, days } of certs) {
    const bytes = buildCert(author, { now: start, days });
    const { cert_id, body } = certFile(bytes, [
      { sig_alg: 'ed25519', key_id: 'k1', bytes: Buffer.from('a') },
      { sig_alg: 'ml-dsa-65', key_id: 'k2', bytes: Buffer.from('b') },
    ]);
    writeFileSync(join(dir, 'certs', `${cert_id}.json`), JSON.stringify(body));
  }
  return dir;
}

test('the enrollment statement is seven fixed lines', () => {
  const { author } = enroll();
  const lines = enrollmentStatement(author).toString('utf8').split('\n');
  assert.deepEqual(lines.slice(0, 1), ['hellohq-author-enrollment/v1']);
  assert.deepEqual(
    lines.slice(1).map((l) => l.split('=')[0]),
    ['slug', 'oidc_issuer', 'oidc_subject', 'ed25519', 'ml-dsa-65', 'tier', ''],
  );
});

test('a sound enrollment has no problems', () => {
  assert.deepEqual(enrollmentProblems(enroll().author, { slugFromFile: 'acme-labs' }), []);
});

test('the proof of possession must verify over the exact record', () => {
  const { author } = enroll();
  assert.match(enrollmentProblems({ ...author, identity: { ...author.identity, oidc_subject: '9999' } }).join(), /proof\.ed25519/);
  assert.match(enrollmentProblems({ ...author, slug: 'other-name' }).join(), /proof\.ed25519/);
  const stranger = enroll('acme-labs').author; // someone else's proof
  assert.match(enrollmentProblems({ ...author, proof: stranger.proof }).join(), /proof\.ed25519/);
  assert.match(enrollmentProblems({ ...author, proof: undefined }).join(), /proof\.ed25519/);
});

test('shape problems are named', () => {
  const { author } = enroll();
  assert.match(enrollmentProblems(author, { slugFromFile: 'someone-else' }).join(), /must match the file name/);
  assert.match(enrollmentProblems({ ...author, tier: 'official' }).join(), /tier/);
  assert.match(enrollmentProblems({ ...author, slug: 'A' }).join(), /slug/);
  assert.match(enrollmentProblems({ ...author, identity: { oidc_issuer: 'http://x', oidc_subject: '1' } }).join(), /https/);
  assert.match(enrollmentProblems({ ...author, public_keys: { ...author.public_keys, 'ml-dsa-65': 'AAAA' } }).join(), /1952/);
  assert.match(enrollmentProblems({ ...author, public_keys: { ...author.public_keys, rsa: 'x' } }).join(), /unknown public_keys/);
  assert.match(enrollmentProblems({ ...author, revoked: 'yes' }).join(), /revoked/);
});

test('the certificate is compact JSON in the order the app parses', () => {
  const { author } = enroll();
  const bytes = buildCert(author, { now: NOW, days: 90 });
  const text = bytes.toString('utf8');
  assert.ok(!/\s/.test(text.replace(/"[^"]*"/g, '')), 'no whitespace outside strings');
  assert.deepEqual(Object.keys(JSON.parse(text)), ['cert_id', 'identity', 'public_keys', 'not_before', 'not_after', 'tier']);
  const cert = JSON.parse(text);
  assert.equal(cert.cert_id, 'author-acme-labs-2026-10-05');
  assert.equal(cert.not_before, '2026-10-05T10:00:00Z');
  assert.equal(cert.not_after, '2027-01-03T10:00:00Z');
  assert.deepEqual(cert.identity, author.identity);
  assert.deepEqual(cert.public_keys, author.public_keys);
  assert.equal(cert.tier, 'author');
  assert.deepEqual(buildCert(author, { now: NOW, days: 90 }), bytes, 'deterministic');
});

test('a revoked or unproven author is never issued a certificate', () => {
  const { author } = enroll();
  assert.throws(() => buildCert({ ...author, revoked: true }, { now: NOW }), /revoked/);
  assert.throws(() => buildCert({ ...author, proof: undefined }, { now: NOW }), /proof/);
  assert.throws(() => buildCert(author, { now: 'yesterday' }), /ISO/);
});

test('a cert is listed valid only inside its window and for an unchanged, un-revoked author', () => {
  const { author } = enroll();
  const dir = registry([author], [{ author, start: NOW, days: 90 }]);
  assert.deepEqual(validAuthorCertIds(dir, plus(1)), ['author-acme-labs-2026-10-05']);
  assert.deepEqual(validAuthorCertIds(dir, plus(-1)), [], 'not yet valid');
  assert.deepEqual(validAuthorCertIds(dir, plus(90)), [], 'not_after is exclusive');

  const revoked = registry([{ ...author, revoked: true }], [{ author, start: NOW, days: 90 }]);
  assert.deepEqual(validAuthorCertIds(revoked, plus(1)), [], 'revoking drops the id');

  const rotated = enroll('acme-labs').author; // same slug, new keys
  const afterRotation = registry([rotated], [{ author, start: NOW, days: 90 }]);
  assert.deepEqual(validAuthorCertIds(afterRotation, plus(1)), [], 'new keys void the old cert');

  const removed = registry([], [{ author, start: NOW, days: 90 }]);
  assert.deepEqual(validAuthorCertIds(removed, plus(1)), [], 'removing the enrollment voids it');
});

test('a registry with no authors or certs lists nothing and needs nothing', () => {
  const dir = mkdtempSync(join(tmpdir(), 'registry-'));
  assert.deepEqual(validAuthorCertIds(dir, NOW), []);
  assert.deepEqual(authorsNeedingCert(dir, NOW), []);
});

test('an author is due a cert when none lasts past the renewal margin', () => {
  const { author } = enroll();
  assert.deepEqual(authorsNeedingCert(registry([author]), NOW), ['acme-labs'], 'never issued');
  const fresh = registry([author], [{ author, start: NOW, days: 90 }]);
  assert.deepEqual(authorsNeedingCert(fresh, plus(10)), []);
  assert.deepEqual(authorsNeedingCert(fresh, plus(61)), ['acme-labs'], '29 days left: renew');
  assert.deepEqual(authorsNeedingCert(fresh, plus(95)), ['acme-labs'], 'expired');
});

test('revoked and unproven authors are never due a cert', () => {
  const { author } = enroll();
  assert.deepEqual(authorsNeedingCert(registry([{ ...author, revoked: true }]), NOW), []);
  assert.deepEqual(authorsNeedingCert(registry([{ ...author, proof: undefined }]), NOW), []);
});

test('certMatchesAuthor compares identity and both keys', () => {
  const { author } = enroll();
  const cert = JSON.parse(buildCert(author, { now: NOW }));
  assert.ok(certMatchesAuthor(cert, author));
  assert.ok(!certMatchesAuthor(cert, { ...author, identity: { ...author.identity, oidc_subject: '1' } }));
  assert.ok(!certMatchesAuthor(cert, { ...author, public_keys: { ...author.public_keys, 'ml-dsa-65': randomBytes(1952).toString('base64') } }));
});

test('stamping needs both algorithms and a real cert id', () => {
  const { author } = enroll();
  const bytes = buildCert(author, { now: NOW });
  const ed = { sig_alg: 'ed25519', key_id: 'k1', bytes: Buffer.from('a') };
  const pq = { sig_alg: 'ml-dsa-65', key_id: 'k2', bytes: Buffer.from('b') };
  assert.throws(() => certFile(bytes, [ed]), /exactly one signature per algorithm/);
  assert.throws(() => certFile(bytes, [ed, ed]), /exactly one signature per algorithm/);
  assert.throws(() => certFile(bytes, [ed, { ...pq, bytes: Buffer.alloc(0) }]), /empty/);
  assert.throws(() => certFile(bytes, [ed, { ...pq, key_id: 'a b' }]), /key_id/);
  assert.throws(() => certFile(Buffer.from('{"cert_id":"../x"}'), [ed, pq]), /cert_id/);
  const { cert_id, body } = certFile(bytes, [pq, ed]);
  assert.equal(cert_id, 'author-acme-labs-2026-10-05');
  assert.equal(Buffer.from(body.author_cert, 'base64').equals(bytes), true, 'the exact bytes are kept');
  assert.deepEqual(body.author_cert_sig.signatures.map((s) => s.sig_alg), ['ed25519', 'ml-dsa-65']);
});

test('check-authors reports problems per file and passes a sound registry', async () => {
  const { authorProblems } = await import('../scripts/check-authors.mjs');
  const { author } = enroll();
  assert.deepEqual(authorProblems(registry([author])), []);
  const bad = registry([{ ...author, tier: 'official' }]);
  assert.match(authorProblems(bad).join('\n'), /^authors\/acme-labs\.json: tier/);
});
