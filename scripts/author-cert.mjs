#!/usr/bin/env node
// Author enrollment and certificate bytes (docs/plugin/25, 27 phase 2).
//
// An author is enrolled by a reviewed PR that adds authors/<slug>.json: their
// OIDC identity, their two public keys, and a proof that they hold the Ed25519
// key. The private signing pipeline then issues a certificate over those facts
// with the registry root keys. This file is the one definition of both byte
// formats; the signer calls it, and tests/fixtures/author-cert-vectors.json
// pins the output.
//
// The certificate is the exact byte string the app parses after verifying it
// (hellohq lib/app/data/model/plugin/plugin_author_cert.dart): compact JSON,
// keys in a fixed order, so signer and verifier never disagree on a re-encode.
//
//   node scripts/author-cert.mjs statement authors/<slug>.json
//   node scripts/author-cert.mjs cert authors/<slug>.json --now <iso> [--days 90]
//   node scripts/author-cert.mjs valid-ids [--now <iso>]
//   node scripts/author-cert.mjs needs-cert [--now <iso>]   # slugs to issue for
import { createPublicKey, verify } from 'node:crypto';
import { existsSync, readdirSync, readFileSync, writeSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const ENROLLMENT_VERSION = 'hellohq-author-enrollment/v1';
export const DEFAULT_LIFETIME_DAYS = 90;
/** Issue a replacement once fewer than this many days remain. */
export const RENEW_BEFORE_DAYS = 30;

const SLUG = /^[a-z][a-z0-9-]{1,38}[a-z0-9]$/;
const DAY_MS = 24 * 60 * 60 * 1000;
// SPKI prefix of a raw 32-byte Ed25519 public key.
const ED25519_SPKI = Buffer.from('302a300506032b6570032100', 'hex');
export const KEY_BYTES = { ed25519: 32, 'ml-dsa-65': 1952 };

const b64 = (s) => Buffer.from(String(s), 'base64');
const isB64 = (s, n) =>
  typeof s === 'string' &&
  /^[A-Za-z0-9+/]+={0,2}$/.test(s) &&
  b64(s).length === n &&
  b64(s).toString('base64') === s;

/** The bytes the author's keys sign to prove they hold them. */
export function enrollmentStatement(author) {
  const line = (name, value) => {
    if (typeof value !== 'string' || /[\r\n]/.test(value)) {
      throw new Error(`enrollment statement: ${name} must be a single-line string`);
    }
    return `${name}=${value}\n`;
  };
  return Buffer.from(
    `${ENROLLMENT_VERSION}\n` +
      line('slug', author.slug) +
      line('oidc_issuer', author.identity?.oidc_issuer) +
      line('oidc_subject', author.identity?.oidc_subject) +
      line('ed25519', author.public_keys?.ed25519) +
      line('ml-dsa-65', author.public_keys?.['ml-dsa-65']) +
      line('tier', author.tier),
    'utf8',
  );
}

/**
 * Problems with an enrollment record ([] when sound). Checks the shape, the key
 * lengths, and the Ed25519 proof of possession. The ML-DSA-65 half cannot be
 * proven here (Node 20/22 have no ML-DSA); that is acceptable because every
 * artifact signature must verify under BOTH keys, so someone who binds another
 * party's ML-DSA key still cannot produce a signature that installs.
 */
export function enrollmentProblems(author, { slugFromFile } = {}) {
  const out = [];
  if (!author || typeof author !== 'object') return ['not an object'];
  if (typeof author.slug !== 'string' || !SLUG.test(author.slug)) out.push('slug must be 3-40 chars of a-z, 0-9, "-"');
  if (slugFromFile != null && author.slug !== slugFromFile) out.push(`slug "${author.slug}" must match the file name "${slugFromFile}"`);
  const id = author.identity;
  for (const f of ['oidc_issuer', 'oidc_subject']) {
    if (typeof id?.[f] !== 'string' || id[f].length === 0 || /[\r\n]/.test(id[f])) out.push(`identity.${f} is required`);
  }
  if (typeof id?.oidc_issuer === 'string' && !/^https:\/\//.test(id.oidc_issuer)) out.push('identity.oidc_issuer must be an https URL');
  if (author.tier !== 'author') out.push('tier must be "author"');
  const keys = author.public_keys ?? {};
  for (const [alg, n] of Object.entries(KEY_BYTES)) {
    if (!isB64(keys[alg], n)) out.push(`public_keys.${alg} must be ${n} bytes, base64`);
  }
  const extra = Object.keys(keys).filter((k) => !(k in KEY_BYTES));
  if (extra.length) out.push(`unknown public_keys: ${extra.join(', ')}`);
  if (author.revoked !== undefined && typeof author.revoked !== 'boolean') out.push('revoked must be a boolean');
  if (out.length) return out;
  try {
    const key = createPublicKey({
      key: Buffer.concat([ED25519_SPKI, b64(keys.ed25519)]),
      format: 'der',
      type: 'spki',
    });
    const sig = author.proof?.ed25519;
    if (!isB64(sig, 64) || !verify(null, enrollmentStatement(author), key, b64(sig))) {
      out.push('proof.ed25519 does not verify over the enrollment statement');
    }
  } catch (e) {
    out.push(`proof check failed: ${e.message}`);
  }
  return out;
}

const iso = (ms) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');

/** `author-<slug>-<yyyy-mm-dd>` of the day the certificate starts. */
export const certIdFor = (slug, notBeforeIso) => `author-${slug}-${notBeforeIso.slice(0, 10)}`;

/** The certificate bytes: compact JSON, fixed key order. */
export function buildCert(author, { now, days = DEFAULT_LIFETIME_DAYS }) {
  const problems = enrollmentProblems(author);
  if (problems.length) throw new Error(`cannot issue: ${problems.join('; ')}`);
  if (author.revoked === true) throw new Error('cannot issue: the author is revoked');
  const start = Date.parse(now);
  if (Number.isNaN(start)) throw new Error('now must be an ISO timestamp');
  const notBefore = iso(start);
  return Buffer.from(
    JSON.stringify({
      cert_id: certIdFor(author.slug, notBefore),
      identity: {
        oidc_issuer: author.identity.oidc_issuer,
        oidc_subject: author.identity.oidc_subject,
      },
      public_keys: {
        ed25519: author.public_keys.ed25519,
        'ml-dsa-65': author.public_keys['ml-dsa-65'],
      },
      not_before: notBefore,
      not_after: iso(start + days * DAY_MS),
      tier: 'author',
    }),
    'utf8',
  );
}

export function loadAuthors(registryDir) {
  const dir = join(registryDir, 'authors');
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((f) => f.endsWith('.json'))
    .sort()
    .map((f) => ({ file: f, author: JSON.parse(readFileSync(join(dir, f), 'utf8')) }));
}

/** Issued certificates in certs/ as { file, cert (parsed), bytes }. */
export function loadCerts(registryDir) {
  const dir = join(registryDir, 'certs');
  if (!existsSync(dir)) return [];
  const out = [];
  for (const f of readdirSync(dir).filter((x) => x.endsWith('.json')).sort()) {
    try {
      const wrapper = JSON.parse(readFileSync(join(dir, f), 'utf8'));
      const bytes = Buffer.from(wrapper.author_cert, 'base64');
      out.push({ file: f, cert: JSON.parse(bytes.toString('utf8')), bytes });
    } catch {
      // A malformed file is never listed as valid.
    }
  }
  return out;
}

const sameKeys = (a, b) =>
  Object.keys(KEY_BYTES).every((alg) => a?.[alg] != null && a[alg] === b?.[alg]);

/** Whether [cert] still binds exactly what an un-revoked enrollment says. */
export function certMatchesAuthor(cert, author) {
  return (
    author.revoked !== true &&
    cert.identity?.oidc_issuer === author.identity.oidc_issuer &&
    cert.identity?.oidc_subject === author.identity.oidc_subject &&
    sameKeys(cert.public_keys, author.public_keys)
  );
}

const inWindow = (cert, nowMs) => {
  const nb = Date.parse(cert.not_before);
  const na = Date.parse(cert.not_after);
  return !Number.isNaN(nb) && !Number.isNaN(na) && nowMs >= nb && nowMs < na;
};

/**
 * The cert ids the index manifest lists as currently valid: in their window and
 * still matching an enrolled, un-revoked author. Revoking an author, or
 * changing their keys, drops the id on the next signing run — no app release.
 */
export function validAuthorCertIds(registryDir, now) {
  const nowMs = Date.parse(now);
  const authors = loadAuthors(registryDir).map((a) => a.author);
  return loadCerts(registryDir)
    .filter(({ cert }) => inWindow(cert, nowMs) && authors.some((a) => certMatchesAuthor(cert, a)))
    .map(({ cert }) => cert.cert_id)
    .sort();
}

/** Slugs of sound, un-revoked authors with no valid cert lasting past the renewal margin. */
export function authorsNeedingCert(registryDir, now) {
  const nowMs = Date.parse(now);
  const certs = loadCerts(registryDir);
  return loadAuthors(registryDir)
    .map((a) => a.author)
    .filter((a) => a.revoked !== true && enrollmentProblems(a).length === 0)
    .filter(
      (a) =>
        !certs.some(
          ({ cert }) =>
            certMatchesAuthor(cert, a) &&
            inWindow(cert, nowMs) &&
            Date.parse(cert.not_after) - nowMs > RENEW_BEFORE_DAYS * DAY_MS,
        ),
    )
    .map((a) => a.slug);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [cmd, ...rest] = process.argv.slice(2);
  const arg = (name, fallback) => {
    const i = rest.indexOf(name);
    return i >= 0 ? rest[i + 1] : fallback;
  };
  const now = arg('--now', new Date().toISOString());
  const readAuthor = (p) => JSON.parse(readFileSync(p, 'utf8'));
  try {
    if (cmd === 'statement') writeSync(1, enrollmentStatement(readAuthor(rest[0])));
    else if (cmd === 'cert') writeSync(1, buildCert(readAuthor(rest[0]), { now, days: Number(arg('--days', DEFAULT_LIFETIME_DAYS)) }));
    else if (cmd === 'valid-ids') console.log(JSON.stringify(validAuthorCertIds('.', now)));
    else if (cmd === 'needs-cert') for (const s of authorsNeedingCert('.', now)) console.log(s);
    else {
      console.error('usage: author-cert.mjs statement|cert <author.json> | valid-ids | needs-cert [--now <iso>]');
      process.exit(2);
    }
  } catch (e) {
    console.error(e.message);
    process.exit(1);
  }
}
