#!/usr/bin/env node
// Author-held artifact signatures (doc 31 phase 3).
//
// A pull request must not write signatures[] or author_cert. An author who
// holds a hybrid key instead submits plugins/<id>/author-signatures.json:
// Ed25519 and ML-DSA-65 signatures over the artifact statement
// (scripts/artifact-statement.mjs). CI checks the Ed25519 half under an
// enrolled key whose id_prefixes cover the plugin id. Node cannot verify
// ML-DSA-65, so that half is checked for length here and verified by the app.
//
// After merge the signing pipeline copies both signatures onto the manifest
// and attaches the author's current certificate. It does not sign with the
// Official KMS keys.
//
//   node scripts/author-signatures.mjs check [registry dir]
//   node scripts/author-signatures.mjs plan [registry dir] [--now <iso>]
//   node scripts/author-signatures.mjs stamp <manifest> [--now <iso>]
//   node scripts/author-signatures.mjs sign <manifest> \
//     --ed25519-key <pem> --mldsa-key <pem>
import { spawnSync } from 'node:child_process';
import { createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { artifactStatement } from './artifact-statement.mjs';
import {
  certMatchesAuthor,
  enrollmentProblems,
  loadAuthors,
  loadCerts,
  prefixCovers,
} from './author-cert.mjs';
import { stampAuthorCert, stampSignatures } from './stamp-artifact-signatures.mjs';

export const ED25519_SIG_BYTES = 64;
export const ML_DSA_65_SIG_BYTES = 3309;
const PLACEHOLDER_HASH = '0'.repeat(64);
const ED25519_SPKI = Buffer.from('302a300506032b6570032100', 'hex');

const b64 = (s) => Buffer.from(String(s), 'base64');
const isB64 = (s, n) =>
  typeof s === 'string' &&
  /^[A-Za-z0-9+/]+={0,2}$/.test(s) &&
  b64(s).length === n &&
  b64(s).toString('base64') === s;

function ed25519Key(rawB64) {
  return createPublicKey({
    key: Buffer.concat([ED25519_SPKI, b64(rawB64)]),
    format: 'der',
    type: 'spki',
  });
}

/** Parsed {ed25519, mlDsa65} signature strings, or a problem string. */
export function parseAuthorSignatures(body) {
  const sigs = body?.signatures;
  if (!Array.isArray(sigs)) return 'author-signatures.json needs a signatures array';
  const byAlg = Object.fromEntries(sigs.map((s) => [s?.sig_alg, s?.signature]));
  if (Object.keys(byAlg).sort().join() !== 'ed25519,ml-dsa-65' || sigs.length !== 2) {
    return 'author-signatures.json needs exactly one ed25519 and one ml-dsa-65 signature';
  }
  if (!isB64(byAlg.ed25519, ED25519_SIG_BYTES)) return 'ed25519 signature must be 64 bytes, base64';
  if (!isB64(byAlg['ml-dsa-65'], ML_DSA_65_SIG_BYTES)) {
    return `ml-dsa-65 signature must be ${ML_DSA_65_SIG_BYTES} bytes, base64`;
  }
  return { ed25519: byAlg.ed25519, mlDsa65: byAlg['ml-dsa-65'] };
}

function pluginDirs(registryDir) {
  const root = join(registryDir, 'plugins');
  if (!existsSync(root)) return [];
  return readdirSync(root, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => d.name)
    .sort();
}

function loadManifest(registryDir, id) {
  const path = join(registryDir, 'plugins', id, 'manifest.json');
  if (!existsSync(path)) return { path, error: 'missing manifest.json' };
  try {
    return { path, manifest: JSON.parse(readFileSync(path, 'utf8')) };
  } catch {
    return { path, error: 'manifest.json is not valid JSON' };
  }
}

/**
 * The enrolled authors whose prefix covers [pluginId] and whose Ed25519 key
 * verifies [edSig] over [statement]. Revoked or unsound enrollments are skipped.
 */
export function matchingAuthors(authors, pluginId, statement, edSig) {
  const hits = [];
  for (const author of authors) {
    if (author.revoked === true || enrollmentProblems(author).length) continue;
    if (!author.id_prefixes.some((p) => prefixCovers(p, pluginId))) continue;
    try {
      if (verify(null, statement, ed25519Key(author.public_keys.ed25519), b64(edSig))) hits.push(author);
    } catch {
      // A key that cannot be parsed simply does not match.
    }
  }
  return hits;
}

/** Problems with every author-signatures.json, and with a Verified plugin that lacks one. */
export function authorSignatureProblems(registryDir) {
  const authors = loadAuthors(registryDir).map((a) => a.author);
  const out = [];
  for (const id of pluginDirs(registryDir)) {
    const sidePath = join(registryDir, 'plugins', id, 'author-signatures.json');
    const { path, manifest, error } = loadManifest(registryDir, id);
    const rel = `plugins/${id}/manifest.json`;
    const hasSide = existsSync(sidePath);
    if (error) {
      if (hasSide) out.push(`${rel}: ${error}`);
      continue;
    }
    const tier = manifest.trust_tier ?? 'community';
    if (!hasSide) {
      if (tier === 'verified') out.push(`${rel}: a Verified plugin needs author-signatures.json`);
      continue;
    }
    const sideRel = `plugins/${id}/author-signatures.json`;
    if (tier !== 'verified') {
      out.push(`${sideRel}: only a Verified plugin carries author signatures`);
      continue;
    }
    if (manifest.provenance === 'core' || manifest.provenance === 'enterprise') {
      out.push(`${sideRel}: provenance "${manifest.provenance}" is not author-signed`);
      continue;
    }
    if (manifest.id !== id) {
      out.push(`${sideRel}: manifest id "${manifest.id}" does not match the directory`);
      continue;
    }
    if (manifest.content_hash_sha256 === PLACEHOLDER_HASH) {
      out.push(`${sideRel}: content_hash_sha256 is still a placeholder`);
      continue;
    }
    let body;
    try {
      body = JSON.parse(readFileSync(sidePath, 'utf8'));
    } catch {
      out.push(`${sideRel}: not valid JSON`);
      continue;
    }
    const parsed = parseAuthorSignatures(body);
    if (typeof parsed === 'string') {
      out.push(`${sideRel}: ${parsed}`);
      continue;
    }
    let statement;
    try {
      statement = artifactStatement(manifest);
    } catch (e) {
      out.push(`${sideRel}: ${e.message}`);
      continue;
    }
    const hits = matchingAuthors(authors, manifest.id, statement, parsed.ed25519);
    if (hits.length !== 1) {
      out.push(
        `${sideRel}: Ed25519 signature must verify under exactly one enrolled author whose prefix covers ${manifest.id} (matched ${hits.length})`,
      );
    }
  }
  return out;
}

const inWindow = (cert, nowMs) => {
  const nb = Date.parse(cert.not_before);
  const na = Date.parse(cert.not_after);
  return !Number.isNaN(nb) && !Number.isNaN(na) && nowMs >= nb && nowMs < na;
};

/** The matching cert with the latest not_after that is inside its window, if any. */
export function currentAuthorCert(registryDir, author, now) {
  const nowMs = Date.parse(now);
  return loadCerts(registryDir)
    .filter(({ cert }) => certMatchesAuthor(cert, author) && inWindow(cert, nowMs))
    .sort((a, b) => Date.parse(b.cert.not_after) - Date.parse(a.cert.not_after))[0];
}

function alreadyStamped(manifest, author, statement, sigs, certFile) {
  const stamped = Array.isArray(manifest.signatures) ? manifest.signatures : [];
  const ed = stamped.find((s) => s?.sig_alg === 'ed25519');
  const pq = stamped.find((s) => s?.sig_alg === 'ml-dsa-65');
  if (!ed || !pq || pq.signature !== sigs.mlDsa65) return false;
  try {
    if (!verify(null, statement, ed25519Key(author.public_keys.ed25519), b64(ed.signature))) return false;
  } catch {
    return false;
  }
  return manifest.author_cert === certFile.body.author_cert;
}

/**
 * Manifest paths whose author signatures verify but are not yet stamped with
 * the author's current certificate. Throws when the tree has signature problems.
 */
export function authorArtifactTargets(registryDir, now) {
  const problems = authorSignatureProblems(registryDir);
  if (problems.length) throw new Error(problems.join('\n'));
  const authors = loadAuthors(registryDir).map((a) => a.author);
  const targets = [];
  for (const id of pluginDirs(registryDir)) {
    const sidePath = join(registryDir, 'plugins', id, 'author-signatures.json');
    if (!existsSync(sidePath)) continue;
    const { manifest } = loadManifest(registryDir, id);
    const sigs = parseAuthorSignatures(JSON.parse(readFileSync(sidePath, 'utf8')));
    const statement = artifactStatement(manifest);
    const author = matchingAuthors(authors, manifest.id, statement, sigs.ed25519)[0];
    const cert = currentAuthorCert(registryDir, author, now);
    if (cert && alreadyStamped(manifest, author, statement, sigs, { body: JSON.parse(readFileSync(join(registryDir, 'certs', cert.file), 'utf8')) })) {
      continue;
    }
    targets.push(join('plugins', id, 'manifest.json'));
  }
  return targets;
}

/** Write signatures[] and author_cert onto [manifestPath]. Returns the manifest. */
export function stampAuthorArtifact(registryDir, manifestPath, now) {
  const abs = join(registryDir, manifestPath);
  const manifest = JSON.parse(readFileSync(abs, 'utf8'));
  const sidePath = join(dirname(abs), 'author-signatures.json');
  const sigs = parseAuthorSignatures(JSON.parse(readFileSync(sidePath, 'utf8')));
  if (typeof sigs === 'string') throw new Error(sigs);
  const statement = artifactStatement(manifest);
  const authors = loadAuthors(registryDir).map((a) => a.author);
  const hits = matchingAuthors(authors, manifest.id, statement, sigs.ed25519);
  if (hits.length !== 1) throw new Error(`expected one matching author, found ${hits.length}`);
  const author = hits[0];
  const cert = currentAuthorCert(registryDir, author, now);
  if (!cert) throw new Error(`no current certificate for author ${author.slug}`);
  const certBody = JSON.parse(readFileSync(join(registryDir, 'certs', cert.file), 'utf8'));
  const stamped = stampAuthorCert(
    stampSignatures(manifest, [
      { sig_alg: 'ed25519', key_id: `author-${author.slug}-ed25519`, bytes: b64(sigs.ed25519) },
      { sig_alg: 'ml-dsa-65', key_id: `author-${author.slug}-ml-dsa-65`, bytes: b64(sigs.mlDsa65) },
    ]),
    certBody,
  );
  writeFileSync(abs, JSON.stringify(stamped, null, 2) + '\n');
  return stamped;
}

function opensslSign(keyPath, message) {
  const dir = mkdtempSync(join(tmpdir(), 'author-sign-'));
  try {
    const input = join(dir, 'msg');
    const output = join(dir, 'sig');
    writeFileSync(input, message);
    const run = spawnSync(
      'openssl',
      ['pkeyutl', '-sign', '-inkey', keyPath, '-rawin', '-in', input, '-out', output],
      { encoding: 'utf8' },
    );
    if (run.status !== 0) {
      throw new Error((run.stderr || run.stdout || 'openssl sign failed').trim());
    }
    return readFileSync(output);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [cmd, ...rest] = process.argv.slice(2);
  const arg = (name) => {
    const i = rest.indexOf(name);
    return i >= 0 ? rest[i + 1] : undefined;
  };
  const now = arg('--now') ?? new Date().toISOString();
  try {
    if (cmd === 'check') {
      const problems = authorSignatureProblems(rest.find((a) => !a.startsWith('--')) ?? '.');
      for (const p of problems) console.log(p);
      if (problems.length) process.exit(1);
      console.log('author signatures are sound');
    } else if (cmd === 'plan') {
      const dir = rest.find((a) => !a.startsWith('--')) ?? '.';
      for (const t of authorArtifactTargets(dir, now)) console.log(t);
    } else if (cmd === 'stamp') {
      stampAuthorArtifact('.', rest[0], now);
      console.log(`stamped ${rest[0]}`);
    } else if (cmd === 'sign') {
      const manifestPath = rest[0];
      const edKey = arg('--ed25519-key');
      const mldsaKey = arg('--mldsa-key');
      if (!manifestPath || !edKey || !mldsaKey) {
        console.error('usage: author-signatures.mjs sign <manifest> --ed25519-key <pem> --mldsa-key <pem>');
        process.exit(2);
      }
      const statement = artifactStatement(JSON.parse(readFileSync(manifestPath, 'utf8')));
      const ed = sign(null, statement, createPrivateKey(readFileSync(edKey)));
      const pq = opensslSign(mldsaKey, statement);
      const body = {
        signatures: [
          { sig_alg: 'ed25519', signature: ed.toString('base64') },
          { sig_alg: 'ml-dsa-65', signature: pq.toString('base64') },
        ],
      };
      const out = join(dirname(manifestPath), 'author-signatures.json');
      writeFileSync(out, JSON.stringify(body, null, 2) + '\n');
      console.log(`wrote ${out}`);
    } else {
      console.error('usage: author-signatures.mjs check|plan [dir] | stamp <manifest> | sign <manifest> --ed25519-key <pem> --mldsa-key <pem>');
      process.exit(2);
    }
  } catch (e) {
    console.error(e.message);
    process.exit(1);
  }
}
