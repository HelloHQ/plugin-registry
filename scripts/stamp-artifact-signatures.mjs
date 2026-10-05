#!/usr/bin/env node
// Write publisher signatures into a manifest's `signatures[]` (SA5).
//
// Run by the private signing pipeline after it has signed the manifest's
// artifact statement (scripts/artifact-statement.mjs) with BOTH keys. It
// replaces the whole `signatures[]` (a re-sign never keeps a stale entry) and
// refuses anything short of one Ed25519 and one ML-DSA-65 signature, so a
// half-signed manifest is never written.
//
//   node scripts/stamp-artifact-signatures.mjs plugins/<id>/manifest.json \
//     --sig ed25519:<key_id>:<raw signature file> \
//     --sig ml-dsa-65:<key_id>:<raw signature file>
//
// Rebuild index.json afterwards: the manifest bytes, and so its pin, change.
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export const REQUIRED_SIG_ALGS = ['ed25519', 'ml-dsa-65'];

/** [manifest] with `signatures` set from [sigs] ({sig_alg, key_id, bytes}). */
export function stampSignatures(manifest, sigs) {
  const algs = sigs.map((s) => s.sig_alg).sort();
  if (JSON.stringify(algs) !== JSON.stringify([...REQUIRED_SIG_ALGS].sort())) {
    throw new Error(
      `need exactly one signature per algorithm (${REQUIRED_SIG_ALGS.join(', ')}); got ${algs.join(', ') || 'none'}`,
    );
  }
  for (const s of sigs) {
    if (!/^[A-Za-z0-9._-]+$/.test(s.key_id)) {
      throw new Error(`bad key_id for ${s.sig_alg}`);
    }
    if (!s.bytes || s.bytes.length === 0) {
      throw new Error(`empty ${s.sig_alg} signature`);
    }
  }
  const { signatures: _old, ...rest } = manifest;
  return {
    ...rest,
    signatures: REQUIRED_SIG_ALGS.map((alg) => {
      const s = sigs.find((x) => x.sig_alg === alg);
      return {
        key_id: s.key_id,
        sig_alg: alg,
        signature: Buffer.from(s.bytes).toString('base64'),
      };
    }),
  };
}

/** [manifest] with the author certificate pair from a certs/<id>.json body. */
export function stampAuthorCert(manifest, certBody) {
  if (typeof certBody?.author_cert !== 'string' || !Array.isArray(certBody?.author_cert_sig?.signatures)) {
    throw new Error('not a certs/<id>.json body (needs author_cert and author_cert_sig.signatures)');
  }
  return { ...manifest, author_cert: certBody.author_cert, author_cert_sig: certBody.author_cert_sig };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [path, ...args] = process.argv.slice(2);
  const sigs = [];
  let certPath;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--cert' && args[i + 1]) {
      certPath = args[++i];
      continue;
    }
    if (args[i] !== '--sig' || !args[i + 1]) {
      console.error('usage: stamp-artifact-signatures.mjs <manifest> --sig <alg>:<key_id>:<file> ... [--cert certs/<id>.json]');
      process.exit(2);
    }
    const [sig_alg, key_id, file] = args[++i].split(':');
    sigs.push({ sig_alg, key_id, bytes: readFileSync(file) });
  }
  let manifest = stampSignatures(JSON.parse(readFileSync(path, 'utf8')), sigs);
  if (certPath) manifest = stampAuthorCert(manifest, JSON.parse(readFileSync(certPath, 'utf8')));
  writeFileSync(path, JSON.stringify(manifest, null, 2) + '\n');
  console.log(`stamped ${sigs.length} signature(s)${certPath ? ' and the author certificate' : ''} into ${path}`);
}
