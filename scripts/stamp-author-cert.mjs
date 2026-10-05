#!/usr/bin/env node
// Write an issued author certificate to certs/<cert_id>.json.
//
// Run by the private signing pipeline after it has signed the certificate
// bytes (scripts/author-cert.mjs cert) with BOTH registry root keys. Refuses
// anything short of one Ed25519 and one ML-DSA-65 signature, like
// stamp-artifact-signatures.mjs, so a half-signed certificate is never written.
// The file holds exactly what the app reads from a manifest's `author_cert` and
// `author_cert_sig`.
//
//   node scripts/stamp-author-cert.mjs <cert bytes file> \
//     --sig ed25519:<key_id>:<raw signature file> \
//     --sig ml-dsa-65:<key_id>:<raw signature file>
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { REQUIRED_SIG_ALGS } from './stamp-artifact-signatures.mjs';

/** The certs/ file body for [certBytes] and [sigs] ({sig_alg, key_id, bytes}). */
export function certFile(certBytes, sigs) {
  const cert = JSON.parse(Buffer.from(certBytes).toString('utf8'));
  if (typeof cert.cert_id !== 'string' || !/^author-[a-z0-9-]+-\d{4}-\d{2}-\d{2}$/.test(cert.cert_id)) {
    throw new Error('certificate has no valid cert_id');
  }
  const algs = sigs.map((s) => s.sig_alg).sort();
  if (JSON.stringify(algs) !== JSON.stringify([...REQUIRED_SIG_ALGS].sort())) {
    throw new Error(`need exactly one signature per algorithm (${REQUIRED_SIG_ALGS.join(', ')}); got ${algs.join(', ') || 'none'}`);
  }
  for (const s of sigs) {
    if (!/^[A-Za-z0-9._-]+$/.test(s.key_id)) throw new Error(`bad key_id for ${s.sig_alg}`);
    if (!s.bytes || s.bytes.length === 0) throw new Error(`empty ${s.sig_alg} signature`);
  }
  return {
    cert_id: cert.cert_id,
    body: {
      author_cert: Buffer.from(certBytes).toString('base64'),
      author_cert_sig: {
        signatures: REQUIRED_SIG_ALGS.map((alg) => {
          const s = sigs.find((x) => x.sig_alg === alg);
          return { key_id: s.key_id, sig_alg: alg, signature: Buffer.from(s.bytes).toString('base64') };
        }),
      },
    },
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [certPath, ...args] = process.argv.slice(2);
  const sigs = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] !== '--sig' || !args[i + 1]) {
      console.error('usage: stamp-author-cert.mjs <cert bytes file> --sig <alg>:<key_id>:<file> ...');
      process.exit(2);
    }
    const [sig_alg, key_id, file] = args[++i].split(':');
    sigs.push({ sig_alg, key_id, bytes: readFileSync(file) });
  }
  const { cert_id, body } = certFile(readFileSync(certPath), sigs);
  mkdirSync('certs', { recursive: true });
  writeFileSync(`certs/${cert_id}.json`, JSON.stringify(body, null, 2) + '\n');
  console.log(`wrote certs/${cert_id}.json`);
}
