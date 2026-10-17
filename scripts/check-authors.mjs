#!/usr/bin/env node
// Validate every authors/<slug>.json enrollment (shape, key lengths and the
// Ed25519 proof of possession), and that no two enrollments share a key or
// claim overlapping id prefixes. Exits 1 and prints one line per problem.
//
//   node scripts/check-authors.mjs [registry dir]
import { fileURLToPath } from 'node:url';
import { enrollmentProblems, loadAuthors } from './author-cert.mjs';

/**
 * Problems between enrollments. A namespace belongs to one author: a prefix
 * that equals, contains or sits under another author's prefix is refused, and
 * so is a public key two enrollments share (one holder, one slug). A revoked
 * enrollment still counts until its file is deleted, so a revoked author's
 * namespace cannot be claimed by someone else in the same change.
 */
export function crossAuthorProblems(entries) {
  const out = [];
  const seen = entries.filter(({ author }) => Array.isArray(author?.id_prefixes));
  for (let i = 0; i < seen.length; i++) {
    for (let j = i + 1; j < seen.length; j++) {
      const a = seen[i];
      const b = seen[j];
      for (const alg of ['ed25519', 'ml-dsa-65']) {
        const key = a.author.public_keys?.[alg];
        if (typeof key === 'string' && key === b.author.public_keys?.[alg]) {
          out.push(`authors/${b.file}: ${alg} key is already enrolled by authors/${a.file}`);
        }
      }
      for (const p of a.author.id_prefixes) {
        for (const q of b.author.id_prefixes) {
          if (typeof p === 'string' && typeof q === 'string' && (p.startsWith(q) || q.startsWith(p))) {
            out.push(`authors/${b.file}: id prefix "${q}" overlaps "${p}" of authors/${a.file}`);
          }
        }
      }
    }
  }
  return out;
}

export function authorProblems(registryDir) {
  const out = [];
  const entries = loadAuthors(registryDir);
  for (const { file, author } of entries) {
    for (const p of enrollmentProblems(author, { slugFromFile: file.replace(/\.json$/, '') })) {
      out.push(`authors/${file}: ${p}`);
    }
  }
  out.push(...crossAuthorProblems(entries));
  return out;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const problems = authorProblems(process.argv[2] ?? '.');
  for (const p of problems) console.log(p);
  if (problems.length) process.exit(1);
  console.log('authors/ is sound');
}
