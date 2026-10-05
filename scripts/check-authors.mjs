#!/usr/bin/env node
// Validate every authors/<slug>.json enrollment (shape, key lengths and the
// Ed25519 proof of possession). Exits 1 and prints one line per problem.
//
//   node scripts/check-authors.mjs [registry dir]
import { fileURLToPath } from 'node:url';
import { enrollmentProblems, loadAuthors } from './author-cert.mjs';

export function authorProblems(registryDir) {
  const out = [];
  for (const { file, author } of loadAuthors(registryDir)) {
    for (const p of enrollmentProblems(author, { slugFromFile: file.replace(/\.json$/, '') })) {
      out.push(`authors/${file}: ${p}`);
    }
  }
  return out;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const problems = authorProblems(process.argv[2] ?? '.');
  for (const p of problems) console.log(p);
  if (problems.length) process.exit(1);
  console.log('authors/ is sound');
}
