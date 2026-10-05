#!/usr/bin/env node
// A pull request never writes publisher signatures (SA5).
//
// `signatures[]` are added only by the private signing pipeline, after merge,
// over the artifact statement (scripts/artifact-statement.mjs). A PR may:
//   - leave them exactly as they are on the base branch, when the statement
//     (id, version, tier, mode, file hash, UI hash) is unchanged; or
//   - drop them (the pipeline re-signs after merge).
// It may never add or edit one (nor author_cert / author_cert_sig), and must drop them when it changes anything
// the statement covers: a kept signature would no longer verify, and the app
// would refuse the plugin until the next re-sign.
//
//   node scripts/check-pr-signatures.mjs <base manifest or ""> <head manifest>
import { existsSync, readFileSync } from 'node:fs';
import { isDeepStrictEqual } from 'node:util';
import { fileURLToPath } from 'node:url';
import { artifactStatement } from './artifact-statement.mjs';

/** Why [head]'s signatures are not acceptable in a PR against [base]
 *  (null when there is no base manifest), or null when they are. */
export function prSignatureProblem(base, head) {
  // The author certificate pair is written only by the signing pipeline too.
  // It does not depend on the artifact statement, so a PR may keep it or drop
  // it (the pipeline re-stamps), but never add or edit it.
  const certKeys = ['author_cert', 'author_cert_sig'];
  const certTouched = certKeys.some((k) => head[k] !== undefined);
  if (certTouched) {
    if (base == null) {
      return 'a new plugin must not carry author_cert; the signing pipeline adds it after merge';
    }
    if (certKeys.some((k) => !isDeepStrictEqual(base[k], head[k]))) {
      return 'author_cert and author_cert_sig are written only by the signing pipeline; keep them as on the base branch or remove them';
    }
  }
  if (head.signatures === undefined) return null;
  if (base == null) {
    return 'a new plugin must not carry signatures; the signing pipeline adds them after merge';
  }
  let same;
  try {
    same = artifactStatement(base).equals(artifactStatement(head));
  } catch (e) {
    return `cannot build the artifact statement: ${e.message}`;
  }
  if (!same) {
    return 'this PR changes what the signatures cover (id, version, tier, mode or a hash); remove signatures and the signing pipeline re-signs after merge';
  }
  if (!isDeepStrictEqual(base.signatures, head.signatures)) {
    return 'signatures are written only by the signing pipeline; keep them as on the base branch or remove them';
  }
  return null;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [basePath, headPath] = process.argv.slice(2);
  const load = (p) => JSON.parse(readFileSync(p, 'utf8'));
  const base = basePath && existsSync(basePath) ? load(basePath) : null;
  const problem = prSignatureProblem(base, load(headPath));
  if (problem) {
    console.log(problem);
    process.exit(1);
  }
}
