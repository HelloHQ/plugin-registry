#!/usr/bin/env node
// An enrollment names the account that owns the plugin id prefixes. Proof of
// possession (check-authors.mjs) shows the enrolling key is held by the
// submitter, but not WHO the submitter is: `identity` was self-declared. This
// closes that for the one issuer the registry can check, GitHub: the pull
// request that adds or changes an enrollment must be opened by the GitHub
// account whose numeric id the enrollment claims.
//
//   PR_AUTHOR_ID=<numeric id> node scripts/check-enrollment-identity.mjs <base ref>
//
// Rules, per enrollment file the pull request touches:
//   - Deleting a file (a revocation) is allowed to anyone who can merge it.
//   - Setting "revoked": true and changing nothing else is allowed likewise.
//   - Otherwise the issuer must be https://github.com, the subject must be the
//     numeric account id (a login can be renamed and re-registered), and it
//     must equal the id of the account that opened the pull request.
//   - An existing enrollment's identity cannot change. Moving a namespace to
//     another account is a revocation followed by a new enrollment.
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

export const GITHUB_ISSUER = 'https://github.com';

const sameJson = (a, b) => JSON.stringify(a) === JSON.stringify(b);

/** True when `after` is `before` with only `revoked` set to true. */
function isRevocation(before, after) {
  if (!before || after?.revoked !== true) return false;
  const { revoked: _a, ...rest } = after;
  const { revoked: _b, ...prior } = before;
  return sameJson(rest, prior);
}

/**
 * Problems for a set of changed enrollments.
 * @param {{file: string, before: object|null, after: object|null}[]} changes
 *   after === null for a deleted file; before === null for a new one.
 * @param {string|undefined} prAuthorId the numeric GitHub id of the PR's opener
 */
export function identityProblems(changes, prAuthorId) {
  const out = [];
  for (const { file, before, after } of changes) {
    if (after == null) continue; // deletion
    if (isRevocation(before, after)) continue;
    const label = `authors/${file}`;
    const issuer = after.identity?.oidc_issuer;
    const subject = after.identity?.oidc_subject;
    if (issuer !== GITHUB_ISSUER) {
      out.push(`${label}: identity.oidc_issuer must be ${GITHUB_ISSUER}; no other issuer can be verified yet`);
      continue;
    }
    if (typeof subject !== 'string' || !/^[1-9][0-9]{0,18}$/.test(subject)) {
      out.push(`${label}: identity.oidc_subject must be the numeric GitHub account id (not the login)`);
      continue;
    }
    if (before && (before.identity?.oidc_issuer !== issuer || before.identity?.oidc_subject !== subject)) {
      out.push(`${label}: the identity of an enrolled author cannot change; revoke and enroll again`);
      continue;
    }
    if (!/^[1-9][0-9]{0,18}$/.test(prAuthorId ?? '')) {
      out.push(`${label}: the pull request author's GitHub id is unknown, so the identity cannot be checked`);
    } else if (prAuthorId !== subject) {
      out.push(
        `${label}: identity.oidc_subject ${subject} is not the account that opened this pull request (${prAuthorId}); ` +
          'an enrollment must be opened by the account it names',
      );
    }
  }
  return out;
}

function git(...args) {
  return execFileSync('git', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
}

/** The enrollment files a pull request touches, with their content before and after. */
export function changedEnrollments(baseRef) {
  const status = git('diff', '--name-status', '--no-renames', `${baseRef}...HEAD`, '--', 'authors/')
    .split('\n')
    .filter(Boolean);
  const out = [];
  for (const line of status) {
    const [code, path] = line.split('\t');
    if (!/^authors\/[^/]+\.json$/.test(path)) continue;
    const show = (ref) => {
      try {
        return JSON.parse(git('show', `${ref}:${path}`));
      } catch {
        return null;
      }
    };
    out.push({
      file: path.slice('authors/'.length),
      before: code === 'A' ? null : show(baseRef),
      after: code === 'D' ? null : show('HEAD'),
    });
  }
  return out;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const baseRef = process.argv[2];
  if (!baseRef) {
    console.error('usage: PR_AUTHOR_ID=<id> check-enrollment-identity.mjs <base ref>');
    process.exit(2);
  }
  const problems = identityProblems(changedEnrollments(baseRef), process.env.PR_AUTHOR_ID);
  for (const p of problems) console.log(p);
  if (problems.length) process.exit(1);
  console.log('enrollment identity matches the pull request author');
}
