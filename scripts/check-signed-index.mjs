#!/usr/bin/env node
// Is the signed index manifest still good? (the signer's dead-man check)
//
// The app rejects the registry when index-manifest.json does not pin the
// current index.json, has expired, or is not signed by the registry root.
// plugin-signing's sign-release keeps all three true, and alerts when one of
// its runs fails, but a run that never starts (runner offline, schedule
// disabled) alerts nobody. This checks the outcome instead, from this repo:
//
//   - index-manifest.json pins sha256(index.json), allowing GRACE_HOURS after
//     index.json last changed for the signer to catch up;
//   - expires_at is more than MIN_DAYS_LEFT away (the signer renews at 7);
//   - index-manifest.json.sig carries an Ed25519 and an ML-DSA-65 signature,
//     and each verifies under the registry root key of its algorithm.
//
// ML-DSA-65 needs Node 24.7 or later (scripts/ml-dsa.mjs). On an older Node
// that half is reported as a problem, never skipped.
//
//   node scripts/check-signed-index.mjs   # exits 1 and prints each problem
import { createHash, createPublicKey, verify } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { verifyMlDsa65 } from './ml-dsa.mjs';

export const GRACE_HOURS = 12;
export const MIN_DAYS_LEFT = 5;

// The registry root Ed25519 public key (raw 32 bytes, base64). Must equal the
// `hellohq-registry-ed25519-2026-01` entry the app bundles
// (HelloHQ/hellohq lib/app/utils/constant/plugin_registry_trust_roots.dart).
export const REGISTRY_ROOT_ED25519 = {
  keyId: 'hellohq-registry-ed25519-2026-01',
  raw: 'S+pDZ3hHBL4rYN29456pknkqbhUimMcg143AWeb0xY8=',
};

// The registry root ML-DSA-65 public key (raw 1952 bytes, base64). Must equal
// the `hellohq-registry-ml-dsa-65-2026-01` entry the app bundles, and
// plugin-signing keys/registry-ml-dsa-65.pub (the KMS nist-pqc export).
export const REGISTRY_ROOT_ML_DSA_65 = {
  keyId: 'hellohq-registry-ml-dsa-65-2026-01',
  raw: [
    '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',
    'bdfk0gHR6vXMXCgV69o=',
  ].join(''),
};

const ed25519Key = (rawB64) =>
  createPublicKey({
    key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(rawB64, 'base64')]),
    format: 'der',
    type: 'spki',
  });

/** Every problem with the signed index (empty when it is good). */
export function signedIndexProblems({
  indexBytes,
  manifestBytes,
  sigBytes,
  indexChangedAt,
  now = new Date(),
  rootKey = REGISTRY_ROOT_ED25519,
  mlDsaRootKey = REGISTRY_ROOT_ML_DSA_65,
}) {
  const problems = [];
  let manifest;
  try {
    manifest = JSON.parse(manifestBytes.toString('utf8'));
  } catch {
    return ['index-manifest.json is not valid JSON'];
  }

  const indexSha = createHash('sha256').update(indexBytes).digest('hex');
  if (manifest.index_sha256 !== indexSha) {
    const hours = (now - indexChangedAt) / 3.6e6;
    if (!(hours < GRACE_HOURS)) {
      problems.push(
        `index-manifest.json does not pin the current index.json (changed ${Math.floor(hours)} h ago); ` +
          'apps reject the registry until sign-release runs',
      );
    }
  }

  const expires = Date.parse(manifest.expires_at);
  if (Number.isNaN(expires)) {
    problems.push('index-manifest.json has no valid expires_at');
  } else {
    const daysLeft = (expires - now) / 8.64e7;
    if (daysLeft <= 0) problems.push(`index-manifest.json expired on ${manifest.expires_at}; apps reject the registry`);
    else if (daysLeft < MIN_DAYS_LEFT) {
      problems.push(
        `index-manifest.json expires on ${manifest.expires_at} (${daysLeft.toFixed(1)} days); ` +
          'sign-release should have renewed it at 7 days',
      );
    }
  }

  let sigs = [];
  try {
    sigs = JSON.parse(sigBytes.toString('utf8')).signatures ?? [];
  } catch {
    problems.push('index-manifest.json.sig is not valid JSON');
  }
  for (const alg of ['ed25519', 'ml-dsa-65']) {
    if (!sigs.some((s) => s?.sig_alg === alg)) problems.push(`index-manifest.json.sig has no ${alg} signature`);
  }
  const halves = [
    ['ed25519', 'Ed25519', rootKey, (key, sig) => verify(null, manifestBytes, ed25519Key(key.raw), sig)],
    ['ml-dsa-65', 'ML-DSA-65', mlDsaRootKey, (key, sig) => verifyMlDsa65(manifestBytes, Buffer.from(key.raw, 'base64'), sig)],
  ];
  for (const [alg, name, key, check] of halves) {
    const s = sigs.find((x) => x?.sig_alg === alg && x.key_id === key.keyId);
    if (s) {
      let ok = false;
      try {
        ok = check(key, Buffer.from(String(s.signature), 'base64'));
      } catch (e) {
        problems.push(`the ${name} signature on index-manifest.json could not be checked: ${e.message}`);
        continue;
      }
      if (!ok) problems.push(`the ${name} signature on index-manifest.json does not verify under the registry root key`);
    } else if (sigs.some((x) => x?.sig_alg === alg)) {
      problems.push(`the ${name} signature is not by ${key.keyId}`);
    }
  }
  return problems;
}

export const WATCHDOG_TITLE = 'Signed index needs attention';

/** Keep one watchdog issue in step with [problems]: open it (assigned) or
 *  comment when there are problems, close it when there are none. `gh` is the
 *  same small facade as plugin-signing's alert (listOpenIssues, comment,
 *  create, close). Returns 'opened' | 'commented' | 'closed' | 'none'. */
export async function reconcileWatchdogIssue(gh, { problems, runUrl, assignees }) {
  const open = (await gh.listOpenIssues()).find((i) => i.title === WATCHDOG_TITLE && !i.pull_request);
  const list = problems.map((p) => `- ${p}`).join('\n');
  if (problems.length) {
    if (open) {
      await gh.comment(open.number, `Still failing: ${runUrl}\n\n${list}`);
      return 'commented';
    }
    await gh.create({
      title: WATCHDOG_TITLE,
      assignees,
      body: [
        `The daily signed-index check failed: ${runUrl}`,
        '',
        list,
        '',
        'The signer (plugin-signing sign-release) renews and re-signs the index; it',
        'may not be running. Check its run history, fix the cause, then dispatch it:',
        '`gh workflow run sign-release.yml --repo HelloHQ/plugin-signing`.',
        'This issue closes itself when the check passes again.',
      ].join('\n'),
    });
    return 'opened';
  }
  if (open) {
    await gh.comment(open.number, `The signed index is good again: ${runUrl}`);
    await gh.close(open.number);
    return 'closed';
  }
  return 'none';
}

export function makeGitHub(github, { owner, repo }) {
  return {
    listOpenIssues: () =>
      github.paginate(github.rest.issues.listForRepo, { owner, repo, state: 'open', per_page: 100 }),
    comment: (issue_number, body) => github.rest.issues.createComment({ owner, repo, issue_number, body }),
    create: ({ title, body, assignees }) => github.rest.issues.create({ owner, repo, title, body, assignees }),
    close: (issue_number) =>
      github.rest.issues.update({ owner, repo, issue_number, state: 'closed', state_reason: 'completed' }),
  };
}

/** Run the check against the files in [dir] (the registry checkout). */
export function checkCheckout(dir = '.') {
  const at = (f) => readFileSync(`${dir}/${f}`);
  const changed = execFileSync('git', ['-C', dir, 'log', '-1', '--format=%cI', '--', 'index.json'], { encoding: 'utf8' }).trim();
  return signedIndexProblems({
    indexBytes: at('index.json'),
    manifestBytes: at('index-manifest.json'),
    sigBytes: at('index-manifest.json.sig'),
    indexChangedAt: changed ? new Date(changed) : new Date(0),
  });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const problems = checkCheckout('.');
  for (const p of problems) console.log(p);
  if (!problems.length) console.log('signed index is good');
  process.exit(problems.length ? 1 : 0);
}
