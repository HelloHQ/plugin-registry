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
//     and the Ed25519 one verifies under the registry root key.
//
//   node scripts/check-signed-index.mjs   # exits 1 and prints each problem
import { createHash, createPublicKey, verify } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export const GRACE_HOURS = 12;
export const MIN_DAYS_LEFT = 5;

// The registry root Ed25519 public key (raw 32 bytes, base64). Must equal the
// `hellohq-registry-ed25519-2026-01` entry the app bundles
// (HelloHQ/hellohq lib/app/utils/constant/plugin_registry_trust_roots.dart).
export const REGISTRY_ROOT_ED25519 = {
  keyId: 'hellohq-registry-ed25519-2026-01',
  raw: 'S+pDZ3hHBL4rYN29456pknkqbhUimMcg143AWeb0xY8=',
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
  const ed = sigs.find((s) => s?.sig_alg === 'ed25519' && s.key_id === rootKey.keyId);
  if (ed) {
    let ok = false;
    try {
      ok = verify(null, manifestBytes, ed25519Key(rootKey.raw), Buffer.from(String(ed.signature), 'base64'));
    } catch {
      ok = false;
    }
    if (!ok) problems.push('the Ed25519 signature on index-manifest.json does not verify under the registry root key');
  } else if (sigs.some((s) => s?.sig_alg === 'ed25519')) {
    problems.push(`the Ed25519 signature is not by ${rootKey.keyId}`);
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
