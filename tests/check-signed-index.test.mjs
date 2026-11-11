// The signed-index watchdog (scripts/check-signed-index.mjs).
//   node --test tests/
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import {
  GRACE_HOURS,
  MIN_DAYS_LEFT,
  REGISTRY_ROOT_ED25519,
  REGISTRY_ROOT_ML_DSA_65,
  signedIndexProblems,
} from '../scripts/check-signed-index.mjs';

const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const rootKey = {
  keyId: 'test-root',
  raw: publicKey.export({ type: 'spki', format: 'der' }).subarray(12).toString('base64'),
};
const pqPair = generateKeyPairSync('ml-dsa-65');
const mlDsaRootKey = {
  keyId: 'test-root-pq',
  raw: pqPair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-1952).toString('base64'),
};
const NOW = new Date('2026-10-17T00:00:00Z');
const DAY = 8.64e7;
const index = Buffer.from('{"schema_version":1,"plugins":[]}\n');
const sha = (b) => createHash('sha256').update(b).digest('hex');

function signed({
  indexSha = sha(index),
  expiresIn = 30 * DAY,
  key = privateKey,
  keyId = 'test-root',
  ed = true,
  pq = true,
  pqKey = pqPair.privateKey,
  pqKeyId = 'test-root-pq',
} = {}) {
  const manifestBytes = Buffer.from(JSON.stringify({
    schema_version: 1, index_sha256: indexSha, sequence: 6,
    issued_at: '2026-10-16T00:00:00Z', expires_at: new Date(NOW.getTime() + expiresIn).toISOString(),
  }));
  const signatures = [];
  if (ed) signatures.push({ key_id: keyId, sig_alg: 'ed25519', signature: sign(null, manifestBytes, key).toString('base64') });
  if (pq) signatures.push({ key_id: pqKeyId, sig_alg: 'ml-dsa-65', signature: sign(null, manifestBytes, pqKey).toString('base64') });
  return { manifestBytes, sigBytes: Buffer.from(JSON.stringify({ signatures })) };
}
const check = (over = {}, s = signed()) =>
  signedIndexProblems({ indexBytes: index, ...s, indexChangedAt: new Date(NOW - 30 * DAY), now: NOW, rootKey, mlDsaRootKey, ...over });

test('a current, unexpired, root-signed index is good', () => {
  assert.deepEqual(check(), []);
});

test('an unpinned index.json is fine inside the grace window and a problem after it', () => {
  const s = signed({ indexSha: 'f'.repeat(64) });
  assert.deepEqual(check({ indexChangedAt: new Date(NOW - (GRACE_HOURS - 1) * 3.6e6) }, s), []);
  const late = check({ indexChangedAt: new Date(NOW - (GRACE_HOURS + 1) * 3.6e6) }, s);
  assert.equal(late.length, 1);
  assert.match(late[0], /does not pin the current index\.json \(changed 13 h ago\)/);
});

test('near expiry and expired are problems; comfortably valid is not', () => {
  assert.deepEqual(check({}, signed({ expiresIn: (MIN_DAYS_LEFT + 1) * DAY })), []);
  assert.match(check({}, signed({ expiresIn: (MIN_DAYS_LEFT - 1) * DAY }))[0], /should have renewed it at 7 days/);
  assert.match(check({}, signed({ expiresIn: -DAY }))[0], /expired on/);
});

test('a bad, foreign or missing signature is a problem', () => {
  const other = generateKeyPairSync('ed25519').privateKey;
  assert.match(check({}, signed({ key: other }))[0], /does not verify under the registry root key/);
  assert.match(check({}, signed({ keyId: 'someone-else' }))[0], /not by test-root/);
  assert.match(check({}, signed({ pq: false }))[0], /no ml-dsa-65 signature/);
  const s = signed();
  const tampered = { ...s, manifestBytes: Buffer.from(s.manifestBytes.toString().replace('"sequence":6', '"sequence":7')) };
  assert.match(check({}, tampered)[0], /does not verify/);
  assert.match(check({}, { ...s, sigBytes: Buffer.from('nope') }).join('|'), /\.sig is not valid JSON/);
});

test('each half is checked: good, bad and missing, for Ed25519 and for ML-DSA-65', () => {
  // good: both halves verify
  assert.deepEqual(check({}, signed()), []);

  // Ed25519 bad (another key) and missing
  const otherEd = generateKeyPairSync('ed25519').privateKey;
  assert.deepEqual(check({}, signed({ key: otherEd })), [
    'the Ed25519 signature on index-manifest.json does not verify under the registry root key',
  ]);
  assert.deepEqual(check({}, signed({ ed: false })), ['index-manifest.json.sig has no ed25519 signature']);

  // ML-DSA-65 bad (another key, a flipped byte, a wrong length), foreign and missing
  const otherPq = generateKeyPairSync('ml-dsa-65').privateKey;
  const badPq = 'the ML-DSA-65 signature on index-manifest.json does not verify under the registry root key';
  assert.deepEqual(check({}, signed({ pqKey: otherPq })), [badPq]);
  const s = signed();
  const body = JSON.parse(s.sigBytes);
  const pqSig = Buffer.from(body.signatures[1].signature, 'base64');
  pqSig[100] ^= 1;
  body.signatures[1].signature = pqSig.toString('base64');
  assert.deepEqual(check({}, { ...s, sigBytes: Buffer.from(JSON.stringify(body)) }), [badPq]);
  body.signatures[1].signature = 'AAAA';
  assert.deepEqual(check({}, { ...s, sigBytes: Buffer.from(JSON.stringify(body)) }), [badPq]);
  assert.deepEqual(check({}, signed({ pqKeyId: 'someone-else' })), ['the ML-DSA-65 signature is not by test-root-pq']);
  assert.deepEqual(check({}, signed({ pq: false })), ['index-manifest.json.sig has no ml-dsa-65 signature']);

  // A manifest changed after signing fails both halves.
  const tampered = { ...s, manifestBytes: Buffer.from(s.manifestBytes.toString().replace('"sequence":6', '"sequence":7')) };
  assert.equal(check({}, tampered).length, 2);
});

test('broken manifest JSON or expiry is reported, never thrown', () => {
  assert.deepEqual(check({ manifestBytes: Buffer.from('{') }), ['index-manifest.json is not valid JSON']);
  const s = signed();
  const noExpiry = Buffer.from(s.manifestBytes.toString().replace(/"expires_at":"[^"]+"/, '"expires_at":"soon"'));
  assert.ok(check({ manifestBytes: noExpiry }, s).includes('index-manifest.json has no valid expires_at'));
});

test('the registry\'s own committed signed index passes with the real root key', () => {
  // In a PR that adds or updates a plugin, index.json legitimately differs from
  // what index-manifest.json pins until the signer runs after merge, so this
  // checks the signature and expiry with the pin inside its grace window.
  const r = (p) => readFileSync(new URL(`../${p}`, import.meta.url));
  const manifestBytes = r('index-manifest.json');
  const now = new Date(Date.parse(JSON.parse(manifestBytes).issued_at) + DAY);
  const problems = signedIndexProblems({
    indexBytes: r('index.json'),
    manifestBytes,
    sigBytes: r('index-manifest.json.sig'),
    indexChangedAt: now,
    now,
  });
  assert.deepEqual(problems, [], 'real files signed by the real registry root');
  assert.equal(REGISTRY_ROOT_ED25519.keyId, 'hellohq-registry-ed25519-2026-01');
  assert.equal(REGISTRY_ROOT_ML_DSA_65.keyId, 'hellohq-registry-ml-dsa-65-2026-01');
  assert.equal(Buffer.from(REGISTRY_ROOT_ML_DSA_65.raw, 'base64').length, 1952);

  // The real ML-DSA-65 half is checked too: a changed manifest fails it.
  const changed = Buffer.from(manifestBytes.toString().replace(/"sequence": *(\d+)/, '"sequence": 999999'));
  const after = signedIndexProblems({
    indexBytes: r('index.json'),
    manifestBytes: changed,
    sigBytes: r('index-manifest.json.sig'),
    indexChangedAt: now,
    now,
  });
  assert.ok(after.includes('the ML-DSA-65 signature on index-manifest.json does not verify under the registry root key'));
});

// ── the watchdog issue ──────────────────────────────────────────────────────
import { WATCHDOG_TITLE, reconcileWatchdogIssue } from '../scripts/check-signed-index.mjs';

function fakeGitHub(issues = []) {
  const calls = [];
  return {
    calls, issues,
    listOpenIssues: async () => issues.filter((i) => i.state === 'open'),
    comment: async (n, body) => calls.push(['comment', n, body]),
    create: async (i) => { calls.push(['create', i]); issues.push({ number: 50, state: 'open', ...i }); },
    close: async (n) => { calls.push(['close', n]); issues.find((i) => i.number === n).state = 'closed'; },
  };
}
const args = (problems) => ({ problems, runUrl: 'https://x/runs/9', assignees: ['calvinchengx'] });

test('watchdog: problems open one assigned issue, then comment on it', async () => {
  const gh = fakeGitHub();
  assert.equal(await reconcileWatchdogIssue(gh, args(['expired'])), 'opened');
  const created = gh.calls[0][1];
  assert.equal(created.title, WATCHDOG_TITLE);
  assert.deepEqual(created.assignees, ['calvinchengx']);
  assert.match(created.body, /- expired/);
  assert.match(created.body, /gh workflow run sign-release\.yml/);
  assert.equal(await reconcileWatchdogIssue(gh, args(['still expired'])), 'commented');
  assert.match(gh.calls[1][2], /Still failing: https:\/\/x\/runs\/9\n\n- still expired/);
  assert.equal(gh.issues.filter((i) => i.state === 'open').length, 1);
});

test('watchdog: a clean check closes the open issue, or does nothing', async () => {
  const gh = fakeGitHub([{ number: 3, state: 'open', title: WATCHDOG_TITLE }, { number: 4, state: 'open', title: 'other' }]);
  assert.equal(await reconcileWatchdogIssue(gh, args([])), 'closed');
  assert.deepEqual(gh.calls.map((c) => [c[0], c[1]]), [['comment', 3], ['close', 3]]);
  assert.equal(gh.issues[1].state, 'open', 'unrelated issues are untouched');
  const quiet = fakeGitHub();
  assert.equal(await reconcileWatchdogIssue(quiet, args([])), 'none');
  assert.deepEqual(quiet.calls, []);
});

test('watchdog workflow: daily, hosted runner, issues write, runs the check', () => {
  const wf = readFileSync(new URL('../.github/workflows/signed-index-watchdog.yml', import.meta.url), 'utf8');
  assert.match(wf, /schedule:/);
  assert.match(wf, /workflow_dispatch:/);
  assert.match(wf, /runs-on: ubuntu-latest/);
  assert.match(wf, /issues: write/);
  assert.match(wf, /scripts\/check-signed-index\.mjs/);
  assert.match(wf, /reconcileWatchdogIssue/);
});
