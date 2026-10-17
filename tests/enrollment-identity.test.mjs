// An enrollment must be opened by the GitHub account it names.
//   node --test tests/*.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { identityProblems } from '../scripts/check-enrollment-identity.mjs';

const author = (subject = '4242', extra = {}) => ({
  slug: 'acme-labs',
  identity: { oidc_issuer: 'https://github.com', oidc_subject: subject },
  id_prefixes: ['com.acme.'],
  tier: 'author',
  ...extra,
});
const added = (a) => [{ file: 'acme-labs.json', before: null, after: a }];

test('a new enrollment opened by the account it names passes', () => {
  assert.deepEqual(identityProblems(added(author('4242')), '4242'), []);
});

test('a new enrollment opened by someone else is refused', () => {
  const [p, ...rest] = identityProblems(added(author('4242')), '9999');
  assert.equal(rest.length, 0);
  assert.match(p, /not the account that opened this pull request \(9999\)/);
});

test('a login instead of the numeric id is refused', () => {
  const [p] = identityProblems(added(author('octocat')), '4242');
  assert.match(p, /numeric GitHub account id/);
});

test('an id with a leading zero or a sign is refused', () => {
  for (const s of ['0123', '-5', '12 3', '']) {
    assert.match(identityProblems(added(author(s)), '4242')[0], /numeric GitHub account id/, JSON.stringify(s));
  }
});

test('an issuer other than GitHub is refused, even one that looks alike', () => {
  for (const iss of ['https://accounts.google.com', 'https://github.com.evil.example', 'http://github.com', 'https://github.com/']) {
    const a = author('4242');
    a.identity.oidc_issuer = iss;
    assert.match(identityProblems(added(a), '4242')[0], /oidc_issuer must be https:\/\/github\.com/, iss);
  }
});

test('an unknown pull request author fails closed', () => {
  for (const id of [undefined, '', 'octocat', '0']) {
    assert.match(identityProblems(added(author('4242')), id)[0], /author's GitHub id is unknown/, String(id));
  }
});

test('the owner may change their own keys or prefixes', () => {
  const before = author('4242');
  const after = author('4242', { id_prefixes: ['com.acme.', 'io.acme.'] });
  assert.deepEqual(identityProblems([{ file: 'acme-labs.json', before, after }], '4242'), []);
});

test("another account cannot edit an enrolled author's file", () => {
  const before = author('4242');
  const after = author('4242', { id_prefixes: ['com.acme.', 'io.acme.'] });
  assert.match(identityProblems([{ file: 'acme-labs.json', before, after }], '9999')[0], /not the account that opened/);
});

test("an existing enrollment's identity cannot be handed to another account", () => {
  const before = author('4242');
  const after = author('9999');
  const [p] = identityProblems([{ file: 'acme-labs.json', before, after }], '9999');
  assert.match(p, /cannot change; revoke and enroll again/);
});

test('a maintainer may revoke by flag or by deleting the file', () => {
  const before = author('4242');
  assert.deepEqual(identityProblems([{ file: 'acme-labs.json', before, after: { ...before, revoked: true } }], '1'), []);
  assert.deepEqual(identityProblems([{ file: 'acme-labs.json', before, after: null }], '1'), []);
});

test('"revoked" together with other edits is not a revocation', () => {
  const before = author('4242');
  const after = { ...before, revoked: true, id_prefixes: ['com.evil.'] };
  assert.match(identityProblems([{ file: 'acme-labs.json', before, after }], '1')[0], /not the account that opened/);
});

test('un-revoking is an edit and needs the owner', () => {
  const before = author('4242', { revoked: true });
  const after = author('4242', { revoked: false });
  assert.match(identityProblems([{ file: 'acme-labs.json', before, after }], '1')[0], /not the account that opened/);
});

test('every problem in a multi-file change is reported', () => {
  const changes = [
    { file: 'a-a-a.json', before: null, after: author('1') },
    { file: 'b-b-b.json', before: null, after: author('2') },
  ];
  assert.equal(identityProblems(changes, '3').length, 2);
});
