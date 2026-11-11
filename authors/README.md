# Author enrollment

One file per author: `authors/<slug>.json`. Merging it lets the private signing
pipeline issue the author a certificate (`certs/`), after which their plugins can
be signed under it. A certificate lasts 90 days and is renewed automatically.

```json
{
  "slug": "acme-labs",
  "identity": { "oidc_issuer": "https://github.com", "oidc_subject": "<stable account id>" },
  "id_prefixes": ["com.example."],
  "public_keys": { "ed25519": "<32 bytes, base64>", "ml-dsa-65": "<1952 bytes, base64>" },
  "tier": "author",
  "proof": { "ed25519": "<64 bytes, base64>", "ml-dsa-65": "<3309 bytes, base64>" }
}
```

`proof.ed25519` and `proof.ml-dsa-65` are your two keys' signatures over the
same enrollment statement:

```sh
node scripts/author-cert.mjs statement authors/acme-labs.json   # the bytes to sign
```

They show you hold both keys you are enrolling. CI verifies both (Node 24.7 or
later) and refuses an enrollment without either. `hqplugin keys enroll` writes
the file with both proofs.

**Identity.** `identity` must be `{"oidc_issuer": "https://github.com", "oidc_subject":
"<your numeric GitHub account id>"}`; find it with `gh api users/<login> --jq .id`.
Use the number, not the login, which can be renamed. CI refuses an enrollment
unless the pull request is opened by that account, so you cannot enroll a
namespace in someone else's name. Changing an enrolled author's identity is not
allowed; revoke and enroll again. Other issuers are not accepted until the
registry can verify them. A maintainer may revoke (delete the file, or set
`"revoked": true` and change nothing else) from any account.

`id_prefixes` is the plugin ids you may sign. Each entry is a dotted namespace
ending in `.` (`com.example.` covers `com.example.widget` and nothing outside
it), with at least two labels. `com.hellohq.` is reserved. The proof covers the
list, so changing it needs a new proof.

**Signing a plugin.** Sign the artifact statement, not the wasm file, and commit
the result next to the manifest as `author-signatures.json`. Do not put
`signatures[]` or `author_cert` on the manifest; the signing pipeline copies
your signatures and attaches your certificate after merge. The plugin id must
sit under one of your prefixes, and `trust_tier` must be `verified`.

```sh
node scripts/author-signatures.mjs sign plugins/<id>/manifest.json \
  --ed25519-key ed25519.pem --mldsa-key mldsa65.pem
```

The ML-DSA half needs OpenSSL 3.5 or newer (`pkeyutl -sign`). CI verifies both
halves, under the enrolled author's two keys, and so does the app.

**Revoking.** Set `"revoked": true`, or delete the file, or change the keys. The
next signing run drops the certificate from the signed index manifest, and apps
stop trusting it on their next catalog refresh. The signer's schedule is best
effort (runs can be hours apart), so a maintainer dispatches it straight after
merging a revocation. No app
release is involved.

`certs/` is written only by the signing pipeline. A pull request may not add or
edit anything in it.
