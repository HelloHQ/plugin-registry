# Author enrollment

One file per author: `authors/<slug>.json`. Merging it lets the private signing
pipeline issue the author a certificate (`certs/`), after which their plugins can
be signed under it. A certificate lasts 90 days and is renewed automatically.

```json
{
  "slug": "acme-labs",
  "identity": { "oidc_issuer": "https://github.com", "oidc_subject": "<stable account id>" },
  "public_keys": { "ed25519": "<32 bytes, base64>", "ml-dsa-65": "<1952 bytes, base64>" },
  "tier": "author",
  "proof": { "ed25519": "<64 bytes, base64>" }
}
```

`proof.ed25519` is your Ed25519 key's signature over the enrollment statement:

```sh
node scripts/author-cert.mjs statement authors/acme-labs.json   # the bytes to sign
```

It shows you hold the key you are enrolling. CI checks it. Every plugin
signature must verify under both of your keys, so an ML-DSA-65 key you do not
hold gets you nothing.

**Revoking.** Set `"revoked": true`, or delete the file, or change the keys. The
next signing run (within 15 minutes) drops the certificate from the signed index
manifest, and apps stop trusting it on their next catalog refresh. No app
release is involved.

`certs/` is written only by the signing pipeline. A pull request may not add or
edit anything in it.
