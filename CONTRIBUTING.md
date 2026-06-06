# Contributing to the HelloHQ Plugin Registry

## Checklist before opening a PR

- [ ] `plugins/<id>/manifest.json` exists and the directory name **exactly**
      equals the manifest `id` (case-sensitive).
- [ ] `id` is reverse-domain, lowercase, and unique. No `hellohq.` prefix
      (reserved for Official plugins).
- [ ] `version` is higher than any previously merged version for this `id`.
- [ ] `wasm_url` (and `ui_bundle_url` for WebView) is public and stable —
      a GitHub Release asset, not a CDN link that can expire.
- [ ] `content_hash_sha256` matches `shasum -a 256` of the published binary.
- [ ] `permissions` lists only what the plugin needs. `read:aggregated_values`
      includes a `scope.portfolios`.
- [ ] `repo` and `author_url` are reachable.
- [ ] `publisher_signing_key_id` is **omitted** on first submission — the
      registry team adds it at merge.

## PR title

```
Add <id> <version>
# or
Update <id> <old> → <new>
# or
Remove <id>
```

## What CI checks

`.github/workflows/validate.yml` runs on every PR:

1. JSON Schema validation against `schema/manifest.schema.json`.
2. Directory name equals `id`.
3. `version` strictly increases vs. the merged manifest.
4. Download `wasm_url`, recompute SHA-256, compare to `content_hash_sha256`.
5. Reachability of `repo` and `author_url`.

CI-green Community plugins can be fast-merged. Plugins requesting Verified-tier
capabilities go through `REVIEW_POLICY.md`.

## Updating

Bump `version`, update `wasm_url` + `content_hash_sha256`, and note any new
permissions in the PR description. Users are re-prompted only for the new
permissions at update time.
