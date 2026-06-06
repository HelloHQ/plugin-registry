# HelloHQ Plugin Registry

The public catalogue of HelloHQ plugins. Modelled on Homebrew taps: one
`manifest.json` per plugin, submitted by pull request. This repository is the
single source of truth for what appears in the in-app Plugin Browser.

```
plugins/
  <reverse.domain.id>/
    manifest.json
schema/
  manifest.schema.json     # validated against by CI
.github/workflows/
  validate.yml             # schema + hash + identity checks
CONTRIBUTING.md
REVIEW_POLICY.md
```

## Submitting a plugin

1. Build your plugin and publish the `.wasm` (and `ui.zip` for WebView) to a
   stable, public URL — a GitHub Release is recommended.
2. Compute `shasum -a 256 plugin.wasm`.
3. Fork this repo, add `plugins/<your-id>/manifest.json` (see
   [`schema/manifest.schema.json`](schema/manifest.schema.json) and the
   [`com.hellohq.hello-world`](plugins/com.hellohq.hello-world/manifest.json)
   example).
4. Open a PR titled `Add <id> <version>`.

CI validates the manifest, verifies the hash, and confirms the directory name
matches `id`. See [CONTRIBUTING.md](CONTRIBUTING.md) and
[REVIEW_POLICY.md](REVIEW_POLICY.md).

## Trust tiers

| Tier | How | Unlocks |
|---|---|---|
| Community | CI passes | All permissions except `read:aggregated_values`, `write:external_output`; declarative + headless UI |
| Verified | Manual security review | aggregated values, file output, WebView UI, Tier 1 Python |
| Official | Built by HelloHQ | — |

The protocol contract lives in
[`HelloHQ/plugin-protocol`](https://github.com/HelloHQ/plugin-protocol); SDKs and
the `hqplugin` CLI in [`HelloHQ/plugin-sdk`](https://github.com/HelloHQ/plugin-sdk).

## License

Registry tooling and schema are Apache 2.0 ([LICENSE](LICENSE)). Each listed
plugin carries its own license as declared in its manifest.
