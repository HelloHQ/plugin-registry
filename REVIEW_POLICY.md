# Review Policy

## Fast-merge (Community tier)

A PR is eligible for fast-merge when **all** of these hold:

- CI is green.
- No `read:aggregated_values`, no `write:external_output` and no `propose:*`.
- `ui_type` is not `webview`.
- `execution_mode` is not `sidecar`.

Fast-merge target: under 1 business day.

## Security review (Verified tier)

Required when the plugin requests any of: `read:aggregated_values`,
`write:external_output`, `propose:holdings`, `propose:valuations`, `network:fetch`,
`ai:inference`, a `webview` UI, or a
Python `sidecar`. Target: 2–5 business days.

The reviewer checklist:

1. **Permission justification** — each sensitive permission is explained and
   proportionate to the stated purpose.
2. **Source audit** — the maintainer reads the plugin source. For closed-source
   plugins the author grants the security team read access to a private repo;
   `repo` may point to a public stub.
3. **Author identity** — `author_url` identifies the author of `repo`.
4. **Binary inspection** — static analysis beyond CI (import/export scan).
5. **For `network:fetch`** — declared origins are author-owned; no relaying of
   HelloHQ data to third parties. Justify why `ai:inference` is insufficient.
6. **For `ai:inference`** — the system prompt cannot exfiltrate data beyond the
   plugin's data permissions, and user input cannot override the system prompt.
7. **For a `webview` UI** — the plugin is Verified tier (a `webview` UI is never
   fast-merged as Community). The manifest's `ui_bundle` SHA-256 matches the
   shipped ZIP. The bundle is **self-contained**: no external CDN/script/style/
   font origins, and no `<script src>`, `fetch`, `XMLHttpRequest`, or WebSocket
   to any origin outside the declared `network:fetch` allowlist — the host
   injects a CSP and `Permissions-Policy` that block these, so a bundle that
   *depends* on them is broken and must be rejected. The bundle does not use
   camera, microphone, or geolocation (host policy denies them).
8. **Combined read + network (exfiltration)** — a plugin holding **both** a
   sensitive `read:*` permission (public `read:currency_rates` excepted) **and**
   `network:fetch` can forward what it reads off-device via `compute`→wasm to an
   allowlisted origin. Scrutinise the pairing: every declared origin is
   author-owned, and the plugin's stated purpose genuinely requires sending
   portfolio-derived data there. The app surfaces this pairing to the user at
   consent (a distinct warning naming the origins), but this registry review is
   the gate that keeps a malicious pairing out.
9. **For `propose:holdings` / `propose:valuations`** — the plugin can only
   *suggest*: the person approves every proposal in the app, and nothing is
   written before that. Check that `scope.kinds` lists only the asset kinds the
   plugin needs, that every source key it proposes against is something it
   really fetched (a wallet address, an exchange asset code), and that
   `display_name` / `source.reference` text carries no links or instructions.
   A plugin that proposes in bulk must justify the volume (the host caps a call
   at 200 proposals).

## Removal

Open a PR deleting `plugins/<id>/`. Already-installed users keep their installed
version; the plugin stops appearing for new users within 24h (registry TTL).

## Appeals

Comment on the existing PR. Do not open a duplicate PR for the same `id`.
