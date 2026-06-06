# Review Policy

## Fast-merge (Community tier)

A PR is eligible for fast-merge when **all** of these hold:

- CI is green.
- No `read:aggregated_values` and no `write:external_output`.
- `ui_type` is not `webview`.
- `execution_mode` is not `sidecar`.

Fast-merge target: under 1 business day.

## Security review (Verified tier)

Required when the plugin requests any of: `read:aggregated_values`,
`write:external_output`, `network:fetch`, `ai:inference`, a `webview` UI, or a
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

## Removal

Open a PR deleting `plugins/<id>/`. Already-installed users keep their installed
version; the plugin stops appearing for new users within 24h (registry TTL).

## Appeals

Comment on the existing PR. Do not open a duplicate PR for the same `id`.
