#!/usr/bin/env node
// Generate index.json — the catalog the HelloHQ app's Plugin Browser fetches —
// from every plugins/<id>/manifest.json. Deterministic (no timestamp) so a
// `--check` run can diff it byte-for-byte in CI.
//
//   node scripts/build-index.mjs          # write index.json
//   node scripts/build-index.mjs --check  # fail if index.json is out of date
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const RAW_BASE =
  'https://raw.githubusercontent.com/HelloHQ/plugin-registry/main';
const PLUGINS_DIR = 'plugins';

const entries = [];
for (const dir of readdirSync(PLUGINS_DIR, { withFileTypes: true })) {
  if (!dir.isDirectory()) continue;
  const manifestPath = join(PLUGINS_DIR, dir.name, 'manifest.json');
  let m;
  try {
    m = JSON.parse(readFileSync(manifestPath, 'utf8'));
  } catch {
    continue; // a directory without a manifest is ignored
  }
  const entry = {
    id: m.id,
    name: m.name,
    version: m.version,
    description: m.description ?? '',
    author: m.author ?? '',
    categories: m.categories ?? [],
    trust_tier: m.trust_tier ?? 'community',
    provenance: m.provenance ?? 'community',
    manifest_url: `${RAW_BASE}/plugins/${m.id}/manifest.json`,
    permissions: (m.permissions ?? []).map((p) =>
      typeof p === 'string' ? p : p.id,
    ),
  };
  // Carry a compact licensing summary for the catalog badge (the manifest
  // holds the authoritative copy). Defaults to open-source.
  const lic = m.licensing ?? {};
  entry.licensing = {
    kind: lic.kind ?? 'open_source',
    ...(lic.spdx != null ? { spdx: lic.spdx } : {}),
    ...(lic.product_id != null ? { product_id: lic.product_id } : {}),
    ...(lic.price_cents != null ? { price_cents: lic.price_cents } : {}),
    ...(lic.currency != null ? { currency: lic.currency } : {}),
    ...(lic.pricing_model != null ? { pricing_model: lic.pricing_model } : {}),
  };
  entries.push(entry);
}

entries.sort((a, b) => a.id.localeCompare(b.id));
const out = JSON.stringify({ schema_version: 1, plugins: entries }, null, 2) + '\n';

if (process.argv.includes('--check')) {
  let existing = '';
  try {
    existing = readFileSync('index.json', 'utf8');
  } catch {
    console.error('index.json is missing. Run: node scripts/build-index.mjs');
    process.exit(1);
  }
  if (existing !== out) {
    console.error(
      'index.json is out of date. Regenerate with: node scripts/build-index.mjs',
    );
    process.exit(1);
  }
  console.log(`index.json is up to date (${entries.length} plugin(s))`);
} else {
  writeFileSync('index.json', out);
  console.log(`Wrote index.json with ${entries.length} plugin(s)`);
}
