#!/usr/bin/env node
// The artifact statement a publisher signature covers (SA5).
//
// A manifest's `signatures[]` are NOT over the plugin file itself: the signer
// (a managed KMS key) only signs inputs up to 64 KiB, and plugin files run to
// megabytes. Each signature covers this short statement instead. The app
// rebuilds the same bytes from the manifest after it has checked the
// downloaded file against content_hash_sha256, so the signature still binds
// the executed bytes — and it also binds the plugin id, version, trust tier,
// execution mode and the UI bundle hash, so a signature cannot be moved to
// another plugin, version or tier, and the UI bundle is covered too.
//
// Format (v1): UTF-8, seven LF-terminated lines, in this order:
//
//   hellohq-plugin-artifact/v1
//   id=<id>
//   version=<version>
//   trust_tier=<trust_tier, "community" when absent>
//   execution_mode=<execution_mode, "wasm" when absent>
//   content_hash_sha256=<64 lowercase hex>
//   ui_bundle_hash_sha256=<64 lowercase hex, or empty when absent>
//
// The app (HelloHQ/hellohq lib/app/data/model/plugin/plugin_artifact_statement
// .dart) builds the same bytes; tests/fixtures/artifact-statement-vectors.json
// is checked by both. Changing the format is a new version line, never an edit.
//
//   node scripts/artifact-statement.mjs plugins/<id>/manifest.json > statement
import { readFileSync, writeSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export const ARTIFACT_STATEMENT_VERSION = 'hellohq-plugin-artifact/v1';

const HEX64 = /^[a-f0-9]{64}$/;

/** The statement bytes for [manifest]. Throws on any value that would make
 *  the statement ambiguous (a line break) or a hash that is not lowercase hex. */
export function artifactStatement(manifest) {
  const field = (name, value) => {
    if (typeof value !== 'string') {
      throw new Error(`artifact statement: ${name} must be a string`);
    }
    if (/[\r\n]/.test(value)) {
      throw new Error(`artifact statement: ${name} contains a line break`);
    }
    return `${name}=${value}\n`;
  };
  const hash = (name, value, { optional = false } = {}) => {
    if (optional && value == null) return field(name, '');
    if (typeof value !== 'string' || !HEX64.test(value)) {
      throw new Error(`artifact statement: ${name} must be 64 lowercase hex`);
    }
    return field(name, value);
  };
  const text =
    `${ARTIFACT_STATEMENT_VERSION}\n` +
    field('id', manifest.id) +
    field('version', manifest.version) +
    field('trust_tier', manifest.trust_tier ?? 'community') +
    field('execution_mode', manifest.execution_mode ?? 'wasm') +
    hash('content_hash_sha256', manifest.content_hash_sha256) +
    hash('ui_bundle_hash_sha256', manifest.ui_bundle_hash_sha256, {
      optional: true,
    });
  return Buffer.from(text, 'utf8');
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const path = process.argv[2];
  if (!path) {
    console.error('usage: node scripts/artifact-statement.mjs <manifest.json>');
    process.exit(2);
  }
  writeSync(1, artifactStatement(JSON.parse(readFileSync(path, 'utf8'))));
}
