#!/usr/bin/env node
// Download a manifest's artifacts and check them against its pins.
//
// Every artifact the app installs is pinned by a hash in the manifest, and the
// app refuses bytes that do not match. This check makes the registry refuse
// them first, so a plugin is never listed with a file nobody has verified:
//
//   - content_hash_sha256 must be a real hash (never the all-zero placeholder),
//     and wasm_url must serve exactly those bytes;
//   - a Wasm plugin's file must be valid WebAssembly, a core module or a
//     component (`wasm-tools validate`; wabt's wasm-validate rejects
//     components);
//   - ui_bundle_url and ui_bundle_hash_sha256 come together, the hash is real,
//     and the URL serves exactly those bytes;
//   - an https sidebar_icon is pinned by sidebar_icon_hash_sha256, served
//     exactly, at most 64 KiB, and a plain SVG: no script, foreignObject, event
//     handler, entity declaration or external reference. (The app draws the
//     verified local copy; a webview plugin's icon may instead be a path inside
//     its already-pinned UI bundle.)
//
//   node scripts/verify-artifacts.mjs plugins/<id>/manifest.json
//
// Prints one line per check; exits 1 with ::error annotations on any failure.
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const PLACEHOLDER_HASH = '0'.repeat(64);
export const MAX_ARTIFACT_BYTES = 64 * 1024 * 1024;
export const MAX_ICON_BYTES = 64 * 1024;

// While existing manifests gain sidebar_icon_hash_sha256, an unpinned https
// icon is a warning; flipped to an error once every listed plugin pins it.
export const REQUIRE_ICON_HASH = false;

/** Why [svg] is not a plain, self-contained SVG icon, or null. Text checks,
 *  deliberately strict: an icon needs none of these. */
export function svgIconProblem(bytes) {
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return 'is not UTF-8 text';
  }
  if (!/<svg[\s>/]/i.test(text)) return 'has no <svg> element';
  const banned = [
    [/<script/i, 'contains <script>'],
    [/<foreignObject/i, 'contains <foreignObject>'],
    [/<!ENTITY/i, 'declares an entity'],
    [/<!DOCTYPE/i, 'has a DOCTYPE'],
    [/\son[a-z]+\s*=/i, 'has an event-handler attribute'],
    [/@import/i, 'uses @import'],
    [/javascript:/i, 'contains a javascript: URL'],
    [/(?:xlink:)?href\s*=\s*["'](?!#)/i, 'references something outside the file (href)'],
    [/url\(\s*["']?(?!#)/i, 'references something outside the file (url())'],
    [/<(?:image|use|iframe|embed|object|audio|video|link|style)\b(?![^>]*href\s*=\s*["']#)/i, 'contains an element that can load external content'],
  ];
  for (const [re, why] of banned) if (re.test(text)) return why;
  return null;
}

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

async function download(url, fetchImpl, maxBytes = MAX_ARTIFACT_BYTES) {
  if (typeof url !== 'string' || !url.startsWith('https://')) {
    throw new Error('not an https URL');
  }
  const res = await fetchImpl(url, { redirect: 'follow' });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const bytes = Buffer.from(await res.arrayBuffer());
  if (bytes.length > maxBytes) {
    throw new Error(`larger than ${maxBytes} bytes`);
  }
  return bytes;
}

/** `wasm-tools validate` on [bytes]; returns an error string or null.
 *  wasm-tools also accepts WAT text, which the app cannot run, so the binary
 *  magic number is checked first. */
export function wasmToolsValidate(bytes) {
  if (bytes.length < 8 || !bytes.subarray(0, 4).equals(Buffer.from([0, 0x61, 0x73, 0x6d]))) {
    return 'not a WebAssembly binary (missing the \\0asm magic number)';
  }
  const dir = mkdtempSync(join(tmpdir(), 'wasm-'));
  try {
    const file = join(dir, 'artifact.wasm');
    writeFileSync(file, bytes);
    const r = spawnSync('wasm-tools', ['validate', '--features', 'all', file], {
      encoding: 'utf8',
    });
    if (r.error) return `could not run wasm-tools (${r.error.message})`;
    return r.status === 0 ? null : (r.stderr || 'invalid').trim().split('\n')[0];
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** Every problem with [manifest]'s artifacts (empty when all checks pass). */
export async function artifactProblems(
  manifest,
  {
    fetchImpl = fetch,
    validateWasm = wasmToolsValidate,
    log = () => {},
    warn = () => {},
    requireIconHash = REQUIRE_ICON_HASH,
  } = {},
) {
  const problems = [];
  const pinned = async (label, url, hash, maxBytes) => {
    if (hash === PLACEHOLDER_HASH) {
      problems.push(`${label} hash is the all-zero placeholder; pin the real SHA-256 of the released file`);
      return null;
    }
    let bytes;
    try {
      bytes = await download(url, fetchImpl, maxBytes);
    } catch (e) {
      problems.push(`could not download ${label} (${e.message}): ${url}`);
      return null;
    }
    const got = sha256(bytes);
    if (got !== hash) {
      problems.push(`${label} SHA-256 mismatch: want ${hash} got ${got}`);
      return null;
    }
    log(`  ${label} SHA-256 ${hash} (${bytes.length} bytes) ✅`);
    return bytes;
  };

  const wasm = await pinned('wasm_url', manifest.wasm_url, manifest.content_hash_sha256);
  if (wasm && (manifest.execution_mode ?? 'wasm') === 'wasm') {
    const err = validateWasm(wasm);
    if (err) problems.push(`wasm_url is not valid WebAssembly: ${err}`);
    else log('  wasm-tools validate ✅');
  }

  const hasUrl = manifest.ui_bundle_url != null;
  const hasHash = manifest.ui_bundle_hash_sha256 != null;
  if (hasUrl !== hasHash) {
    problems.push('ui_bundle_url and ui_bundle_hash_sha256 must both be set or both be absent');
  } else if (hasUrl) {
    await pinned('ui_bundle_url', manifest.ui_bundle_url, manifest.ui_bundle_hash_sha256);
  }

  const icon = manifest.sidebar_icon;
  const iconHash = manifest.sidebar_icon_hash_sha256;
  if (typeof icon === 'string' && /^[a-z][a-z0-9+.-]*:/i.test(icon)) {
    if (!icon.startsWith('https://')) {
      problems.push('sidebar_icon must be an https URL (or a path inside the UI bundle)');
    } else if (iconHash == null) {
      const msg = 'sidebar_icon has no sidebar_icon_hash_sha256; the app will show a generic icon instead';
      if (requireIconHash) problems.push(msg);
      else warn(msg);
    } else {
      const svg = await pinned('sidebar_icon', icon, iconHash, MAX_ICON_BYTES);
      if (svg) {
        const why = svgIconProblem(svg);
        if (why) problems.push(`sidebar_icon ${why}`);
        else log('  sidebar_icon is a plain SVG ✅');
      }
    }
  } else if (icon == null && iconHash != null) {
    problems.push('sidebar_icon_hash_sha256 is set but sidebar_icon is not');
  } else if (icon != null && iconHash != null) {
    problems.push('sidebar_icon_hash_sha256 applies only to an https sidebar_icon; a bundle-path icon is pinned by the UI bundle');
  }
  return problems;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const path = process.argv[2];
  if (!path) {
    console.error('usage: node scripts/verify-artifacts.mjs <manifest.json>');
    process.exit(2);
  }
  const manifest = JSON.parse(readFileSync(path, 'utf8'));
  const problems = await artifactProblems(manifest, {
    log: (l) => console.log(l),
    warn: (w) => console.log(`::warning file=${path}::${w}`),
  });
  for (const p of problems) console.log(`::error file=${path}::${p}`);
  process.exit(problems.length ? 1 : 0);
}
