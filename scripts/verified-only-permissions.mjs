#!/usr/bin/env node
// Prints, one per line, every Verified-only permission id a manifest declares
// through its `permissions` list. CI (.github/workflows/validate.yml, step 6)
// uses it so the rule is testable (tests/verified-only-permissions.test.mjs).
//
// `propose:*` is matched by PREFIX, not by a list: a propose permission added
// later (for example the deferred `propose:transactions`) is Verified-only from
// the day it exists, the same rule the HelloHQ app applies at run time.
//
// `ai:inference` and `write:external_output` are still listed in the workflow
// itself and are not duplicated here.
//
//   node scripts/verified-only-permissions.mjs plugins/<id>/manifest.json
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

export const VERIFIED_ONLY_PREFIXES = ["propose:"];

/** Verified-only permission ids in [manifest] (an already-parsed object). */
export function verifiedOnlyPermissions(manifest) {
  const perms = Array.isArray(manifest?.permissions) ? manifest.permissions : [];
  const out = [];
  for (const p of perms) {
    const id = p?.id;
    if (typeof id !== "string") continue;
    if (VERIFIED_ONLY_PREFIXES.some((prefix) => id.startsWith(prefix))) out.push(id);
  }
  return out;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  const file = process.argv[2];
  if (!file) {
    console.error("usage: verified-only-permissions.mjs <manifest.json>");
    process.exit(2);
  }
  for (const id of verifiedOnlyPermissions(JSON.parse(readFileSync(file, "utf8")))) {
    console.log(id);
  }
}
