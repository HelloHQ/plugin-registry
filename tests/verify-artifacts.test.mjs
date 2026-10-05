// Artifact download + pin checks (scripts/verify-artifacts.mjs).
//   node --test tests/
// The wasm-tools tests need `wasm-tools` on PATH (validate.yml installs it);
// they are skipped locally without it.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  MAX_ARTIFACT_BYTES,
  MAX_ICON_BYTES,
  PLACEHOLDER_HASH,
  artifactProblems,
  svgIconProblem,
  wasmToolsValidate,
} from "../scripts/verify-artifacts.mjs";

const sha = (b) => createHash("sha256").update(b).digest("hex");
const CORE = Buffer.from([0, 0x61, 0x73, 0x6d, 1, 0, 0, 0]); // empty core module
const COMPONENT = Buffer.from([0, 0x61, 0x73, 0x6d, 0x0d, 0, 1, 0]); // empty component
const UI = Buffer.from("PK fake ui bundle");
const hasWasmTools = !spawnSync("wasm-tools", ["--version"]).error;

const files = {
  "https://example.com/plugin.wasm": COMPONENT,
  "https://example.com/ui.zip": UI,
};
const fakeFetch = (served = files) => async (url) =>
  served[url] === undefined
    ? { ok: false, status: 404 }
    : { ok: true, status: 200, arrayBuffer: async () => served[url] };
const okValidator = () => null;

const manifest = (over = {}) => ({
  id: "com.example.demo",
  version: "1.0.0",
  wasm_url: "https://example.com/plugin.wasm",
  content_hash_sha256: sha(COMPONENT),
  ...over,
});
const check = (m, opts = {}) =>
  artifactProblems(m, { fetchImpl: fakeFetch(), validateWasm: okValidator, ...opts });

test("a manifest whose files match its pins passes", async () => {
  assert.deepEqual(await check(manifest()), []);
  assert.deepEqual(
    await check(manifest({ ui_bundle_url: "https://example.com/ui.zip", ui_bundle_hash_sha256: sha(UI) })),
    [],
  );
});

test("the placeholder content hash is an error and nothing is downloaded", async () => {
  let fetched = 0;
  const problems = await check(manifest({ content_hash_sha256: PLACEHOLDER_HASH }), {
    fetchImpl: async () => { fetched++; return { ok: false, status: 500 }; },
  });
  assert.equal(problems.length, 1);
  assert.match(problems[0], /wasm_url hash is the all-zero placeholder/);
  assert.equal(fetched, 0);
});

test("a hash mismatch is an error", async () => {
  const problems = await check(manifest({ content_hash_sha256: sha(CORE) }));
  assert.match(problems[0], /wasm_url SHA-256 mismatch/);
});

test("an unreachable, non-https or oversized file is an error", async () => {
  assert.match((await check(manifest({ wasm_url: "https://example.com/gone.wasm" })))[0], /HTTP 404/);
  assert.match((await check(manifest({ wasm_url: "http://example.com/plugin.wasm" })))[0], /not an https URL/);
  const big = Buffer.alloc(MAX_ARTIFACT_BYTES + 1);
  const problems = await check(manifest({ content_hash_sha256: sha(big) }), {
    fetchImpl: fakeFetch({ "https://example.com/plugin.wasm": big }),
  });
  assert.match(problems[0], /larger than/);
});

test("a Wasm plugin must validate; a sidecar plugin is not run through it", async () => {
  const bad = () => "boom";
  assert.match((await check(manifest(), { validateWasm: bad }))[0], /not valid WebAssembly: boom/);
  assert.match((await check(manifest({ execution_mode: "wasm" }), { validateWasm: bad }))[0], /boom/);
  assert.deepEqual(await check(manifest({ execution_mode: "sidecar" }), { validateWasm: bad }), []);
});

test("UI bundle: url and hash together, real hash, matching bytes", async () => {
  const url = "https://example.com/ui.zip";
  assert.match((await check(manifest({ ui_bundle_url: url })))[0], /both be set or both be absent/);
  assert.match((await check(manifest({ ui_bundle_hash_sha256: sha(UI) })))[0], /both be set or both be absent/);
  assert.match(
    (await check(manifest({ ui_bundle_url: url, ui_bundle_hash_sha256: PLACEHOLDER_HASH })))[0],
    /ui_bundle_url hash is the all-zero placeholder/,
  );
  assert.match(
    (await check(manifest({ ui_bundle_url: url, ui_bundle_hash_sha256: sha(CORE) })))[0],
    /ui_bundle_url SHA-256 mismatch/,
  );
});

test("problems in both files are all reported", async () => {
  const problems = await check(manifest({
    content_hash_sha256: PLACEHOLDER_HASH,
    ui_bundle_url: "https://example.com/ui.zip",
    ui_bundle_hash_sha256: PLACEHOLDER_HASH,
  }));
  assert.equal(problems.length, 2);
});

test("WAT text and other non-binary content are refused before wasm-tools runs", () => {
  for (const b of [Buffer.from("(module)"), Buffer.from("nope"), Buffer.alloc(0), CORE.subarray(0, 4)]) {
    assert.match(wasmToolsValidate(b), /not a WebAssembly binary/);
  }
});

test("wasm-tools accepts a core module and a component, rejects a broken one", { skip: !hasWasmTools }, () => {
  assert.equal(wasmToolsValidate(CORE), null);
  assert.equal(wasmToolsValidate(COMPONENT), null);
  assert.notEqual(wasmToolsValidate(Buffer.concat([CORE, Buffer.from([0x99])])), null);
});

test("validate.yml runs the artifact check and installs wasm-tools", () => {
  const wf = readFileSync(new URL("../.github/workflows/validate.yml", import.meta.url), "utf8");
  assert.match(wf, /node scripts\/verify-artifacts\.mjs "\$manifest"/);
  assert.match(wf, /bin\/wasm-tools" --version/);
  assert.match(wf, /sha256sum -c -/, "the wasm-tools download is hash-pinned");
  assert.doesNotMatch(wf, /apt-get install -y wabt|^\s*if ! wasm-validate/m, "wabt cannot validate components");
});

// ── sidebar_icon ────────────────────────────────────────────────────────────
const ICON = Buffer.from(
  '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 24 24">' +
  '<defs><linearGradient id="g"><stop offset="0"/></linearGradient><path id="p" d="M0 0h24v24H0z"/></defs>' +
  '<use href="#p" fill="url(#g)"/><use xlink:href="#p"/><path d="M4 4h16v16H4z" fill="currentColor"/></svg>',
);
const ICON_URL = "https://example.com/icon.svg";
const withIcon = (over = {}) => manifest({ sidebar_icon: ICON_URL, sidebar_icon_hash_sha256: sha(ICON), ...over });
const iconFetch = (icon = ICON) => fakeFetch({ ...files, [ICON_URL]: icon });

test("a pinned, plain SVG icon passes", async () => {
  assert.deepEqual(await check(withIcon(), { fetchImpl: iconFetch() }), []);
});

test("an https icon without a hash warns now and fails once required", async () => {
  const warnings = [];
  const m = manifest({ sidebar_icon: ICON_URL });
  assert.deepEqual(await check(m, { fetchImpl: iconFetch(), warn: (w) => warnings.push(w) }), []);
  assert.match(warnings[0], /no sidebar_icon_hash_sha256/);
  const problems = await check(m, { fetchImpl: iconFetch(), requireIconHash: true });
  assert.match(problems[0], /no sidebar_icon_hash_sha256/);
});

test("icon hash mismatch, placeholder, oversize and non-https fail", async () => {
  assert.match((await check(withIcon({ sidebar_icon_hash_sha256: sha(UI) }), { fetchImpl: iconFetch() }))[0], /sidebar_icon SHA-256 mismatch/);
  assert.match((await check(withIcon({ sidebar_icon_hash_sha256: PLACEHOLDER_HASH }), { fetchImpl: iconFetch() }))[0], /placeholder/);
  const big = Buffer.concat([ICON, Buffer.alloc(MAX_ICON_BYTES)]);
  assert.match((await check(withIcon({ sidebar_icon_hash_sha256: sha(big) }), { fetchImpl: iconFetch(big) }))[0], /larger than 65536/);
  for (const url of ["http://example.com/icon.svg", "data:image/svg+xml,<svg/>", "file:///etc/icon.svg"]) {
    assert.match((await check(withIcon({ sidebar_icon: url }), { fetchImpl: iconFetch() }))[0], /must be an https URL/, url);
  }
});

test("a bundle-path icon needs no hash; a hash without an https icon is refused", async () => {
  assert.deepEqual(await check(manifest({ sidebar_icon: "icons/plugin.svg" })), []);
  assert.match((await check(manifest({ sidebar_icon: "icons/plugin.svg", sidebar_icon_hash_sha256: sha(ICON) })))[0], /applies only to an https sidebar_icon/);
  assert.match((await check(manifest({ sidebar_icon_hash_sha256: sha(ICON) })))[0], /sidebar_icon is not/);
});

test("unsafe or non-SVG icons are refused", async () => {
  const bad = {
    "<svg><script>alert(1)</script></svg>": /<script>/,
    "<svg><foreignObject><div/></foreignObject></svg>": /foreignObject/,
    '<svg onload="x()"></svg>': /event-handler/,
    '<svg><a href="https://evil.example/">x</a></svg>': /outside the file \(href\)/,
    '<svg><use xlink:href="https://evil.example/s.svg#a"/></svg>': /outside the file \(href\)/,
    '<svg><path fill="url(https://evil.example/p)"/></svg>': /outside the file \(url\(\)\)/,
    '<svg><style>@import "https://evil.example/x.css";</style></svg>': /@import|element that can load/,
    "<svg><image width=\"1\"/></svg>": /element that can load/,
    '<!DOCTYPE svg [<!ENTITY x "y">]><svg/>': /entity|DOCTYPE/,
    '<svg><a href="javascript:alert(1)"/></svg>': /javascript:|href/,
    "<html><body/></html>": /no <svg> element/,
  };
  for (const [text, re] of Object.entries(bad)) {
    assert.match(svgIconProblem(Buffer.from(text)) ?? "ok", re, text);
    const b = Buffer.from(text);
    const problems = await check(withIcon({ sidebar_icon_hash_sha256: sha(b) }), { fetchImpl: iconFetch(b) });
    assert.equal(problems.length, 1, text);
  }
  assert.match(svgIconProblem(Buffer.from([0xff, 0xfe, 0x00])), /not UTF-8/);
});
