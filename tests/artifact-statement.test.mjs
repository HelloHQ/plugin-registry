// Artifact statement (SA5) and signature stamping.
//   node --test tests/
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { generateKeyPairSync, sign, verify } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  ARTIFACT_STATEMENT_VERSION,
  artifactStatement,
} from "../scripts/artifact-statement.mjs";
import { prSignatureProblem } from "../scripts/check-pr-signatures.mjs";
import { stampSignatures } from "../scripts/stamp-artifact-signatures.mjs";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020");
const addFormats = require("ajv-formats");

const read = (p) => JSON.parse(readFileSync(new URL(p, import.meta.url), "utf8"));
const schema = read("../schema/manifest.schema.json");
const { vectors } = read("./fixtures/artifact-statement-vectors.json");
const scriptPath = (name) => fileURLToPath(new URL(`../scripts/${name}`, import.meta.url));

const ajv = new (Ajv2020.default ?? Ajv2020)({ strict: false, allErrors: true });
(addFormats.default ?? addFormats)(ajv);
const validate = ajv.compile(schema);

const base = () => ({
  ...read("./fixtures/valid-propose.json"),
  content_hash_sha256: "ab".repeat(32),
});
const sigs = () => [
  { sig_alg: "ed25519", key_id: "hellohq-official-ed25519-2026-01", bytes: Buffer.from([1, 2, 3]) },
  { sig_alg: "ml-dsa-65", key_id: "hellohq-official-ml-dsa-65-2026-01", bytes: Buffer.from([4, 5, 6]) },
];

test("every shared vector builds its exact statement", () => {
  assert.ok(vectors.length >= 3);
  for (const v of vectors) {
    assert.equal(artifactStatement(v.manifest).toString("utf8"), v.statement, v.name);
  }
});

test("the format is seven LF-terminated lines starting with the version", () => {
  const text = artifactStatement(vectors[0].manifest).toString("utf8");
  assert.ok(text.startsWith(`${ARTIFACT_STATEMENT_VERSION}\n`));
  assert.ok(text.endsWith("\n"));
  assert.ok(!text.includes("\r"));
  assert.equal(text.split("\n").length, 8); // 7 lines + the empty tail
});

test("absent tier, mode and UI hash take their defaults", () => {
  const text = artifactStatement({
    id: "com.example.a", version: "1.0.0", content_hash_sha256: "cd".repeat(32),
  }).toString("utf8");
  assert.match(text, /\ntrust_tier=community\n/);
  assert.match(text, /\nexecution_mode=wasm\n/);
  assert.ok(text.endsWith("\nui_bundle_hash_sha256=\n"));
});

test("a line break in any field is refused, never signed", () => {
  for (const key of ["id", "version", "trust_tier", "execution_mode"]) {
    for (const bad of ["x\ny", "x\r", "\nx"]) {
      const m = { ...vectors[0].manifest, [key]: bad };
      assert.throws(() => artifactStatement(m), /line break/, `${key}=${JSON.stringify(bad)}`);
    }
  }
});

test("hashes must be 64 lowercase hex", () => {
  const m = vectors[0].manifest;
  for (const bad of ["AB".repeat(32), "ab".repeat(31), "zz".repeat(32), "", 7, null]) {
    assert.throws(() => artifactStatement({ ...m, content_hash_sha256: bad }), /lowercase hex/);
  }
  assert.throws(() => artifactStatement({ ...m, ui_bundle_hash_sha256: "AB".repeat(32) }), /lowercase hex/);
  assert.throws(() => artifactStatement({ ...m, ui_bundle_hash_sha256: "" }), /lowercase hex/);
});

test("a non-string field is refused", () => {
  assert.throws(() => artifactStatement({ ...vectors[0].manifest, version: 1 }), /must be a string/);
  assert.throws(() => artifactStatement({ ...vectors[0].manifest, id: undefined }), /must be a string/);
});

test("the CLI writes exactly the statement bytes", () => {
  const dir = mkdtempSync(join(tmpdir(), "stmt-"));
  for (const v of vectors) {
    const path = join(dir, "manifest.json");
    writeFileSync(path, JSON.stringify(v.manifest));
    const out = execFileSync(process.execPath, [scriptPath("artifact-statement.mjs"), path]);
    assert.equal(out.toString("utf8"), v.statement, v.name);
  }
});

test("schema: signatures use sig_alg, the field the app reads", () => {
  const stamped = stampSignatures(base(), sigs());
  assert.equal(validate(stamped), true, JSON.stringify(validate.errors));
  const legacy = {
    ...base(),
    signatures: [{ alg: "ed25519", key_id: "k", signature: "AQID" }],
  };
  assert.equal(validate(legacy), false, "the old `alg` field must be rejected");
  const noAlg = { ...base(), signatures: [{ key_id: "k", signature: "AQID" }] };
  assert.equal(validate(noAlg), false);
  const unknownAlg = { ...base(), signatures: [{ sig_alg: "rsa", key_id: "k", signature: "AQID" }] };
  assert.equal(validate(unknownAlg), false);
  const emptySig = { ...base(), signatures: [{ sig_alg: "ed25519", key_id: "k", signature: "" }] };
  assert.equal(validate(emptySig), false);
});

test("stamping writes one entry per algorithm and replaces old ones", () => {
  const old = { ...base(), signatures: [{ sig_alg: "ed25519", key_id: "stale", signature: "AA==" }] };
  const out = stampSignatures(old, sigs());
  assert.deepEqual(out.signatures, [
    { key_id: "hellohq-official-ed25519-2026-01", sig_alg: "ed25519", signature: "AQID" },
    { key_id: "hellohq-official-ml-dsa-65-2026-01", sig_alg: "ml-dsa-65", signature: "BAUG" },
  ]);
  const { signatures: _a, ...restOut } = out;
  const { signatures: _b, ...restOld } = old;
  assert.deepEqual(restOut, restOld, "nothing else changes");
});

test("stamping refuses anything short of a full hybrid pair", () => {
  const [ed, pq] = sigs();
  assert.throws(() => stampSignatures(base(), [ed]), /exactly one signature per algorithm/);
  assert.throws(() => stampSignatures(base(), [pq]), /exactly one signature per algorithm/);
  assert.throws(() => stampSignatures(base(), [ed, ed]), /exactly one signature per algorithm/);
  assert.throws(() => stampSignatures(base(), [ed, pq, ed]), /exactly one signature per algorithm/);
  assert.throws(() => stampSignatures(base(), []), /got none/);
  assert.throws(() => stampSignatures(base(), [ed, { ...pq, bytes: Buffer.alloc(0) }]), /empty ml-dsa-65/);
  assert.throws(() => stampSignatures(base(), [{ ...ed, key_id: "a:b" }, pq]), /bad key_id/);
});

test("stamping does not change the statement, so the signature still verifies", () => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const manifest = base();
  const sig = sign(null, artifactStatement(manifest), privateKey);
  const stamped = stampSignatures(manifest, [
    { sig_alg: "ed25519", key_id: "k-ed", bytes: sig },
    { sig_alg: "ml-dsa-65", key_id: "k-pq", bytes: Buffer.from([9]) },
  ]);
  const roundTrip = JSON.parse(JSON.stringify(stamped));
  const back = Buffer.from(roundTrip.signatures[0].signature, "base64");
  assert.ok(verify(null, artifactStatement(roundTrip), publicKey, back));
  // ...and the same signature does not verify for another version or tier.
  for (const change of [{ version: "1.0.1" }, { trust_tier: "official" }, { content_hash_sha256: "cd".repeat(32) }]) {
    assert.ok(!verify(null, artifactStatement({ ...roundTrip, ...change }), publicKey, back), JSON.stringify(change));
  }
});

test("the stamping CLI rewrites the manifest in place", () => {
  const dir = mkdtempSync(join(tmpdir(), "stamp-"));
  const path = join(dir, "manifest.json");
  writeFileSync(path, JSON.stringify(base()));
  writeFileSync(join(dir, "ed.sig"), Buffer.from([1, 2, 3]));
  writeFileSync(join(dir, "pq.sig"), Buffer.from([4, 5, 6]));
  execFileSync(process.execPath, [
    scriptPath("stamp-artifact-signatures.mjs"), path,
    "--sig", `ed25519:k-ed:${join(dir, "ed.sig")}`,
    "--sig", `ml-dsa-65:k-pq:${join(dir, "pq.sig")}`,
  ]);
  const written = readFileSync(path, "utf8");
  assert.ok(written.endsWith("}\n"));
  const m = JSON.parse(written);
  assert.equal(validate(m), true, JSON.stringify(validate.errors));
  assert.deepEqual(m.signatures.map((s) => s.sig_alg), ["ed25519", "ml-dsa-65"]);
});

// ── PR signature rule (scripts/check-pr-signatures.mjs) ─────────────────────

test("PR: unsigned manifests are always fine", () => {
  assert.equal(prSignatureProblem(null, base()), null);
  assert.equal(prSignatureProblem(base(), { ...base(), version: "1.0.1" }), null);
});

test("PR: a new plugin may not arrive signed", () => {
  assert.match(prSignatureProblem(null, stampSignatures(base(), sigs())), /new plugin/);
});

test("PR: unchanged signatures on an unchanged statement are kept", () => {
  const signed = stampSignatures(base(), sigs());
  assert.equal(prSignatureProblem(signed, structuredClone(signed)), null);
  // A change outside the statement (description) keeps them too.
  assert.equal(prSignatureProblem(signed, { ...structuredClone(signed), description: "new" }), null);
});

test("PR: dropping signatures is always allowed", () => {
  const signed = stampSignatures(base(), sigs());
  const { signatures: _s, ...dropped } = signed;
  assert.equal(prSignatureProblem(signed, { ...dropped, version: "2.0.0" }), null);
});

test("PR: adding or editing a signature is refused", () => {
  const signed = stampSignatures(base(), sigs());
  assert.match(prSignatureProblem(base(), signed), /only by the signing pipeline/);
  const edited = structuredClone(signed);
  edited.signatures[0].signature = "AAAA";
  assert.match(prSignatureProblem(signed, edited), /only by the signing pipeline/);
  const rekeyed = structuredClone(signed);
  rekeyed.signatures[1].key_id = "other";
  assert.match(prSignatureProblem(signed, rekeyed), /only by the signing pipeline/);
});

test("PR: changing what the signatures cover while keeping them is refused", () => {
  const signed = stampSignatures(base(), sigs());
  for (const change of [
    { version: "1.0.1" },
    { trust_tier: "official" },
    { execution_mode: "sidecar" },
    { content_hash_sha256: "cd".repeat(32) },
    { ui_bundle_hash_sha256: "ef".repeat(32) },
  ]) {
    assert.match(prSignatureProblem(signed, { ...structuredClone(signed), ...change }), /remove signatures/, JSON.stringify(change));
  }
});

test("PR: the CLI exits non-zero with the reason", () => {
  const dir = mkdtempSync(join(tmpdir(), "prsig-"));
  const head = join(dir, "head.json");
  writeFileSync(head, JSON.stringify(stampSignatures(base(), sigs())));
  let failed = false;
  try {
    execFileSync(process.execPath, [scriptPath("check-pr-signatures.mjs"), "", head]);
  } catch (e) {
    failed = true;
    assert.match(e.stdout.toString(), /new plugin/);
  }
  assert.ok(failed);
  const ok = join(dir, "ok.json");
  writeFileSync(ok, JSON.stringify(base()));
  execFileSync(process.execPath, [scriptPath("check-pr-signatures.mjs"), "", ok]);
});

test("validate.yml runs the PR signature rule", () => {
  const wf = readFileSync(new URL("../.github/workflows/validate.yml", import.meta.url), "utf8");
  assert.match(wf, /node scripts\/check-pr-signatures\.mjs "\$base_arg" "\$manifest"/);
});
