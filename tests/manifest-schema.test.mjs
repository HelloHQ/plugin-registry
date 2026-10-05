// Schema + CI-helper tests for the propose-only permissions.
//   node --test tests/
// Needs `ajv@8` and `ajv-formats` resolvable (the validate workflow installs
// them next to the checkout).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { createRequire } from "node:module";
import { verifiedOnlyPermissions } from "../scripts/verified-only-permissions.mjs";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020");
const addFormats = require("ajv-formats");

const read = (p) => JSON.parse(readFileSync(new URL(p, import.meta.url), "utf8"));
const schema = read("../schema/manifest.schema.json");
const fixture = (name) => read(`./fixtures/${name}.json`);

const ajv = new (Ajv2020.default ?? Ajv2020)({ strict: false, allErrors: true });
(addFormats.default ?? addFormats)(ajv);
const validate = ajv.compile(schema);
const ok = (m) => validate(m) === true;

// MUST equal PluginProposePermission.kinds in HelloHQ/hellohq
// (lib/app/data/model/plugin/plugin_propose_scope.dart).
const HELLOHQ_KINDS = [
  "stock_ticker", "crypto_ticker", "crypto_exchange", "home",
  "car", "precious_metal", "domain", "loan_mortgage",
];

test("permission id enum lists both propose ids", () => {
  const ids = schema.properties.permissions.items.properties.id.enum;
  assert.ok(ids.includes("propose:holdings"));
  assert.ok(ids.includes("propose:valuations"));
  assert.ok(!ids.includes("propose:transactions"), "transactions is deferred");
});

test("kind enum equals the hellohq kind set exactly", () => {
  const rule = schema.properties.permissions.items.allOf.find((r) =>
    JSON.stringify(r.if).includes("propose:holdings"));
  const kinds = rule.then.properties.scope.properties.kinds.items.enum;
  assert.deepEqual([...kinds].sort(), [...HELLOHQ_KINDS].sort());
});

test("existing hello-world manifest still validates", () => {
  assert.ok(ok(read("../plugins/com.hellohq.hello-world/manifest.json")),
    JSON.stringify(validate.errors));
});

for (const name of ["valid-propose", "valid-all-kinds"]) {
  test(`${name} validates`, () => {
    assert.ok(ok(fixture(name)), JSON.stringify(validate.errors));
  });
}

const invalid = readdirSync(new URL("./fixtures", import.meta.url))
  .filter((f) => f.startsWith("invalid-"))
  .map((f) => f.replace(/\.json$/, ""));

test("there are invalid fixtures to run", () => assert.ok(invalid.length >= 9));

for (const name of invalid) {
  test(`${name} is rejected`, () => {
    assert.equal(ok(fixture(name)), false);
  });
}

test("a propose permission without scope.kinds fails on scope, with a path", () => {
  assert.equal(ok(fixture("invalid-missing-scope")), false);
  assert.ok(validate.errors.some((e) => e.instancePath.startsWith("/permissions/0")));
});

test("every propose permission is checked, not just the first", () => {
  assert.equal(ok(fixture("invalid-second-permission-unscoped")), false);
  assert.ok(validate.errors.some((e) => e.instancePath.startsWith("/permissions/1")));
});

test("other permissions are unaffected by the propose rule", () => {
  const m = fixture("valid-propose");
  m.permissions.push({ id: "plugin:storage" });
  assert.ok(ok(m), JSON.stringify(validate.errors));
});

// --- Verified-only (CI step 6 helper) --------------------------------------

test("a Community manifest declaring propose is flagged Verified-only", () => {
  for (const name of ["community-propose", "community-propose-no-tier"]) {
    const m = fixture(name);
    assert.notEqual(m.trust_tier, "verified");
    assert.ok(verifiedOnlyPermissions(m).length > 0, name);
  }
});

test("the helper flags every propose id, known or future, and nothing else", () => {
  assert.deepEqual(
    verifiedOnlyPermissions({ permissions: [
      { id: "propose:holdings" }, { id: "plugin:storage" },
      { id: "propose:transactions" }, { id: "network:fetch" },
    ] }),
    ["propose:holdings", "propose:transactions"],
  );
});

test("the helper is total on malformed manifests", () => {
  for (const m of [null, undefined, 1, "x", [], {}, { permissions: 3 },
    { permissions: [null, 1, {}, { id: 5 }] }]) {
    assert.deepEqual(verifiedOnlyPermissions(m), []);
  }
});

test("validate.yml still wires the helper into the tier check", () => {
  const yml = readFileSync(new URL("../.github/workflows/validate.yml", import.meta.url), "utf8");
  assert.ok(yml.includes("scripts/verified-only-permissions.mjs"));
  assert.ok(yml.includes("node --test tests/*.test.mjs"));
});
