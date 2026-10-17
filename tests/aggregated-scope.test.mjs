// read:aggregated_values needs an explicit portfolio scope, except in a
// first-party plugin (trust_tier official AND provenance core).
//   node --test tests/
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020");
const addFormats = require("ajv-formats");

const read = (p) => JSON.parse(readFileSync(new URL(p, import.meta.url), "utf8"));
const ajv = new (Ajv2020.default ?? Ajv2020)({ strict: false, allErrors: true });
(addFormats.default ?? addFormats)(ajv);
const validate = ajv.compile(read("../schema/manifest.schema.json"));
const ok = (m) => validate(m) === true;

// A valid Official sidecar manifest (hello-python) to vary.
const base = read("../plugins/com.hellohq.hello-python/manifest.json");
const AGG = { id: "read:aggregated_values" };
const SCOPED = { id: "read:aggregated_values", scope: { portfolios: ["ptf_abc"] } };
const make = ({ tier, provenance, permission }) => {
  const m = { ...base, permissions: [...base.permissions, permission] };
  if (tier === undefined) delete m.trust_tier; else m.trust_tier = tier;
  if (provenance === undefined) delete m.provenance; else m.provenance = provenance;
  return m;
};

test("the base manifest validates, so the cases below differ only in the rule", () => {
  assert.ok(ok(base), JSON.stringify(validate.errors));
  assert.ok(ok(make({ tier: "official", provenance: "core", permission: { id: "read:asset_count" } })));
});

test("an Official first-party plugin may omit the portfolio scope", () => {
  assert.ok(ok(make({ tier: "official", provenance: "core", permission: AGG })),
    JSON.stringify(validate.errors));
});

test("an Official first-party plugin may still give one", () => {
  assert.ok(ok(make({ tier: "official", provenance: "core", permission: SCOPED })));
});

test("any other plugin must give a portfolio scope", () => {
  for (const [tier, provenance] of [
    [undefined, undefined], // a fresh third-party submission
    [undefined, "community"],
    ["community", "community"],
    ["verified", "community"],
    ["verified", undefined],
    ["official", "community"], // Official alone is not first-party
    ["official", undefined],
    ["verified", "core"], // core alone is not first-party
    [undefined, "core"],
    ["verified", "enterprise"],
  ]) {
    assert.equal(ok(make({ tier, provenance, permission: AGG })), false, `${tier}/${provenance}`);
  }
});

test("a scoped grant is accepted at every tier", () => {
  for (const [tier, provenance] of [
    [undefined, undefined],
    ["community", "community"],
    ["verified", "community"],
  ]) {
    assert.ok(ok(make({ tier, provenance, permission: SCOPED })), `${tier}/${provenance}`);
  }
});

test("a scope without portfolios is still refused, first-party or not", () => {
  const bad = { id: "read:aggregated_values", scope: { origins: ["x.example.com"] } };
  assert.equal(ok(make({ tier: "verified", provenance: "community", permission: bad })), false);
});
