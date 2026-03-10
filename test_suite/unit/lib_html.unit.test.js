import test from "node:test";
import assert from "node:assert/strict";

import {
  HttpError,
  toHttpError,
  successEnvelope,
  errorEnvelope,
  jsonResponse,
  apiError,
  isNonArrayObject,
  normalizeHeaderName,
  getPathValue,
  looksJson,
  looksYaml,
  normalizeHeaderMap,
} from "../../src/common/lib.js";
import { escapeHtml, capitalize, htmlPage } from "../../src/common/html.js";

test("lib helpers: envelopes and errors", async () => {
  const ok = successEnvelope({ a: 1 }, { t: 1 });
  assert.equal(ok.ok, true);
  const err = errorEnvelope("X", "msg", { x: 1 }, { m: 1 });
  assert.equal(err.error.code, "X");
  assert.deepEqual(err.meta, { m: 1 });

  const res = jsonResponse(201, { ok: true }, { "x-a": 1 });
  assert.equal(res.status, 201);
  assert.equal(res.headers.get("x-a"), "1");

  const api = apiError(400, "BAD", "bad", { d: 1 }, { m: 2 });
  assert.equal(api.status, 400);
  const parsed = await api.json();
  assert.equal(parsed.error.code, "BAD");

  const wrapped = toHttpError(new Error("boom"));
  assert.ok(wrapped instanceof HttpError);
  assert.equal(wrapped.status, 500);
});

test("lib helpers: object/header/path utils", () => {
  assert.equal(isNonArrayObject({}), true);
  assert.equal(isNonArrayObject([]), false);
  assert.equal(normalizeHeaderName(" X-Test "), "x-test");
  assert.equal(getPathValue({ a: { b: 2 } }, "a.b"), 2);
  assert.equal(getPathValue({ a: 1 }, "a.b"), null);
  assert.equal(looksJson("application/ld+json"), true);
  assert.equal(looksYaml("application/x-yaml"), true);

  const h = new Headers({ "X-A": "1" });
  assert.deepEqual(normalizeHeaderMap(h), { "x-a": "1" });
  assert.deepEqual(normalizeHeaderMap({ A: 1 }), { a: "1" });
});

test("html helpers escape and render", () => {
  assert.equal(escapeHtml('<a>&"\''), "&lt;a&gt;&amp;&quot;&#039;");
  assert.equal(capitalize("hello"), "Hello");
  const page = htmlPage("<X>", "<p>ok</p>");
  assert.match(page, /&lt;X&gt;/);
  assert.match(page, /<p>ok<\/p>/);
});
