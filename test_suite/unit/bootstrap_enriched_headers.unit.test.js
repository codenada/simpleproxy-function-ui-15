import test from "node:test";
import assert from "node:assert/strict";

import { HttpError, isPlainObject, normalizeHeaderName } from "../../src/common/lib.js";
import { parseBootstrapEnrichedHeadersJson } from "../../src/common/bootstrap_enriched_headers.js";

function parse(raw, env = {}) {
  return parseBootstrapEnrichedHeadersJson(raw, env, {
    HttpError,
    isPlainObject,
    normalizeHeaderName,
  });
}

test("parseBootstrapEnrichedHeadersJson parses valid object and substitutes vars", () => {
  const out = parse(JSON.stringify({ "X-Test": "token ${API_KEY}" }), { API_KEY: "abc123" });
  assert.deepEqual(out, { "x-test": "token abc123" });
});

test("parseBootstrapEnrichedHeadersJson returns empty object for blank input", () => {
  assert.deepEqual(parse(""), {});
  assert.deepEqual(parse("   "), {});
});

test("parseBootstrapEnrichedHeadersJson throws for invalid JSON", () => {
  assert.throws(
    () => parse("{bad json"),
    (err) => err instanceof HttpError && err.code === "INVALID_BOOTSTRAP_HEADERS"
  );
});

test("parseBootstrapEnrichedHeadersJson throws for non-object JSON", () => {
  assert.throws(
    () => parse(JSON.stringify(["x"])),
    (err) => err instanceof HttpError && err.code === "INVALID_BOOTSTRAP_HEADERS"
  );
});

test("parseBootstrapEnrichedHeadersJson throws for invalid header name", () => {
  assert.throws(
    () => parse(JSON.stringify({ "bad header": "value" })),
    (err) => err instanceof HttpError && err.code === "INVALID_BOOTSTRAP_HEADERS"
  );
});

test("parseBootstrapEnrichedHeadersJson throws when referenced variable is missing", () => {
  assert.throws(
    () => parse(JSON.stringify({ "X-Test": "token ${MISSING}" }), {}),
    (err) => err instanceof HttpError && err.code === "MISSING_BOOTSTRAP_SECRET"
  );
});
