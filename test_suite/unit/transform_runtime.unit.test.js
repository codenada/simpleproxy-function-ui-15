import test from "node:test";
import assert from "node:assert/strict";

import { createTransformRuntimeApi } from "../../src/common/transform_runtime.js";

const api = createTransformRuntimeApi({
  isPlainObject: (v) => !!v && typeof v === "object" && !Array.isArray(v),
  normalizeHeaderName: (n) => String(n || "").toLowerCase(),
  defaultHeaderForwarding: { mode: "blacklist", names: ["x-internal"] },
  internalAuthHeadersSet: new Set(["authorization"]),
  loadJsonata: async () => (expr) => ({ evaluate: (obj) => (expr === "x" ? obj.x : null) }),
});

test("header forwarding policy and checks", () => {
  const p = api.getInboundHeaderFilteringPolicy({});
  assert.equal(api.shouldForwardIncomingHeader("x-test", p), true);
  assert.equal(api.shouldForwardIncomingHeader("x-internal", p), false);
  assert.equal(api.shouldForwardIncomingHeader("authorization", p), false);

  const whitelist = api.getInboundHeaderFilteringPolicy({
    transform: { target_response: { header_filtering: { mode: "whitelist", names: ["x-pass"] } } },
  });
  assert.equal(api.shouldForwardIncomingHeader("x-pass", whitelist), true);
  assert.equal(api.shouldForwardIncomingHeader("x-other", whitelist), false);
});

test("rule matching and selection", () => {
  const section = {
    rules: [
      {
        name: "r1",
        match_status: [200],
        match_method: ["GET"],
        match_path: ["/ok*"],
        match_headers: [{ name: "content-type", value: "*json*" }],
      },
      { name: "r2", match_status: ["4xx"] },
    ],
  };
  const { matchedRule, trace } = api.selectTransformRule(section, {
    status: 200,
    method: "GET",
    headers: { "content-type": "application/json" },
    path: "/ok/1",
    type: "json",
  });
  assert.equal(matchedRule.name, "r1");
  assert.equal(trace.length, 1);

  const miss = api.selectTransformRule(section, {
    status: 500,
    method: "POST",
    headers: { "content-type": "text/plain" },
    path: "/bad",
    type: "text",
  });
  assert.equal(miss.matchedRule, null);
  assert.equal(miss.trace.length, 2);
});

test("shouldRunTransform honors constraints", () => {
  assert.equal(api.shouldRunTransform({ status: { allow: [200] } }, 200, "application/json", 10), true);
  assert.equal(api.shouldRunTransform({ status: { deny: ["5xx"] } }, 500, "application/json", 10), false);
  assert.equal(api.shouldRunTransform({ content_type: { allow: ["application/json"] } }, 200, "text/plain", 10), false);
  assert.equal(api.shouldRunTransform({ content_type: { deny: ["text/*"] } }, 200, "text/plain", 10), false);
  assert.equal(api.shouldRunTransform({ max_response_bytes: 5 }, 200, "application/json", 10), false);
  assert.equal(api.shouldRunTransform(null, 200, "application/json", 10), true);
});

test("evalJsonataWithTimeout executes evaluator", async () => {
  const out = await api.evalJsonataWithTimeout("x", { x: 7 }, 1000);
  assert.equal(out, 7);
});
