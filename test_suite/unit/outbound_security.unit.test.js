import test from "node:test";
import assert from "node:assert/strict";

import {
  createOutboundSecurityApi,
  normalizeRequestSecurityConfig,
  inspectRequestSecurityViolations,
} from "../../src/common/outbound_security.js";
import { HttpError } from "../../src/common/lib.js";

test("normalizeRequestSecurityConfig validates and normalizes", () => {
  const { value, problems } = normalizeRequestSecurityConfig({
    require_https: true,
    block_private_networks: false,
    method_allowlist: ["get", "POST"],
    timeout_ms: 1000,
    max_response_bytes: null,
    allowed_hosts: ["https://Example.com", "api.test"],
  });
  assert.equal(problems.length, 0);
  assert.deepEqual(value.method_allowlist, ["GET", "POST"]);
  assert.deepEqual(value.allowed_hosts, ["example.com", "api.test"]);

  const bad = normalizeRequestSecurityConfig({ method_allowlist: [""] });
  assert.ok(bad.problems.length > 0);
});

test("inspectRequestSecurityViolations flags unsafe targets", () => {
  const a = inspectRequestSecurityViolations("$.req", { url: "http://example.com" });
  assert.ok(a.some((x) => x.path.includes("require_https")));
  const b = inspectRequestSecurityViolations("$.req", { url: "https://127.0.0.1" });
  assert.ok(b.some((x) => x.path.includes("block_private_networks")));
});

test("outbound policy assertions and timeout fetch", async () => {
  const api = createOutboundSecurityApi();
  const policy = api.readPolicyFromRequestModel({
    security: { require_https: true, method_allowlist: ["GET"], allowed_hosts: ["api.example.com"] },
  });

  assert.throws(
    () => api.assertOutboundRequestPolicy({ url: "https://bad.example.com", method: "GET", policy, envAllowedHosts: [] }),
    (e) => e instanceof HttpError && e.code === "UPSTREAM_HOST_NOT_ALLOWED"
  );

  assert.throws(
    () => api.assertOutboundRequestPolicy({ url: "http://api.example.com", method: "GET", policy, envAllowedHosts: [] }),
    (e) => e instanceof HttpError && e.code === "UPSTREAM_PROTOCOL_NOT_ALLOWED"
  );

  api.assertOutboundRequestPolicy({ url: "https://api.example.com", method: "GET", policy, envAllowedHosts: [] });

  const out = await api.fetchWithPolicy("https://x", { method: "GET" }, { timeout_ms: 10 }, async () => new Response("ok"));
  assert.equal(out.status, 200);
});
