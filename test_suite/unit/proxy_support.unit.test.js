import test from "node:test";
import assert from "node:assert/strict";

import { createProxySupportApi } from "../../src/common/proxy_support.js";
import { HttpError } from "../../src/common/lib.js";

const api = createProxySupportApi({
  HttpError,
  getStoredContentType: (h) => (h.get("content-type") || "").toLowerCase(),
  isPlainObject: (v) => !!v && typeof v === "object" && !Array.isArray(v),
  safeMetaHeaders: new Set(["content-type", "cache-control"]),
});

function reqWithBody(body, contentType = "application/json") {
  return new Request("https://x", {
    method: "POST",
    headers: { "content-type": contentType },
    body,
  });
}

test("readJsonWithLimit/readTextWithLimit and content-type enforcement", async () => {
  assert.deepEqual(await api.readJsonWithLimit(reqWithBody(JSON.stringify({ a: 1 })), 1024), { a: 1 });
  await assert.rejects(() => api.readJsonWithLimit(reqWithBody("{"), 1024), (e) => e?.code === "INVALID_JSON");
  await assert.rejects(
    () => api.readJsonWithLimit(new Request("https://x", { method: "POST" }), 1024),
    (e) => e?.code === "EMPTY_BODY"
  );

  assert.equal(await api.readTextWithLimit(reqWithBody("hello", "text/plain"), 1024), "hello");
  await assert.rejects(() => api.readTextWithLimit(reqWithBody("x".repeat(40)), 10), (e) => e?.code === "REQUEST_TOO_LARGE");

  assert.throws(
    () => api.enforceInvokeContentType(reqWithBody("{}", "text/plain")),
    (e) => e?.code === "UNSUPPORTED_MEDIA_TYPE"
  );
});

test("validateInvokePayload and safe url checks", () => {
  const okProblems = api.validateInvokePayload({
    upstream: {
      method: "GET",
      url: "https://api.example.com",
      headers: { a: "1" },
      body: { type: "none" },
    },
  });
  assert.equal(okProblems.length, 0);

  const bad = api.validateInvokePayload({ upstream: { method: "BAD", url: "" } });
  assert.ok(bad.length >= 2);

  api.assertSafeUpstreamUrl("https://api.example.com", new Set(["api.example.com"]));
  assert.throws(
    () => api.assertSafeUpstreamUrl("http://api.example.com", null),
    (e) => e?.code === "UPSTREAM_PROTOCOL_NOT_ALLOWED"
  );
  assert.throws(
    () => api.assertSafeUpstreamUrl("https://localhost", null),
    (e) => e?.code === "UPSTREAM_HOST_BLOCKED"
  );
  assert.throws(
    () => api.assertSafeUpstreamUrl("https://10.0.0.1", null),
    (e) => e?.code === "UPSTREAM_IP_BLOCKED"
  );
});

test("response/body utility helpers", async () => {
  assert.equal(api.detectResponseType("application/json"), "json");
  assert.equal(api.detectResponseType("text/plain"), "text");
  assert.equal(api.detectResponseType("application/octet-stream"), "binary");

  const smallResp = new Response("hello");
  const buf = await api.readResponseWithLimit(smallResp, 1024);
  assert.equal(api.decodeBody(buf), "hello");
  assert.equal(api.parseJsonOrNull('{"a":1}').a, 1);
  assert.equal(api.parseJsonOrNull("{"), null);

  const h = new Headers({ "content-type": "application/json", "x-secret": "n" });
  assert.deepEqual(api.toSafeUpstreamHeaders(h), { "content-type": "application/json" });

  assert.equal(api.resolveUpstreamUrl("/v1", "https://api.example.com").toString(), "https://api.example.com/v1");
  assert.equal(api.resolveUpstreamUrl("https://evil.com/a", "https://api.example.com").toString(), "https://api.example.com/a");
});
