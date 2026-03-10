import test from "node:test";
import assert from "node:assert/strict";

import { createObservabilityApi } from "../../src/common/observability.js";
import { HttpError } from "../../src/common/lib.js";

function createKv() {
  const map = new Map();
  return {
    map,
    api: () => ({
      get: async (k) => (map.has(k) ? map.get(k) : null),
      put: async (k, v) => map.set(k, String(v)),
    }),
  };
}

function makeObs(kv, opts = {}) {
  return createObservabilityApi({
    adminRoot: "/admin",
    kvDebugEnabledUntilMsKey: "debug_until",
    builtinDebugRedactHeaders: ["authorization", "x-admin-key"],
    debugMaxTraceChars: 5000,
    debugMaxBodyPreviewChars: 200,
    ensureKvBinding: () => {},
    kvStore: kv.api,
    normalizeHeaderMap: (h) => Object.fromEntries(new Headers(h).entries()),
    loadConfigV1: async () => ({ debug: { max_debug_session_seconds: 60, loggingEndpoint: { http_request: null } } }),
    getEnvInt: (_e, _k, d) => d,
    defaults: { MAX_REQ_BYTES: 1024 },
    enforceInvokeContentType: (req) => {
      const ct = req.headers.get("content-type") || "";
      if (!ct.includes("application/json")) throw new HttpError(415, "UNSUPPORTED_MEDIA_TYPE", "bad");
    },
    readJsonWithLimit: async (req) => JSON.parse(await req.text()),
    jsonResponse: (status, body) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } }),
    htmlPage: (title, body) => `<h1>${title}</h1>${body}`,
    escapeHtml: (s) => String(s),
    buildHttpRequestInit: async () => ({ method: "POST", headers: new Headers() }),
    nowMs: () => 1_700_000_000_000,
    httpRequest: opts.httpRequest || (async () => new Response("ok", { status: 200 })),
  });
}

test("debug status get/put/delete flow", async () => {
  const kv = createKv();
  const obs = makeObs(kv);
  const env = {};

  let res = await obs.handleDebugGet(env);
  let body = await res.json();
  assert.equal(body.data.enabled, false);

  await assert.rejects(
    () => obs.handleDebugPut(new Request("https://x", { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify({ enabled: true, ttl_seconds: 999 }) }), env),
    /ttl_seconds exceeds/
  );

  res = await obs.handleDebugPut(new Request("https://x", { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify({ enabled: true, ttl_seconds: 30 }) }), env);
  body = await res.json();
  assert.equal(body.data.enabled, true);

  res = await obs.handleDebugDelete(env);
  body = await res.json();
  assert.equal(body.data.enabled, false);
});

test("live log disabled and last trace views", async () => {
  const kv = createKv();
  const obs = makeObs(kv);
  const env = {};

  await assert.rejects(() => obs.handleLiveLogStream(env), (e) => e?.code === "LOGGING_DISABLED");

  const html = await obs.handleDebugLastGet(new Request("https://x", { headers: { accept: "text/html" } }));
  const text = await html.text();
  assert.match(text, /No debug trace/);
});

test("recordDebugTraceAndSink emits debug headers and sink status", async () => {
  const kv = createKv();
  const obs = makeObs(kv, {
    httpRequest: async () => new Response("no", { status: 500 }),
  });

  const headers = await obs.recordDebugTraceAndSink({
    debugTrace: {
      id: "t1",
      inbound: { timestamp: new Date().toISOString(), method: "GET", path: "/", headers: {}, body_preview: "" },
      outbound: { timestamp: new Date().toISOString(), url: "https://x", method: "GET", headers: {}, body_preview: "" },
      target_response: { timestamp: new Date().toISOString(), status: 200, headers: {}, body_preview: "ok" },
    },
    transformInfo: { action: "passthrough", matched_rule: null, expression_source: null, output_preview: { ok: true } },
    finalHttpStatus: 200,
    finalBody: { ok: true },
    config: {
      debug: {
        loggingEndpoint: {
          http_request: { url: "https://sink.example.com", method: "POST" },
        },
      },
    },
    env: {},
  });

  assert.equal(headers["X-Proxy-Debug"], "True");
  assert.match(headers["X-Proxy-Debug-Logging-Endpoint-Status"], /error/);

  const last = await obs.handleDebugLastGet(new Request("https://x", { headers: { accept: "text/plain" } }));
  assert.equal(last.status, 200);
  assert.match(await last.text(), /INBOUND REQUEST/);
});
