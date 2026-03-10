import test from "node:test";
import assert from "node:assert/strict";

import { createRequestAuthApi } from "../../src/common/request_auth.js";

function createKv() {
  const store = new Map();
  return {
    get: async (_env, key) => (store.has(key) ? store.get(key) : null),
    put: async (_env, key, value) => {
      store.set(key, String(value));
    },
    store,
  };
}

function makeApi(kv, opts = {}) {
  return createRequestAuthApi({
    isNonArrayObject: (v) => !!v && typeof v === "object" && !Array.isArray(v),
    isPlainObject: (v) => !!v && typeof v === "object" && !Array.isArray(v),
    getPathValue: (obj, path) => path.split(".").reduce((cur, p) => (cur && p in cur ? cur[p] : null), obj),
    authProfilePrefix: (p) => (p === "target" ? "auth/target" : p === "logging" ? "auth/logging" : null),
    authProfileKvKey: (p, f) => (p ? `auth/${p}/${f}` : null),
    httpSecretKvKey: (ref) => (/^[a-zA-Z0-9_.-]{1,64}$/.test(String(ref || "")) ? `secret/${ref}` : null),
    kvGetValue: kv.get,
    kvPutValue: kv.put,
    authProfileFields: ["current", "secondary", "issued_at_ms", "expires_at_ms", "secondary_issued_at_ms", "secondary_expires_at_ms"],
    httpRequest: opts.httpRequest || (async () => new Response(JSON.stringify({ data: { key: "rotated", ttl: 20 } }))),
  });
}

test("resolveAuthProfileHeaders substitutes profile placeholders", async () => {
  const kv = createKv();
  await kv.put({}, "auth/target/current", "abc");
  await kv.put({}, "auth/target/expires_at_ms", "1700000000000");
  const api = makeApi(kv);

  const out = await api.resolveAuthProfileHeaders(
    "target",
    {
      http_auth: {
        profiles: {
          target: {
            headers: {
              Authorization: "Bearer {{current}}",
              "X-Exp": "{{expires_at}}",
              "X-Exp-Iso": "{{expires_at_iso}}",
            },
          },
        },
      },
    },
    {}
  );

  assert.equal(out.Authorization, "Bearer abc");
  assert.ok(out["X-Exp"].length > 0);
  assert.ok(out["X-Exp-Iso"].includes("T"));
});

test("buildHttpRequestInit handles static secret auth and body types", async () => {
  const kv = createKv();
  await kv.put({}, "secret/my_ref", "sekret");
  const api = makeApi(kv);

  const jsonInit = await api.buildHttpRequestInit(
    {
      method: "POST",
      http_authorization: {
        type: "static",
        secret_ref: "my_ref",
        headers: { Authorization: "Bearer {{my_ref}}" },
      },
      body: { type: "json", value: { a: 1 } },
    },
    {},
    {}
  );
  assert.equal(jsonInit.headers.get("Authorization"), "Bearer sekret");
  assert.equal(jsonInit.headers.get("content-type"), "application/json");
  assert.equal(jsonInit.body, JSON.stringify({ a: 1 }));

  const urlEncodedInit = await api.buildHttpRequestInit(
    {
      method: "POST",
      body: { type: "urlencoded", value: { a: "1", b: "2" } },
    },
    {},
    {}
  );
  assert.equal(urlEncodedInit.headers.get("content-type"), "application/x-www-form-urlencoded");
  assert.match(urlEncodedInit.body, /a=1/);

  const rawInit = await api.buildHttpRequestInit(
    {
      method: "POST",
      body: { type: "raw", content_type: "text/plain", raw: "hello" },
    },
    {},
    {}
  );
  assert.equal(rawInit.headers.get("content-type"), "text/plain");
  assert.equal(rawInit.body, "hello");
});

test("buildHttpRequestInit key_rotation flow refreshes scoped placeholders", async () => {
  const kv = createKv();
  const api = makeApi(kv, {
    httpRequest: async () =>
      new Response(
        JSON.stringify({
          data: { token: "new-token", ttl: 30 },
        })
      ),
  });

  const init = await api.buildHttpRequestInit(
    {
      method: "GET",
      __kv_scope: "target",
      http_authorization: {
        type: "key_rotation",
        auth_headers: {
          Authorization: "Bearer ${current_token_value}",
          "X-TTL": "${current_token_ttl}",
        },
        key_rotation_http_request: {
          method: "POST",
          url: "https://issuer.example.com",
          headers: { "x-a": "${current_token_value}" },
          body: { type: "json", value: { a: "${current_token_ttl}" } },
        },
        key_rotation_http_response: {
          current_token_value: "data.token",
          current_token_ttl: "data.ttl",
          current_token_ttl_unit: "seconds",
        },
      },
    },
    {},
    {}
  );

  assert.equal(init.headers.get("Authorization"), "Bearer new-token");
  assert.equal(init.headers.get("X-TTL"), "30");
  assert.equal(kv.store.get("target/current_token_ttl_unit"), "seconds");
});

test("buildHttpRequestInit throws for missing static secret", async () => {
  const kv = createKv();
  const api = makeApi(kv);
  await assert.rejects(
    () =>
      api.buildHttpRequestInit(
        {
          method: "GET",
          http_authorization: {
            type: "static",
            secret_ref: "missing_ref",
            headers: { Authorization: "Bearer {{missing_ref}}" },
          },
        },
        {},
        {}
      ),
    (e) => e?.code === "MISSING_HTTP_AUTH_SECRET"
  );
});
