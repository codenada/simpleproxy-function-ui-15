import test from "node:test";
import assert from "node:assert/strict";

import { createJwtAuthApi } from "../../src/common/jwt_auth.js";

function makeJwtApi(overrides = {}) {
  return createJwtAuthApi({
    buildHttpRequestInit: async () => ({ method: "GET", headers: new Headers() }),
    nowMs: () => 1_700_000_000_000,
    httpRequest: async () => new Response(JSON.stringify({ keys: [] }), { status: 200 }),
    ...overrides,
  });
}

test("extractJwtFromHeaders handles bearer and raw modes", () => {
  const api = makeJwtApi();
  const h = new Headers({ authorization: "Bearer abc.def.ghi" });
  assert.equal(api.extractJwtFromHeaders(h, { header: "Authorization", scheme: "Bearer" }), "abc.def.ghi");
  assert.equal(api.extractJwtFromHeaders(new Headers({ "x-jwt": "raw.token" }), { header: "x-jwt", scheme: "" }), "raw.token");
  assert.throws(
    () => api.extractJwtFromHeaders(new Headers(), { header: "authorization" }),
    (e) => e?.code === "JWT_MISSING"
  );
});

test("signJwtHs256 + verifyJwtHs256 roundtrip", async () => {
  const api = makeJwtApi();
  const token = await api.signJwtHs256({ sub: "u1", exp: 2_000_000_000 }, "secret");
  const payload = await api.verifyJwtHs256(token, "secret", { audience: null });
  assert.equal(payload.sub, "u1");
  await assert.rejects(() => api.verifyJwtHs256(token, "wrong", {}), (e) => e?.code === "JWT_INVALID");
});

test("verifyJwtHs256 validates exp/nbf/aud/iss", async () => {
  const api = makeJwtApi();
  const base = { iss: "issuer", aud: "aud", exp: 2_000_000_000 };
  const token = await api.signJwtHs256(base, "secret");
  await api.verifyJwtHs256(token, "secret", { issuer: "issuer", audience: "aud" });
  await assert.rejects(() => api.verifyJwtHs256(token, "secret", { issuer: "bad" }), /JWT issuer mismatch/);
  await assert.rejects(() => api.verifyJwtHs256(token, "secret", { audience: "bad" }), /audience mismatch/);

  const expired = await api.signJwtHs256({ exp: 1 }, "secret");
  await assert.rejects(() => api.verifyJwtHs256(expired, "secret", {}), /JWT has expired/);
});

test("verifyJwtRs256 failure paths are enforced", async () => {
  const api = makeJwtApi();
  await assert.rejects(() => api.verifyJwtRs256("a.b.c", {}, {}, {}), /JWT alg must be RS256|JWT header or payload/);

  const hs = await api.signJwtHs256({ exp: 2_000_000_000 }, "secret");
  await assert.rejects(() => api.verifyJwtRs256(hs, {}, {}, {}), /JWT alg must be RS256/);

  const rsToken = [
    Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT", kid: "k1" })).toString("base64url"),
    Buffer.from(JSON.stringify({ exp: 2_000_000_000 })).toString("base64url"),
    Buffer.from("sig").toString("base64url"),
  ].join(".");

  await assert.rejects(
    () => api.verifyJwtRs256(rsToken, {}, {}, {}),
    /jwt.inbound.http_request is required/
  );

  const apiNoKeys = makeJwtApi({
    httpRequest: async () => new Response(JSON.stringify({ keys: [] }), { status: 200 }),
  });
  await assert.rejects(
    () => apiNoKeys.verifyJwtRs256(rsToken, { http_request: { url: "https://jwks.example.com" } }, {}, {}),
    /No JWKS keys available/
  );
});
