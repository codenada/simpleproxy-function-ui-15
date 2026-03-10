import test from "node:test";
import assert from "node:assert/strict";

import { dispatchPublicRoute } from "../../src/common/routes/public.js";

function makeCtx() {
  const calls = [];
  const handlers = {
    handleStatusPage: async () => ({ t: "status" }),
    handleBootstrapPost: async () => ({ t: "bootstrap" }),
    handleRequest: async () => ({ t: "request" }),
    handleRotateByKind: async (kind) => ({ t: `rotate:${kind}` }),
    handleRootProxyRequest: async () => ({ t: "root-proxy" }),
  };
  const auth = {
    requireProxyKey: async () => calls.push("proxy"),
    requireIssuerKey: async () => calls.push("issuer"),
    requireAdminAuth: async () => calls.push("admin"),
  };
  return { calls, handlers, auth };
}

test("public route dispatch handles root/status/request/rotations", async () => {
  const { handlers, auth, calls } = makeCtx();
  const base = {
    env: {},
    ctx: {},
    reservedRoot: "/_apiproxy",
    handlers,
    auth,
  };

  let out = await dispatchPublicRoute({ ...base, normalizedPath: "/", request: new Request("https://x/", { method: "GET" }), options: { exposeStatusBootstrapAtRoot: true } });
  assert.equal(out.t, "status");

  out = await dispatchPublicRoute({ ...base, normalizedPath: "/", request: new Request("https://x/", { method: "POST" }), options: { exposeStatusBootstrapAtRoot: true } });
  assert.equal(out.t, "bootstrap");

  out = await dispatchPublicRoute({ ...base, normalizedPath: "/", request: new Request("https://x/", { method: "GET", headers: { "X-Proxy-Key": "k" } }) });
  assert.equal(out.t, "root-proxy");

  out = await dispatchPublicRoute({ ...base, normalizedPath: "/", request: new Request("https://x/", { method: "GET" }), options: { enableStatusBootstrap: true } });
  assert.equal(out.status, 302);

  out = await dispatchPublicRoute({ ...base, normalizedPath: "/_apiproxy", request: new Request("https://x/_apiproxy", { method: "GET" }) });
  assert.equal(out.t, "status");

  out = await dispatchPublicRoute({ ...base, normalizedPath: "/_apiproxy", request: new Request("https://x/_apiproxy", { method: "POST" }) });
  assert.equal(out.t, "bootstrap");

  out = await dispatchPublicRoute({ ...base, normalizedPath: "/_apiproxy/request", request: new Request("https://x/_apiproxy/request", { method: "POST" }) });
  assert.equal(out.t, "request");

  out = await dispatchPublicRoute({ ...base, normalizedPath: "/_apiproxy/keys/proxy/rotate", request: new Request("https://x/_apiproxy/keys/proxy/rotate", { method: "POST" }) });
  assert.equal(out.t, "rotate:proxy");

  out = await dispatchPublicRoute({ ...base, normalizedPath: "/_apiproxy/keys/issuer/rotate", request: new Request("https://x/_apiproxy/keys/issuer/rotate", { method: "POST" }) });
  assert.equal(out.t, "rotate:issuer");

  out = await dispatchPublicRoute({ ...base, normalizedPath: "/_apiproxy/keys/admin/rotate", request: new Request("https://x/_apiproxy/keys/admin/rotate", { method: "POST" }) });
  assert.equal(out.t, "rotate:admin");

  assert.deepEqual(calls, ["proxy", "issuer", "admin"]);
});

test("public route dispatch honors disabled options and returns null", async () => {
  const { handlers, auth } = makeCtx();
  const out = await dispatchPublicRoute({
    normalizedPath: "/_apiproxy/request",
    request: new Request("https://x/_apiproxy/request", { method: "POST" }),
    env: {},
    ctx: {},
    reservedRoot: "/_apiproxy",
    handlers,
    auth,
    options: { enableRequest: false, enableSelfRotate: false, enableStatusBootstrap: false, enableRootProxy: false },
  });
  assert.equal(out, null);
});
