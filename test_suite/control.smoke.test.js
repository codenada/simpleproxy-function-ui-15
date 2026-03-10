import test from "node:test";
import assert from "node:assert/strict";

import {
  SERIAL,
  controlWorker,
  createEnv,
  minimalValidConfigPatch,
  callSpecificWorker,
  bootstrapKeys,
  solvePowChallenge,
} from "./smoke.helpers.mjs";

test("GET / initializes missing keys and serves onboarding HTML", SERIAL, async () => {
  const env = createEnv();

  const response = await callSpecificWorker(controlWorker, env, {
    method: "GET",
    path: "/",
    headers: {
      cookie: "apiproxy_browser_verified=1",
    },
  });

  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") || "", /text\/html/i);
  const html = await response.text();
  assert.match(html, /SimpleProxy/i);
  assert.match(html, /Login with your Admin Key/i);
  assert.ok(await env.CONFIG.get("proxy_key"));
  assert.ok(await env.CONFIG.get("admin_key"));
});

test("Admin endpoints accept both X-Admin-Key and bearer access token", SERIAL, async () => {
  const env = createEnv();
  const { adminKey } = await bootstrapKeys(env);

  const byKeyResponse = await callSpecificWorker(controlWorker, env, {
    method: "GET",
    path: "/admin/version",
    headers: {
      "x-admin-key": adminKey,
    },
  });
  assert.equal(byKeyResponse.status, 200);

  const tokenResponse = await callSpecificWorker(controlWorker, env, {
    method: "POST",
    path: "/admin/access-token",
    headers: {
      "x-admin-key": adminKey,
    },
  });
  assert.equal(tokenResponse.status, 200);
  const tokenPayload = await tokenResponse.json();
  const token = tokenPayload?.data?.access_token;
  assert.ok(token);

  const byBearerResponse = await callSpecificWorker(controlWorker, env, {
    method: "GET",
    path: "/admin/version",
    headers: {
      authorization: `Bearer ${token}`,
    },
  });
  assert.equal(byBearerResponse.status, 200);
});

test("Admin access-token endpoint enforces RPM limit", SERIAL, async () => {
  const env = createEnv();
  const { adminKey } = await bootstrapKeys(env);
  const ip = "198.51.100.77";

  for (let i = 0; i < 10; i += 1) {
    const response = await callSpecificWorker(controlWorker, env, {
      method: "POST",
      path: "/admin/access-token",
      headers: {
        "x-admin-key": adminKey,
        "cf-connecting-ip": ip,
      },
    });
    assert.equal(response.status, 200);
  }

  const limited = await callSpecificWorker(controlWorker, env, {
    method: "POST",
    path: "/admin/access-token",
    headers: {
      "x-admin-key": adminKey,
      "cf-connecting-ip": ip,
    },
  });
  assert.equal(limited.status, 429);
  const payload = await limited.json();
  assert.equal(payload?.error?.code, "RATE_LIMITED");
});

test("Admin config PUT roundtrip is reflected in status page", SERIAL, async (t) => {
  try {
    await import("yaml");
  } catch {
    t.skip("yaml dependency is unavailable in this local test environment");
    return;
  }

  const env = createEnv();
  const { adminKey } = await bootstrapKeys(env);

  const putResponse = await callSpecificWorker(controlWorker, env, {
    method: "PUT",
    path: "/admin/config",
    headers: {
      "x-admin-key": adminKey,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      ...minimalValidConfigPatch({
        proxyName: "Smoke Test Proxy",
        http_requests: {
          outbound_proxy: {
            method: "GET",
            url: "https://config.example",
            headers: {},
            body: { type: "none" },
          },
        },
      }),
    }),
  });
  assert.equal(putResponse.status, 200);

  const statusResponse = await callSpecificWorker(controlWorker, env, {
    method: "GET",
    path: "/",
    headers: {
      cookie: "apiproxy_browser_verified=1",
    },
  });
  assert.equal(statusResponse.status, 200);
  const html = await statusResponse.text();
  assert.match(html, /Smoke Test Proxy/);
});

test("Live log stream returns LOGGING_DISABLED when debug is off", SERIAL, async () => {
  const env = createEnv();
  const { adminKey } = await bootstrapKeys(env);

  const response = await callSpecificWorker(controlWorker, env, {
    method: "GET",
    path: "/admin/live-log/stream",
    headers: {
      "x-admin-key": adminKey,
    },
  });

  assert.equal(response.status, 409);
  const payload = await response.json();
  assert.equal(payload?.error?.code, "LOGGING_DISABLED");
});

test("Control worker does not expose /request", SERIAL, async () => {
  const env = createEnv({}, {
    config_json_v1: JSON.stringify(minimalValidConfigPatch()),
  });
  const { proxyKey } = await bootstrapKeys(env);
  const response = await callSpecificWorker(controlWorker, env, {
    method: "POST",
    path: "/_apiproxy/request",
    headers: {
      "content-type": "application/json",
      "x-proxy-key": proxyKey,
    },
    body: JSON.stringify({
      upstream: { method: "GET", url: "/json" },
    }),
  });
  assert.equal(response.status, 404);
});

test("Control worker exposes onboarding at root and hides /_apiproxy", SERIAL, async () => {
  const env = createEnv({
    BROWSER_CHALLENGE_DIFFICULTY: "2",
  }, {
    config_json_v1: JSON.stringify(minimalValidConfigPatch()),
  });

  const rootResponse = await callSpecificWorker(controlWorker, env, {
    method: "GET",
    path: "/",
  });
  assert.equal(rootResponse.status, 200);
  const challengeHtml = await rootResponse.text();
  assert.match(challengeHtml, /Browser Check/i);
  const idMatch = challengeHtml.match(/const challengeId = "([a-f0-9]+)";/i);
  const prefixMatch = challengeHtml.match(/const targetPrefix = "(0+)";/i);
  assert.ok(idMatch?.[1]);
  assert.ok(prefixMatch?.[1]);
  const nonce = await solvePowChallenge(idMatch[1], prefixMatch[1]);
  const verifyResponse = await callSpecificWorker(controlWorker, env, {
    method: "POST",
    path: "/admin/browser-verify",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ challenge_id: idMatch[1], nonce }),
  });
  assert.equal(verifyResponse.status, 200);
  const verifyCookie = verifyResponse.headers.get("set-cookie") || "";
  assert.match(verifyCookie, /apiproxy_browser_verified=1/i);

  const verifiedResponse = await callSpecificWorker(controlWorker, env, {
    method: "GET",
    path: "/",
    headers: { cookie: verifyCookie },
  });
  assert.equal(verifiedResponse.status, 200);
  const html = await verifiedResponse.text();
  assert.match(html, /Get Started/i);

  const hiddenResponse = await callSpecificWorker(controlWorker, env, {
    method: "GET",
    path: "/_apiproxy/",
  });
  assert.equal(hiddenResponse.status, 404);
});

test("Control admin page requires auth and loads from tokenized admin URL", SERIAL, async () => {
  const env = createEnv({}, {
    config_json_v1: JSON.stringify(minimalValidConfigPatch()),
  });
  const { adminKey } = await bootstrapKeys(env);

  const denied = await callSpecificWorker(controlWorker, env, {
    method: "GET",
    path: "/admin",
  });
  assert.equal(denied.status, 404);

  const tokenResponse = await callSpecificWorker(controlWorker, env, {
    method: "POST",
    path: "/admin/access-token",
    headers: {
      "x-admin-key": adminKey,
    },
  });
  assert.equal(tokenResponse.status, 200);
  const tokenPayload = await tokenResponse.json();
  const token = tokenPayload?.data?.access_token;
  assert.ok(token);
  const adminUrl = tokenPayload?.data?.admin_url;
  assert.ok(adminUrl);

  const authorized = await callSpecificWorker(controlWorker, env, {
    method: "GET",
    path: "/admin",
    headers: {
      authorization: `Bearer ${token}`,
    },
  });
  assert.equal(authorized.status, 200);
  const html = await authorized.text();
  assert.match(html, /Admin Console/);
});

test("Control worker keeps /_apiproxy bootstrap endpoints disabled", SERIAL, async () => {
  const env = createEnv({}, {
    config_json_v1: JSON.stringify(minimalValidConfigPatch()),
  });
  const response = await callSpecificWorker(controlWorker, env, {
    method: "GET",
    path: "/_apiproxy/",
  });
  assert.equal(response.status, 404);
});

test("Control worker exposes admin self-rotate endpoint", SERIAL, async () => {
  const env = createEnv({}, {
    config_json_v1: JSON.stringify(minimalValidConfigPatch()),
  });
  const { adminKey } = await bootstrapKeys(env);
  const response = await callSpecificWorker(controlWorker, env, {
    method: "POST",
    path: "/_apiproxy/keys/admin/rotate",
    headers: {
      "x-admin-key": adminKey,
    },
  });
  assert.equal(response.status, 200);
});
