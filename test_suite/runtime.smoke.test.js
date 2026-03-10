import test from "node:test";
import assert from "node:assert/strict";

import { ipMatchesCidr, ipMatchesAnyCidr } from "../src/common/cidr.js";
import {
  SERIAL,
  runtimeWorker,
  createEnv,
  minimalValidConfigPatch,
  callSpecificWorker,
  bootstrapKeys,
} from "./smoke.helpers.mjs";

test("CIDR matcher supports IPv4 and IPv6 ranges", SERIAL, async () => {
  assert.equal(ipMatchesCidr("203.0.113.45", "203.0.113.0/24"), true);
  assert.equal(ipMatchesCidr("203.0.114.45", "203.0.113.0/24"), false);
  assert.equal(ipMatchesCidr("2001:db8::1", "2001:db8::/32"), true);
  assert.equal(ipMatchesCidr("2001:db9::1", "2001:db8::/32"), false);
});

test("CIDR allowlist matcher allows when any CIDR matches", SERIAL, async () => {
  assert.equal(ipMatchesAnyCidr("198.51.100.10", ["10.0.0.0/8", "198.51.100.0/24"]), true);
  assert.equal(ipMatchesAnyCidr("198.51.101.10", ["10.0.0.0/8", "198.51.100.0/24"]), false);
});

test("POST /_apiproxy/request without proxy key returns UNAUTHORIZED", SERIAL, async () => {
  const env = createEnv();
  await bootstrapKeys(env);

  const response = await callSpecificWorker(runtimeWorker, env, {
    method: "POST",
    path: "/_apiproxy/request",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify({
      upstream: {
        method: "GET",
        url: "/json",
      },
    }),
  });

  assert.equal(response.status, 401);
  const payload = await response.json();
  assert.equal(payload?.error?.code, "UNAUTHORIZED");
});

test("POST /_apiproxy/request with invalid payload returns INVALID_REQUEST", SERIAL, async () => {
  const env = createEnv();
  const { proxyKey } = await bootstrapKeys(env);

  const response = await callSpecificWorker(runtimeWorker, env, {
    method: "POST",
    path: "/_apiproxy/request",
    headers: {
      "content-type": "application/json",
      "x-proxy-key": proxyKey,
    },
    body: JSON.stringify({
      upstream: {
        method: "NOPE",
        url: "https://example.com/json",
      },
    }),
  });

  assert.equal(response.status, 400);
  const payload = await response.json();
  assert.equal(payload?.error?.code, "INVALID_REQUEST");
});

test("POST /_apiproxy/request valid passthrough returns ok envelope", SERIAL, async () => {
  const env = createEnv({}, {
    config_json_v1: JSON.stringify(minimalValidConfigPatch()),
  });
  const { proxyKey } = await bootstrapKeys(env);

  const realFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response(JSON.stringify({ hello: "world" }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });

  try {
    const response = await callSpecificWorker(runtimeWorker, env, {
      method: "POST",
      path: "/_apiproxy/request",
      headers: {
        "content-type": "application/json",
        "x-proxy-key": proxyKey,
      },
      body: JSON.stringify({
        upstream: {
          method: "GET",
          url: "/json",
        },
      }),
    });

    assert.equal(response.status, 200);
    const payload = await response.json();
    assert.equal(payload?.ok, true);
    assert.deepEqual(payload?.data, { hello: "world" });
    assert.equal(payload?.meta?.status, 200);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("ROTATE_OVERLAP_MS=0 invalidates old proxy key immediately after rotate", SERIAL, async () => {
  const env = createEnv({ ROTATE_OVERLAP_MS: "0" }, {
    config_json_v1: JSON.stringify(minimalValidConfigPatch()),
  });
  const { proxyKey: oldKey } = await bootstrapKeys(env);

  const rotateResponse = await callSpecificWorker(runtimeWorker, env, {
    method: "POST",
    path: "/_apiproxy/keys/proxy/rotate",
    headers: {
      "x-proxy-key": oldKey,
    },
  });

  assert.equal(rotateResponse.status, 200);
  const rotatePayload = await rotateResponse.json();
  const newKey = rotatePayload?.data?.proxy_key;
  assert.ok(newKey);
  assert.notEqual(newKey, oldKey);

  const deniedResponse = await callSpecificWorker(runtimeWorker, env, {
    method: "POST",
    path: "/_apiproxy/request",
    headers: {
      "content-type": "application/json",
      "x-proxy-key": oldKey,
    },
    body: JSON.stringify({
      upstream: {
        method: "GET",
        url: "https://example.com/json",
      },
    }),
  });

  assert.equal(deniedResponse.status, 401);
  const deniedPayload = await deniedResponse.json();
  assert.equal(deniedPayload?.error?.code, "UNAUTHORIZED");

  const realFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response(JSON.stringify({ ok: 1 }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });

  try {
    const allowedResponse = await callSpecificWorker(runtimeWorker, env, {
      method: "POST",
      path: "/_apiproxy/request",
      headers: {
        "content-type": "application/json",
        "x-proxy-key": newKey,
      },
      body: JSON.stringify({
        upstream: {
          method: "GET",
          url: "/json",
        },
      }),
    });

    assert.equal(allowedResponse.status, 200);
    const allowedPayload = await allowedResponse.json();
    assert.equal(allowedPayload?.ok, true);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("Missing configured outbound target host returns MISSING_TARGET_HOST_CONFIG", SERIAL, async () => {
  const env = createEnv({}, {
    config_json_v1: JSON.stringify(minimalValidConfigPatch({
      http_requests: {},
    })),
  });
  const { proxyKey } = await bootstrapKeys(env);

  const response = await callSpecificWorker(runtimeWorker, env, {
    method: "POST",
    path: "/_apiproxy/request",
    headers: {
      "content-type": "application/json",
      "x-proxy-key": proxyKey,
    },
    body: JSON.stringify({
      upstream: {
        method: "GET",
        url: "/json",
      },
    }),
  });

  assert.equal(response.status, 503);
  const payload = await response.json();
  assert.equal(payload?.error?.code, "MISSING_TARGET_HOST_CONFIG");
});

test("Runtime worker does not expose admin routes", SERIAL, async () => {
  const env = createEnv({}, {
    config_json_v1: JSON.stringify(minimalValidConfigPatch()),
  });
  const { adminKey } = await bootstrapKeys(env);
  const response = await callSpecificWorker(runtimeWorker, env, {
    method: "GET",
    path: "/admin/version",
    headers: {
      "x-admin-key": adminKey,
    },
  });
  assert.equal(response.status, 404);
});

test("Runtime worker disables /_apiproxy bootstrap endpoints", SERIAL, async () => {
  const env = createEnv({}, {
    config_json_v1: JSON.stringify(minimalValidConfigPatch()),
  });
  const response = await callSpecificWorker(runtimeWorker, env, {
    method: "GET",
    path: "/_apiproxy/",
  });
  assert.equal(response.status, 404);
});

test("Runtime worker does not expose admin self-rotate endpoint", SERIAL, async () => {
  const env = createEnv({}, {
    config_json_v1: JSON.stringify(minimalValidConfigPatch()),
  });
  const { adminKey } = await bootstrapKeys(env);
  const response = await callSpecificWorker(runtimeWorker, env, {
    method: "POST",
    path: "/_apiproxy/keys/admin/rotate",
    headers: {
      "x-admin-key": adminKey,
    },
  });
  assert.equal(response.status, 404);
});

test("Runtime proxy IP filter blocks requests outside allowed CIDR", SERIAL, async () => {
  const env = createEnv({}, {
    config_json_v1: JSON.stringify(minimalValidConfigPatch({
      traffic_controls: {
        ip_filter: {
          enabled: true,
          allowed_cidrs: ["203.0.113.0/24"],
        },
      },
    })),
  });
  const { proxyKey } = await bootstrapKeys(env);

  const response = await callSpecificWorker(runtimeWorker, env, {
    method: "POST",
    path: "/_apiproxy/request",
    headers: {
      "content-type": "application/json",
      "x-proxy-key": proxyKey,
      "cf-connecting-ip": "198.51.100.20",
    },
    body: JSON.stringify({
      upstream: { method: "GET", url: "/json" },
    }),
  });

  assert.equal(response.status, 403);
  const payload = await response.json();
  assert.equal(payload?.error?.code, "IP_NOT_ALLOWED");
});

test("Runtime proxy request RPM limit enforces when enabled", SERIAL, async () => {
  const env = createEnv({}, {
    config_json_v1: JSON.stringify(minimalValidConfigPatch({
      traffic_controls: {
        request_rate_limit: {
          enabled: true,
          rpm_rate_limit: 1,
        },
      },
    })),
  });
  const { proxyKey } = await bootstrapKeys(env);

  const first = await callSpecificWorker(runtimeWorker, env, {
    method: "POST",
    path: "/_apiproxy/request",
    headers: {
      "content-type": "application/json",
      "x-proxy-key": proxyKey,
      "cf-connecting-ip": "198.51.100.33",
    },
    body: JSON.stringify({
      upstream: { method: "GET", url: "/json" },
    }),
  });
  assert.notEqual(first.status, 429);

  const second = await callSpecificWorker(runtimeWorker, env, {
    method: "POST",
    path: "/_apiproxy/request",
    headers: {
      "content-type": "application/json",
      "x-proxy-key": proxyKey,
      "cf-connecting-ip": "198.51.100.33",
    },
    body: JSON.stringify({
      upstream: { method: "GET", url: "/json" },
    }),
  });

  assert.equal(second.status, 429);
  const payload = await second.json();
  assert.equal(payload?.error?.code, "RATE_LIMITED");
});
