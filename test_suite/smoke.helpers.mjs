import assert from "node:assert/strict";
import runtimeWorker from "../src/runtime/runtime_entry.js";
import controlWorker from "../src/control/control_entry.js";

const SERIAL = { concurrency: false };

function createMockKvBinding(initial = {}) {
  const store = new Map(Object.entries(initial));

  return {
    _store: store,
    async get(key, options) {
      const value = store.get(String(key));
      if (value === undefined) return null;
      if (options && options.type === "json") {
        try {
          return JSON.parse(String(value));
        } catch {
          return null;
        }
      }
      return value;
    },
    async put(key, value) {
      store.set(String(key), String(value));
    },
    async delete(key) {
      store.delete(String(key));
    },
    async list(options = {}) {
      const prefix = String(options.prefix || "");
      const keys = [];
      for (const name of store.keys()) {
        if (!prefix || name.startsWith(prefix)) keys.push({ name });
      }
      keys.sort((a, b) => a.name.localeCompare(b.name));
      return { keys, list_complete: true, cursor: "" };
    },
  };
}

function createEnv(vars = {}, initialKv = {}) {
  return {
    CONFIG: createMockKvBinding(initialKv),
    BUILD_TIMESTAMP: "dev",
    ...vars,
  };
}

function minimalValidConfigPatch(extra = {}) {
  return {
    http_requests: {
      outbound_proxy: {
        method: "GET",
        url: "https://example.com",
        headers: {},
        body: { type: "none" },
      },
    },
    targetCredentialRotation: {
      response: {
        ttl_path: "data.ttl",
      },
    },
    ...extra,
  };
}

function createCtx() {
  return {
    waitUntil() {},
  };
}

async function callSpecificWorker(workerImpl, env, { method = "GET", path = "/", headers = {}, body } = {}) {
  const url = `https://example.workers.dev${path}`;
  const request = new Request(url, {
    method,
    headers,
    body,
  });
  return workerImpl.fetch(request, env, createCtx());
}

async function bootstrapKeys(env) {
  const response = await callSpecificWorker(controlWorker, env, {
    method: "GET",
    path: "/",
    headers: {
      cookie: "apiproxy_browser_verified=1",
    },
  });
  assert.equal(response.status, 200);
  const proxyKey = await env.CONFIG.get("proxy_key");
  const adminKey = await env.CONFIG.get("admin_key");
  assert.ok(proxyKey);
  assert.ok(adminKey);
  return { proxyKey, adminKey };
}

async function sha256Hex(input) {
  const bytes = new TextEncoder().encode(String(input));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

async function solvePowChallenge(challengeId, targetPrefix) {
  let nonce = 0;
  while (true) {
    const hash = await sha256Hex(`${challengeId}:${nonce}`);
    if (hash.startsWith(targetPrefix)) return nonce;
    nonce += 1;
  }
}

export {
  SERIAL,
  runtimeWorker,
  controlWorker,
  createEnv,
  minimalValidConfigPatch,
  callSpecificWorker,
  bootstrapKeys,
  solvePowChallenge,
};
