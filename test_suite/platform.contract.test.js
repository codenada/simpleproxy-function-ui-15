import test from "node:test";
import assert from "node:assert/strict";

import { createPlatformAdapters } from "../src/platform/index.js";
import { createCloudflareStorage } from "../src/platform/cloudflare/storage/index.js";
import { StorageConnectorError } from "../src/platform/interface/storage.js";

test("platform adapters expose expected contracts", async () => {
  const platform = createPlatformAdapters();

  assert.equal(typeof platform.createStorageConnector, "function");
  assert.equal(typeof platform.clock?.nowMs, "function");
  assert.equal(typeof platform.http?.request, "function");
  assert.equal(typeof platform.crypto?.randomBytes, "function");
  assert.equal(typeof platform.crypto?.sha256Hex, "function");
  assert.ok(platform.crypto?.subtle);

  const now = platform.clock.nowMs();
  assert.equal(typeof now, "number");
  assert.ok(Number.isFinite(now));

  const bytes = platform.crypto.randomBytes(32);
  assert.equal(bytes.length, 32);

  const digest = await platform.crypto.sha256Hex("simpleproxy");
  assert.equal(digest, "7150147b4bf9cc509f553d59cbff694ebf749beb4e09ef8f97932046f43ccc27");
});

test("cloudflare storage connector is stable per env and validates KV binding", async () => {
  const env = {};
  const a = createCloudflareStorage(env);
  const b = createCloudflareStorage(env);
  assert.equal(a, b);

  await assert.rejects(
    () => a.keyValue.get("x"),
    (error) => {
      assert.ok(error instanceof StorageConnectorError);
      assert.equal(error.code, "MISSING_KV_BINDING");
      return true;
    }
  );
});
