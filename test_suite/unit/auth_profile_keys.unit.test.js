import test from "node:test";
import assert from "node:assert/strict";

import {
  authProfilePrefix,
  authProfileKvKey,
  isValidHttpSecretRef,
  httpSecretKvKey,
  createAuthProfileKeyResolvers,
} from "../../src/common/auth_profile_keys.js";

const PREFIX_MAP = {
  logging: "auth/logging",
  target: "auth/target",
  jwt_inbound: "auth/jwt_inbound",
};

test("authProfilePrefix resolves known profile names", () => {
  assert.equal(authProfilePrefix("logging", PREFIX_MAP), "auth/logging");
  assert.equal(authProfilePrefix(" target ", PREFIX_MAP), "auth/target");
  assert.equal(authProfilePrefix("unknown", PREFIX_MAP), null);
});

test("authProfileKvKey builds field keys only for supported profiles", () => {
  assert.equal(authProfileKvKey("logging", "current", PREFIX_MAP), "auth/logging/current");
  assert.equal(authProfileKvKey("unknown", "current", PREFIX_MAP), null);
});

test("isValidHttpSecretRef accepts expected charset and length", () => {
  assert.equal(isValidHttpSecretRef("abc-DEF_123.test"), true);
  assert.equal(isValidHttpSecretRef(""), false);
  assert.equal(isValidHttpSecretRef("bad value"), false);
  assert.equal(isValidHttpSecretRef("x".repeat(65)), false);
});

test("httpSecretKvKey rejects invalid refs and applies prefix", () => {
  assert.equal(httpSecretKvKey("token_1", "http_secret:"), "http_secret:token_1");
  assert.equal(httpSecretKvKey("bad value", "http_secret:"), null);
});

test("createAuthProfileKeyResolvers returns bound helpers", () => {
  const resolvers = createAuthProfileKeyResolvers({
    prefixMap: PREFIX_MAP,
    secretPrefix: "http_secret:",
  });
  assert.equal(resolvers.authProfilePrefix("jwt_inbound"), "auth/jwt_inbound");
  assert.equal(resolvers.authProfileKvKey("target", "expires_at_ms"), "auth/target/expires_at_ms");
  assert.equal(resolvers.httpSecretKvKey("secret_ref"), "http_secret:secret_ref");
});
