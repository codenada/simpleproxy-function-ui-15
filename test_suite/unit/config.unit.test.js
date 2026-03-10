import test from "node:test";
import assert from "node:assert/strict";

import { HttpError } from "../../src/common/lib.js";
import { validateAndNormalizeConfigV1 } from "../../src/common/config.js";

test("validateAndNormalizeConfigV1 accepts minimal valid config", () => {
  const normalized = validateAndNormalizeConfigV1({
    http_requests: {
      outbound_proxy: {
        method: "GET",
        url: "https://example.com",
      },
    },
    targetCredentialRotation: {
      response: {
        ttl_path: "data.ttl",
      },
    },
  });
  assert.equal(typeof normalized, "object");
  assert.equal(normalized.http_requests.outbound_proxy.method, "GET");
});

test("validateAndNormalizeConfigV1 rejects unsupported http auth profile names", () => {
  assert.throws(
    () =>
      validateAndNormalizeConfigV1({
        http_requests: {
          outbound_proxy: {
            method: "GET",
            url: "https://example.com",
          },
        },
        targetCredentialRotation: {
          response: {
            ttl_path: "data.ttl",
          },
        },
        http_auth: {
          profiles: {
            unknown_profile: {
              headers: {
                authorization: "x",
              },
            },
          },
        },
      }),
    (err) => err instanceof HttpError && err.code === "INVALID_CONFIG"
  );
});

test("validateAndNormalizeConfigV1 rejects invalid static secret_ref", () => {
  assert.throws(
    () =>
      validateAndNormalizeConfigV1({
        http_requests: {
          outbound_proxy: {
            method: "GET",
            url: "https://example.com",
            http_authorization: {
              type: "static",
              static: {
                headers: {},
                secret_ref: "bad value",
              },
            },
          },
        },
        targetCredentialRotation: {
          response: {
            ttl_path: "data.ttl",
          },
        },
      }),
    (err) => err instanceof HttpError && err.code === "INVALID_CONFIG"
  );
});
