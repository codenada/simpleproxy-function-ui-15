import test from "node:test";
import assert from "node:assert/strict";

import {
  createConfigApi,
  parseYamlConfigText,
  stringifyYamlConfig,
  validateAndNormalizeConfigV1,
  migrateConfigToV1,
  DEFAULT_CONFIG_V1,
} from "../../src/common/config.js";

function createKv() {
  const map = new Map();
  return {
    map,
    store: () => ({
      get: async (k) => (map.has(k) ? map.get(k) : null),
      put: async (k, v) => map.set(k, String(v)),
    }),
  };
}

function createConfigService(kv) {
  return createConfigApi({
    ensureKvBinding: () => {},
    kvStore: kv.store,
    kvConfigYamlKey: "config_yaml_v1",
    kvConfigJsonKey: "config_json_v1",
  });
}

const richConfig = {
  proxy_friendly_name: "SimpleProxy",
  http_requests: {
    outbound_proxy: {
      method: "POST",
      url: "https://api.example.com/v1",
      headers: [{ name: "x-a", value: "1" }],
      body_type: "json",
      body: { q: 1 },
      security: {
        require_https: true,
        block_private_networks: true,
        method_allowlist: ["GET", "POST"],
        timeout_ms: 2000,
        max_response_bytes: 100000,
        allowed_hosts: ["https://api.example.com"],
      },
      http_authorization: {
        type: "key_rotation",
        key_rotation: {
          profile: "target",
        },
      },
    },
    jwt_fetch: {
      method: "GET",
      url: "https://auth.example.com/jwks",
    },
  },
  http_auth: {
    profiles: {
      target: {
        headers: {
          authorization: "Bearer {{current}}",
        },
        timestamp_format: "epoch_seconds",
      },
      logging: {
        headers: {
          authorization: "Bearer {{current}}",
        },
      },
    },
  },
  jwt: {
    mode: "verify_external_tokens",
    verify_external_tokens: {
      clock_skew_seconds: 30,
      http_request: {
        method: "GET",
        url: "https://auth.example.com/jwks",
      },
    },
    outbound: {
      enabled: true,
      ttl_seconds: 1800,
    },
  },
  proxy_access_control: {
    proxy_key: { expiry_in_seconds: 3600 },
    jwt_issuer_key: { expiry_in_seconds: 3600 },
    admin_key: { expiry_in_seconds: 3600 },
  },
  targetCredentialRotation: {
    enabled: true,
    strategy: "json_ttl",
    request: {
      method: "POST",
      url: "https://issuer.example.com/rotate",
      headers: { "content-type": "application/json" },
      body: { type: "json", value: { scope: "x" } },
    },
    response: {
      key_path: "data.key",
      ttl_path: "data.ttl",
      ttl_unit: "seconds",
      expires_at_path: null,
    },
    trigger: {
      refresh_skew_seconds: 60,
      retry_once_on_401: true,
    },
  },
  transform: {
    enabled: true,
    source_request: {
      enabled: true,
      defaultExpr: "$",
      fallback: "passthrough",
      rules: [
        {
          name: "source-post",
          match_method: ["POST"],
          match_path: ["/v1/*"],
          match_headers: [{ name: "x-mode", value: "live" }],
          expr: "$",
        },
      ],
    },
    target_response: {
      enabled: true,
      defaultExpr: "$",
      fallback: "transform_default",
      header_filtering: {
        mode: "whitelist",
        names: ["content-type"],
      },
      rules: [
        {
          name: "target-200",
          match_status: [200, "2xx"],
          match_type: "json",
          match_headers: [{ name: "content-type", value: "*json*" }],
          expr: "$",
        },
      ],
    },
  },
  header_forwarding: {
    mode: "blacklist",
    names: ["x-admin-key", "x-proxy-key"],
  },
  traffic_controls: {
    ip_filter: {
      enabled: true,
      allowed_cidrs: ["10.0.0.0/8", "::/0"],
    },
    request_rate_limit: {
      enabled: true,
      rpm_rate_limit: 20,
    },
  },
  logging: {
    max_logging_session_seconds: 300,
  },
};

test("validateAndNormalizeConfigV1 handles rich valid config and aliases", () => {
  const normalized = validateAndNormalizeConfigV1(richConfig);
  assert.equal(normalized.proxyName, "SimpleProxy");
  assert.equal(normalized.jwt.inbound.enabled, true);
  assert.equal(normalized.jwt.inbound.mode, "shared_secret");
  assert.equal(normalized.http_requests.outbound_proxy.method, "POST");
  assert.equal(normalized.targetCredentialRotation.enabled, true);
  assert.equal(normalized.transform.target_response.rules[0].match_type, "json");
  assert.equal(normalized.traffic_controls.request_rate_limit.rpm_rate_limit, 20);
  assert.equal(normalized.debug.max_debug_session_seconds, 300);
});

test("validateAndNormalizeConfigV1 aggregates many validation errors", () => {
  assert.throws(
    () =>
      validateAndNormalizeConfigV1({
        targetHost: "https://legacy.example.com",
        http_requests: {
          bad: {
            method: "POST",
            url: "http://bad.example.com",
            headers: [123],
            body_type: "oops",
            security: { require_https: "yes", method_allowlist: [""], timeout_ms: -1 },
            http_authorization: { type: "weird" },
          },
        },
        http_auth: { profiles: { unknown: { headers: [] } } },
        jwt: { enabled: "yes", inbound: { mode: "bad", header: "" }, outbound: { ttl_seconds: 0 } },
        apiKeyPolicy: { proxyExpirySeconds: 0 },
        targetCredentialRotation: { enabled: true, response: { key_path: "", ttl_unit: "days" } },
        transform: { source_request: { rules: "nope" }, target_response: { rules: [{ name: "", expr: "" }] } },
        header_forwarding: { mode: "invalid", names: [""] },
        traffic_controls: { ip_filter: { allowed_cidrs: [""] }, request_rate_limit: { rpm_rate_limit: 0 } },
      }),
    (e) => e?.code === "INVALID_CONFIG" && Array.isArray(e?.details?.problems) && e.details.problems.length > 8
  );
});

test("yaml parse/stringify and migrate behavior", async () => {
  const yamlText = await stringifyYamlConfig(validateAndNormalizeConfigV1(richConfig));
  const parsed = await parseYamlConfigText(yamlText);
  assert.equal(parsed.proxyName, "SimpleProxy");

  await assert.rejects(() => parseYamlConfigText(""), (e) => e?.code === "INVALID_CONFIG");
  await assert.rejects(() => parseYamlConfigText("::::"), (e) => e?.code === "INVALID_CONFIG");

  assert.deepEqual(migrateConfigToV1({ a: 1 }, "0"), { a: 1 });
  assert.throws(() => migrateConfigToV1({}, "99"), (e) => e?.code === "UNSUPPORTED_CONFIG_SCHEMA");
});

test("createConfigApi load/save flows include bootstrap and stored schema handling", async () => {
  const kv = createKv();
  const api = createConfigService(kv);
  const env = {};

  const defaultCfg = await api.loadConfigV1(env);
  assert.deepEqual(defaultCfg, DEFAULT_CONFIG_V1);

  const normalized = validateAndNormalizeConfigV1(richConfig);
  await api.saveConfigObjectV1(normalized, env);
  assert.ok(kv.map.get("config_yaml_v1"));
  assert.ok(kv.map.get("config_json_v1"));

  const yamlStored = await api.loadConfigYamlV1(env);
  assert.equal(typeof yamlStored, "string");

  const yamlText = await stringifyYamlConfig(normalized);
  const fromYaml = await api.saveConfigFromYamlV1(yamlText, env);
  assert.equal(fromYaml.proxyName, "SimpleProxy");

  const loaded = await api.loadConfigV1(env);
  assert.equal(loaded.proxyName, "SimpleProxy");

  kv.map.set("config_json_v1", "{bad json");
  await assert.rejects(() => api.loadConfigV1(env), (e) => e?.code === "INVALID_STORED_CONFIG");

  const bootEnv = { BOOTSTRAP_CONFIG_YAML: yamlText };
  const boot = await api.loadConfigV1(bootEnv);
  assert.equal(boot.proxyName, "SimpleProxy");

  const badBootEnv = { BOOTSTRAP_CONFIG_YAML: "::::" };
  await assert.rejects(() => api.loadConfigV1(badBootEnv), (e) => e?.code === "INVALID_BOOTSTRAP_CONFIG");
});
