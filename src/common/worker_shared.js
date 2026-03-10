import { StorageConnectorError } from "../platform/interface/storage.js";

const KV_PROXY_KEY = "proxy_key";
const KV_ADMIN_KEY = "admin_key";
const KV_ISSUER_KEY = "issuer_key";
const KV_PROXY_KEY_OLD = "proxy_key_old";
const KV_PROXY_KEY_OLD_EXPIRES_AT = "proxy_key_old_expires_at";
const KV_PROXY_PRIMARY_KEY_CREATED_AT = "proxy_primary_key_created_at";
const KV_PROXY_SECONDARY_KEY_CREATED_AT = "proxy_secondary_key_created_at";
const KV_ISSUER_KEY_OLD = "issuer_key_old";
const KV_ISSUER_KEY_OLD_EXPIRES_AT = "issuer_key_old_expires_at";
const KV_ISSUER_PRIMARY_KEY_CREATED_AT = "issuer_primary_key_created_at";
const KV_ISSUER_SECONDARY_KEY_CREATED_AT = "issuer_secondary_key_created_at";
const KV_ADMIN_KEY_OLD = "admin_key_old";
const KV_ADMIN_KEY_OLD_EXPIRES_AT = "admin_key_old_expires_at";
const KV_ADMIN_PRIMARY_KEY_CREATED_AT = "admin_primary_key_created_at";
const KV_ADMIN_SECONDARY_KEY_CREATED_AT = "admin_secondary_key_created_at";
const KV_CONFIG_YAML = "config_yaml_v1";
const KV_CONFIG_JSON = "config_json_v1";
const KV_ENRICHED_HEADER_PREFIX = "enriched_header:";
const KV_HTTP_SECRET_PREFIX = "http_secret:";
const KV_BOOTSTRAP_ENRICHED_HEADER_NAMES = "bootstrap_enriched_header_names_v1";
const KV_DEBUG_ENABLED_UNTIL_MS = "debug_enabled_until_ms";

const AUTH_PROFILE_PREFIXES = {
  logging: "auth/logging",
  target: "auth/target",
  jwt_inbound: "auth/jwt_inbound",
};
const AUTH_PROFILE_FIELDS = [
  "current",
  "secondary",
  "issued_at_ms",
  "expires_at_ms",
  "secondary_issued_at_ms",
  "secondary_expires_at_ms",
];

const RESERVED_ROOT = "/_apiproxy";
const ADMIN_ROOT = "/admin";
const DEFAULT_DOCS_URL = "https://github.com/codenada/simpleproxy-function-dev/blob/main/README.md";
const DEBUG_MAX_TRACE_CHARS = 32000;
const DEBUG_MAX_BODY_PREVIEW_CHARS = 4000;

const DEFAULTS = {
  ALLOWED_HOSTS: "",
  MAX_REQ_BYTES: 256 * 1024,
  MAX_RESP_BYTES: 1024 * 1024,
  MAX_EXPR_BYTES: 16 * 1024,
  TRANSFORM_TIMEOUT_MS: 400,
  ROTATE_OVERLAP_MS: 10 * 60 * 1000,
  ADMIN_ACCESS_TOKEN_TTL_SECONDS: 3600,
};

const EXPECTED_REQUEST_SCHEMA = {
  upstream: {
    method: "GET|POST|PUT|PATCH|DELETE",
    url: "/path or https://... (resolved against configured http_requests.outbound_proxy.url)",
    headers: "mapping<headerName,string> (optional)",
    auth_profile: "string (optional)",
    body: {
      type: "none|json|urlencoded|raw",
      value: "any (optional)",
      raw: "string (optional)",
      content_type: "string (optional)",
    },
  },
};

const SAFE_META_HEADERS = new Set([
  "content-type",
  "cache-control",
  "etag",
  "last-modified",
  "content-language",
  "expires",
]);
const HOP_BY_HOP_HEADERS = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "host",
  "content-length",
]);
const INTERNAL_AUTH_HEADERS = new Set(["x-proxy-key", "x-admin-key", "x-issuer-key"]);
const JWKS_CACHE_TTL_MS = 5 * 60 * 1000;
const BUILTIN_DEBUG_REDACT_HEADERS = new Set([
  "authorization",
  "proxy-authorization",
  "cookie",
  "set-cookie",
  "x-proxy-key",
  "x-admin-key",
]);

function normalizePathname(pathname) {
  const raw = String(pathname || "/");
  if (raw === "/") return "/";
  const trimmed = raw.replace(/\/+$/, "");
  return trimmed || "/";
}

function renderWorkerError({ error, pathname, toHttpError, htmlPage, escapeHtml, apiError }) {
  const err = toHttpError(error);

  if (pathname === RESERVED_ROOT && err.status >= 500) {
    return new Response(
      htmlPage(
        "Configuration error",
        `<p><b>Error:</b> ${escapeHtml(err.code)}</p>
         <p>${escapeHtml(err.message)}</p>
         <p>Fix your Worker setup and redeploy.</p>`
      ),
      { status: err.status, headers: { "content-type": "text/html; charset=utf-8" } }
    );
  }

  return apiError(err.status, err.code, err.message, err.details);
}

function createKvHelpers({ HttpError, createStorageConnector }) {
  function stateStore(env) {
    return createStorageConnector(env);
  }

  function secretStore(env) {
    // Cloudflare default adapter currently maps both intents to KV.
    return stateStore(env).keyValue;
  }

  function dataStore(env) {
    // Cloudflare default adapter currently maps both intents to KV.
    return stateStore(env).keyValue;
  }

  function kvStore(env) {
    // Backward-compatible alias during migration.
    return dataStore(env);
  }

  async function kvGetValue(env, key) {
    return kvStore(env).get(key);
  }

  async function kvPutValue(env, key, value) {
    return kvStore(env).put(key, value);
  }

  function ensureKvBinding(env) {
    const kv = dataStore(env);
    try {
      kv.assertReady();
    } catch (e) {
      if (!(e instanceof StorageConnectorError) || e.code !== "MISSING_KV_BINDING") throw e;
      throw new HttpError(
        500,
        "MISSING_KV_BINDING",
        "KV binding CONFIG is missing.",
        {
          setup: "Add [[kv_namespaces]] binding = \"CONFIG\" in wrangler.toml and redeploy.",
        }
      );
    }
  }

  return {
    stateStore,
    secretStore,
    dataStore,
    kvStore,
    kvGetValue,
    kvPutValue,
    ensureKvBinding,
  };
}

export {
  KV_PROXY_KEY,
  KV_ADMIN_KEY,
  KV_ISSUER_KEY,
  KV_PROXY_KEY_OLD,
  KV_PROXY_KEY_OLD_EXPIRES_AT,
  KV_PROXY_PRIMARY_KEY_CREATED_AT,
  KV_PROXY_SECONDARY_KEY_CREATED_AT,
  KV_ISSUER_KEY_OLD,
  KV_ISSUER_KEY_OLD_EXPIRES_AT,
  KV_ISSUER_PRIMARY_KEY_CREATED_AT,
  KV_ISSUER_SECONDARY_KEY_CREATED_AT,
  KV_ADMIN_KEY_OLD,
  KV_ADMIN_KEY_OLD_EXPIRES_AT,
  KV_ADMIN_PRIMARY_KEY_CREATED_AT,
  KV_ADMIN_SECONDARY_KEY_CREATED_AT,
  KV_CONFIG_YAML,
  KV_CONFIG_JSON,
  KV_ENRICHED_HEADER_PREFIX,
  KV_HTTP_SECRET_PREFIX,
  KV_BOOTSTRAP_ENRICHED_HEADER_NAMES,
  KV_DEBUG_ENABLED_UNTIL_MS,
  AUTH_PROFILE_PREFIXES,
  AUTH_PROFILE_FIELDS,
  RESERVED_ROOT,
  ADMIN_ROOT,
  DEFAULT_DOCS_URL,
  DEBUG_MAX_TRACE_CHARS,
  DEBUG_MAX_BODY_PREVIEW_CHARS,
  DEFAULTS,
  EXPECTED_REQUEST_SCHEMA,
  SAFE_META_HEADERS,
  HOP_BY_HOP_HEADERS,
  INTERNAL_AUTH_HEADERS,
  JWKS_CACHE_TTL_MS,
  BUILTIN_DEBUG_REDACT_HEADERS,
  normalizePathname,
  renderWorkerError,
  createKvHelpers,
};
