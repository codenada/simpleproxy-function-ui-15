import {
  htmlPage,
  escapeHtml,
  capitalize,
} from "./ui.js";
import { parseBootstrapEnrichedHeadersJson } from "../common/bootstrap_enriched_headers.js";
import {
  HttpError,
  toHttpError,
  jsonResponse,
  apiError,
  isNonArrayObject,
  isPlainObject,
  normalizeHeaderName,
  getPathValue,
  getStoredContentType,
  looksJson,
  looksYaml,
  normalizeHeaderMap,
} from "../common/lib.js";
import { ERROR_CODES } from "../common/error_codes.js";
import {
  DEFAULT_CONFIG_V1,
  VALID_TRANSFORM_TYPES,
  createConfigApi,
  parseYamlConfigText,
  stringifyYamlConfig,
  validateAndNormalizeConfigV1,
} from "../common/config.js";
import { createRequestAuthApi } from "../common/request_auth.js";
import { createJwtAuthApi } from "../common/jwt_auth.js";
import { createKeyAuthApi } from "../common/key_auth.js";
import { createTransformRuntimeApi } from "../common/transform_runtime.js";
import { createObservabilityApi } from "../common/observability.js";
import { createAdminUiApi } from "./admin_ui.js";
import { createSwaggerApi } from "./swagger.js";
import { createBootstrapApi } from "./bootstrap.js";
import { loadAdminConfig } from "./admin_config.js";
import { createControlConfigHandlers } from "./handlers/config_handlers.js";
import { createControlDebugHandlers } from "./handlers/debug_handlers.js";
import { createControlSecretsHandlers } from "./handlers/secrets_handlers.js";
import { createControlEnrichedHeadersHandlers } from "./handlers/enriched_headers_handlers.js";
import {
  CONTROL_RESERVED_ROOT,
  CONTROL_ADMIN_ROOT,
  readControlEnv,
} from "./control_routes.js";
import { createPlatformAdapters } from "../platform/index.js";
import { createProxySupportApi } from "../common/proxy_support.js";
import { dispatchPublicRoute } from "../common/routes/public.js";
import { dispatchAdminRoute } from "./routes/admin.js";
import { buildControlRouteHandlers } from "./routes/handler_registry.js";
import { createRouteAuth } from "../common/routes/route_auth.js";
import { getClientIp, createCidrMatcher } from "../common/traffic_controls.js";
import {
  createAuthProfileKeyResolvers,
} from "../common/auth_profile_keys.js";
import {
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
  DEFAULT_DOCS_URL,
  DEBUG_MAX_TRACE_CHARS,
  DEBUG_MAX_BODY_PREVIEW_CHARS,
  DEFAULTS,
  SAFE_META_HEADERS,
  INTERNAL_AUTH_HEADERS,
  JWKS_CACHE_TTL_MS,
  BUILTIN_DEBUG_REDACT_HEADERS,
  normalizePathname,
  renderWorkerError,
  createKvHelpers,
} from "../common/worker_shared.js";

const RESERVED_ROOT = CONTROL_RESERVED_ROOT;
const ADMIN_ROOT = CONTROL_ADMIN_ROOT;

/**
 * Control/admin worker.
 *
 * Endpoints:
 * - GET /                        : onboarding/login/status page
 * - POST /                       : bootstrap action
 * - POST /_apiproxy/keys/admin/rotate
 * - POST /admin/browser-verify
 * - POST /admin/access-token
 * - GET /admin/version
 * - POST /admin/keys/{proxy|issuer|admin}/rotate
 * - GET/PUT /admin/config
 * - POST /admin/config/validate
 * - POST /admin/config/test-rule
 * - GET/PUT/DELETE /admin/debug
 * - GET /admin/debug/last
 * - GET /admin/live-log/stream
 * - GET /admin/swagger
 * - GET /admin/swagger/openapi.json
 * - PUT/DELETE /admin/debug/loggingSecret
 */

let jsonataFactory = null;
let yamlApi = null;
const PLATFORM = createPlatformAdapters();

function createWorker() {
  function shouldApplyAdminIpFilter(pathname) {
    return pathname === "/" || pathname === RESERVED_ROOT || pathname.startsWith(`${ADMIN_ROOT}`);
  }

  function isIpAllowed(request) {
    const cfg = loadAdminConfig();
    const enabled = !!cfg?.admin?.ip_filter?.enabled;
    const allowedCidrs = cfg?.admin?.ip_filter?.allowed_cidrs;
    return isIpAllowedByCidr(getClientIp(request), allowedCidrs, enabled);
  }

  return {
    async fetch(request, env, ctx) {
      const { pathname } = new URL(request.url);
      const normalizedPath = normalizePathname(pathname);

      try {
        if (shouldApplyAdminIpFilter(normalizedPath) && !isIpAllowed(request)) {
          return apiError(403, "IP_NOT_ALLOWED", "IP address is not allowed.");
        }

        const publicResponse = await dispatchPublicRoute({
          normalizedPath,
          request,
          env,
          ctx,
          reservedRoot: RESERVED_ROOT,
          handlers: routeHandlers,
          auth: routeAuth,
          options: {
            enableRootProxy: false,
            enableStatusBootstrap: false,
            enableRequest: false,
            enableProxyRotate: false,
            enableIssuerRotate: false,
            enableAdminRotate: true,
            exposeStatusBootstrapAtRoot: true,
          },
        });
        if (publicResponse) return publicResponse;

        const adminResponse = await dispatchAdminRoute({
          normalizedPath,
          request,
          env,
          adminRoot: ADMIN_ROOT,
          handlers: routeHandlers,
          auth: routeAuth,
        });
        if (adminResponse) return adminResponse;

        return apiError(404, ERROR_CODES.NOT_FOUND, "Route not found");
      } catch (error) {
        return renderWorkerError({
          error,
          pathname: normalizedPath,
          toHttpError,
          htmlPage,
          escapeHtml,
          apiError,
        });
      }
    },
  };
}

export default createWorker();

// Expose config validator for local tooling (not used by Worker runtime).
export { createWorker, validateAndNormalizeConfigV1 };

const { secretStore, dataStore, ensureKvBinding } = createKvHelpers({
  HttpError,
  createStorageConnector: PLATFORM.createStorageConnector,
});
const authProfileKeyResolvers = createAuthProfileKeyResolvers({
  prefixMap: AUTH_PROFILE_PREFIXES,
  secretPrefix: KV_HTTP_SECRET_PREFIX,
});

const proxySupportApi = createProxySupportApi({
  HttpError,
  getStoredContentType,
  isPlainObject,
  safeMetaHeaders: SAFE_META_HEADERS,
});
const {
  getEnvInt,
  readJsonWithLimit,
  readTextWithLimit,
  enforceInvokeContentType,
  detectResponseType,
} = proxySupportApi;

const configApi = createConfigApi({
  ensureKvBinding,
  kvStore: dataStore,
  kvConfigYamlKey: KV_CONFIG_YAML,
  kvConfigJsonKey: KV_CONFIG_JSON,
});

const requestAuthApi = createRequestAuthApi({
  isNonArrayObject,
  isPlainObject,
  getPathValue,
  authProfilePrefix: authProfileKeyResolvers.authProfilePrefix,
  authProfileKvKey: authProfileKeyResolvers.authProfileKvKey,
  httpSecretKvKey: authProfileKeyResolvers.httpSecretKvKey,
  kvGetValue: (env, key) => secretStore(env).get(key),
  kvPutValue: (env, key, value) => secretStore(env).put(key, value),
  authProfileFields: AUTH_PROFILE_FIELDS,
  httpRequest: PLATFORM.http.request,
});

const jwtAuthApi = createJwtAuthApi({
  buildHttpRequestInit: (req, config, env) => requestAuthApi.buildHttpRequestInit(req, config, env),
  jwksCacheTtlMs: JWKS_CACHE_TTL_MS,
  nowMs: PLATFORM.clock.nowMs,
  httpRequest: PLATFORM.http.request,
  subtle: PLATFORM.crypto.subtle,
});

const keyAuthApi = createKeyAuthApi({
  constants: {
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
  },
  ensureKvBinding,
  secretStore,
  dataStore,
  loadConfigV1: (env) => configApi.loadConfigV1(env),
  loadAdminConfig,
  getEnvInt,
  defaults: DEFAULTS,
  reservedRoot: RESERVED_ROOT,
  generateSecret,
  parseMs,
  capitalize,
  escapeHtml,
  htmlPage,
  jsonResponse,
  signJwtHs256: (payload, secret) => jwtAuthApi.signJwtHs256(payload, secret),
  verifyJwtHs256: (token, secret, cfg) => jwtAuthApi.verifyJwtHs256(token, secret, cfg),
});

const transformRuntimeApi = createTransformRuntimeApi({
  isPlainObject,
  normalizeHeaderName,
  defaultHeaderForwarding: DEFAULT_CONFIG_V1.header_forwarding,
  internalAuthHeadersSet: INTERNAL_AUTH_HEADERS,
  loadJsonata,
});

const observabilityApi = createObservabilityApi({
  adminRoot: ADMIN_ROOT,
  kvDebugEnabledUntilMsKey: KV_DEBUG_ENABLED_UNTIL_MS,
  builtinDebugRedactHeaders: BUILTIN_DEBUG_REDACT_HEADERS,
  debugMaxTraceChars: DEBUG_MAX_TRACE_CHARS,
  debugMaxBodyPreviewChars: DEBUG_MAX_BODY_PREVIEW_CHARS,
  ensureKvBinding,
  kvStore: dataStore,
  normalizeHeaderMap,
  loadConfigV1: (env) => configApi.loadConfigV1(env),
  getEnvInt,
  defaults: DEFAULTS,
  enforceInvokeContentType,
  readJsonWithLimit,
  jsonResponse,
  htmlPage,
  escapeHtml,
  buildHttpRequestInit: (req, config, env) => requestAuthApi.buildHttpRequestInit(req, config, env),
  nowMs: PLATFORM.clock.nowMs,
  httpRequest: PLATFORM.http.request,
});

const adminUiApi = createAdminUiApi({
  adminRoot: ADMIN_ROOT,
});

const swaggerApi = createSwaggerApi({
  htmlPage,
  reservedRoot: RESERVED_ROOT,
  adminRoot: ADMIN_ROOT,
});

const bootstrapApi = createBootstrapApi({
  constants: {
    kvProxyKey: KV_PROXY_KEY,
    kvAdminKey: KV_ADMIN_KEY,
    kvProxyPrimaryCreatedAt: KV_PROXY_PRIMARY_KEY_CREATED_AT,
    kvAdminPrimaryCreatedAt: KV_ADMIN_PRIMARY_KEY_CREATED_AT,
    kvBootstrapKeysShownOnce: "bootstrap_keys_shown_once",
    adminRoot: ADMIN_ROOT,
    defaultDocsUrl: DEFAULT_DOCS_URL,
  },
  ensureKvBinding,
  secretGetValue: (env, key) => secretStore(env).get(key),
  secretPutValue: (env, key, value, options = undefined) => secretStore(env).put(key, value, options),
  dataGetValue: (env, key) => dataStore(env).get(key),
  dataPutValue: (env, key, value, options = undefined) => dataStore(env).put(key, value, options),
  dataDeleteValue: (env, key) => dataStore(env).delete(key),
  loadConfigV1: (env) => configApi.loadConfigV1(env),
  loadAdminConfig,
  generateSecret,
  HttpError,
  nowMs: PLATFORM.clock.nowMs,
  randomHexGenerator: (bytes = 16) =>
    Array.from(PLATFORM.crypto.randomBytes(bytes), (b) => b.toString(16).padStart(2, "0")).join(""),
  sha256HexDigest: PLATFORM.crypto.sha256Hex,
});

function buildRouteHandlers() {
  return buildControlRouteHandlers({
    bootstrapApi,
    adminUiApi,
    swaggerApi,
    handleRotateByKind: keyAuthApi.handleRotateByKind,
    handleAdminAccessTokenPost: keyAuthApi.handleAdminAccessTokenPost,
    handleVersion,
    handleKeysStatusGet,
    ...configHandlers,
    ...debugHandlers,
    ...secretsHandlers,
    ...enrichedHeadersHandlers,
  });
}

const isIpAllowedByCidr = createCidrMatcher();
const configHandlers = createControlConfigHandlers({
  HttpError,
  DEFAULT_CONFIG_V1,
  VALID_TRANSFORM_TYPES,
  isNonArrayObject,
  isPlainObject,
  getStoredContentType,
  looksJson,
  looksYaml,
  normalizeHeaderMap,
  jsonResponse,
  parseYamlConfigText,
  stringifyYamlConfig,
  validateAndNormalizeConfigV1,
  loadConfigV1: configApi.loadConfigV1,
  loadConfigYamlV1: configApi.loadConfigYamlV1,
  saveConfigFromYamlV1: configApi.saveConfigFromYamlV1,
  saveConfigObjectV1: configApi.saveConfigObjectV1,
  getEnvInt,
  readJsonWithLimit,
  readTextWithLimit,
  enforceInvokeContentType,
  detectResponseType,
  selectTransformRule: transformRuntimeApi.selectTransformRule,
  evalJsonataWithTimeout: transformRuntimeApi.evalJsonataWithTimeout,
  loadYamlApi,
  defaults: DEFAULTS,
});
const debugHandlers = createControlDebugHandlers({
  observabilityApi,
  HttpError,
  enforceInvokeContentType,
  readJsonWithLimit,
  getEnvInt,
  defaults: DEFAULTS,
  authProfileKvKey: authProfileKeyResolvers.authProfileKvKey,
  secretStore,
  nowMs: PLATFORM.clock.nowMs,
  jsonResponse,
});
const secretsHandlers = createControlSecretsHandlers({
  adminRoot: ADMIN_ROOT,
  HttpError,
  authProfilePrefix: authProfileKeyResolvers.authProfilePrefix,
  authProfileKvKey: authProfileKeyResolvers.authProfileKvKey,
  authProfileFields: AUTH_PROFILE_FIELDS,
  httpSecretKvKey: authProfileKeyResolvers.httpSecretKvKey,
  enforceInvokeContentType,
  readJsonWithLimit,
  getEnvInt,
  defaults: DEFAULTS,
  secretStore,
  nowMs: PLATFORM.clock.nowMs,
  jsonResponse,
});
const enrichedHeadersHandlers = createControlEnrichedHeadersHandlers({
  HttpError,
  adminRoot: ADMIN_ROOT,
  ensureKvBinding,
  dataStore,
  kvEnrichedHeaderPrefix: KV_ENRICHED_HEADER_PREFIX,
  kvBootstrapEnrichedHeaderNames: KV_BOOTSTRAP_ENRICHED_HEADER_NAMES,
  normalizeHeaderName,
  isPlainObject,
  getBootstrapEnrichedHeaders,
  enforceInvokeContentType,
  readJsonWithLimit,
  getEnvInt,
  defaults: DEFAULTS,
  jsonResponse,
});
const routeHandlers = buildRouteHandlers();
const routeAuth = createRouteAuth(keyAuthApi);

async function loadYamlApi() {
  if (yamlApi) return yamlApi;
  try {
    const mod = await import("yaml");
    yamlApi = {
      parse: mod.parse,
      stringify: mod.stringify,
    };
    if (typeof yamlApi.parse !== "function" || typeof yamlApi.stringify !== "function") {
      throw new Error("yaml parse/stringify not available");
    }
    return yamlApi;
  } catch (e) {
    throw new HttpError(
      500,
      "MISSING_YAML_DEPENDENCY",
      "yaml dependency is not available in this Worker build.",
      {
        setup: "Ensure yaml is listed in package.json dependencies and deploy from repository root.",
        cause: String(e?.message || e),
      }
    );
  }
}

function getBootstrapEnrichedHeaders(env) {
  return parseBootstrapEnrichedHeadersJson(env?.BOOTSTRAP_ENRICHED_HEADERS_JSON, env, {
    HttpError,
    isPlainObject,
    normalizeHeaderName,
  });
}

function base64url(bytes) {
  const bin = String.fromCharCode(...bytes);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function generateSecret() {
  const bytes = PLATFORM.crypto.randomBytes(32);
  return base64url(bytes);
}

async function loadJsonata() {
  if (jsonataFactory) return jsonataFactory;

  try {
    const mod = await import("jsonata");
    jsonataFactory = mod?.default || mod;
    if (typeof jsonataFactory !== "function") {
      throw new Error("jsonata default export is not a function");
    }
    return jsonataFactory;
  } catch (e) {
    throw new HttpError(
      500,
      "MISSING_JSONATA_DEPENDENCY",
      "jsonata dependency is not available in this Worker build.",
      {
        setup: "Ensure jsonata is listed in package.json dependencies and deploy from repository root.",
        cause: String(e?.message || e),
      }
    );
  }
}

function handleVersion(env) {
  const controlEnv = readControlEnv(env);
  return jsonResponse(200, {
    ok: true,
    data: { version: controlEnv.buildVersion, build_timestamp: controlEnv.buildTimestamp || null },
    meta: {},
  });
}

function parseMs(raw) {
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? n : 0;
}

async function handleKeysStatusGet(env) {
  const now = PLATFORM.clock.nowMs();
  const [proxyState, issuerState, adminState, config] = await Promise.all([
    keyAuthApi.getKeyAuthState("proxy", env),
    keyAuthApi.getKeyAuthState("issuer", env),
    keyAuthApi.getKeyAuthState("admin", env),
    configApi.loadConfigV1(env),
  ]);

  const cleanup = [];
  function normalize(kind, state) {
    let primaryCreatedAt = parseMs(state.primaryCreatedAt);
    let secondaryCreatedAt = parseMs(state.secondaryCreatedAt);
    const oldExpiresAt = parseMs(state.oldExpiresAt);
    const secondaryActive = !!state.old && oldExpiresAt > now;
    if (state.current && !primaryCreatedAt) {
      primaryCreatedAt = now;
      cleanup.push(secretStore(env).put(state.cfg.primaryCreatedAt, String(primaryCreatedAt)));
    }
    if (!state.old) {
      secondaryCreatedAt = 0;
    } else if (!secondaryCreatedAt) {
      secondaryCreatedAt = now;
      cleanup.push(secretStore(env).put(state.cfg.secondaryCreatedAt, String(secondaryCreatedAt)));
    }
    if (state.old && oldExpiresAt <= now) {
      cleanup.push(secretStore(env).delete(state.cfg.old), secretStore(env).delete(state.cfg.oldExpiresAt), secretStore(env).delete(state.cfg.secondaryCreatedAt));
      secondaryCreatedAt = 0;
    }
    const expirySeconds = config?.apiKeyPolicy?.[keyAuthApi.keyKindConfig(kind).policyKey] ?? null;
    return {
      primary_active: !!state.current,
      secondary_active: secondaryActive,
      [`${kind}_primary_key_created_at`]: primaryCreatedAt || 0,
      [`${kind}_secondary_key_created_at`]: secondaryActive ? secondaryCreatedAt || 0 : 0,
      expiry_seconds: expirySeconds,
    };
  }

  const proxyData = normalize("proxy", proxyState);
  const issuerData = normalize("issuer", issuerState);
  const adminData = normalize("admin", adminState);

  if (cleanup.length > 0) await Promise.all(cleanup);

  return jsonResponse(200, {
    ok: true,
    data: {
      proxy: proxyData,
      issuer: issuerData,
      admin: adminData,
    },
    meta: {},
  });
}
