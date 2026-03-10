import { HttpError } from "./lib.js";
import { getClientIp, createInMemoryRpmLimiter } from "./traffic_controls.js";

const allowAdminTokenRpm = createInMemoryRpmLimiter();
const MAX_ROTATION_AUDIT_ENTRIES = 200;

function createKeyAuthApi({
  constants,
  ensureKvBinding,
  secretStore,
  dataStore,
  loadConfigV1,
  loadAdminConfig,
  getEnvInt,
  defaults,
  reservedRoot,
  generateSecret,
  parseMs,
  capitalize,
  escapeHtml,
  htmlPage,
  jsonResponse,
  signJwtHs256,
  verifyJwtHs256,
}) {
  async function secretGetValue(env, key) {
    return secretStore(env).get(key);
  }

  async function secretPutValue(env, key, value) {
    return secretStore(env).put(key, value);
  }

  async function secretDeleteValue(env, key) {
    return secretStore(env).delete(key);
  }

  async function dataGetValue(env, key) {
    return dataStore(env).get(key);
  }

  async function dataPutValue(env, key, value) {
    return dataStore(env).put(key, value);
  }

  function getRotationAuditKvKey(kind) {
    return `audit:key_rotation:${kind}`;
  }

  function getRotationAuthMethod(request) {
    const token = getAdminAccessTokenFromRequest(request);
    if (token) return "admin_access_token";
    const adminKey = String(request?.headers?.get("x-admin-key") || "").trim();
    if (adminKey) return "x-admin-key";
    return "unknown";
  }

  async function appendRotationAuditLog(kind, request, env, details) {
    ensureKvBinding(env);
    const key = getRotationAuditKvKey(kind);
    let existing = [];
    try {
      const raw = await dataGetValue(env, key);
      const parsed = JSON.parse(raw || "[]");
      if (Array.isArray(parsed)) existing = parsed;
    } catch {
      existing = [];
    }

    const entry = {
      ts_ms: Date.now(),
      kind,
      auth_method: getRotationAuthMethod(request),
      source_ip: getClientIp(request),
      ...details,
    };
    const next = [entry, ...existing].slice(0, MAX_ROTATION_AUDIT_ENTRIES);
    await dataPutValue(env, key, JSON.stringify(next));
  }

  const rotationProfiles = {
    proxy: {
      current: constants.KV_PROXY_KEY,
      old: constants.KV_PROXY_KEY_OLD,
      oldExpiresAt: constants.KV_PROXY_KEY_OLD_EXPIRES_AT,
      primaryCreatedAt: constants.KV_PROXY_PRIMARY_KEY_CREATED_AT,
      secondaryCreatedAt: constants.KV_PROXY_SECONDARY_KEY_CREATED_AT,
      header: "X-Proxy-Key",
      missingCode: "NOT_INITIALIZED",
      missingMessage: `Proxy not initialized. Visit ${reservedRoot} first.`,
      unauthorizedCode: "UNAUTHORIZED",
      unauthorizedMessage: "Missing or invalid X-Proxy-Key",
      policyKey: "proxyExpirySeconds",
      responseKey: "proxy_key",
    },
    issuer: {
      current: constants.KV_ISSUER_KEY,
      old: constants.KV_ISSUER_KEY_OLD,
      oldExpiresAt: constants.KV_ISSUER_KEY_OLD_EXPIRES_AT,
      primaryCreatedAt: constants.KV_ISSUER_PRIMARY_KEY_CREATED_AT,
      secondaryCreatedAt: constants.KV_ISSUER_SECONDARY_KEY_CREATED_AT,
      header: "X-Issuer-Key",
      missingCode: "ISSUER_NOT_CONFIGURED",
      missingMessage: "Issuer key is not initialized.",
      unauthorizedCode: "UNAUTHORIZED_ISSUER",
      unauthorizedMessage: "Missing or invalid X-Issuer-Key",
      policyKey: "issuerExpirySeconds",
      responseKey: "issuer_key",
    },
    admin: {
      current: constants.KV_ADMIN_KEY,
      old: constants.KV_ADMIN_KEY_OLD,
      oldExpiresAt: constants.KV_ADMIN_KEY_OLD_EXPIRES_AT,
      primaryCreatedAt: constants.KV_ADMIN_PRIMARY_KEY_CREATED_AT,
      secondaryCreatedAt: constants.KV_ADMIN_SECONDARY_KEY_CREATED_AT,
      header: "X-Admin-Key",
      missingCode: "ADMIN_NOT_CONFIGURED",
      missingMessage: "Admin key is not initialized.",
      unauthorizedCode: "UNAUTHORIZED_ADMIN",
      unauthorizedMessage: "Missing or invalid X-Admin-Key",
      policyKey: "adminExpirySeconds",
      responseKey: "admin_key",
    },
  };

  function getRotationProfile(kind) {
    const profile = rotationProfiles[kind];
    if (profile) return profile;
    throw new HttpError(404, "INVALID_KEY_KIND", "Invalid key kind", {
      expected: Object.keys(rotationProfiles),
      received: kind,
    });
  }

  function enforceAdminTokenRpm(request) {
    const adminConfig = loadAdminConfig();
    const enabled = !!adminConfig?.admin?.get_admin_token_endpoint?.enabled;
    const rpmLimit = Number(adminConfig?.admin?.get_admin_token_endpoint?.rpm_rate_limit || 10);
    const key = getClientIp(request);
    const allowed = allowAdminTokenRpm(key, rpmLimit, enabled);
    if (allowed) return;
    throw new HttpError(429, "RATE_LIMITED", "Too many admin token requests. Please wait and retry.");
  }

  function keyKindConfig(kind) {
    return getRotationProfile(kind);
  }

  async function readKeyStateByProfile(cfg, env) {
    ensureKvBinding(env);
    const [current, old, oldExpiresAtRaw, primaryCreatedAtRaw, secondaryCreatedAtRaw] = await Promise.all([
      secretGetValue(env, cfg.current),
      secretGetValue(env, cfg.old),
      secretGetValue(env, cfg.oldExpiresAt),
      secretGetValue(env, cfg.primaryCreatedAt),
      secretGetValue(env, cfg.secondaryCreatedAt),
    ]);
    const oldExpiresAt = Number(oldExpiresAtRaw || 0);
    const primaryCreatedAt = Number(primaryCreatedAtRaw || 0);
    const secondaryCreatedAt = Number(secondaryCreatedAtRaw || 0);
    return { cfg, current, old, oldExpiresAt, primaryCreatedAt, secondaryCreatedAt };
  }

  async function getKeyAuthState(kind, env) {
    const cfg = keyKindConfig(kind);
    return readKeyStateByProfile(cfg, env);
  }

  async function requireKeyKind(request, env, kind) {
    const { cfg, current, old, oldExpiresAt, primaryCreatedAt, secondaryCreatedAt } = await getKeyAuthState(kind, env);
    if (!current) {
      const details = kind === "admin" ? { setup: `Visit ${reservedRoot} to bootstrap keys.` } : null;
      throw new HttpError(503, cfg.missingCode, cfg.missingMessage, details);
    }

    const got = request.headers.get(cfg.header) || "";

    const cfgDoc = await loadConfigV1(env);
    const expirySeconds = cfgDoc?.apiKeyPolicy?.[cfg.policyKey] ?? null;
    const now = Date.now();
    const primaryExpired =
      expirySeconds !== null &&
      Number.isFinite(primaryCreatedAt) &&
      primaryCreatedAt > 0 &&
      primaryCreatedAt + Number(expirySeconds) * 1000 <= now;
    if (primaryExpired && got === current) {
      throw new HttpError(401, cfg.unauthorizedCode, `${cfg.unauthorizedMessage} (primary key expired)`);
    }
    if (got === current) return;

    const oldActive = !!old && Number.isFinite(oldExpiresAt) && oldExpiresAt > now;
    const secondaryExpired =
      expirySeconds !== null &&
      Number.isFinite(secondaryCreatedAt) &&
      secondaryCreatedAt > 0 &&
      secondaryCreatedAt + Number(expirySeconds) * 1000 <= now;
    if (oldActive && !secondaryExpired && got === old) return;

    if (!!old && Number.isFinite(oldExpiresAt) && oldExpiresAt <= now) {
      await Promise.all([secretDeleteValue(env, cfg.old), secretDeleteValue(env, cfg.oldExpiresAt), secretDeleteValue(env, cfg.secondaryCreatedAt)]);
    }

    if (old && Number.isFinite(oldExpiresAt) && oldExpiresAt > now) {
      throw new HttpError(401, cfg.unauthorizedCode, `${cfg.unauthorizedMessage} (old key overlap is active)`);
    }
    throw new HttpError(401, cfg.unauthorizedCode, cfg.unauthorizedMessage);
  }

  async function requireProxyKey(request, env) {
    await requireKeyKind(request, env, "proxy");
  }

  async function requireAdminKey(request, env) {
    await requireKeyKind(request, env, "admin");
  }

  async function requireIssuerKey(request, env) {
    await requireKeyKind(request, env, "issuer");
  }

  async function getIssuerKeyState(env) {
    const state = await getKeyAuthState("issuer", env);
    if (!state.current) {
      const cfg = keyKindConfig("issuer");
      throw new HttpError(503, cfg.missingCode, cfg.missingMessage);
    }
    return state;
  }

  async function getProxyKey(env) {
    ensureKvBinding(env);
    return secretGetValue(env, constants.KV_PROXY_KEY);
  }

  async function getAdminKey(env) {
    ensureKvBinding(env);
    return secretGetValue(env, constants.KV_ADMIN_KEY);
  }

  function getAdminAccessTokenFromRequest(request) {
    try {
      const url = new URL(request.url);
      const queryToken = String(url.searchParams.get("admin_access_token") || "").trim();
      if (queryToken) return queryToken;
    } catch {}
    const explicit = String(request.headers.get("X-Admin-Access-Token") || "").trim();
    if (explicit) return explicit;
    const auth = String(request.headers.get("authorization") || "");
    const match = auth.match(/^Bearer\s+(.+)$/i);
    return match ? match[1].trim() : "";
  }

  async function getAdminJwtSecret(env) {
    const configured = String(env?.ADMIN_UI_JWT_SECRET || "").trim();
    if (configured) return configured;
    const adminKey = await getAdminKey(env);
    if (!adminKey) {
      throw new HttpError(503, "ADMIN_NOT_CONFIGURED", "Admin key is not initialized.", {
        setup: `Visit ${reservedRoot} to bootstrap keys.`,
      });
    }
    return adminKey;
  }

  async function validateAdminAccessToken(token, env) {
    if (!token) return false;
    const secret = await getAdminJwtSecret(env);
    try {
      await verifyJwtHs256(token, secret, { issuer: "apiproxy", audience: "apiproxy-admin-ui", clock_skew_seconds: 0 });
      return true;
    } catch {
      return false;
    }
  }

  async function requireAdminAuth(request, env) {
    const token = getAdminAccessTokenFromRequest(request);
    if (token) {
      const ok = await validateAdminAccessToken(token, env);
      if (ok) return;
      throw new HttpError(401, "UNAUTHORIZED_ADMIN", "Invalid or expired admin access token");
    }
    await requireAdminKey(request, env);
  }

  async function handleAdminAccessTokenPost(request, env) {
    enforceAdminTokenRpm(request);
    const ttlSeconds = Math.max(60, getEnvInt(env, "ADMIN_ACCESS_TOKEN_TTL_SECONDS", defaults.ADMIN_ACCESS_TOKEN_TTL_SECONDS));
    const nowSec = Math.floor(Date.now() / 1000);
    const expiresAtMs = (nowSec + ttlSeconds) * 1000;
    const secret = await getAdminJwtSecret(env);
    const token = await signJwtHs256(
      {
        iss: "apiproxy",
        aud: "apiproxy-admin-ui",
        iat: nowSec,
        exp: nowSec + ttlSeconds,
        scope: "admin_ui",
      },
      secret
    );
    const requestUrl = new URL(request.url);
    const adminUrl = `${requestUrl.origin}/admin?admin_access_token=${encodeURIComponent(token)}`;
    return jsonResponse(200, {
      ok: true,
      data: {
        access_token: token,
        admin_url: adminUrl,
        expires_at_ms: expiresAtMs,
        ttl_seconds: ttlSeconds,
      },
      meta: {},
    });
  }

  async function rotateKey(kind, request, env) {
    const cfg = getRotationProfile(kind);
    const overlapMs = getEnvInt(env, "ROTATE_OVERLAP_MS", defaults.ROTATE_OVERLAP_MS);
    const now = Date.now();
    const oldExpiresAt = now + Math.max(0, overlapMs);
    const [state, config] = await Promise.all([getKeyAuthState(kind, env), loadConfigV1(env)]);
    const current = state.current;
    const currentPrimaryCreatedAt = parseMs(state.primaryCreatedAt);
    const newKey = generateSecret();
    const expirySeconds = config?.apiKeyPolicy?.[cfg.policyKey] ?? null;

    await Promise.all([secretPutValue(env, cfg.current, newKey), secretPutValue(env, cfg.primaryCreatedAt, String(now))]);
    if (current && overlapMs > 0) {
      await Promise.all([
        secretPutValue(env, cfg.old, current),
        secretPutValue(env, cfg.oldExpiresAt, String(oldExpiresAt)),
        secretPutValue(env, cfg.secondaryCreatedAt, String(currentPrimaryCreatedAt || now)),
      ]);
    } else {
      await Promise.all([secretDeleteValue(env, cfg.old), secretDeleteValue(env, cfg.oldExpiresAt), secretDeleteValue(env, cfg.secondaryCreatedAt)]);
    }

    // Best-effort audit log: do not fail key rotation if logging has issues.
    try {
      await appendRotationAuditLog(kind, request, env, {
        old_key_overlap_active: !!current && overlapMs > 0,
        old_key_overlap_ms: current ? Math.max(0, overlapMs) : 0,
        policy_expiry_seconds: expirySeconds,
      });
    } catch {}

    const acceptsHtml = (request.headers.get("accept") || "").includes("text/html");
    if (acceptsHtml) {
      return new Response(
        htmlPage(
          `${capitalize(kind)} key rotated`,
          `<p>Store this new ${escapeHtml(kind)} key and replace the old value immediately.</p>
           <pre style="padding:12px;border:1px solid #ddd;border-radius:8px;white-space:pre-wrap;word-break:break-all;">${escapeHtml(
             newKey
           )}</pre>`
        ),
        { headers: { "content-type": "text/html; charset=utf-8" } }
      );
    }

    return jsonResponse(200, {
      ok: true,
      data: {
        kind,
        [cfg.responseKey]: newKey,
        old_key_overlap_active: !!current && overlapMs > 0,
        old_key_overlap_ms: current ? Math.max(0, overlapMs) : 0,
        expiry_seconds: expirySeconds,
      },
    });
  }

  async function handleRotateByKind(kind, request, env) {
    return rotateKey(kind, request, env);
  }

  return {
    keyKindConfig,
    getKeyAuthState,
    requireKeyKind,
    getProxyKey,
    getAdminKey,
    getIssuerKeyState,
    requireProxyKey,
    requireAdminKey,
    requireIssuerKey,
    getAdminAccessTokenFromRequest,
    getAdminJwtSecret,
    validateAdminAccessToken,
    requireAdminAuth,
    handleAdminAccessTokenPost,
    getRotationProfile,
    rotateKey,
    handleRotateByKind,
  };
}

export { createKeyAuthApi };
