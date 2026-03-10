import { isValidHttpSecretRef } from "../../common/auth_profile_keys.js";

function createControlSecretsHandlers(deps) {
  const {
    adminRoot,
    HttpError,
    authProfilePrefix,
    authProfileKvKey,
    authProfileFields,
    httpSecretKvKey,
    enforceInvokeContentType,
    readJsonWithLimit,
    getEnvInt,
    defaults,
    secretStore,
    nowMs,
    jsonResponse,
  } = deps;

  function parseHttpAuthSecretPath(pathname) {
    const base = `${adminRoot}/http-auth/`;
    if (!pathname.startsWith(base)) return null;
    const rest = pathname.slice(base.length);
    const parts = rest.split("/");
    if (parts.length !== 2) return null;
    if (parts[1] !== "secret") return null;
    const profile = decodeURIComponent(parts[0] || "");
    return profile || null;
  }

  async function handleHttpAuthSecretRoute(pathname, request, env) {
    const profile = parseHttpAuthSecretPath(pathname);
    if (!profile) {
      throw new HttpError(404, "NOT_FOUND", "Route not found");
    }
    if (!authProfilePrefix(profile)) {
      throw new HttpError(400, "INVALID_REQUEST", "Unsupported auth profile");
    }
    if (request.method === "PUT") return await handleHttpAuthSecretPut(profile, request, env);
    if (request.method === "GET") return await handleHttpAuthSecretGet(profile, env);
    if (request.method === "DELETE") return await handleHttpAuthSecretDelete(profile, env);
    throw new HttpError(405, "METHOD_NOT_ALLOWED", "Method not allowed");
  }

  async function handleHttpAuthSecretPut(profile, request, env) {
    enforceInvokeContentType(request);
    const body = await readJsonWithLimit(request, getEnvInt(env, "MAX_REQ_BYTES", defaults.MAX_REQ_BYTES));
    const value = String(body?.value || "").trim();
    if (!value) {
      throw new HttpError(400, "INVALID_REQUEST", "value is required", {
        expected: { value: "secret-string" },
      });
    }
    const key = authProfileKvKey(profile, "current");
    const issuedKey = authProfileKvKey(profile, "issued_at_ms");
    if (key) {
      await Promise.all([
        secretStore(env).put(key, value),
        issuedKey ? secretStore(env).put(issuedKey, String(nowMs())) : Promise.resolve(),
      ]);
    }
    return jsonResponse(200, {
      ok: true,
      data: {
        profile,
        secret_set: true,
      },
      meta: {},
    });
  }

  async function handleHttpAuthSecretGet(profile, env) {
    const key = authProfileKvKey(profile, "current");
    const secret = key ? await secretStore(env).get(key) : null;
    return jsonResponse(200, {
      ok: true,
      data: {
        profile,
        secret_set: !!secret,
      },
      meta: {},
    });
  }

  async function handleHttpAuthSecretDelete(profile, env) {
    const deletes = authProfileFields
      .map((field) => authProfileKvKey(profile, field))
      .filter(Boolean)
      .map((key) => secretStore(env).delete(key));
    if (deletes.length) await Promise.all(deletes);
    return jsonResponse(200, {
      ok: true,
      data: {
        profile,
        secret_set: false,
      },
      meta: {},
    });
  }

  function parseHttpSecretPath(pathname) {
    const base = `${adminRoot}/http-secrets/`;
    if (!pathname.startsWith(base)) return null;
    const rest = pathname.slice(base.length);
    if (!rest || rest.includes("/")) return null;
    const ref = decodeURIComponent(rest || "").trim();
    if (!isValidHttpSecretRef(ref)) return null;
    return ref;
  }

  async function handleHttpSecretRoute(pathname, request, env) {
    const ref = parseHttpSecretPath(pathname);
    if (!ref) {
      throw new HttpError(404, "NOT_FOUND", "Route not found");
    }
    if (request.method === "PUT") return await handleHttpSecretPut(ref, request, env);
    if (request.method === "GET") return await handleHttpSecretGet(ref, env);
    if (request.method === "DELETE") return await handleHttpSecretDelete(ref, env);
    throw new HttpError(405, "METHOD_NOT_ALLOWED", "Method not allowed");
  }

  async function handleHttpSecretPut(ref, request, env) {
    enforceInvokeContentType(request);
    const body = await readJsonWithLimit(request, getEnvInt(env, "MAX_REQ_BYTES", defaults.MAX_REQ_BYTES));
    const value = String(body?.value || "").trim();
    if (!value) {
      throw new HttpError(400, "INVALID_REQUEST", "value is required", {
        expected: { value: "secret-string" },
      });
    }
    const key = httpSecretKvKey(ref);
    if (!key) {
      throw new HttpError(400, "INVALID_REQUEST", "Invalid secret reference");
    }
    await secretStore(env).put(key, value);
    return jsonResponse(200, {
      ok: true,
      data: {
        secret_ref: ref,
        secret_set: true,
      },
      meta: {},
    });
  }

  async function handleHttpSecretGet(ref, env) {
    const key = httpSecretKvKey(ref);
    const secret = key ? await secretStore(env).get(key) : null;
    return jsonResponse(200, {
      ok: true,
      data: {
        secret_ref: ref,
        secret_set: !!secret,
      },
      meta: {},
    });
  }

  async function handleHttpSecretDelete(ref, env) {
    const key = httpSecretKvKey(ref);
    if (key) await secretStore(env).delete(key);
    return jsonResponse(200, {
      ok: true,
      data: {
        secret_ref: ref,
        secret_set: false,
      },
      meta: {},
    });
  }

  return {
    handleHttpAuthSecretRoute,
    handleHttpSecretRoute,
  };
}

export { createControlSecretsHandlers };
