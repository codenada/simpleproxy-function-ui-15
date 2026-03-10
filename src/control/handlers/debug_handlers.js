function createControlDebugHandlers(deps) {
  const {
    observabilityApi,
    HttpError,
    enforceInvokeContentType,
    readJsonWithLimit,
    getEnvInt,
    defaults,
    authProfileKvKey,
    secretStore,
    nowMs,
    jsonResponse,
  } = deps;

  async function handleDebugLastGet(request) {
    return observabilityApi.handleDebugLastGet(request);
  }

  async function handleLiveLogStream(env) {
    return observabilityApi.handleLiveLogStream(env);
  }

  async function handleDebugLoggingSecretPut(request, env) {
    enforceInvokeContentType(request);
    const body = await readJsonWithLimit(request, getEnvInt(env, "MAX_REQ_BYTES", defaults.MAX_REQ_BYTES));
    const value = String(body?.value || "").trim();
    if (!value) {
      throw new HttpError(400, "INVALID_REQUEST", "value is required", {
        expected: { value: "secret-string" },
      });
    }
    const key = authProfileKvKey("logging", "current");
    const issuedKey = authProfileKvKey("logging", "issued_at_ms");
    if (key) {
      await Promise.all([
        secretStore(env).put(key, value),
        issuedKey ? secretStore(env).put(issuedKey, String(nowMs())) : Promise.resolve(),
      ]);
    }
    return jsonResponse(200, {
      ok: true,
      data: {
        logging_secret_set: true,
      },
      meta: {},
    });
  }

  async function handleDebugLoggingSecretGet(env) {
    const key = authProfileKvKey("logging", "current");
    const secret = key ? await secretStore(env).get(key) : null;
    return jsonResponse(200, {
      ok: true,
      data: {
        logging_secret_set: !!secret,
      },
      meta: {},
    });
  }

  async function handleDebugLoggingSecretDelete(env) {
    const key = authProfileKvKey("logging", "current");
    const issuedKey = authProfileKvKey("logging", "issued_at_ms");
    const expiresKey = authProfileKvKey("logging", "expires_at_ms");
    const secondaryKey = authProfileKvKey("logging", "secondary");
    const secondaryIssuedKey = authProfileKvKey("logging", "secondary_issued_at_ms");
    const secondaryExpiresKey = authProfileKvKey("logging", "secondary_expires_at_ms");
    const deletes = [
      key,
      issuedKey,
      expiresKey,
      secondaryKey,
      secondaryIssuedKey,
      secondaryExpiresKey,
    ].filter(Boolean).map((k) => secretStore(env).delete(k));
    if (deletes.length) await Promise.all(deletes);
    return jsonResponse(200, {
      ok: true,
      data: {
        logging_secret_set: false,
      },
      meta: {},
    });
  }

  return {
    handleDebugGet: observabilityApi.handleDebugGet,
    handleDebugPut: observabilityApi.handleDebugPut,
    handleDebugDelete: observabilityApi.handleDebugDelete,
    handleDebugLastGet,
    handleLiveLogStream,
    handleDebugLoggingSecretPut,
    handleDebugLoggingSecretGet,
    handleDebugLoggingSecretDelete,
  };
}

export { createControlDebugHandlers };
