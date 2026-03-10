function createControlConfigHandlers(deps) {
  const {
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
    loadConfigV1,
    loadConfigYamlV1,
    saveConfigFromYamlV1,
    saveConfigObjectV1,
    getEnvInt,
    readJsonWithLimit,
    readTextWithLimit,
    enforceInvokeContentType,
    detectResponseType,
    selectTransformRule,
    evalJsonataWithTimeout,
    loadYamlApi,
    defaults,
  } = deps;

  async function readConfigInputByContentType(request, maxBytes) {
    const contentType = getStoredContentType(request.headers);
    if (looksJson(contentType)) {
      const body = await readJsonWithLimit(request, maxBytes);
      if (!isPlainObject(body)) {
        throw new HttpError(400, "INVALID_CONFIG", "Configuration JSON must be an object");
      }
      return { format: "json", config: validateAndNormalizeConfigV1(body) };
    }
    if (looksYaml(contentType)) {
      const yamlText = await readTextWithLimit(request, maxBytes);
      const normalized = await parseYamlConfigText(yamlText);
      return { format: "yaml", config: normalized, yamlText };
    }
    throw new HttpError(415, "UNSUPPORTED_MEDIA_TYPE", "Content-Type must be application/json or text/yaml");
  }

  async function readNormalizedConfigRequest(request, env) {
    const maxReq = getEnvInt(env, "MAX_REQ_BYTES", defaults.MAX_REQ_BYTES);
    return readConfigInputByContentType(request, maxReq);
  }

  function toNullablePositiveInt(raw, field) {
    if (raw === null || raw === undefined || raw === "") return null;
    const n = Number(raw);
    if (!Number.isInteger(n) || n < 1) {
      throw new HttpError(400, "INVALID_REQUEST", `${field} must be a positive integer or null`);
    }
    return n;
  }

  async function handleConfigGet(env) {
    const yamlText = await loadConfigYamlV1(env);
    return new Response(yamlText, {
      status: 200,
      headers: { "content-type": "text/yaml; charset=utf-8" },
    });
  }

  async function handleConfigPut(request, env) {
    const parsed = await readNormalizedConfigRequest(request, env);
    const normalized =
      parsed.format === "yaml"
        ? await saveConfigFromYamlV1(parsed.yamlText, env)
        : await saveConfigObjectV1(parsed.config, env);
    return jsonResponse(200, {
      ok: true,
      data: {
        message: "Configuration updated",
        config: normalized,
      },
      meta: {},
    });
  }

  async function handleConfigValidate(request, env) {
    const parsed = await readNormalizedConfigRequest(request, env);
    return jsonResponse(200, {
      ok: true,
      data: {
        valid: true,
        config: parsed.config,
      },
      meta: {},
    });
  }

  async function handleConfigTestRule(request, env) {
    enforceInvokeContentType(request);
    const maxReq = getEnvInt(env, "MAX_REQ_BYTES", defaults.MAX_REQ_BYTES);
    const body = await readJsonWithLimit(request, maxReq);

    let config;
    if (typeof body?.config_yaml === "string" && body.config_yaml.trim()) {
      config = await parseYamlConfigText(body.config_yaml);
    } else if (body?.config && isNonArrayObject(body.config)) {
      config = validateAndNormalizeConfigV1(body.config);
    } else {
      config = await loadConfigV1(env);
    }

    const sample = body?.response;
    if (!isNonArrayObject(sample)) {
      throw new HttpError(400, "INVALID_REQUEST", "response object is required", {
        expected: {
          response: {
            status: 404,
            headers: { "content-type": "application/json" },
            body: { error: "Not found" },
            type: "json",
          },
        },
      });
    }

    const status = Number(sample.status);
    if (!Number.isInteger(status) || status < 100 || status > 599) {
      throw new HttpError(400, "INVALID_REQUEST", "response.status must be an integer 100-599");
    }

    const headers = normalizeHeaderMap(sample.headers);
    const contentType = headers["content-type"] || "";
    const type = sample.type ? String(sample.type).toLowerCase() : detectResponseType(contentType);
    if (!VALID_TRANSFORM_TYPES.has(type)) {
      throw new HttpError(400, "INVALID_REQUEST", "response.type must be one of json, text, binary, any");
    }

    const ctx = { status, headers, type };
    const targetResponseSection = config?.transform?.target_response || DEFAULT_CONFIG_V1.transform.target_response;
    const { matchedRule, trace } = selectTransformRule(targetResponseSection, ctx);

    let expression = null;
    let source = "none";
    if (matchedRule) {
      expression = matchedRule.expr;
      source = `rule:${matchedRule.name}`;
    } else if (targetResponseSection.fallback === "transform_default" && targetResponseSection.defaultExpr) {
      expression = targetResponseSection.defaultExpr;
      source = "defaultExpr";
    }

    let output = null;
    if (expression) {
      try {
        output = await evalJsonataWithTimeout(
          expression,
          { status, headers, body: sample.body },
          getEnvInt(env, "TRANSFORM_TIMEOUT_MS", defaults.TRANSFORM_TIMEOUT_MS)
        );
      } catch (e) {
        throw new HttpError(422, "TRANSFORM_ERROR", "JSONata evaluation failed in test-rule", {
          cause: String(e?.message || e),
        });
      }
    }

    return jsonResponse(200, {
      ok: true,
      data: {
        matched_rule: matchedRule ? matchedRule.name : null,
        expression_source: source,
        fallback_behavior: targetResponseSection.fallback,
        output,
        trace,
      },
      meta: {},
    });
  }

  async function handleKeyRotationConfigGet(env) {
    const config = await loadConfigV1(env);
    const section = config?.targetCredentialRotation || DEFAULT_CONFIG_V1.targetCredentialRotation;
    return jsonResponse(200, {
      ok: true,
      data: {
        enabled: !!section.enabled,
        strategy: String(section.strategy || "json_ttl"),
        request_yaml: await stringifyYamlConfig(section.request || {}),
        request: section.request || {},
        key_path: String(section?.response?.key_path || ""),
        ttl_path: section?.response?.ttl_path ?? null,
        ttl_unit: String(section?.response?.ttl_unit || "seconds"),
        expires_at_path: section?.response?.expires_at_path ?? null,
        refresh_skew_seconds: Number(section?.trigger?.refresh_skew_seconds ?? 300),
        retry_once_on_401: !!section?.trigger?.retry_once_on_401,
        proxy_expiry_seconds: config?.apiKeyPolicy?.proxyExpirySeconds ?? null,
        issuer_expiry_seconds: config?.apiKeyPolicy?.issuerExpirySeconds ?? null,
        admin_expiry_seconds: config?.apiKeyPolicy?.adminExpirySeconds ?? null,
      },
      meta: {},
    });
  }

  async function handleKeyRotationConfigPut(request, env) {
    enforceInvokeContentType(request);
    const body = await readJsonWithLimit(request, getEnvInt(env, "MAX_REQ_BYTES", defaults.MAX_REQ_BYTES));
    const existing = await loadConfigV1(env);

    let requestObj = null;
    if (isNonArrayObject(body?.request)) {
      requestObj = body.request;
    } else {
      const requestYaml = String(body?.request_yaml || "").trim();
      if (!requestYaml) {
        throw new HttpError(400, "INVALID_REQUEST", "request_yaml or request is required", {
          expected: { request_yaml: "method: POST\\nurl: https://..." },
        });
      }
      try {
        const yaml = await loadYamlApi();
        requestObj = yaml.parse(requestYaml);
      } catch (e) {
        throw new HttpError(400, "INVALID_REQUEST", "request_yaml could not be parsed", {
          cause: String(e?.message || e),
        });
      }
      if (!isNonArrayObject(requestObj)) {
        throw new HttpError(400, "INVALID_REQUEST", "request_yaml must parse to an object");
      }
    }

    const next = {
      ...existing,
      apiKeyPolicy: {
        proxyExpirySeconds: toNullablePositiveInt(body?.proxy_expiry_seconds, "proxy_expiry_seconds"),
        issuerExpirySeconds: toNullablePositiveInt(body?.issuer_expiry_seconds, "issuer_expiry_seconds"),
        adminExpirySeconds: toNullablePositiveInt(body?.admin_expiry_seconds, "admin_expiry_seconds"),
      },
      targetCredentialRotation: {
        enabled: !!body?.enabled,
        strategy: body?.strategy === "oauth_client_credentials" ? "oauth_client_credentials" : "json_ttl",
        request: requestObj,
        response: {
          key_path: String(body?.key_path || ""),
          ttl_path: body?.ttl_path === "" ? null : body?.ttl_path ?? null,
          ttl_unit: String(body?.ttl_unit || "seconds"),
          expires_at_path: body?.expires_at_path === "" ? null : body?.expires_at_path ?? null,
        },
        trigger: {
          refresh_skew_seconds: Number(body?.refresh_skew_seconds ?? 300),
          retry_once_on_401: !!body?.retry_once_on_401,
        },
      },
    };

    const normalized = await saveConfigObjectV1(next, env);
    return jsonResponse(200, {
      ok: true,
      data: {
        message: "Key rotation configuration updated",
        key_rotation: normalized.targetCredentialRotation,
        api_key_policy: normalized.apiKeyPolicy,
      },
      meta: {},
    });
  }

  function normalizeTransformRuleInput(rule, direction) {
    if (!isNonArrayObject(rule)) return null;
    const out = {
      name: String(rule.name || "").trim(),
      expr: String(rule.expr || ""),
    };
    if (!out.name || !out.expr.trim()) return null;
    if (direction === "target_response") {
      if (Array.isArray(rule.match_status ?? rule.status)) out.match_status = rule.match_status ?? rule.status;
      out.match_type = String(rule.match_type ?? rule.type ?? "any").toLowerCase();
    }
    if (direction === "source_request") {
      if (Array.isArray(rule.match_method ?? rule.method)) {
        out.match_method = (rule.match_method ?? rule.method).map((m) => String(m || "").toUpperCase()).filter(Boolean);
      }
      if (Array.isArray(rule.match_path ?? rule.path)) {
        out.match_path = (rule.match_path ?? rule.path).map((p) => String(p || "")).filter(Boolean);
      }
    }
    if (Array.isArray(rule.match_headers ?? rule.headers)) {
      out.match_headers = (rule.match_headers ?? rule.headers)
        .map((item) => ({ name: String(item?.name || "").toLowerCase(), value: String(item?.value || "") }))
        .filter((item) => item.name && item.value);
    } else if (isNonArrayObject(rule.headerMatch)) {
      out.match_headers = Object.entries(rule.headerMatch)
        .map(([name, value]) => ({ name: String(name || "").toLowerCase(), value: String(value || "") }))
        .filter((item) => item.name && item.value);
    }
    return out;
  }

  async function handleTransformConfigGet(env) {
    const config = await loadConfigV1(env);
    const transform = config?.transform || DEFAULT_CONFIG_V1.transform;
    return jsonResponse(200, {
      ok: true,
      data: {
        enabled: transform.enabled !== false,
        source_request: transform.source_request || DEFAULT_CONFIG_V1.transform.source_request,
        target_response: transform.target_response || DEFAULT_CONFIG_V1.transform.target_response,
      },
      meta: {},
    });
  }

  async function handleTransformConfigPut(request, env) {
    enforceInvokeContentType(request);
    const body = await readJsonWithLimit(request, getEnvInt(env, "MAX_REQ_BYTES", defaults.MAX_REQ_BYTES));
    const existing = await loadConfigV1(env);
    const currentTransform = existing?.transform || DEFAULT_CONFIG_V1.transform;
    const sourceRequestIn = isNonArrayObject(body?.source_request) ? body.source_request : currentTransform.source_request;
    const targetResponseIn = isNonArrayObject(body?.target_response) ? body.target_response : currentTransform.target_response;

    function normalizeRules(rules, direction) {
      if (!Array.isArray(rules)) return [];
      return rules
        .map((rule) => normalizeTransformRuleInput(rule, direction))
        .filter((rule) => rule !== null);
    }

    const sourceRequestRules = normalizeRules(sourceRequestIn?.rules, "source_request");
    const targetResponseRules = normalizeRules(targetResponseIn?.rules, "target_response");
    const next = {
      ...existing,
      transform: {
        enabled: body?.enabled === undefined ? currentTransform.enabled !== false : !!body.enabled,
        source_request: {
          enabled: sourceRequestIn?.enabled === undefined ? !!currentTransform?.source_request?.enabled : !!sourceRequestIn.enabled,
          custom_js_preprocessor: sourceRequestIn?.custom_js_preprocessor === undefined
            ? (currentTransform?.source_request?.custom_js_preprocessor ?? null)
            : (sourceRequestIn.custom_js_preprocessor === null ? null : String(sourceRequestIn.custom_js_preprocessor || "").trim() || null),
          defaultExpr: String(sourceRequestIn?.defaultExpr ?? currentTransform?.source_request?.defaultExpr ?? ""),
          fallback: String(sourceRequestIn?.fallback ?? currentTransform?.source_request?.fallback ?? "passthrough"),
          rules: sourceRequestRules,
        },
        target_response: {
          enabled: targetResponseIn?.enabled === undefined ? !!currentTransform?.target_response?.enabled : !!targetResponseIn.enabled,
          custom_js_preprocessor: targetResponseIn?.custom_js_preprocessor === undefined
            ? (currentTransform?.target_response?.custom_js_preprocessor ?? null)
            : (targetResponseIn.custom_js_preprocessor === null ? null : String(targetResponseIn.custom_js_preprocessor || "").trim() || null),
          defaultExpr: String(targetResponseIn?.defaultExpr ?? currentTransform?.target_response?.defaultExpr ?? ""),
          fallback: String(targetResponseIn?.fallback ?? currentTransform?.target_response?.fallback ?? "passthrough"),
          header_filtering: isPlainObject(targetResponseIn?.header_filtering)
            ? targetResponseIn.header_filtering
            : (currentTransform?.target_response?.header_filtering ?? DEFAULT_CONFIG_V1.transform.target_response.header_filtering),
          rules: targetResponseRules,
        },
      },
    };
    const normalized = await saveConfigObjectV1(next, env);
    return jsonResponse(200, {
      ok: true,
      data: {
        message: "Transform configuration updated",
        transform: normalized.transform,
      },
      meta: {},
    });
  }

  return {
    handleConfigGet,
    handleConfigPut,
    handleConfigValidate,
    handleConfigTestRule,
    handleKeyRotationConfigGet,
    handleKeyRotationConfigPut,
    handleTransformConfigGet,
    handleTransformConfigPut,
  };
}

export { createControlConfigHandlers };
