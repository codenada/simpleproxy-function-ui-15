function toUpperSnakeCase(name) {
  return String(name || "")
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .replace(/[-\s]+/g, "_")
    .toUpperCase();
}

function resolveTemplateVar(varName, env) {
  const candidates = [String(varName || ""), toUpperSnakeCase(varName)];
  for (const candidate of candidates) {
    const value = env?.[candidate];
    if (typeof value === "string" && value.length > 0) return value;
  }
  return null;
}

function resolveTemplateVars(text, env, HttpError) {
  return String(text).replace(/\$\{([A-Za-z0-9_]+)\}/g, (_m, varName) => {
    const value = resolveTemplateVar(varName, env);
    if (value === null) {
      throw new HttpError(500, "MISSING_BOOTSTRAP_SECRET", "A referenced bootstrap secret variable is missing.", {
        variable: varName,
      });
    }
    return value;
  });
}

function normalizeBootstrapHeaderName(name, normalizeHeaderName, HttpError) {
  const normalized = normalizeHeaderName(name);
  if (!normalized || !/^[!#$%&'*+.^_`|~0-9a-z-]+$/.test(normalized)) {
    throw new HttpError(500, "INVALID_BOOTSTRAP_HEADERS", "Each bootstrap header name must be a valid HTTP header token.", {
      header: name,
    });
  }
  return normalized;
}

function parseBootstrapEnrichedHeadersJson(raw, env, { HttpError, isPlainObject, normalizeHeaderName }) {
  const input = String(raw || "").trim();
  if (!input) return {};

  let parsed;
  try {
    parsed = JSON.parse(input);
  } catch (e) {
    throw new HttpError(500, "INVALID_BOOTSTRAP_HEADERS", "BOOTSTRAP_ENRICHED_HEADERS_JSON is not valid JSON.", {
      cause: String(e?.message || e),
    });
  }
  if (!isPlainObject(parsed)) {
    throw new HttpError(500, "INVALID_BOOTSTRAP_HEADERS", "BOOTSTRAP_ENRICHED_HEADERS_JSON must be a JSON object.");
  }

  const out = {};
  for (const [name, value] of Object.entries(parsed)) {
    const normalized = normalizeBootstrapHeaderName(name, normalizeHeaderName, HttpError);
    if (typeof value !== "string") {
      throw new HttpError(500, "INVALID_BOOTSTRAP_HEADERS", "Each bootstrap header value must be a string.", {
        header: normalized,
      });
    }
    out[normalized] = resolveTemplateVars(value, env, HttpError);
  }
  return out;
}

export { parseBootstrapEnrichedHeadersJson };
