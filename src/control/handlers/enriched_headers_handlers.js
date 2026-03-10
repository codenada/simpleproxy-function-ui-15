function createControlEnrichedHeadersHandlers(deps) {
  const {
    HttpError,
    adminRoot,
    ensureKvBinding,
    dataStore,
    kvEnrichedHeaderPrefix,
    kvBootstrapEnrichedHeaderNames,
    normalizeHeaderName,
    isPlainObject,
    getBootstrapEnrichedHeaders,
    enforceInvokeContentType,
    readJsonWithLimit,
    getEnvInt,
    defaults,
    jsonResponse,
  } = deps;

  function assertValidHeaderName(raw) {
    const name = normalizeHeaderName(raw);
    if (!name) {
      throw new HttpError(400, "INVALID_REQUEST", "Header name is required.");
    }
    // RFC 7230 token chars.
    if (!/^[!#$%&'*+.^_`|~0-9a-z-]+$/.test(name)) {
      throw new HttpError(400, "INVALID_REQUEST", "Invalid HTTP header name.", { header: raw });
    }
    return name;
  }

  function enrichedHeaderKvKey(name) {
    return `${kvEnrichedHeaderPrefix}${name}`;
  }

  async function syncBootstrapEnrichedHeaders(env, managedHeaders) {
    ensureKvBinding(env);
    const names = Object.keys(managedHeaders || {});
    const prevRaw = await dataStore(env).get(kvBootstrapEnrichedHeaderNames);
    let prev = [];
    try {
      const parsed = JSON.parse(prevRaw || "[]");
      if (Array.isArray(parsed)) prev = parsed.map((n) => normalizeHeaderName(n)).filter(Boolean);
    } catch {
      prev = [];
    }
    const prevSet = new Set(prev);
    const nextSet = new Set(names);

    const deletes = [];
    for (const name of prevSet) {
      if (!nextSet.has(name)) deletes.push(dataStore(env).delete(enrichedHeaderKvKey(name)));
    }

    const gets = await Promise.all(names.map((name) => dataStore(env).get(enrichedHeaderKvKey(name))));
    const puts = [];
    for (let i = 0; i < names.length; i += 1) {
      const name = names[i];
      const desired = managedHeaders[name];
      if (gets[i] !== desired) {
        puts.push(dataStore(env).put(enrichedHeaderKvKey(name), desired));
      }
    }

    const prevSorted = [...prevSet].sort();
    const nextSorted = [...nextSet].sort();
    const namesChanged = prevSorted.length !== nextSorted.length || prevSorted.some((n, i) => n !== nextSorted[i]);
    const ops = [...deletes, ...puts];
    if (namesChanged) {
      ops.push(dataStore(env).put(kvBootstrapEnrichedHeaderNames, JSON.stringify(nextSorted)));
    }
    if (ops.length > 0) {
      await Promise.all(ops);
    }
  }

  async function listEnrichedHeaderNames(env, managedHeaders = null) {
    ensureKvBinding(env);
    const out = [];
    let cursor = undefined;

    while (true) {
      const page = await dataStore(env).list({
        prefix: kvEnrichedHeaderPrefix,
        cursor,
        limit: 1000,
      });
      for (const entry of page.keys || []) {
        const key = String(entry.name || "");
        if (!key.startsWith(kvEnrichedHeaderPrefix)) continue;
        out.push(key.slice(kvEnrichedHeaderPrefix.length));
      }
      if (!page.list_complete) {
        cursor = page.cursor;
        continue;
      }
      break;
    }

    if (managedHeaders && isPlainObject(managedHeaders)) {
      for (const name of Object.keys(managedHeaders)) out.push(name);
    }

    return [...new Set(out)].sort();
  }

  async function handleEnrichedHeadersList(env) {
    const names = await listEnrichedHeaderNames(env, getBootstrapEnrichedHeaders(env));
    return jsonResponse(200, {
      enriched_headers: names,
    });
  }

  async function handleEnrichedHeaderPut(request, env, headerNameRaw) {
    enforceInvokeContentType(request);
    const headerName = assertValidHeaderName(headerNameRaw);
    const managedHeaders = getBootstrapEnrichedHeaders(env);
    if (Object.prototype.hasOwnProperty.call(managedHeaders, headerName)) {
      throw new HttpError(409, "HEADER_MANAGED_BY_ENV", "Header is managed by BOOTSTRAP_ENRICHED_HEADERS_JSON and cannot be changed via API.", {
        header: headerName,
        hint: "Update BOOTSTRAP_ENRICHED_HEADERS_JSON and redeploy.",
      });
    }
    const body = await readJsonWithLimit(request, getEnvInt(env, "MAX_REQ_BYTES", defaults.MAX_REQ_BYTES));
    const value = body?.value;
    if (typeof value !== "string" || !value.length) {
      throw new HttpError(400, "INVALID_REQUEST", "value is required and must be a non-empty string", {
        expected: { value: "string" },
      });
    }

    await dataStore(env).put(enrichedHeaderKvKey(headerName), value);
    const names = await listEnrichedHeaderNames(env, managedHeaders);
    return jsonResponse(200, {
      enriched_headers: names,
    });
  }

  async function handleEnrichedHeaderDelete(env, headerNameRaw) {
    const headerName = assertValidHeaderName(headerNameRaw);
    const managedHeaders = getBootstrapEnrichedHeaders(env);
    if (Object.prototype.hasOwnProperty.call(managedHeaders, headerName)) {
      throw new HttpError(409, "HEADER_MANAGED_BY_ENV", "Header is managed by BOOTSTRAP_ENRICHED_HEADERS_JSON and cannot be deleted via API.", {
        header: headerName,
        hint: "Update BOOTSTRAP_ENRICHED_HEADERS_JSON and redeploy.",
      });
    }
    const kvKey = enrichedHeaderKvKey(headerName);
    const existing = await dataStore(env).get(kvKey);
    if (!existing) {
      throw new HttpError(404, "HEADER_NOT_FOUND", "No enriched header exists for the provided name.", {
        name: headerName,
        hint: `List current enriched headers at ${adminRoot}/headers.`,
      });
    }
    await dataStore(env).delete(kvKey);
    const names = await listEnrichedHeaderNames(env, managedHeaders);
    return jsonResponse(200, {
      enriched_headers: names,
    });
  }

  return {
    handleEnrichedHeadersList,
    handleEnrichedHeaderPut,
    handleEnrichedHeaderDelete,
  };
}

export { createControlEnrichedHeadersHandlers };
