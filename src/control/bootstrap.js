import {
  htmlPage,
  escapeHtml,
  renderOnboardingHeader,
  renderAdminLoginOptions,
  renderInitAdminLoginScript,
  renderSecretField,
  renderSecretFieldScript,
} from "./ui.js";
import { getClientIp, createInMemoryRpmLimiter } from "../common/traffic_controls.js";

const allowLoginPageRpm = createInMemoryRpmLimiter();

function createBootstrapApi({
  constants,
  ensureKvBinding,
  secretGetValue,
  secretPutValue,
  dataGetValue,
  dataPutValue,
  dataDeleteValue,
  loadConfigV1,
  loadAdminConfig,
  generateSecret,
  HttpError,
  nowMs = () => Date.now(),
  randomHexGenerator = null,
  sha256HexDigest = null,
}) {
  const {
    kvProxyKey,
    kvAdminKey,
    kvProxyPrimaryCreatedAt,
    kvAdminPrimaryCreatedAt,
    kvBootstrapKeysShownOnce,
    adminRoot,
    defaultDocsUrl,
  } = constants;

  function getDocsConfig(env) {
    const adminConfig = loadAdminConfig();
    const configured = String(adminConfig?.admin?.docs_url || "").trim();
    const raw = String(configured || defaultDocsUrl || "").trim();
    const baseUrl = (raw || defaultDocsUrl).replace(/#.*$/, "");
    return {
      baseUrl,
      sectionUrl: (sectionAnchor) => `${baseUrl}#${sectionAnchor}`,
    };
  }

  function getDocsBaseUrl(env) {
    return getDocsConfig(env).baseUrl;
  }

  function getDocsSectionUrl(env, sectionAnchor) {
    return getDocsConfig(env).sectionUrl(sectionAnchor);
  }

  async function bootstrapMissingKeys(env) {
    ensureKvBinding(env);
    const [existingProxy, existingAdmin] = await Promise.all([secretGetValue(env, kvProxyKey), secretGetValue(env, kvAdminKey)]);
    let createdProxy = null;
    let createdAdmin = null;
    const writes = [];

    if (!existingProxy) {
      createdProxy = generateSecret();
      writes.push(secretPutValue(env, kvProxyKey, createdProxy), secretPutValue(env, kvProxyPrimaryCreatedAt, String(nowMs())));
    }
    if (!existingAdmin) {
      createdAdmin = generateSecret();
      writes.push(secretPutValue(env, kvAdminKey, createdAdmin), secretPutValue(env, kvAdminPrimaryCreatedAt, String(nowMs())));
    }
    if (writes.length > 0) await Promise.all(writes);

    return {
      createdProxy,
      createdAdmin,
      proxyExists: !!(existingProxy || createdProxy),
      adminExists: !!(existingAdmin || createdAdmin),
    };
  }

  function parseCookies(request) {
    const raw = String(request?.headers?.get("cookie") || "");
    const out = new Map();
    if (!raw) return out;
    for (const pair of raw.split(";")) {
      const idx = pair.indexOf("=");
      if (idx <= 0) continue;
      const k = pair.slice(0, idx).trim();
      const v = pair.slice(idx + 1).trim();
      if (!k) continue;
      out.set(k, v);
    }
    return out;
  }

  function isBrowserVerified(request) {
    const cookies = parseCookies(request);
    return cookies.get("apiproxy_browser_verified") === "1";
  }

  function randomHex(bytes = 16) {
    if (typeof randomHexGenerator === "function") return randomHexGenerator(bytes);
    const arr = new Uint8Array(bytes);
    crypto.getRandomValues(arr);
    return Array.from(arr, (b) => b.toString(16).padStart(2, "0")).join("");
  }

  async function sha256Hex(input) {
    if (typeof sha256HexDigest === "function") return sha256HexDigest(input);
    const bytes = new TextEncoder().encode(String(input));
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
  }

  function getBrowserChallengeConfig(env) {
    const adminConfig = loadAdminConfig();
    const base = adminConfig?.admin?.browser_challenge || {};
    const envDifficulty = Number(env?.BROWSER_CHALLENGE_DIFFICULTY);
    const difficulty = Number.isFinite(envDifficulty)
      ? Math.max(1, Math.min(6, Math.floor(envDifficulty)))
      : Math.max(1, Math.min(6, Number(base?.difficulty || 4)));
    const challengeTtlSeconds = Math.max(30, Math.min(3600, Number(base?.challenge_ttl_seconds || 300)));
    const verifiedCookieTtlSeconds = Math.max(30, Math.min(86400, Number(base?.verified_cookie_ttl_seconds || 600)));
    return {
      enabled: !!base?.enabled,
      difficulty,
      challengeTtlSeconds,
      verifiedCookieTtlSeconds,
    };
  }

  function enforceLoginPageRateLimit(request) {
    const adminConfig = loadAdminConfig();
    const loginConfig = adminConfig?.admin?.login_page || {};
    const enabled = !!loginConfig.enabled;
    const rpmLimit = Number(loginConfig.rpm_rate_limit || 20);
    const key = getClientIp(request);
    const allowed = allowLoginPageRpm(key, rpmLimit, enabled);
    if (allowed) return null;
    return new Response(
      htmlPage(
        "Rate limited",
        "<p>Too many requests. Please wait a minute and try again.</p>"
      ),
      {
        status: 429,
        headers: {
          "content-type": "text/html; charset=utf-8",
          "cache-control": "no-store",
        },
      }
    );
  }

  async function createBrowserChallenge(env) {
    const challengeId = randomHex(16);
    const challengeConfig = getBrowserChallengeConfig(env);
    const difficulty = challengeConfig.difficulty;
    await dataPutValue(
      env,
      `browser_challenge:${challengeId}`,
      JSON.stringify({ difficulty, created_at_ms: nowMs() }),
      { expirationTtl: challengeConfig.challengeTtlSeconds }
    );
    return { challengeId, difficulty };
  }

  async function handleBrowserChallengePage(env) {
    const { challengeId, difficulty } = await createBrowserChallenge(env);
    const targetPrefix = "0".repeat(Math.max(1, Math.min(6, Number(difficulty) || 4)));
    return new Response(
      htmlPage(
        "API Transform Proxy",
        `${renderOnboardingHeader()}
         <h2 style="margin:0 0 10px 0;">Browser Check</h2>
         <p style="margin:0 0 10px 0;color:#334155;">Verifying browser JavaScript support before loading admin onboarding.</p>
         <div id="browser-check-status" style="font-size:13px;color:#475569;">Computing challenge...</div>
         <script>
           (function () {
             const challengeId = ${JSON.stringify(challengeId)};
             const targetPrefix = ${JSON.stringify(targetPrefix)};
             const endpoint = ${JSON.stringify(`${adminRoot}/browser-verify`)};
             const statusNode = document.getElementById('browser-check-status');
             const enc = new TextEncoder();
             async function sha256Hex(input) {
               const digest = await crypto.subtle.digest('SHA-256', enc.encode(input));
               const bytes = Array.from(new Uint8Array(digest));
               return bytes.map((b) => b.toString(16).padStart(2, '0')).join('');
             }
             async function solve() {
               let nonce = 0;
               while (true) {
                 const hash = await sha256Hex(challengeId + ':' + String(nonce));
                 if (hash.startsWith(targetPrefix)) return nonce;
                 nonce += 1;
                 if (nonce % 250 === 0 && statusNode) statusNode.textContent = 'Computing challenge... (' + nonce + ')';
               }
             }
             (async () => {
               try {
                 const nonce = await solve();
                 const res = await fetch(endpoint, {
                   method: 'POST',
                   headers: { 'content-type': 'application/json' },
                   body: JSON.stringify({ challenge_id: challengeId, nonce }),
                 });
                 if (!res.ok) throw new Error('verification failed');
                 window.location.reload();
               } catch {
                 if (statusNode) statusNode.textContent = 'Browser verification failed. Refresh and try again.';
               }
             })();
           })();
         </script>`
      ),
      { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" } }
    );
  }

  async function handleBrowserVerifyPost(request, env) {
    ensureKvBinding(env);
    let payload = null;
    try {
      payload = await request.json();
    } catch {
      throw new HttpError(400, "INVALID_JSON", "Request body must be valid JSON.");
    }
    const challengeId = String(payload?.challenge_id || "").trim();
    const nonce = String(payload?.nonce ?? "").trim();
    if (!challengeId || !nonce) {
      throw new HttpError(400, "INVALID_REQUEST", "challenge_id and nonce are required.");
    }
    const raw = await dataGetValue(env, `browser_challenge:${challengeId}`);
    if (!raw) {
      throw new HttpError(400, "BROWSER_CHALLENGE_EXPIRED", "Browser challenge expired. Refresh and try again.");
    }
    let challenge = null;
    try {
      challenge = JSON.parse(raw);
    } catch {
      throw new HttpError(500, "INVALID_CHALLENGE_STATE", "Stored challenge is invalid.");
    }
    const difficulty = Math.max(1, Math.min(6, Number(challenge?.difficulty) || 4));
    const hash = await sha256Hex(`${challengeId}:${nonce}`);
    const targetPrefix = "0".repeat(difficulty);
    if (!hash.startsWith(targetPrefix)) {
      throw new HttpError(400, "INVALID_BROWSER_PROOF", "Browser proof is invalid.");
    }
    await dataDeleteValue(env, `browser_challenge:${challengeId}`);
    const challengeConfig = getBrowserChallengeConfig(env);
    return new Response(
      JSON.stringify({ ok: true }),
      {
        status: 200,
        headers: {
          "content-type": "application/json; charset=utf-8",
          "cache-control": "no-store",
          "set-cookie": `apiproxy_browser_verified=1; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${challengeConfig.verifiedCookieTtlSeconds}`,
        },
      }
    );
  }

  function renderLoginOnlyPage(config, env) {
    const docsUrl = getDocsBaseUrl(env);
    const proxyName = String(config?.proxyName || "").trim();
    return new Response(
      htmlPage(
        "API Transform Proxy",
        `${renderOnboardingHeader(proxyName)}
       <h2 style="margin:0 0 10px 0;">Step 2 - View/Configure This Proxy</h2>
       ${renderAdminLoginOptions(docsUrl)}
       ${renderInitAdminLoginScript(adminRoot)}`
      ),
      { headers: { "content-type": "text/html; charset=utf-8" } }
    );
  }

  async function handleInitPage(env, request) {
    ensureKvBinding(env);
    const { createdProxy, createdAdmin } = await bootstrapMissingKeys(env);
    if (!createdProxy || !createdAdmin) {
      const config = await loadConfigV1(env);
      return renderLoginOnlyPage(config, env);
    }
    await dataPutValue(env, kvBootstrapKeysShownOnce, "1");
    const docsUrl = getDocsBaseUrl(env);

    return new Response(
      htmlPage(
        "API Transform Proxy",
        `${renderOnboardingHeader()}
       <h2 style="margin:0 0 10px 0;">Get Started</h2>
       <h3 style="margin:0 0 10px 0;">Step 1 - Get your credentials</h3>
       <div role="alert" style="border:1px solid #fecaca;background:#fff1f2;color:#7f1d1d;border-radius:10px;padding:10px 12px;margin:0 0 12px 0;">
         <div style="font-weight:700;">Save these API keys now</div>
         <div style="font-size:13px;">This is the only time they will be visible. Store them securely before leaving this page.</div>
       </div>
       ${renderSecretField(
         "Admin API Secret (To administer this proxy)",
         createdAdmin,
         "admin-api-secret",
         "API Key (New). Copy to a safe place. This key cannot be viewed more than once.",
         true
       )}
       ${renderSecretField(
         "Requestor API Secret (To call endpoints through this proxy)",
         createdProxy,
         "requestor-api-secret",
         "API Key (New). Copy to a safe place. This key cannot be viewed more than once.",
         true
       )}
       <h2 style="margin:16px 0 10px 0;">Step 2 - View/Configure This Proxy</h2>
       ${renderAdminLoginOptions(docsUrl)}
       ${renderSecretFieldScript()}
       ${renderInitAdminLoginScript(adminRoot)}`
      ),
      { headers: { "content-type": "text/html; charset=utf-8" } }
    );
  }

  async function handleStatusPage(env, request) {
    ensureKvBinding(env);
    const rateLimitResponse = enforceLoginPageRateLimit(request);
    if (rateLimitResponse) return rateLimitResponse;
    const challengeConfig = getBrowserChallengeConfig(env);
    if (new URL(request.url).pathname === "/" && challengeConfig.enabled && !isBrowserVerified(request)) {
      return handleBrowserChallengePage(env);
    }
    const [proxyKey, adminKey, shownOnce, config] = await Promise.all([
      secretGetValue(env, kvProxyKey),
      secretGetValue(env, kvAdminKey),
      dataGetValue(env, kvBootstrapKeysShownOnce),
      loadConfigV1(env),
    ]);
    const proxyInitialized = !!proxyKey;
    const adminInitialized = !!adminKey;
    const isTrueFirstRun = !shownOnce && !proxyInitialized && !adminInitialized;
    if (isTrueFirstRun) {
      return handleInitPage(env, request);
    }
    return renderLoginOnlyPage(config, env);
  }

  async function handleBootstrapPost(env) {
    const { createdProxy, createdAdmin } = await bootstrapMissingKeys(env);
    if (!createdProxy && !createdAdmin) {
      throw new HttpError(409, "ALREADY_INITIALIZED", "Proxy and admin keys already exist; existing keys are never returned.");
    }
    return new Response(
      JSON.stringify({
        ok: true,
        data: {
          description: "initialization key generation",
          proxy_key: createdProxy || null,
          admin_key: createdAdmin || null,
        },
      }),
      {
        status: 200,
        headers: { "content-type": "application/json; charset=utf-8" },
      }
    );
  }

  return {
    getDocsBaseUrl,
    getDocsSectionUrl,
    bootstrapMissingKeys,
    handleInitPage,
    handleStatusPage,
    handleBootstrapPost,
    handleBrowserVerifyPost,
  };
}

export { createBootstrapApi };
