import adminConfigYaml from "./admin_master.yaml";

const DEFAULT_ADMIN_CONFIG = {
  admin: {
    docs_url: "",
    login_page: {
      enabled: true,
      rpm_rate_limit: 20,
    },
    get_admin_token_endpoint: {
      enabled: true,
      rpm_rate_limit: 10,
    },
    browser_challenge: {
      enabled: true,
      difficulty: 4,
      challenge_ttl_seconds: 300,
      verified_cookie_ttl_seconds: 600,
    },
    ip_filter: {
      enabled: false,
      allowed_cidrs: ["0.0.0.0/0", "::/0"],
    },
  },
};

let cached = null;

function toPositiveInt(value, fallback, min, max) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  const i = Math.floor(n);
  return Math.max(min, Math.min(max, i));
}

function normalizeAdminConfig(raw) {
  const merged = {
    admin: {
      ...DEFAULT_ADMIN_CONFIG.admin,
      ...(raw?.admin && typeof raw.admin === "object" ? raw.admin : {}),
      login_page: {
        ...DEFAULT_ADMIN_CONFIG.admin.login_page,
        ...(raw?.admin?.login_page && typeof raw.admin.login_page === "object" ? raw.admin.login_page : {}),
      },
      get_admin_token_endpoint: {
        ...DEFAULT_ADMIN_CONFIG.admin.get_admin_token_endpoint,
        ...(raw?.admin?.get_admin_token_endpoint && typeof raw.admin.get_admin_token_endpoint === "object"
          ? raw.admin.get_admin_token_endpoint
          : {}),
      },
      browser_challenge: {
        ...DEFAULT_ADMIN_CONFIG.admin.browser_challenge,
        ...(raw?.admin?.browser_challenge && typeof raw.admin.browser_challenge === "object"
          ? raw.admin.browser_challenge
          : {}),
      },
      ip_filter: {
        ...DEFAULT_ADMIN_CONFIG.admin.ip_filter,
        ...(raw?.admin?.ip_filter && typeof raw.admin.ip_filter === "object" ? raw.admin.ip_filter : {}),
      },
    },
  };

  merged.admin.browser_challenge.enabled = !!merged.admin.browser_challenge.enabled;
  merged.admin.login_page.enabled = !!merged.admin.login_page.enabled;
  merged.admin.get_admin_token_endpoint.enabled = !!merged.admin.get_admin_token_endpoint.enabled;
  merged.admin.ip_filter.enabled = !!merged.admin.ip_filter.enabled;
  merged.admin.login_page.rpm_rate_limit = toPositiveInt(
    merged.admin.login_page.rpm_rate_limit,
    DEFAULT_ADMIN_CONFIG.admin.login_page.rpm_rate_limit,
    1,
    10000
  );
  merged.admin.get_admin_token_endpoint.rpm_rate_limit = toPositiveInt(
    merged.admin.get_admin_token_endpoint.rpm_rate_limit,
    DEFAULT_ADMIN_CONFIG.admin.get_admin_token_endpoint.rpm_rate_limit,
    1,
    10000
  );
  merged.admin.browser_challenge.difficulty = toPositiveInt(
    merged.admin.browser_challenge.difficulty,
    DEFAULT_ADMIN_CONFIG.admin.browser_challenge.difficulty,
    1,
    6
  );
  merged.admin.browser_challenge.challenge_ttl_seconds = toPositiveInt(
    merged.admin.browser_challenge.challenge_ttl_seconds,
    DEFAULT_ADMIN_CONFIG.admin.browser_challenge.challenge_ttl_seconds,
    30,
    3600
  );
  merged.admin.browser_challenge.verified_cookie_ttl_seconds = toPositiveInt(
    merged.admin.browser_challenge.verified_cookie_ttl_seconds,
    DEFAULT_ADMIN_CONFIG.admin.browser_challenge.verified_cookie_ttl_seconds,
    30,
    86400
  );
  merged.admin.docs_url = String(merged.admin.docs_url || "").trim();
  const allowedCidrs = Array.isArray(merged.admin?.ip_filter?.allowed_cidrs)
    ? merged.admin.ip_filter.allowed_cidrs.map((v) => String(v || "").trim()).filter(Boolean)
    : [];
  merged.admin.ip_filter.allowed_cidrs =
    allowedCidrs.length > 0 ? Array.from(new Set(allowedCidrs)) : [...DEFAULT_ADMIN_CONFIG.admin.ip_filter.allowed_cidrs];
  return merged;
}

function parseSimpleAdminYaml(text) {
  const src = String(text || "");
  const out = {};
  const docs = src.match(/^\s*docs_url:\s*["']?(.+?)["']?\s*$/m);
  if (docs?.[1]) out.docs_url = docs[1].trim();

  function parseField(name) {
    const re = new RegExp(`^\\s*${name}:\\s*([^\\n#]+)`, "m");
    const m = src.match(re);
    if (!m?.[1]) return undefined;
    return String(m[1]).trim().replace(/^["']|["']$/g, "");
  }

  const browser = {};
  const enabledRaw = parseField("enabled");
  if (enabledRaw !== undefined) browser.enabled = /^(true|1|yes)$/i.test(enabledRaw);
  const difficultyRaw = parseField("difficulty");
  if (difficultyRaw !== undefined) browser.difficulty = Number(difficultyRaw);
  const ttlRaw = parseField("challenge_ttl_seconds");
  if (ttlRaw !== undefined) browser.challenge_ttl_seconds = Number(ttlRaw);
  const cookieRaw = parseField("verified_cookie_ttl_seconds");
  if (cookieRaw !== undefined) browser.verified_cookie_ttl_seconds = Number(cookieRaw);

  const loginPage = {};
  const loginEnabledMatch = src.match(/^\s*login_page:\s*$[\s\S]*?^\s*enabled:\s*(true|false)\s*$/m);
  if (loginEnabledMatch?.[1]) loginPage.enabled = loginEnabledMatch[1].toLowerCase() === "true";
  const loginRateMatch = src.match(/^\s*login_page:\s*$[\s\S]*?^\s*rpm_rate_limit:\s*([0-9]+)\s*$/m);
  if (loginRateMatch?.[1]) loginPage.rpm_rate_limit = Number(loginRateMatch[1]);

  const tokenEndpoint = {};
  const tokenEnabledMatch = src.match(/^\s*get_admin_token_endpoint:\s*$[\s\S]*?^\s*enabled:\s*(true|false)\s*$/m);
  if (tokenEnabledMatch?.[1]) tokenEndpoint.enabled = tokenEnabledMatch[1].toLowerCase() === "true";
  const tokenRateMatch = src.match(/^\s*get_admin_token_endpoint:\s*$[\s\S]*?^\s*rpm_rate_limit:\s*([0-9]+)\s*$/m);
  if (tokenRateMatch?.[1]) tokenEndpoint.rpm_rate_limit = Number(tokenRateMatch[1]);

  const ipFilter = {};
  const ipEnabledMatch = src.match(/^\s*ip_filter:\s*$[\s\S]*?^\s*enabled:\s*(true|false)\s*$/m);
  if (ipEnabledMatch?.[1]) ipFilter.enabled = ipEnabledMatch[1].toLowerCase() === "true";
  const lines = src.split(/\r?\n/);
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    const match = line.match(/^(\s*)allowed_cidrs:\s*$/);
    if (!match) continue;
    const baseIndent = match[1].length;
    const items = [];
    for (let j = i + 1; j < lines.length; j += 1) {
      const next = lines[j];
      if (!next.trim()) continue;
      const indent = (next.match(/^(\s*)/)?.[1] || "").length;
      if (indent <= baseIndent) break;
      const item = next.match(/^\s*-\s*(.+?)\s*$/);
      if (!item?.[1]) continue;
      items.push(String(item[1]).replace(/^["']|["']$/g, "").trim());
    }
    if (items.length > 0) ipFilter.allowed_cidrs = items;
    break;
  }

  out.login_page = loginPage;
  out.get_admin_token_endpoint = tokenEndpoint;
  out.browser_challenge = browser;
  out.ip_filter = ipFilter;
  return { admin: out };
}

function loadAdminConfig() {
  if (cached) return cached;
  try {
    const parsed = parseSimpleAdminYaml(adminConfigYaml);
    cached = normalizeAdminConfig(parsed);
  } catch {
    cached = DEFAULT_ADMIN_CONFIG;
  }
  return cached;
}

export { loadAdminConfig, DEFAULT_ADMIN_CONFIG };
