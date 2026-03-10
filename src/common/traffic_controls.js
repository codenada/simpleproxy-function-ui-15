import { parseCidr, parseIp } from "./cidr.js";

function getClientIp(request) {
  const direct = String(request?.headers?.get("cf-connecting-ip") || "").trim();
  if (direct) return direct;
  const forwarded = String(request?.headers?.get("x-forwarded-for") || "").trim();
  if (!forwarded) return "unknown";
  return forwarded.split(",")[0].trim() || "unknown";
}

function createInMemoryRpmLimiter() {
  const state = new Map();
  return function allowRpm(key, rpmLimit, enabled = true) {
    if (!enabled) return true;
    const limit = Number(rpmLimit);
    if (!Number.isFinite(limit) || limit <= 0) return true;
    if (!key || key === "unknown") return true;
    const windowMinute = Math.floor(Date.now() / 60000);
    const current = state.get(key);
    if (!current || current.windowMinute !== windowMinute) {
      state.set(key, { windowMinute, count: 1 });
      return true;
    }
    if (current.count >= limit) return false;
    current.count += 1;
    return true;
  };
}

function createCidrMatcher() {
  let cacheKey = "";
  let compiled = [];

  function compile(allowedCidrs) {
    const list = Array.isArray(allowedCidrs) ? allowedCidrs.map((v) => String(v || "").trim()).filter(Boolean) : [];
    const key = list.join("|");
    if (key === cacheKey) return compiled;
    cacheKey = key;
    compiled = list
      .map((cidr) => parseCidr(cidr))
      .filter((cidr) => !!cidr);
    return compiled;
  }

  return function isIpAllowed(ipText, allowedCidrs, enabled = true) {
    if (!enabled) return true;
    const ip = String(ipText || "").trim();
    if (!ip || ip === "unknown") return true;
    const parsedIp = parseIp(ip);
    if (!parsedIp) return true;
    const cidrs = compile(allowedCidrs);
    if (cidrs.length === 0) return true;

    return cidrs.some((cidr) => {
      if (cidr.family !== parsedIp.family) return false;
      if (cidr.family === 4) {
        const prefix = cidr.prefix;
        const mask = prefix <= 0 ? 0 : (prefix >= 32 ? 0xffffffff : (0xffffffff << (32 - prefix)) >>> 0);
        return ((parsedIp.value & mask) >>> 0) === ((cidr.value & mask) >>> 0);
      }
      const prefix = cidr.prefix;
      const mask = prefix <= 0 ? 0n : (prefix >= 128 ? ((1n << 128n) - 1n) : (((1n << BigInt(prefix)) - 1n) << BigInt(128 - prefix)));
      return (parsedIp.value & mask) === (cidr.value & mask);
    });
  };
}

export { getClientIp, createInMemoryRpmLimiter, createCidrMatcher };
