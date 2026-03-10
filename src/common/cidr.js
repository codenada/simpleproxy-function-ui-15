function normalizeIpText(ip) {
  return String(ip || "").trim().replace(/^\[|\]$/g, "");
}

function parseIpv4(ip) {
  const parts = String(ip).split(".");
  if (parts.length !== 4) return null;
  let out = 0;
  for (const part of parts) {
    if (!/^\d+$/.test(part)) return null;
    const n = Number(part);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    out = (out << 8) | n;
  }
  return out >>> 0;
}

function parseIpv6(ip) {
  const lower = String(ip).toLowerCase();
  if (!lower) return null;
  if (lower.includes(".")) return null;
  if ((lower.match(/::/g) || []).length > 1) return null;

  const [leftRaw, rightRaw] = lower.split("::");
  const left = leftRaw ? leftRaw.split(":").filter(Boolean) : [];
  const right = rightRaw ? rightRaw.split(":").filter(Boolean) : [];

  if (left.length + right.length > 8) return null;

  const fill = 8 - (left.length + right.length);
  const groups = lower.includes("::")
    ? [...left, ...new Array(fill).fill("0"), ...right]
    : lower.split(":");

  if (groups.length !== 8) return null;

  let value = 0n;
  for (const group of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(group)) return null;
    value = (value << 16n) + BigInt(parseInt(group, 16));
  }
  return value;
}

function parseIp(ipText) {
  const ip = normalizeIpText(ipText);
  const v4 = parseIpv4(ip);
  if (v4 !== null) return { family: 4, value: v4 };
  const v6 = parseIpv6(ip);
  if (v6 !== null) return { family: 6, value: v6 };
  return null;
}

function parseCidr(cidrText) {
  const raw = String(cidrText || "").trim();
  if (!raw) return null;
  const slash = raw.indexOf("/");
  const ipText = slash >= 0 ? raw.slice(0, slash).trim() : raw;
  const prefixText = slash >= 0 ? raw.slice(slash + 1).trim() : "";
  const ip = parseIp(ipText);
  if (!ip) return null;
  const maxBits = ip.family === 4 ? 32 : 128;
  const prefix = prefixText ? Number(prefixText) : maxBits;
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > maxBits) return null;
  return { family: ip.family, prefix, value: ip.value };
}

function ipv4Mask(prefix) {
  if (prefix <= 0) return 0;
  if (prefix >= 32) return 0xffffffff;
  return (0xffffffff << (32 - prefix)) >>> 0;
}

function ipv6Mask(prefix) {
  if (prefix <= 0) return 0n;
  if (prefix >= 128) return (1n << 128n) - 1n;
  return ((1n << BigInt(prefix)) - 1n) << BigInt(128 - prefix);
}

function ipMatchesCidr(ipText, cidrText) {
  const ip = parseIp(ipText);
  const cidr = parseCidr(cidrText);
  if (!ip || !cidr || ip.family !== cidr.family) return false;

  if (ip.family === 4) {
    const mask = ipv4Mask(cidr.prefix);
    return ((ip.value & mask) >>> 0) === ((cidr.value & mask) >>> 0);
  }

  const mask = ipv6Mask(cidr.prefix);
  return (ip.value & mask) === (cidr.value & mask);
}

function ipMatchesAnyCidr(ipText, cidrs) {
  if (!Array.isArray(cidrs) || cidrs.length === 0) return true;
  return cidrs.some((cidr) => ipMatchesCidr(ipText, cidr));
}

export { parseIp, parseCidr, ipMatchesCidr, ipMatchesAnyCidr };
