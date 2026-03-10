function authProfilePrefix(name, prefixMap) {
  const key = String(name || "").trim();
  return prefixMap?.[key] || null;
}

function authProfileKvKey(profile, field, prefixMap) {
  const prefix = authProfilePrefix(profile, prefixMap);
  if (!prefix) return null;
  return `${prefix}/${field}`;
}

function isValidHttpSecretRef(ref) {
  return /^[a-zA-Z0-9_.-]{1,64}$/.test(String(ref || ""));
}

function httpSecretKvKey(ref, prefix = "http_secret/") {
  const key = String(ref || "").trim();
  if (!isValidHttpSecretRef(key)) return null;
  return `${prefix}${key}`;
}

function createAuthProfileKeyResolvers({ prefixMap, secretPrefix }) {
  return {
    authProfilePrefix: (name) => authProfilePrefix(name, prefixMap),
    authProfileKvKey: (profile, field) => authProfileKvKey(profile, field, prefixMap),
    httpSecretKvKey: (ref) => httpSecretKvKey(ref, secretPrefix),
  };
}

export {
  authProfilePrefix,
  authProfileKvKey,
  isValidHttpSecretRef,
  httpSecretKvKey,
  createAuthProfileKeyResolvers,
};
