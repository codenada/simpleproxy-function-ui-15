import { createCryptoInterface } from "../interface/crypto.js";

async function sha256Hex(input) {
  const bytes = new TextEncoder().encode(String(input));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

function randomBytes(length) {
  const size = Math.max(1, Number(length) || 1);
  const bytes = new Uint8Array(size);
  crypto.getRandomValues(bytes);
  return bytes;
}

function createCloudflareCrypto() {
  return createCryptoInterface({
    randomBytes,
    sha256Hex,
    subtle: crypto.subtle,
  });
}

export { createCloudflareCrypto };
