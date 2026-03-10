function createCryptoInterface({ randomBytes, sha256Hex, subtle }) {
  return { randomBytes, sha256Hex, subtle };
}

export { createCryptoInterface };
