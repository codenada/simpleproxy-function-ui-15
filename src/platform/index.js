import { createCloudflareStorage } from "./cloudflare/storage/index.js";
import { createCloudflareClock } from "./cloudflare/clock.js";
import { createCloudflareHttpClient } from "./cloudflare/http.js";
import { createCloudflareCrypto } from "./cloudflare/crypto.js";

// Default platform adapter for one-click Cloudflare deploys.
// Customers can replace this mapping in their own repos.
function createStorageConnector(env) {
  return createCloudflareStorage(env);
}

function createPlatformAdapters() {
  return {
    createStorageConnector,
    clock: createCloudflareClock(),
    http: createCloudflareHttpClient(),
    crypto: createCloudflareCrypto(),
  };
}

export { createStorageConnector, createPlatformAdapters };
