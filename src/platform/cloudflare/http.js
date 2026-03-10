import { createHttpClientInterface } from "../interface/http.js";

function createCloudflareHttpClient() {
  return createHttpClientInterface({
    request: async (url, init) => fetch(url, init),
  });
}

export { createCloudflareHttpClient };
