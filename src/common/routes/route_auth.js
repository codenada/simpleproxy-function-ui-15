function createRouteAuth(keyAuthApi) {
  return {
    requireProxyKey: (request, env) => keyAuthApi.requireProxyKey(request, env),
    requireIssuerKey: (request, env) => keyAuthApi.requireIssuerKey(request, env),
    requireAdminKey: (request, env) => keyAuthApi.requireAdminKey(request, env),
    requireAdminAuth: (request, env) => keyAuthApi.requireAdminAuth(request, env),
  };
}

export { createRouteAuth };
