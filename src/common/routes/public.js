import { PUBLIC_ROUTE_SUFFIXES } from "./public_route_suffixes.js";

async function dispatchPublicRoute({ normalizedPath, request, env, ctx, reservedRoot, handlers, auth, options = {} }) {
  const {
    enableRootProxy = true,
    enableStatusBootstrap = true,
    enableRequest = true,
    enableSelfRotate = true,
    enableProxyRotate = undefined,
    enableIssuerRotate = undefined,
    enableAdminRotate = undefined,
    exposeStatusBootstrapAtRoot = false,
  } = options;

  const allowProxyRotate = enableProxyRotate === undefined ? enableSelfRotate : !!enableProxyRotate;
  const allowIssuerRotate = enableIssuerRotate === undefined ? enableSelfRotate : !!enableIssuerRotate;
  const allowAdminRotate = enableAdminRotate === undefined ? enableSelfRotate : !!enableAdminRotate;

  if (exposeStatusBootstrapAtRoot && normalizedPath === "/" && request.method === "GET") {
    return handlers.handleStatusPage(env, request);
  }
  if (exposeStatusBootstrapAtRoot && normalizedPath === "/" && request.method === "POST") {
    return handlers.handleBootstrapPost(env);
  }

  if (enableRootProxy && normalizedPath === "/" && request.method === "GET") {
    if (request.headers.get("X-Proxy-Key")) {
      return handlers.handleRootProxyRequest(request, env, ctx);
    }
    if (enableStatusBootstrap) {
      return Response.redirect(new URL(`${reservedRoot}/`, request.url).toString(), 302);
    }
    return null;
  }

  if (enableStatusBootstrap && normalizedPath === reservedRoot && request.method === "GET") {
    return handlers.handleStatusPage(env, request);
  }
  if (enableStatusBootstrap && normalizedPath === reservedRoot && request.method === "POST") {
    return handlers.handleBootstrapPost(env);
  }
  if (enableRequest && normalizedPath === `${reservedRoot}${PUBLIC_ROUTE_SUFFIXES.REQUEST}` && request.method === "POST") {
    return handlers.handleRequest(request, env, ctx);
  }

  if (allowProxyRotate && normalizedPath === `${reservedRoot}${PUBLIC_ROUTE_SUFFIXES.KEYS_PROXY_ROTATE}` && request.method === "POST") {
    await auth.requireProxyKey(request, env);
    return handlers.handleRotateByKind("proxy", request, env);
  }
  if (allowIssuerRotate && normalizedPath === `${reservedRoot}${PUBLIC_ROUTE_SUFFIXES.KEYS_ISSUER_ROTATE}` && request.method === "POST") {
    await auth.requireIssuerKey(request, env);
    return handlers.handleRotateByKind("issuer", request, env);
  }
  if (allowAdminRotate && normalizedPath === `${reservedRoot}${PUBLIC_ROUTE_SUFFIXES.KEYS_ADMIN_ROTATE}` && request.method === "POST") {
    await auth.requireAdminAuth(request, env);
    return handlers.handleRotateByKind("admin", request, env);
  }

  return null;
}

export { dispatchPublicRoute };
