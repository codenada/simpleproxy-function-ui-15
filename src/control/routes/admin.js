import { ERROR_CODES } from "../../common/error_codes.js";
import { CONTROL_ADMIN_PATHS } from "../control_routes.js";

async function dispatchAdminRoute({ normalizedPath, request, env, adminRoot, handlers, auth }) {
  if (normalizedPath === `${adminRoot}${CONTROL_ADMIN_PATHS.BROWSER_VERIFY}` && request.method === "POST") {
    return handlers.handleBrowserVerifyPost(request, env);
  }
  if (normalizedPath === adminRoot && request.method === "GET") {
    try {
      await auth.requireAdminAuth(request, env);
    } catch {
      return new Response(JSON.stringify({ error: { code: ERROR_CODES.NOT_FOUND, message: "Route not found" } }), {
        status: 404,
        headers: { "content-type": "application/json; charset=utf-8" },
      });
    }
    return handlers.handleAdminPage();
  }
  if (normalizedPath === `${adminRoot}${CONTROL_ADMIN_PATHS.SWAGGER_PAGE}` && request.method === "GET") {
    await auth.requireAdminAuth(request, env);
    return handlers.handleAdminSwaggerPage(request);
  }
  if (normalizedPath === `${adminRoot}${CONTROL_ADMIN_PATHS.SWAGGER_SPEC}` && request.method === "GET") {
    await auth.requireAdminAuth(request, env);
    return handlers.handleAdminSwaggerSpec(request);
  }
  if (normalizedPath === `${adminRoot}${CONTROL_ADMIN_PATHS.ACCESS_TOKEN}` && request.method === "POST") {
    await auth.requireAdminKey(request, env);
    return handlers.handleAdminAccessTokenPost(request, env);
  }
  if (normalizedPath === `${adminRoot}${CONTROL_ADMIN_PATHS.VERSION}` && request.method === "GET") {
    await auth.requireAdminAuth(request, env);
    return handlers.handleVersion(env);
  }

  if (normalizedPath === `${adminRoot}${CONTROL_ADMIN_PATHS.KEYS_PROXY_ROTATE}` && request.method === "POST") {
    await auth.requireAdminAuth(request, env);
    return handlers.handleRotateByKind("proxy", request, env);
  }
  if (normalizedPath === `${adminRoot}${CONTROL_ADMIN_PATHS.KEYS_ISSUER_ROTATE}` && request.method === "POST") {
    await auth.requireAdminAuth(request, env);
    return handlers.handleRotateByKind("issuer", request, env);
  }
  if (normalizedPath === `${adminRoot}${CONTROL_ADMIN_PATHS.KEYS_ADMIN_ROTATE}` && request.method === "POST") {
    await auth.requireAdminAuth(request, env);
    return handlers.handleRotateByKind("admin", request, env);
  }
  if (normalizedPath === `${adminRoot}${CONTROL_ADMIN_PATHS.KEYS}` && request.method === "GET") {
    await auth.requireAdminAuth(request, env);
    return handlers.handleKeysStatusGet(env);
  }

  if (normalizedPath === `${adminRoot}${CONTROL_ADMIN_PATHS.CONFIG}` && request.method === "GET") {
    await auth.requireAdminAuth(request, env);
    return handlers.handleConfigGet(env);
  }
  if (normalizedPath === `${adminRoot}${CONTROL_ADMIN_PATHS.CONFIG}` && request.method === "PUT") {
    await auth.requireAdminAuth(request, env);
    return handlers.handleConfigPut(request, env);
  }
  if (normalizedPath === `${adminRoot}${CONTROL_ADMIN_PATHS.CONFIG_VALIDATE}` && request.method === "POST") {
    await auth.requireAdminAuth(request, env);
    return handlers.handleConfigValidate(request, env);
  }
  if (normalizedPath === `${adminRoot}${CONTROL_ADMIN_PATHS.CONFIG_TEST_RULE}` && request.method === "POST") {
    await auth.requireAdminAuth(request, env);
    return handlers.handleConfigTestRule(request, env);
  }
  if (normalizedPath === `${adminRoot}${CONTROL_ADMIN_PATHS.KEY_ROTATION_CONFIG}` && request.method === "GET") {
    await auth.requireAdminAuth(request, env);
    return handlers.handleKeyRotationConfigGet(env);
  }
  if (normalizedPath === `${adminRoot}${CONTROL_ADMIN_PATHS.KEY_ROTATION_CONFIG}` && request.method === "PUT") {
    await auth.requireAdminAuth(request, env);
    return handlers.handleKeyRotationConfigPut(request, env);
  }
  if (normalizedPath === `${adminRoot}${CONTROL_ADMIN_PATHS.TRANSFORM_CONFIG}` && request.method === "GET") {
    await auth.requireAdminAuth(request, env);
    return handlers.handleTransformConfigGet(env);
  }
  if (normalizedPath === `${adminRoot}${CONTROL_ADMIN_PATHS.TRANSFORM_CONFIG}` && request.method === "PUT") {
    await auth.requireAdminAuth(request, env);
    return handlers.handleTransformConfigPut(request, env);
  }

  if (normalizedPath === `${adminRoot}${CONTROL_ADMIN_PATHS.DEBUG}` && request.method === "GET") {
    await auth.requireAdminAuth(request, env);
    return handlers.handleDebugGet(env);
  }
  if (normalizedPath === `${adminRoot}${CONTROL_ADMIN_PATHS.DEBUG}` && request.method === "PUT") {
    await auth.requireAdminAuth(request, env);
    return handlers.handleDebugPut(request, env);
  }
  if (normalizedPath === `${adminRoot}${CONTROL_ADMIN_PATHS.DEBUG}` && request.method === "DELETE") {
    await auth.requireAdminAuth(request, env);
    return handlers.handleDebugDelete(env);
  }
  if (normalizedPath === `${adminRoot}${CONTROL_ADMIN_PATHS.DEBUG_LAST}` && request.method === "GET") {
    await auth.requireAdminAuth(request, env);
    return handlers.handleDebugLastGet(request);
  }
  if (normalizedPath === `${adminRoot}${CONTROL_ADMIN_PATHS.LIVE_LOG_STREAM}` && request.method === "GET") {
    await auth.requireAdminAuth(request, env);
    return handlers.handleLiveLogStream(env);
  }

  if (normalizedPath === `${adminRoot}${CONTROL_ADMIN_PATHS.DEBUG_LOGGING_SECRET}` && request.method === "PUT") {
    await auth.requireAdminAuth(request, env);
    return handlers.handleDebugLoggingSecretPut(request, env);
  }
  if (normalizedPath === `${adminRoot}${CONTROL_ADMIN_PATHS.DEBUG_LOGGING_SECRET}` && request.method === "GET") {
    await auth.requireAdminAuth(request, env);
    return handlers.handleDebugLoggingSecretGet(env);
  }
  if (normalizedPath === `${adminRoot}${CONTROL_ADMIN_PATHS.DEBUG_LOGGING_SECRET}` && request.method === "DELETE") {
    await auth.requireAdminAuth(request, env);
    return handlers.handleDebugLoggingSecretDelete(env);
  }

  if (normalizedPath.startsWith(`${adminRoot}${CONTROL_ADMIN_PATHS.HTTP_AUTH_PREFIX}`)) {
    await auth.requireAdminAuth(request, env);
    return handlers.handleHttpAuthSecretRoute(normalizedPath, request, env);
  }
  if (normalizedPath.startsWith(`${adminRoot}${CONTROL_ADMIN_PATHS.HTTP_SECRETS_PREFIX}`)) {
    await auth.requireAdminAuth(request, env);
    return handlers.handleHttpSecretRoute(normalizedPath, request, env);
  }
  if (normalizedPath === `${adminRoot}${CONTROL_ADMIN_PATHS.HEADERS}` && request.method === "GET") {
    await auth.requireAdminAuth(request, env);
    return handlers.handleEnrichedHeadersList(env);
  }
  if (normalizedPath.startsWith(`${adminRoot}${CONTROL_ADMIN_PATHS.HEADERS_PREFIX}`) && request.method === "PUT") {
    await auth.requireAdminAuth(request, env);
    const headerName = normalizedPath.slice(`${adminRoot}${CONTROL_ADMIN_PATHS.HEADERS_PREFIX}`.length);
    return handlers.handleEnrichedHeaderPut(request, env, headerName);
  }
  if (normalizedPath.startsWith(`${adminRoot}${CONTROL_ADMIN_PATHS.HEADERS_PREFIX}`) && request.method === "DELETE") {
    await auth.requireAdminAuth(request, env);
    const headerName = normalizedPath.slice(`${adminRoot}${CONTROL_ADMIN_PATHS.HEADERS_PREFIX}`.length);
    return handlers.handleEnrichedHeaderDelete(env, headerName);
  }

  return null;
}

export { dispatchAdminRoute };
