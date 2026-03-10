function applyBootstrapHandlers(handlers, deps) {
  handlers.handleStatusPage = (env, request) => deps.bootstrapApi.handleStatusPage(env, request);
  handlers.handleBootstrapPost = (env) => deps.bootstrapApi.handleBootstrapPost(env);
  handlers.handleBrowserVerifyPost = (request, env) => deps.bootstrapApi.handleBrowserVerifyPost(request, env);
}

function applyAdminShellHandlers(handlers, deps) {
  handlers.handleRotateByKind = deps.handleRotateByKind;
  handlers.handleAdminPage = () => deps.adminUiApi.handleAdminPage();
  handlers.handleAdminSwaggerPage = (request) => deps.swaggerApi.handleAdminSwaggerPage(request);
  handlers.handleAdminSwaggerSpec = (request) => deps.swaggerApi.handleAdminSwaggerSpec(request);
  handlers.handleAdminAccessTokenPost = deps.handleAdminAccessTokenPost;
  handlers.handleVersion = deps.handleVersion;
  handlers.handleKeysStatusGet = deps.handleKeysStatusGet;
}

function applyConfigHandlers(handlers, deps) {
  handlers.handleConfigGet = deps.handleConfigGet;
  handlers.handleConfigPut = deps.handleConfigPut;
  handlers.handleConfigValidate = deps.handleConfigValidate;
  handlers.handleConfigTestRule = deps.handleConfigTestRule;
  handlers.handleKeyRotationConfigGet = deps.handleKeyRotationConfigGet;
  handlers.handleKeyRotationConfigPut = deps.handleKeyRotationConfigPut;
  handlers.handleTransformConfigGet = deps.handleTransformConfigGet;
  handlers.handleTransformConfigPut = deps.handleTransformConfigPut;
}

function applyDebugHandlers(handlers, deps) {
  handlers.handleDebugGet = deps.handleDebugGet;
  handlers.handleDebugPut = deps.handleDebugPut;
  handlers.handleDebugDelete = deps.handleDebugDelete;
  handlers.handleDebugLastGet = deps.handleDebugLastGet;
  handlers.handleLiveLogStream = deps.handleLiveLogStream;
  handlers.handleDebugLoggingSecretPut = deps.handleDebugLoggingSecretPut;
  handlers.handleDebugLoggingSecretGet = deps.handleDebugLoggingSecretGet;
  handlers.handleDebugLoggingSecretDelete = deps.handleDebugLoggingSecretDelete;
}

function applySecretAndHeaderHandlers(handlers, deps) {
  handlers.handleHttpAuthSecretRoute = deps.handleHttpAuthSecretRoute;
  handlers.handleHttpSecretRoute = deps.handleHttpSecretRoute;
  handlers.handleEnrichedHeadersList = deps.handleEnrichedHeadersList;
  handlers.handleEnrichedHeaderPut = deps.handleEnrichedHeaderPut;
  handlers.handleEnrichedHeaderDelete = deps.handleEnrichedHeaderDelete;
}

function buildControlRouteHandlers(deps) {
  const handlers = {};
  applyBootstrapHandlers(handlers, deps);
  applyAdminShellHandlers(handlers, deps);
  applyConfigHandlers(handlers, deps);
  applyDebugHandlers(handlers, deps);
  applySecretAndHeaderHandlers(handlers, deps);
  return handlers;
}

export { buildControlRouteHandlers };
