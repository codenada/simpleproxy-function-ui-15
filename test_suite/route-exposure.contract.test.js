import test from "node:test";
import assert from "node:assert/strict";
import {
  SERIAL,
  runtimeWorker,
  controlWorker,
  createEnv,
  callSpecificWorker,
  bootstrapKeys,
} from "./smoke.helpers.mjs";

test("runtime worker does not expose control/admin routes", SERIAL, async () => {
  const env = createEnv();
  const forbiddenRuntimePaths = [
    "/admin",
    "/admin/version",
    "/admin/config",
    "/_apiproxy",
  ];

  for (const path of forbiddenRuntimePaths) {
    const response = await callSpecificWorker(runtimeWorker, env, { method: "GET", path });
    assert.equal(response.status, 404, `runtime should hide ${path}`);
  }
});

test("control worker does not expose runtime request routes", SERIAL, async () => {
  const env = createEnv();
  await bootstrapKeys(env);

  const forbiddenControlPaths = [
    { method: "POST", path: "/_apiproxy/request" },
    { method: "POST", path: "/_apiproxy/keys/proxy/rotate" },
    { method: "POST", path: "/_apiproxy/keys/issuer/rotate" },
  ];

  for (const { method, path } of forbiddenControlPaths) {
    const response = await callSpecificWorker(controlWorker, env, { method, path });
    assert.equal(response.status, 404, `control should hide ${method} ${path}`);
  }
});
