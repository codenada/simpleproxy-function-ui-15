import test from "node:test";
import assert from "node:assert/strict";
import { performance } from "node:perf_hooks";

import { createCidrMatcher, createInMemoryRpmLimiter } from "../src/common/traffic_controls.js";

function measure(label, fn, iterations = 20000) {
  const started = performance.now();
  for (let i = 0; i < iterations; i += 1) fn(i);
  const elapsedMs = performance.now() - started;
  return { label, elapsedMs, opsPerSec: (iterations / elapsedMs) * 1000 };
}

test("perf: cidr matcher remains cheap when disabled", () => {
  const isAllowed = createCidrMatcher();
  const disabled = measure("cidr-disabled", () => {
    isAllowed("203.0.113.10", ["10.0.0.0/8"], false);
  });
  const enabled = measure("cidr-enabled", () => {
    isAllowed("203.0.113.10", ["0.0.0.0/0"], true);
  });

  assert.ok(disabled.elapsedMs < enabled.elapsedMs * 0.9 || disabled.elapsedMs < 15);
});

test("perf: rpm limiter supports hot-path throughput", () => {
  const limiter = createInMemoryRpmLimiter();
  const result = measure("rpm-limiter", (i) => {
    limiter(`ip-${i % 1000}`, 1000, true);
  });

  assert.ok(result.opsPerSec > 100000, `ops/s too low: ${Math.round(result.opsPerSec)}`);
});
