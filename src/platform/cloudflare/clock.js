import { createClockInterface } from "../interface/clock.js";

function createCloudflareClock() {
  return createClockInterface({
    nowMs: () => Date.now(),
  });
}

export { createCloudflareClock };
