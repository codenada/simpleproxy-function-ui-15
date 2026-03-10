# Platform Adapters

This folder is the platform boundary for the project.

- `interface/` defines adapter contracts used by worker logic.
- `cloudflare/` provides the default adapter implementation for one-click deploys.
- `index.js` composes the default adapter mapping.

Customer-owned repos can replace `src/platform/index.js` and keep runtime/control logic unchanged.
