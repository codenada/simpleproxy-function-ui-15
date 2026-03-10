# Platform Interface Contracts

The worker logic depends on these interfaces only:

- `clock`: `nowMs() -> number`
- `http`: `request(url, init) -> Promise<Response>`
- `crypto`:
  - `randomBytes(length) -> Uint8Array`
  - `sha256Hex(input) -> Promise<string>`
  - `subtle` WebCrypto interface
- `storage`:
  - `keyValue` (`get/put/delete/list`)
  - `secrets`
  - `durable`

Cloudflare defaults are implemented under `src/platform/cloudflare`.
