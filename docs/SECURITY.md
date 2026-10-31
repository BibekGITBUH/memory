# Security model and operational notes

## Authentication and authorization

- OAuth opaque access/refresh tokens are returned once and stored in `access-tokens.json` / `refresh-tokens.json` only as HMAC-SHA256 hashes using `TOKEN_PEPPER`.
- API keys are returned once, then only their hashes are stored in `api-keys.json`.
- User passwords are stored in `users.json` as per-user salted scrypt hashes.
- OAuth client secrets are stored as keyed hashes.
- Client assertion JWT `jti` values are tracked as hashes to reject replay.
- OAuth access tokens are audience/resource-bound to `PUBLIC_BASE_URL/mcp`.
- OAuth authorization codes are short-lived, one-time, PKCE-bound, client-bound, redirect-bound, and resource-bound.
- OAuth authorization state must be 16-8192 characters and is returned unchanged to the client after approval or denial.
- Authorization responses include the configured issuer (`iss`) on both approval and consent denial.
- Tool-level scopes are independently checked by each MCP tool.

## File safety

- Each JSON file is parsed and validated against a Zod schema before use.
- Updates are serialized in-process and use `proper-lockfile` across processes.
- Writes use `write-file-atomic` with fsync enabled.
- Previous file contents are copied into `data/backups/` before normal updates; snapshots are rotated per file.
- Invalid JSON is not overwritten automatically. Restore a known backup after inspection.

## Network safety

- The server binds to loopback by default.
- Express Host validation allows the configured public hostname and explicit loopback hosts.
- Trusting forwarded headers is opt-in through `TRUST_PROXY`; only enable it behind the intended trusted local reverse proxy.
- CIMD/JWKS metadata fetches require HTTPS, reject redirects and local/private IP resolution, pin validated DNS addresses into the outgoing request, and cap response bodies at 64 KiB.
- ChatGPT's published CIMD/JWKS host has a 30-second bounded metadata fetch timeout to accommodate transient slow responses; other hosts retain the 6-second timeout.
- HTTP Basic is accepted only over HTTPS or a loopback connection.
- HTTPS OAuth redirect URIs must match exactly. HTTP loopback redirects are restricted to `localhost`, `127.0.0.1`, or `[::1]`; only their port may vary for native clients using an ephemeral callback port.
- The CSP permits arbitrary form destinations only on consent pages requesting an HTTP loopback redirect. The rendered consent form itself still submits to the fixed configured server origin; non-loopback consent pages retain the configured-origin form policy.
- No-auth requires explicit opt-in, a loopback public base URL, and a local request; it is rejected in production.
- Rate limits and request-size limits apply.
- Browser authorization consent forms post to the configured public origin. The Content Security Policy `form-action` directive allows the configured URL scheme to accommodate browsers that reject the explicit same-origin host source; rendered application forms still use fixed destinations.

## Important deployment limitation

`TRUST_PROXY=true` configures Express to trust one proxy hop. The default Cloudflare Tunnel command connects through a local cloudflared process. Keep the application port bound to `127.0.0.1`, do not expose it directly, and do not reuse this setting if the Node listener becomes directly reachable from untrusted networks.

## Data deletion and backups

The `delete` tool removes the target record from the live memory JSON array and scrubs that ID from the project's automatic/manual memory snapshots under `data/backups/`. Copies outside this folder are not affected. Remove external backups separately when retention policy requires it.
