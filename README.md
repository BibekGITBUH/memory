# Universal Multi-Platform MCP Memory Server

A TypeScript/Node.js remote MCP server with exactly three tools (`create`, `delete`, `list`), JSON-file persistence, Express, Streamable HTTP, OAuth 2.1, bearer tokens, API keys, Basic authentication, and an optional local-only no-auth mode.

> **Important:** This repository contains the implementation and setup guides. It has not been connected to an external ChatGPT or Claude account from this environment. Run the verification steps below on your Windows PC before exposing it through a tunnel.

## 1. What is included

- Official MCP TypeScript SDK v2 server package and Node Streamable HTTP adapter.
- Main endpoint: `POST /mcp`, with `GET` and `DELETE` transport requests also routed through the SDK adapter.
- Exactly three MCP tools:
  - `create({ content })` — creates a UUID and timestamp and persists the memory.
  - `delete({ id })` — permanently removes the memory from the active JSON store and scrubs that ID from local memory backup snapshots.
  - `list()` — returns every active memory with ID, content, and creation timestamp.
- JSON files for memories, users, OAuth clients, authorization codes, access tokens, refresh tokens, API keys, and used client assertions.
- Zod JSON validation, atomic writes, serialized in-process operations, cross-process file locks, rolling local backups, and a manual backup/restore command.
- OAuth authorization-code flow with PKCE S256, DCR, CIMD, exact redirect URI checks, state, resource/audience binding, consent, access and refresh tokens, token rotation, reuse detection, and revocation.
- Independent authentication modes: `oauth`, `bearer`, `api-key`, `basic`, `none`, and `multi-auth`.
- Admin session routes to create and revoke API keys. Newly generated API keys are displayed only once and stored as hashes.
- Optional local stdio adapter reusing the exact same three MCP tool registrations.

## 2. Requirements

- Windows 11, macOS, or Linux.
- Node.js 20.19+; Node.js 22 LTS is recommended.
- npm 10+.
- Cloudflare `cloudflared` only when you want a public HTTPS URL for remote clients.

The Node.js and npm versions detected during the latest dependency verification are recorded in [docs/VERSIONS.md](./docs/VERSIONS.md). Dependency versions are pinned in `package.json` and `package-lock.json`.

Check your versions:

```powershell
node --version
npm --version
```

## 3. Install on Windows PowerShell

Extract the ZIP, open PowerShell in the `universal-mcp-memory-server` folder, and run:

```powershell
Copy-Item .env.example .env
notepad .env
npm install
```

Before starting, edit `.env` and replace the following values:

- `ADMIN_USERNAME`: the username for the server's initial administrator account.
- `ADMIN_PASSWORD`: a unique password with at least 14 characters.
- `TOKEN_PEPPER`: a random secret of at least 32 characters.
- `SESSION_SECRET`: a different random secret of at least 32 characters.

Example PowerShell commands to generate two independent Base64 secrets:

```powershell
$bytes1 = New-Object byte[] 48
[Security.Cryptography.RandomNumberGenerator]::Fill($bytes1)
$tokenPepper = [Convert]::ToBase64String($bytes1)

$bytes2 = New-Object byte[] 48
[Security.Cryptography.RandomNumberGenerator]::Fill($bytes2)
$sessionSecret = [Convert]::ToBase64String($bytes2)

Write-Host "TOKEN_PEPPER=$tokenPepper"
Write-Host "SESSION_SECRET=$sessionSecret"
```

Copy the two generated values into `.env`. Do not use the same value for both secrets. Keep `.env` private and do not commit it to Git.

The first startup creates the `admin` account in `data/users.json`. The password is stored as a salted scrypt hash, not plaintext. After the first successful startup, you may clear `ADMIN_PASSWORD` in `.env`; the stored account remains available. Changing `ADMIN_PASSWORD` after `users.json` already exists does not reset that account.

`TEST_BEARER_TOKEN` and `TEST_API_KEY` are blank by default. You can leave them blank and use OAuth or create API keys from the admin endpoint. For local testing only, you can set either value to a long random string. The API key is added to `data/api-keys.json` as a hash at startup.

## 4. Start and verify locally

```powershell
npm run dev
```

The default listener is:

```text
http://127.0.0.1:3000
```

Open these URLs in your browser:

- `http://127.0.0.1:3000/` — service page.
- `http://127.0.0.1:3000/health` — health response.
- `http://127.0.0.1:3000/.well-known/oauth-protected-resource` — root protected-resource discovery.
- `http://127.0.0.1:3000/.well-known/oauth-protected-resource/mcp` — path-specific RFC 9728 discovery for the `/mcp` resource.
- `http://127.0.0.1:3000/.well-known/oauth-authorization-server` — authorization-server discovery.
- `http://127.0.0.1:3000/login` — local administrator sign-in.

On first run, the `data` folder is populated with JSON files. Do not edit them while the server is running. Back up the complete `data` folder before manual changes.

Build and run the production TypeScript output:

```powershell
npm run build
npm start
```

Run the automated tests:

```powershell
npm test
```

## 5. Authentication modes

### Multi-auth (default)

`AUTH_MODE=multi-auth` enables the mechanisms whose `ENABLE_*` value is `true`:

| Method | Request credential | Scope source |
|---|---|---|
| OAuth | `Authorization: Bearer <access-token>` | OAuth grant |
| Static bearer | `Authorization: Bearer <TEST_BEARER_TOKEN>` | `TEST_BEARER_SCOPES` |
| API key | `X-API-Key: <key>` or `Authorization: ApiKey <key>` | API-key record |
| Basic | `Authorization: Basic <base64(username:password)>` | User record |
| No auth | No credential | Local-development only; explicit opt-in |

OAuth and static bearer tokens both use the Bearer header. The server first checks an active OAuth access-token record, then checks the configured static test token. API-key and Basic methods are evaluated independently.

### OAuth

Set `ENABLE_OAUTH=true`. OAuth is the recommended method for public remote clients. The server exposes:

| Endpoint | Purpose |
|---|---|
| `GET /.well-known/oauth-protected-resource` | RFC 9728 root protected-resource metadata |
| `GET /.well-known/oauth-protected-resource/mcp` | Path-specific metadata for `/mcp` (used in the Bearer challenge) |
| `GET /.well-known/oauth-authorization-server` | RFC 8414 authorization-server metadata |
| `GET /authorize` | Authorization and consent screen |
| `POST /token` | Authorization-code and refresh-token exchange |
| `POST /register` | Dynamic Client Registration (DCR) |
| `POST /revoke` | OAuth token revocation |

The authorization and token requests must contain `resource` equal to the canonical MCP resource URL (`PUBLIC_BASE_URL` + `/mcp`). Tokens are opaque, stored as keyed hashes, and bound to this resource. The code flow requires PKCE S256 for public and confidential clients.

Supported client authentication methods:

- `none` for public clients using PKCE.
- `client_secret_basic` for confidential DCR clients.
- `client_secret_post` for confidential DCR clients.
- `private_key_jwt` for CIMD clients whose metadata document provides `jwks` or `jwks_uri`.

DCR secrets are shown once at registration. CIMD documents are fetched only from HTTPS hostnames that resolve to public IPs; redirects, local/private IPs, oversized documents, and disallowed hosts are rejected. Set `CIMD_ALLOWED_HOSTS` to a semicolon-separated hostname allowlist when you want a stricter policy.

Refresh tokens rotate. Reuse of an already consumed refresh token revokes the token family. OAuth consent is tied to a signed browser session and a CSRF token.

### Bearer token

Set `ENABLE_BEARER=true` and optionally set `TEST_BEARER_TOKEN` and `TEST_BEARER_SCOPES`. This credential is intended for local testing or tightly controlled integrations. It is not a replacement for per-user OAuth authorization on a public production endpoint.

### API keys

Set `ENABLE_API_KEY=true`. Sign in to `/login` using the initial admin account. Then:

1. `GET /admin/session` returns the browser-session CSRF token.
2. `POST /admin/api-keys` creates a key. Send the CSRF value in `X-CSRF-Token` and JSON body such as `{"name":"Claude test","scopes":["memory:read"],"expiresInDays":30}`.
3. Save the returned `key` immediately. It cannot be shown again because only its hash is stored.
4. `GET /admin/api-keys` lists key metadata without hashes or plaintext credentials.
5. `DELETE /admin/api-keys/<id>` revokes a key. Include the same `X-CSRF-Token` header.

The endpoints require an administrator browser session. Here is a copy-paste PowerShell example for creating a read/write API key on the local server (replace the password):

```powershell
$base = 'http://127.0.0.1:3000'
$loginPage = Invoke-WebRequest -Uri "$base/login" -SessionVariable session
$loginCsrf = [regex]::Match($loginPage.Content, 'name="csrf" value="([^"]+)"').Groups[1].Value
Invoke-WebRequest -Uri "$base/login" -Method Post -WebSession $session -Body @{
  username = 'admin'
  password = 'YOUR_ADMIN_PASSWORD'
  csrf = $loginCsrf
  return_to = '/'
} | Out-Null
$admin = Invoke-RestMethod -Uri "$base/admin/session" -WebSession $session
$key = Invoke-RestMethod -Uri "$base/admin/api-keys" -Method Post -WebSession $session `
  -Headers @{ 'X-CSRF-Token' = $admin.csrf } -ContentType 'application/json' `
  -Body (@{ name = 'Claude connector'; scopes = @('memory:read','memory:write'); expiresInDays = 30 } | ConvertTo-Json)
$key.key  # Copy this once; it is not retrievable later.
```

No additional MCP tools are added.

### Basic authentication

Set `ENABLE_BASIC=true`. The initial admin username/password are usable as Basic credentials because the password hash is stored in `users.json`. Do not send Basic credentials over public HTTP. The middleware permits Basic only over HTTPS or on a loopback development request.

### No authentication

No-auth is disabled by default. To use it for local testing only, explicitly set:

```dotenv
AUTH_MODE=none
ENABLE_NO_AUTH=true
PUBLIC_BASE_URL=http://127.0.0.1:3000
```

The application also checks the request host and remote socket for loopback. No-auth is rejected if `PUBLIC_BASE_URL` is a public hostname or when `NODE_ENV=production`. A Cloudflare Tunnel hostname is not accepted by the local no-auth path. Never use no-auth for a public server.

## 6. Scopes

The server uses two scopes so read-only access can be enforced:

| Tool | Required scope |
|---|---|
| `list` | `memory:read` |
| `create` | `memory:write` |
| `delete` | `memory:write` |

`memory:write` also implies read access. A credential with only `memory:read` cannot create or delete. The source specification repeated a single `memory` scope but also required that read-only users be unable to mutate data; the two-scope design makes that rule enforceable.

## 7. Cloudflare Tunnel setup

Keep the server bound to `127.0.0.1`. Do not bind the Node process to `0.0.0.0` for this workflow.

1. Start the app with `npm run dev`.
2. Open another PowerShell window and run:

   ```powershell
   cloudflared tunnel --url http://127.0.0.1:3000
   ```

3. Copy the generated `https://....trycloudflare.com` URL.
4. Stop and restart the Node app after setting `.env`:

   ```dotenv
   PUBLIC_BASE_URL=https://YOUR-ASSIGNED-NAME.trycloudflare.com
   TRUST_PROXY=true
   ```

5. Keep both the app and `cloudflared` processes running. Re-check the two discovery endpoints through the HTTPS URL.

The quick-tunnel hostname changes between tunnel sessions. Whenever it changes, update `PUBLIC_BASE_URL`, restart the app, and reconnect/re-authorize remote clients. OAuth issuer, resource identifier, discovery metadata, and token audience all depend on this value.

### Stable named tunnel

For a stable hostname, create a named Cloudflare Tunnel in your Cloudflare account and route a DNS name such as `memory.example.com` to it. A typical `config.yml` has this shape (replace all placeholders with values from your own Cloudflare setup):

```yaml
tunnel: YOUR_TUNNEL_UUID
credentials-file: C:\Users\YOUR_WINDOWS_USER\.cloudflared\YOUR_TUNNEL_UUID.json
ingress:
  - hostname: memory.example.com
    service: http://127.0.0.1:3000
  - service: http_status:404
```

Set `PUBLIC_BASE_URL=https://memory.example.com`, keep `HOST=127.0.0.1`, and set `TRUST_PROXY=true` only because Cloudflared is the trusted local proxy in this setup. Protect the Cloudflare credentials file; do not put it in this ZIP or source control.

## 8. Connect ChatGPT

The server supports the remote MCP/OAuth components ChatGPT documents: HTTPS, Streamable HTTP, protected-resource metadata, authorization-server metadata, PKCE, DCR, and CIMD. ChatGPT's documentation says it can use CIMD for public clients with `none` or signed `private_key_jwt` token authentication, and can use DCR when configured.

Connection procedure (where the account/workspace exposes the feature):

1. Make the server publicly reachable over HTTPS and confirm `https://YOUR_HOST/.well-known/oauth-protected-resource/mcp` and `https://YOUR_HOST/.well-known/oauth-authorization-server` return JSON. The root protected-resource URL is also provided for compatibility.
2. In ChatGPT web, open **Plugins** and select **Add custom MCP server** (the exact location may vary with workspace UI rollout).
3. Enter the server URL: `https://YOUR_HOST/mcp`.
4. Choose OAuth. Use the supported CIMD option when available, or DCR if the connection flow offers it.
5. Complete the server's sign-in and consent screen using the admin account created on first startup.
6. Install the custom MCP server and verify the `create`, `delete`, and `list` tools are shown.

To disconnect, open ChatGPT **Settings → Connectors** (or the workspace's connected-apps page), select this server, and choose its remove/disconnect action. The current label can vary by rollout.

**Plan eligibility matters.** Current OpenAI Help Center documentation lists custom MCP connections and full MCP support for Business and Enterprise/Edu workspaces; Pro is described as limited to read/fetch, and Free is not listed. The account used to prepare this project is on Free, so the ChatGPT UI may not offer the custom server feature. That is an OpenAI account/workspace eligibility limitation, not an endpoint setting in this server. Re-check OpenAI's current help page before troubleshooting OAuth.

OpenAI sources:

- https://help.openai.com/en/articles/12584461-connecting-custom-mcp-servers-in-chatgpt
- https://developers.openai.com/api/docs/guides/custom-mcp-server

## 9. Connect Claude.ai

Anthropic documents remote custom MCP connectors for Claude Free, Pro, Max, Team, and Enterprise; its help page says Free users are limited to one custom connector. Remote connectors connect from Anthropic's cloud, so the server must be reachable over the public internet.

1. Open **Customize → Connectors** in Claude.ai.
2. Choose **Add custom connector** (or the organization-level connector setup on Team/Enterprise).
3. Enter a name and `https://YOUR_HOST/mcp`.
4. Choose **Sign in now** or **Sign in when needed** for OAuth.
5. For OAuth client identity, choose Claude's published identity (CIMD) when offered, or automatic registration (DCR). The server implements both mechanisms.
6. Complete the OAuth browser flow and approve the requested memory scopes.
7. Enable the connector from the conversation's **Connectors** menu and verify all three tools are listed.

For fixed credentials instead of OAuth, use the Request headers section:

- API key: header name `X-API-Key`, value the key generated in `/admin/api-keys`.
- Static bearer: header name `Authorization`, value `Bearer <TEST_BEARER_TOKEN>`.
- Basic: header name `Authorization`, value `Basic <BASE64(username:password)>`. Use Basic only over the public HTTPS URL.

A fixed shared API key or bearer token gives each connector the same permissions associated with that credential. Prefer per-user OAuth where possible. Team/Enterprise admins control who can add organization connectors.

To disconnect, open **Customize → Connectors**, select this custom connector, and remove or disable it. The exact menu label can vary with Claude.ai rollout.

Anthropic sources:

- https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp
- https://support.claude.com/en/articles/11176164-use-connectors-to-extend-claude-s-capabilities

## 10. Connect Claude Code

### Remote HTTP with OAuth

From a terminal:

```powershell
claude mcp add --transport http memory https://YOUR_HOST/mcp
```

Then inside Claude Code run `/mcp` and complete the browser login, or run:

```powershell
claude mcp login memory
```

The server supports DCR and CIMD. Claude Code documents both automatic DCR and CIMD discovery for remote HTTP MCP.

### Remote HTTP with an API key

```powershell
claude mcp add --transport http --header "X-API-Key: YOUR_API_KEY" memory https://YOUR_HOST/mcp
```

### Remote HTTP with a bearer token

```powershell
claude mcp add --transport http --header "Authorization: Bearer YOUR_TEST_BEARER_TOKEN" memory https://YOUR_HOST/mcp
```

### Remote HTTP with Basic authentication

Use Basic only with the public HTTPS URL. Generate the header value in PowerShell (replace the username/password with the admin account credentials):

```powershell
$basic = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('admin:YOUR_ADMIN_PASSWORD'))
claude mcp add --transport http --header "Authorization: Basic $basic" memory https://YOUR_HOST/mcp
```

Use one authentication method per configured server. If an Authorization header is statically configured, Claude Code will use it as the server credential rather than falling back to OAuth.

Check and remove the server:

```powershell
claude mcp list
claude mcp get memory
claude mcp remove memory
```

### Local HTTP without Cloudflare

Start the server on the same PC, then add it using the local address:

```powershell
claude mcp add --transport http --header "X-API-Key: YOUR_LOCAL_API_KEY" local-memory http://127.0.0.1:3000/mcp
```

The local endpoint is only reachable by clients that can access your PC's loopback interface. This is not a remote-cloud connection.

### Local stdio

In a PowerShell window opened at the extracted project folder:

```powershell
claude mcp add --transport stdio local-memory -- npx tsx .\src\stdio.ts
```

The stdio adapter uses the same JSON memory repository and the same three MCP tools. It is a local process launched by Claude Code; it does not use the Express listener, remote OAuth, Cloudflare Tunnel, or HTTP credentials. Install dependencies first with `npm install`.

Anthropic's current Claude Code MCP guide documents the `claude mcp add --transport http` and `--header` syntax, OAuth sign-in, and stdio configuration:

- https://code.claude.com/docs/en/mcp

## 11. Local transport differences

| Connection | Where server process runs | How client reaches it | Tunnel needed? |
|---|---|---|---|
| Local stdio | Your PC, launched by the AI client | stdin/stdout | No |
| Local HTTP | Your PC | `http://127.0.0.1:3000/mcp` | No, for a client on the same PC |
| Remote HTTP | Your PC or hosted server | Public HTTPS `/mcp` | Yes, if the server remains on your PC |

ChatGPT and Claude.ai remote connectors use remote server infrastructure. A localhost URL on your PC is not reachable by their cloud systems. Claude Code can use local stdio, local HTTP, or remote HTTP.

## 12. Manual MCP Inspector check

With the HTTP server running:

```powershell
npx @modelcontextprotocol/inspector
```

In the Inspector UI, select **Streamable HTTP**, enter `http://127.0.0.1:3000/mcp`, and provide one enabled credential in the Headers section:

- `Authorization: Bearer <TEST_BEARER_TOKEN>`, or
- `X-API-Key: <API_KEY>`.

Initialize the connection, open the tools list, and verify exactly `create`, `delete`, and `list` appear. Test in this order:

1. Call `create` with `{"content":"Inspector test memory"}` and copy the returned ID.
2. Call `list` and verify the memory appears.
3. Call `delete` with the returned ID and verify success.
4. Call `list` again and verify it no longer appears.
5. For a read-only API key, call `list` successfully and confirm `create` and `delete` return insufficient-scope errors.

## 13. Backup and recovery

Automatic rolling snapshots are stored under `data/backups/` when a JSON store is updated. To create a manual snapshot of all JSON files:

```powershell
npm run backup
```

Restore one JSON file from its newest matching snapshot:

```powershell
npm run restore -- memories.json
```

Or specify an exact backup filename:

```powershell
npm run restore -- memories.json memories-2026-10-31T10-00-00-000Z-abcd1234.json
```

Backups contain sensitive user and token metadata. Keep `data/backups` private. When a memory is deleted, the repository also removes that memory ID from local memory backup snapshots so a later restore will not resurrect it. This only affects backup files managed in this project's `data/backups` folder; manually copied or external backups must be handled separately.

## 14. Project structure

```text
universal-mcp-memory-server/
├─ data/                         # Created/filled at runtime; not committed
├─ scripts/
│  ├─ backup.ts
│  └─ restore.ts
├─ src/
│  ├─ auth/
│  │  ├─ auth.middleware.ts
│  │  ├─ session.ts
│  │  ├─ users.service.ts
│  │  ├─ scopes.ts
│  │  └─ oauth/
│  │     ├─ client.service.ts
│  │     ├─ metadata.ts
│  │     ├─ oauth.routes.ts
│  │     └─ pkce.service.ts
│  ├─ config/env.ts
│  ├─ mcp/server.ts
│  ├─ routes/admin.routes.ts
│  ├─ storage/
│  │  ├─ json-store.ts
│  │  ├─ memory.repository.ts
│  │  ├─ schemas.ts
│  │  └─ stores.ts
│  ├─ utils/crypto.ts
│  ├─ app.ts
│  ├─ index.ts
│  └─ stdio.ts
├─ tests/
├─ .env.example
├─ package.json
└─ tsconfig.json
```

## 15. Troubleshooting

### `Cannot POST /register`

This usually means the running server does not have the DCR route loaded, the request is going to the wrong public origin/path, or an older process is still running. This project mounts `POST /register`; rebuild/restart it and check `GET /.well-known/oauth-authorization-server` for a `registration_endpoint` value. If that value is absent, OAuth is disabled or you are reaching a different server instance.

### OAuth says resource mismatch

Set `PUBLIC_BASE_URL` to the exact public HTTPS origin and restart the server. The authorization request and token request must use the same `resource` value advertised by Protected Resource Metadata, which is `https://YOUR_HOST/mcp`.

### `redirect_uri` mismatch

The server uses exact string matching. Reconnect so the AI client registers its current callback URI through DCR or presents its CIMD metadata. Do not manually substitute a Claude callback URL or a ChatGPT callback URL; use the exact callback URI supplied by the client.

### `invalid_client`

Check the configured token endpoint authentication method and whether the client sends `client_id`, a client secret, or a signed client assertion as required. Public clients use `none` with PKCE; confidential DCR clients use the one-time secret.

### Claude.ai cannot reach the server

Remote Claude connectors connect from Anthropic's cloud, not from your local browser. Check the public HTTPS tunnel, the exact `/mcp` URL, the tunnel process, Host validation, and `PUBLIC_BASE_URL`. A local-only HTTP URL will not work from claude.ai.

### Cloudflare Tunnel fails after restarting

A quick-tunnel URL can change. Copy the new URL into `PUBLIC_BASE_URL`, restart the Node server, then reconnect the client. For fewer reconnects, use a stable named tunnel and DNS name.

### No tools appear

Use MCP Inspector against the exact `/mcp` URL. Check that authentication passed and that the server's `tools/list` response contains exactly the three expected tool names. The server is stateless, so each HTTP MCP request must include its authorization header.

### `npm run build` reports package/API mismatch

The project targets the official MCP TypeScript SDK v2 split packages. Confirm `npm install` installed `@modelcontextprotocol/server`, `@modelcontextprotocol/node`, and `@modelcontextprotocol/express` from the same v2 release line. Do not mix SDK v1 imports (`@modelcontextprotocol/sdk/...`) with the v2 package imports in this project.

## 16. Compatibility and verification status

| Client | Server-side integration included | Provider-side path documented | External account connection verified here? |
|---|---|---|---|
| ChatGPT custom MCP | OAuth, DCR, CIMD, resource metadata, Streamable HTTP | Yes; account/workspace eligibility applies | No |
| Claude.ai custom connector | OAuth, DCR, CIMD, bearer/API-key request headers, Streamable HTTP | Yes; plan/workspace permissions apply | No |
| Claude Code remote HTTP | OAuth/DCR/CIMD and fixed headers | Yes | No |
| Claude Code local stdio | Local stdio adapter | Yes | No |

This table intentionally distinguishes implemented server behavior and provider-documented setup from an actual end-to-end connection test. No external provider has been used to authorize this server in this build session.

## 17. Security notes

- Never expose `.env`, `data/`, `data/backups/`, or the Cloudflare credential file.
- Use HTTPS for every remote connection.
- Keep `HOST=127.0.0.1` when Cloudflared is the public ingress.
- Use OAuth for user-specific remote access. API keys and static bearer tokens are shared secrets.
- Give remote clients the least privilege needed. A `memory:read` key cannot create or delete memories.
- Rotate `TOKEN_PEPPER` only when you are prepared to invalidate existing OAuth tokens and API keys.
- If `SESSION_SECRET` is rotated, existing browser sessions become invalid.
- Disable auth modes you do not use.
- Keep `ENABLE_NO_AUTH=false` for anything reachable beyond loopback.
- Review tool calls carefully: `delete` permanently removes the selected memory from the active store and local memory backup snapshots.
