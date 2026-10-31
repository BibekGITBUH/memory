# Client compatibility notes

This file records provider-documented behavior as of 2026-10-31. It does not certify a live connection to any provider account.

## ChatGPT

The server implements remote Streamable HTTP, HTTPS deployment, RFC 9728 Protected Resource Metadata, RFC 8414 Authorization Server Metadata, OAuth authorization code + PKCE S256, DCR, and CIMD. The authorization server advertises `client_id_metadata_document_supported: true`. CIMD supports public `none` clients and `private_key_jwt` clients with a JWKS document. OpenAI's custom-MCP documentation describes CIMD and DCR for ChatGPT custom MCP servers.

Current account eligibility is separate from protocol compatibility. OpenAI's current help page lists custom MCP server connections/full MCP for Business and Enterprise/Edu; Pro is limited to read/fetch; Free is not listed. The current user's account is Free. Consequently, a server can be protocol-compatible but still unavailable in that ChatGPT UI account.

## Claude.ai

Anthropic documents custom remote MCP connectors for Free, Pro, Max, Team, and Enterprise, with Free limited to one custom connector. The connector flow can select OAuth identity method, DCR, and fixed request headers for API key/bearer authentication. Team/Enterprise workspace owners control organization-level connector availability. The remote connector request originates from Anthropic cloud infrastructure, so the server must be publicly reachable.

## Claude Code

Anthropic documents HTTP/Streamable HTTP MCP, OAuth login, DCR and CIMD discovery, fixed request headers, and local stdio processes. Claude Code uses dynamically allocated localhost callback ports for OAuth; this server allows the port to vary for a registered HTTP loopback callback while still requiring the same loopback host and callback path. The command form `claude mcp add --transport http <name> <url>` supports `--header`. Stdio uses `claude mcp add --transport stdio <name> -- <command> [args...]`.

## Test status

- Static implementation present: yes.
- Automated tests authored: yes.
- Automated tests executed in this environment: no (npm registry request timed out before dependencies could be installed).
- Live ChatGPT connection: not tested.
- Live Claude.ai connection: not tested.
- Live Claude Code connection: not tested.
