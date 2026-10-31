import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import ipaddr from 'ipaddr.js';
import { Agent, request } from 'undici';
import { z } from 'zod/v4';
import type { AppConfig } from '../../config/env.js';
import type { Stores } from '../../storage/stores.js';
import type { OAuthClient } from '../../storage/schemas.js';
import { isValidRedirectUri } from './redirect.service.js';

const metadataSchema = z.object({
  client_id: z.string().url(),
  client_name: z.string().optional(),
  redirect_uris: z.array(z.string().url()).min(1),
  grant_types: z.array(z.string()).optional(),
  response_types: z.array(z.string()).optional(),
  token_endpoint_auth_method: z.enum(['none', 'private_key_jwt']).default('none'),
  jwks: z.object({ keys: z.array(z.record(z.string(), z.unknown())).min(1) }).optional(),
  jwks_uri: z.string().url().optional()
}).passthrough();

const DEFAULT_METADATA_TIMEOUT_MS = 6_000;
const CHATGPT_METADATA_TIMEOUT_MS = 30_000;

function publicAddress(value: string): boolean {
  try { return ipaddr.parse(value).range() === 'unicast'; } catch { return false; }
}

async function fetchSafeJson(urlValue: string, config: AppConfig): Promise<Record<string, unknown>> {
  const url = new URL(urlValue);
  if (url.protocol !== 'https:' || url.username || url.password || url.hash || isIP(url.hostname)) {
    throw new Error('CIMD/JWKS URLs must be public HTTPS hostnames without credentials or fragments.');
  }
  if (url.hostname === 'localhost' || url.hostname.endsWith('.localhost') || url.hostname.endsWith('.local')) {
    throw new Error('Private/local CIMD hosts are blocked.');
  }
  if (config.cimdAllowedHosts.length && !config.cimdAllowedHosts.includes(url.hostname.toLowerCase())) {
    throw new Error('CIMD hostname is not in CIMD_ALLOWED_HOSTS.');
  }
  const addresses = await lookup(url.hostname, { all: true, verbatim: true });
  if (addresses.length === 0 || addresses.some(entry => !publicAddress(entry.address))) {
    throw new Error('CIMD/JWKS hostname resolves to a non-public IP address; request blocked.');
  }
  // Pin the validated DNS result into this request to reduce DNS-rebinding SSRF risk.
  const pinned = addresses.map(item => ({ address: item.address, family: item.family }));
  const lookupPinned = ((_hostname: string, options: { all?: boolean }, callback: (error: NodeJS.ErrnoException | null, address: string | { address: string; family: number }[], family?: number) => void) => {
    if (options && options.all) callback(null, pinned);
    else callback(null, pinned[0]!.address, pinned[0]!.family);
  }) as never;
  const dispatcher = new Agent({ connect: { lookup: lookupPinned } });
  const timeoutMs = url.hostname === 'chatgpt.com' ? CHATGPT_METADATA_TIMEOUT_MS : DEFAULT_METADATA_TIMEOUT_MS;
  try {
    const response = await request(url, {
      dispatcher,
      headersTimeout: timeoutMs,
      bodyTimeout: timeoutMs,
      headers: { accept: 'application/json' }
    });
    if (response.statusCode < 200 || response.statusCode >= 300) throw new Error(`CIMD/JWKS fetch failed with HTTP ${response.statusCode}.`);
    const contentType = String(response.headers['content-type'] ?? '');
    if (!contentType.includes('application/json')) throw new Error('CIMD/JWKS response must be application/json.');
    const chunks: Buffer[] = [];
    let totalBytes = 0;
    for await (const chunk of response.body) {
      const buffer = Buffer.from(chunk);
      totalBytes += buffer.length;
      if (totalBytes > 65536) { response.body.destroy(); throw new Error('CIMD/JWKS response exceeds the 64 KiB limit.'); }
      chunks.push(buffer);
    }
    const text = Buffer.concat(chunks).toString('utf8');
    const parsed: unknown = JSON.parse(text);
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) throw new Error('CIMD/JWKS response must be a JSON object.');
    return parsed as Record<string, unknown>;
  } finally {
    await dispatcher.close();
  }
}

export async function resolveOAuthClient(clientId: string, stores: Stores, config: AppConfig): Promise<OAuthClient | undefined> {
  const stored = (await stores.oauthClients.read()).find(client => client.clientId === clientId && client.disabledAt === null);
  if (stored && (!stored.metadataDocument || Date.now() - new Date(stored.createdAt).getTime() < 10 * 60_000)) return stored;
  if (!clientId.startsWith('https://')) return undefined;

  const raw = await fetchSafeJson(clientId, config);
  const parsed = metadataSchema.safeParse(raw);
  if (!parsed.success || parsed.data.client_id !== clientId) throw new Error('Invalid Client ID Metadata Document. client_id must exactly match the document URL.');
  const metadata = parsed.data;
  if (metadata.redirect_uris.some(uri => !isValidRedirectUri(uri))) throw new Error('CIMD redirect URI is not HTTPS or an allowed loopback URI.');
  const declaredGrantTypes = metadata.grant_types ?? ['authorization_code', 'refresh_token'];
  const responseTypes = metadata.response_types ?? ['code'];
  if (!declaredGrantTypes.includes('authorization_code') || !responseTypes.includes('code') || responseTypes.some(type => type !== 'code')) throw new Error('CIMD client must support the authorization_code grant and code response type.');
  const grantTypes = declaredGrantTypes.filter(grant => ['authorization_code', 'refresh_token'].includes(grant));
  if (metadata.token_endpoint_auth_method === 'private_key_jwt' && !metadata.jwks && !metadata.jwks_uri) {
    throw new Error('private_key_jwt clients must supply jwks or jwks_uri.');
  }
  let clientMetadata: Record<string, unknown> = { ...raw };
  if (metadata.jwks_uri) {
    const jwks = await fetchSafeJson(metadata.jwks_uri, config);
    if (!Array.isArray(jwks['keys']) || jwks['keys'].length === 0) throw new Error('The CIMD jwks_uri did not return a valid JWK set.');
    clientMetadata = { ...clientMetadata, jwks };
  }
  const client: OAuthClient = {
    clientId,
    clientName: metadata.client_name ?? new URL(clientId).hostname,
    redirectUris: metadata.redirect_uris,
    tokenEndpointAuthMethod: metadata.token_endpoint_auth_method,
    grantTypes,
    responseTypes,
    metadataDocument: true,
    metadata: clientMetadata,
    createdAt: new Date().toISOString(),
    disabledAt: null
  };
  await stores.oauthClients.update(clients => clients.some(item => item.clientId === clientId)
    ? clients.map(item => item.clientId === clientId ? client : item)
    : [...clients, client]);
  return client;
}
