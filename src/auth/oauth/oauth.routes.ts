import { Router, type Request, type Response } from 'express';
import { randomUUID } from 'node:crypto';
import { z } from 'zod/v4';
import { createLocalJWKSet, jwtVerify } from 'jose';
import type { AppConfig } from '../../config/env.js';
import type { Stores } from '../../storage/stores.js';
import type { OAuthClient, AuthorizationCode, AccessTokenRecord, RefreshTokenRecord } from '../../storage/schemas.js';
import { hashOpaque, randomToken, safeStringEqual } from '../../utils/crypto.js';
import { resolveOAuthClient } from './client.service.js';
import { validatePkce, verifyPkce } from './pkce.service.js';
import { isValidRedirectUri, matchesRedirectUri } from './redirect.service.js';
import { isValidOAuthState } from './state.service.js';
import { authorizationResponseUrl } from './authorization-response.js';
import { getBrowserSession } from '../session.js';

const dcrSchema = z.object({
  client_name: z.string().min(1).max(120).default('MCP client'),
  redirect_uris: z.array(z.string().url()).min(1).max(20),
  grant_types: z.array(z.string()).default(['authorization_code', 'refresh_token']),
  response_types: z.array(z.string()).default(['code']),
  token_endpoint_auth_method: z.enum(['none', 'client_secret_basic', 'client_secret_post']).default('none')
});

const allowedScopes = new Set(['memory:read', 'memory:write']);
const tokenAssertionType = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
type OAuthScope = AuthorizationCode['scope'][number];

function stringField(input: unknown, key: string): string {
  const value = (input as Record<string, unknown> | undefined)?.[key];
  return typeof value === 'string' ? value : '';
}

function requestClientId(req: Request, body: Record<string, unknown>): string {
  const fromBody = stringField(body, 'client_id');
  if (fromBody) return fromBody;
  const header = req.header('authorization') ?? '';
  if (!/^Basic\s+/i.test(header)) return '';
  try {
    const decoded = Buffer.from(header.replace(/^Basic\s+/i, ''), 'base64').toString('utf8');
    const separator = decoded.indexOf(':');
    return separator > 0 ? decodeURIComponent(decoded.slice(0, separator)) : '';
  } catch { return ''; }
}

function htmlEscape(value: string): string {
  return value.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#39;');
}

function htmlPage(title: string, body: string): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${htmlEscape(title)}</title></head><body><main><h1>${htmlEscape(title)}</h1>${body}</main></body></html>`;
}

function oauthError(res: Response, status: number, error: string, description: string): void {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Pragma', 'no-cache');
  res.status(status).json({ error, error_description: description });
}

function parseScopes(value: string): OAuthScope[] | undefined {
  const scopes = [...new Set(value.trim().split(/\s+/).filter(Boolean))];
  if (scopes.length === 0) return ['memory:read'];
  const validScopes = scopes.filter((scope): scope is OAuthScope => allowedScopes.has(scope));
  return validScopes.length === scopes.length ? validScopes : undefined;
}

interface AuthorizationRequest {
  client: OAuthClient;
  clientId: string;
  redirectUri: string;
  state: string;
  scope: string[];
  codeChallenge: string;
  resource: string;
}

function userHasScope(userScopes: readonly string[], requested: string): boolean {
  return userScopes.includes('memory:write') || userScopes.includes(requested);
}

async function validateAuthorizationRequest(query: Record<string, unknown>, stores: Stores, config: AppConfig): Promise<AuthorizationRequest> {
  const responseType = stringField(query, 'response_type');
  const clientId = stringField(query, 'client_id');
  const redirectUri = stringField(query, 'redirect_uri');
  const state = stringField(query, 'state');
  const challenge = stringField(query, 'code_challenge');
  const method = stringField(query, 'code_challenge_method');
  const resource = stringField(query, 'resource');
  const scope = parseScopes(stringField(query, 'scope'));
  if (responseType !== 'code') throw new Error('response_type must be code.');
  if (!clientId || !redirectUri || !isValidOAuthState(state)) throw new Error('client_id, redirect_uri, and a high-entropy state value (16-8192 characters) are required.');
  if (!scope) throw new Error('One or more requested scopes are not supported.');
  if (!validatePkce(challenge, method)) throw new Error('PKCE S256 is required.');
  if (resource !== config.resource) throw new Error('The resource parameter must exactly identify this MCP server.');
  const client = await resolveOAuthClient(clientId, stores, config);
  if (!client) throw new Error('Unknown OAuth client. Register the client or provide a valid Client ID Metadata Document.');
  if (!isValidRedirectUri(redirectUri) || !client.redirectUris.some(uri => matchesRedirectUri(uri, redirectUri))) throw new Error('redirect_uri must match a registered redirect URI.');
  return { client, clientId, redirectUri, state, scope, codeChallenge: challenge, resource };
}

function authorizationRequestFromBody(body: Record<string, unknown>): Record<string, unknown> {
  return {
    response_type: body['response_type'],
    client_id: body['client_id'],
    redirect_uri: body['redirect_uri'],
    state: body['state'],
    scope: body['scope'],
    code_challenge: body['code_challenge'],
    code_challenge_method: body['code_challenge_method'],
    resource: body['resource']
  };
}

async function validateClientAuthentication(
  req: Request,
  body: Record<string, unknown>,
  client: OAuthClient,
  stores: Stores,
  config: AppConfig
): Promise<boolean> {
  const authHeader = req.header('authorization') ?? '';
  let authClientId = stringField(body, 'client_id');
  let secret = stringField(body, 'client_secret');
  if (/^Basic\s+/i.test(authHeader)) {
    try {
      const decoded = Buffer.from(authHeader.replace(/^Basic\s+/i, ''), 'base64').toString('utf8');
      const sep = decoded.indexOf(':');
      if (sep < 1) return false;
      authClientId = decodeURIComponent(decoded.slice(0, sep));
      secret = decodeURIComponent(decoded.slice(sep + 1));
    } catch { return false; }
  }
  if (authClientId && authClientId !== client.clientId) return false;

  if (client.tokenEndpointAuthMethod === 'none') return !secret && Boolean(authClientId || client.metadataDocument);
  if (client.tokenEndpointAuthMethod === 'client_secret_basic' || client.tokenEndpointAuthMethod === 'client_secret_post') {
    if (client.tokenEndpointAuthMethod === 'client_secret_basic' && !/^Basic\s+/i.test(authHeader)) return false;
    if (client.tokenEndpointAuthMethod === 'client_secret_post' && !stringField(body, 'client_secret')) return false;
    if (!client.clientSecretHash || !secret) return false;
    return safeStringEqual(hashOpaque(secret, config.tokenPepper), client.clientSecretHash);
  }

  if (client.tokenEndpointAuthMethod === 'private_key_jwt') {
    if (stringField(body, 'client_assertion_type') !== tokenAssertionType) return false;
    const assertion = stringField(body, 'client_assertion');
    const metadata = client.metadata as { jwks?: { keys?: unknown[] } } | undefined;
    const keys = metadata?.jwks?.keys;
    if (!assertion || !Array.isArray(keys) || keys.length === 0) return false;
    try {
      const localJwks = createLocalJWKSet({ keys: keys as never[] });
      const { payload } = await jwtVerify(assertion, localJwks, {
        audience: `${config.issuer}/token`,
        issuer: client.clientId,
        subject: client.clientId,
        algorithms: ['RS256', 'PS256', 'ES256', 'EdDSA'],
        maxTokenAge: '5m',
        clockTolerance: '30s'
      });
      const now = new Date();
      const nowSeconds = Math.floor(now.getTime() / 1000);
      if (typeof payload.jti !== 'string' || payload.jti.length < 8 || typeof payload.exp !== 'number' || typeof payload.iat !== 'number') return false;
      if (payload.exp <= nowSeconds || payload.exp > nowSeconds + 600 || payload.iat > nowSeconds + 60) return false;
      const assertionHash = hashOpaque(`${client.clientId}:${payload.jti}`, config.tokenPepper);
      const used = (await stores.assertions.read()).some(item => safeStringEqual(item.hash, assertionHash) && new Date(item.expiresAt) > now);
      if (used) return false;
      const expiry = new Date(payload.exp * 1000).toISOString();
      await stores.assertions.update(rows => [...rows.filter(row => new Date(row.expiresAt) > now), { hash: assertionHash, expiresAt: expiry }]);
      return true;
    } catch { return false; }
  }
  return false;
}

async function issueTokenPair(
  stores: Stores,
  config: AppConfig,
  userId: string,
  clientId: string,
  scope: RefreshTokenRecord['scope'],
  resource: string,
  familyId: RefreshTokenRecord['familyId'] = randomUUID()
): Promise<Record<string, unknown>> {
  const now = new Date();
  const accessToken = randomToken(32);
  const refreshToken = randomToken(48);
  const accessRecord: AccessTokenRecord = {
    hash: hashOpaque(accessToken, config.tokenPepper),
    familyId,
    clientId,
    userId,
    scope,
    resource,
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + config.accessTokenTtlSeconds * 1000).toISOString(),
    revokedAt: null,
    lastUsedAt: null
  };
  const refreshRecord: RefreshTokenRecord = {
    hash: hashOpaque(refreshToken, config.tokenPepper),
    familyId,
    clientId,
    userId,
    scope,
    resource,
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + config.refreshTokenTtlSeconds * 1000).toISOString(),
    usedAt: null,
    revokedAt: null
  };
  await stores.accessTokens.update(rows => [...rows, accessRecord]);
  await stores.refreshTokens.update(rows => [...rows, refreshRecord]);
  return {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: config.accessTokenTtlSeconds,
    refresh_token: refreshToken,
    scope: scope.join(' ')
  };
}

export function createOAuthRouter(config: AppConfig, stores: Stores): Router {
  const router = Router();

  router.post('/register', async (req, res) => {
    try {
      const parsed = dcrSchema.safeParse(req.body);
      if (!parsed.success) { oauthError(res, 400, 'invalid_client_metadata', parsed.error.message); return; }
      const data = parsed.data;
      if (!data.grant_types.includes('authorization_code') || !data.response_types.includes('code') || data.grant_types.some(grant => !['authorization_code', 'refresh_token'].includes(grant)) || data.response_types.some(type => type !== 'code')) {
        oauthError(res, 400, 'invalid_client_metadata', 'Only authorization_code grant and code response type are supported.'); return;
      }
      if (data.redirect_uris.some(uri => !isValidRedirectUri(uri))) {
        oauthError(res, 400, 'invalid_redirect_uri', 'Redirect URIs must use HTTPS or loopback HTTP.'); return;
      }
      const clientId = randomUUID();
      const clientSecret = data.token_endpoint_auth_method === 'none' ? undefined : randomToken(40);
      const client: OAuthClient = {
        clientId,
        clientName: data.client_name,
        redirectUris: data.redirect_uris,
        tokenEndpointAuthMethod: data.token_endpoint_auth_method,
        ...(clientSecret ? { clientSecretHash: hashOpaque(clientSecret, config.tokenPepper) } : {}),
        grantTypes: data.grant_types,
        responseTypes: data.response_types,
        metadataDocument: false,
        createdAt: new Date().toISOString(),
        disabledAt: null
      };
      await stores.oauthClients.update(rows => [...rows, client]);
      res.setHeader('Cache-Control', 'no-store');
      res.status(201).json({
        client_id: clientId,
        ...(clientSecret ? { client_secret: clientSecret, client_secret_expires_at: 0 } : {}),
        client_name: client.clientName,
        redirect_uris: client.redirectUris,
        grant_types: client.grantTypes,
        response_types: client.responseTypes,
        token_endpoint_auth_method: client.tokenEndpointAuthMethod,
        client_id_issued_at: Math.floor(Date.now() / 1000)
      });
    } catch (error) {
      oauthError(res, 400, 'invalid_client_metadata', error instanceof Error ? error.message : 'Client registration failed.');
    }
  });

  router.get('/authorize', async (req, res) => {
    try {
      const authRequest = await validateAuthorizationRequest(req.query as Record<string, unknown>, stores, config);
      const session = await getBrowserSession(req, stores, config);
      if (!session) {
        res.redirect(302, `/login?return_to=${encodeURIComponent(req.originalUrl)}`);
        return;
      }
      const unavailableScopes = authRequest.scope.filter(scope => !userHasScope(session.user.scopes, scope));
      if (unavailableScopes.length) throw new Error(`Your account is not authorized for: ${unavailableScopes.join(', ')}.`);
      const hidden = (key: string, value: string): string => `<input type="hidden" name="${key}" value="${htmlEscape(value)}">`;
      const fields: [string, string][] = [
        ['response_type', 'code'], ['client_id', authRequest.clientId], ['redirect_uri', authRequest.redirectUri],
        ['state', authRequest.state], ['scope', authRequest.scope.join(' ')], ['code_challenge', authRequest.codeChallenge],
        ['code_challenge_method', 'S256'], ['resource', authRequest.resource]
      ];
      const hiddenFields = fields.map(([key, value]) => hidden(key, value)).join('');
      res.type('html').send(htmlPage('Authorize MCP Memory Server', `
        <p><strong>${htmlEscape(authRequest.client.clientName)}</strong> requests access to your memories.</p>
        <ul>${authRequest.scope.map(scope => `<li>${htmlEscape(scope)}</li>`).join('')}</ul>
        <p>Read permission lets the client list stored memories. Write permission lets it create and permanently delete memories.</p>
        <form method="post" action="${htmlEscape(new URL(config.publicBaseUrl).origin)}/authorize">${hiddenFields}${hidden('csrf', session.csrf)}<button type="submit" name="decision" value="allow">Allow</button> <button type="submit" name="decision" value="deny">Deny</button></form>
      `));
    } catch (error) {
      res.status(400).type('html').send(htmlPage('Authorization request rejected', `<p>${htmlEscape(error instanceof Error ? error.message : 'Invalid authorization request.')}</p>`));
    }
  });

  router.post('/authorize', async (req, res) => {
    try {
      const session = await getBrowserSession(req, stores, config);
      if (!session || !safeStringEqual(session.csrf, stringField(req.body, 'csrf'))) { res.status(403).send('Invalid or expired CSRF token.'); return; }
      const decision = stringField(req.body, 'decision');
      const authRequest = await validateAuthorizationRequest(authorizationRequestFromBody(req.body), stores, config);
      const unavailableScopes = authRequest.scope.filter(scope => !userHasScope(session.user.scopes, scope));
      if (unavailableScopes.length) { res.status(403).type('html').send(htmlPage('Insufficient permission', `<p>Your account is not authorized for: ${htmlEscape(unavailableScopes.join(', '))}.</p>`)); return; }
      if (decision !== 'allow') {
        res.redirect(302, authorizationResponseUrl(authRequest.redirectUri, {
          error: 'access_denied',
          state: authRequest.state,
          issuer: config.issuer
        }));
        return;
      }
      const code = randomToken(32);
      const now = new Date();
      const record: AuthorizationCode = {
        hash: hashOpaque(code, config.tokenPepper),
        clientId: authRequest.clientId,
        userId: session.user.id,
        redirectUri: authRequest.redirectUri,
        scope: authRequest.scope as ('memory:read' | 'memory:write')[],
        resource: authRequest.resource,
        codeChallenge: authRequest.codeChallenge,
        createdAt: now.toISOString(),
        expiresAt: new Date(now.getTime() + config.authorizationCodeTtlSeconds * 1000).toISOString(),
        consumedAt: null
      };
      await stores.authorizationCodes.update(rows => [...rows, record]);
      res.redirect(302, authorizationResponseUrl(authRequest.redirectUri, {
        code,
        state: authRequest.state,
        issuer: config.issuer
      }));
    } catch (error) {
      res.status(400).type('html').send(htmlPage('Authorization failed', `<p>${htmlEscape(error instanceof Error ? error.message : 'Authorization failed.')}</p>`));
    }
  });

  router.post('/token', async (req, res) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    try {
      if (!config.enableOAuth) { oauthError(res, 404, 'unsupported', 'OAuth is disabled.'); return; }
      const grantType = stringField(body, 'grant_type');
      const clientId = requestClientId(req, body);
      if (!clientId) { oauthError(res, 400, 'invalid_request', 'client_id is required (in the body or HTTP Basic authentication).'); return; }
      const client = await resolveOAuthClient(clientId, stores, config);
      if (!client || !await validateClientAuthentication(req, body, client, stores, config)) {
        oauthError(res, 401, 'invalid_client', 'Client authentication failed.'); return;
      }
      if (grantType === 'authorization_code') {
        const code = stringField(body, 'code');
        const redirectUri = stringField(body, 'redirect_uri');
        const verifier = stringField(body, 'code_verifier');
        const resource = stringField(body, 'resource');
        if (!code || !redirectUri || !verifier || resource !== config.resource) { oauthError(res, 400, 'invalid_request', 'code, redirect_uri, code_verifier, and the correct resource are required.'); return; }
        const hash = hashOpaque(code, config.tokenPepper);
        let selected: AuthorizationCode | undefined;
        const now = new Date();
        await stores.authorizationCodes.update(rows => rows.map(row => {
          if (!safeStringEqual(row.hash, hash)) return row;
          selected = row;
          if (row.consumedAt === null && new Date(row.expiresAt) > now && row.clientId === client.clientId && row.redirectUri === redirectUri && row.resource === resource && verifyPkce(verifier, row.codeChallenge)) {
            return { ...row, consumedAt: now.toISOString() };
          }
          return row;
        }));
        if (!selected || selected.consumedAt !== null || new Date(selected.expiresAt) <= now || selected.clientId !== client.clientId || selected.redirectUri !== redirectUri || selected.resource !== resource || !verifyPkce(verifier, selected.codeChallenge)) {
          oauthError(res, 400, 'invalid_grant', 'Authorization code is invalid, expired, already used, or failed PKCE/resource validation.'); return;
        }
        const tokenPayload = await issueTokenPair(stores, config, selected.userId, client.clientId, selected.scope, selected.resource);
        res.setHeader('Cache-Control', 'no-store'); res.setHeader('Pragma', 'no-cache'); res.json(tokenPayload); return;
      }

      if (grantType === 'refresh_token') {
        const presented = stringField(body, 'refresh_token');
        const resource = stringField(body, 'resource');
        if (!presented || resource !== config.resource) { oauthError(res, 400, 'invalid_request', 'refresh_token and the correct resource are required.'); return; }
        const hash = hashOpaque(presented, config.tokenPepper);
        const now = new Date();
        let found: RefreshTokenRecord | undefined;
        await stores.refreshTokens.update(items => items.map(item => {
          if (!safeStringEqual(item.hash, hash) || item.clientId !== client.clientId) return item;
          found = item;
          if (item.usedAt === null && item.revokedAt === null && new Date(item.expiresAt) > now && item.resource === resource) {
            return { ...item, usedAt: now.toISOString() };
          }
          return item;
        }));
        if (!found) { oauthError(res, 400, 'invalid_grant', 'Refresh token is invalid.'); return; }
        if (found.usedAt !== null) {
          await stores.refreshTokens.update(items => items.map(item => item.familyId === found!.familyId ? { ...item, revokedAt: now.toISOString() } : item));
          await stores.accessTokens.update(items => items.map(item => item.familyId === found!.familyId ? { ...item, revokedAt: now.toISOString() } : item));
          oauthError(res, 400, 'invalid_grant', 'Refresh token reuse detected; the token family has been revoked.'); return;
        }
        if (found.revokedAt !== null || new Date(found.expiresAt) <= now || found.resource !== resource) { oauthError(res, 400, 'invalid_grant', 'Refresh token is expired, revoked, or bound to another resource.'); return; }
        const requestedScope = stringField(body, 'scope');
        const nextScope = requestedScope ? parseScopes(requestedScope) : found.scope;
        if (!nextScope || nextScope.some(scope => !found!.scope.includes(scope))) { oauthError(res, 400, 'invalid_scope', 'A refresh request cannot expand the originally granted scopes.'); return; }
        const tokenPayload = await issueTokenPair(stores, config, found.userId, client.clientId, nextScope, found.resource, found.familyId);
        res.setHeader('Cache-Control', 'no-store'); res.setHeader('Pragma', 'no-cache'); res.json(tokenPayload); return;
      }
      oauthError(res, 400, 'unsupported_grant_type', 'Only authorization_code and refresh_token grants are supported.');
    } catch (error) {
      oauthError(res, 400, 'invalid_request', error instanceof Error ? error.message : 'Token request failed.');
    }
  });

  router.post('/revoke', async (req, res) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const token = stringField(body, 'token');
    const hint = stringField(body, 'token_type_hint');
    const clientId = requestClientId(req, body);
    if (!token || !clientId) { oauthError(res, 400, 'invalid_request', 'token and client_id are required (client_id may use HTTP Basic authentication).'); return; }
    try {
      const client = await resolveOAuthClient(clientId, stores, config);
      if (!client || !await validateClientAuthentication(req, body, client, stores, config)) { oauthError(res, 401, 'invalid_client', 'Client authentication failed.'); return; }
      const hash = hashOpaque(token, config.tokenPepper);
      const now = new Date().toISOString();
      let matched = false;
      if (hint !== 'refresh_token') {
        const access = (await stores.accessTokens.read()).find(row => safeStringEqual(row.hash, hash) && row.clientId === client.clientId);
        if (access) {
          matched = true;
          await stores.accessTokens.update(rows => rows.map(row => row.hash === hash ? { ...row, revokedAt: now } : row));
        }
      }
      if (!matched || hint === 'refresh_token') {
        const refresh = (await stores.refreshTokens.read()).find(row => safeStringEqual(row.hash, hash) && row.clientId === client.clientId);
        if (refresh) {
          matched = true;
          await stores.refreshTokens.update(rows => rows.map(row => row.familyId === refresh.familyId ? { ...row, revokedAt: now } : row));
          await stores.accessTokens.update(rows => rows.map(row => row.familyId === refresh.familyId ? { ...row, revokedAt: now } : row));
        }
      }
      res.status(200).end();
    } catch {
      // RFC 7009 intentionally does not disclose whether a token existed.
      res.status(200).end();
    }
  });

  return router;
}
