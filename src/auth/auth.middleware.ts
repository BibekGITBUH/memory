import type { NextFunction, Request, Response } from 'express';
import type { AppConfig } from '../config/env.js';
import type { Stores } from '../storage/stores.js';
import type { AuthContext, AuthenticatedRequest } from './auth.types.js';
import { constantTimeHashMatch, hashOpaque, safeStringEqual, verifyPassword } from '../utils/crypto.js';
import { hasScope } from './scopes.js';

function localRequest(req: Request): boolean {
  const host = (req.hostname || '').toLowerCase();
  const remote = req.socket.remoteAddress || '';
  const localHost = ['localhost', '127.0.0.1', '::1'].includes(host);
  const localSocket = ['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(remote);
  return localHost && localSocket;
}

function modeAllows(config: AppConfig, method: string): boolean {
  if (config.authMode === 'multi-auth') return true;
  return config.authMode === method;
}

function parseBasic(header: string): { username: string; password: string } | undefined {
  const match = /^Basic\s+(.+)$/i.exec(header);
  if (!match?.[1]) return undefined;
  try {
    const decoded = Buffer.from(match[1], 'base64').toString('utf8');
    const separator = decoded.indexOf(':');
    if (separator < 1) return undefined;
    return { username: decoded.slice(0, separator), password: decoded.slice(separator + 1) };
  } catch { return undefined; }
}

function challenge(config: AppConfig): string {
  if (!config.enableOAuth) return 'Bearer realm="mcp-memory"';
  const metadata = `${config.publicBaseUrl}/.well-known/oauth-protected-resource/mcp`;
  return `Bearer realm="mcp-memory", resource_metadata="${metadata}", scope="memory:read memory:write"`;
}

function reject(res: Response, config: AppConfig, message = 'Authentication required.'): void {
  res.setHeader('WWW-Authenticate', challenge(config));
  res.status(401).json({ error: 'unauthorized', error_description: message });
}

export function createAuthMiddleware(config: AppConfig, stores: Stores) {
  return async (req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> => {
    try {
      const authorization = req.header('authorization') ?? '';
      const xApiKey = req.header('x-api-key');
      const now = new Date();

      if (/^Bearer\s+/i.test(authorization) && modeAllows(config, 'oauth') && config.enableOAuth) {
        const token = authorization.replace(/^Bearer\s+/i, '').trim();
        const hash = hashOpaque(token, config.tokenPepper);
        const records = await stores.accessTokens.read();
        const found = records.find(row => safeStringEqual(row.hash, hash) && row.revokedAt === null && new Date(row.expiresAt) > now && row.resource === config.resource);
        if (found) {
          const user = (await stores.users.read()).find(item => item.id === found.userId && item.disabledAt === null);
          if (!user) { reject(res, config, 'The token owner is disabled or missing.'); return; }
          req.authContext = { userId: found.userId, username: user.username, scopes: found.scope, method: 'oauth', clientId: found.clientId };
          await stores.accessTokens.update(rows => rows.map(row => row.hash === hash ? { ...row, lastUsedAt: now.toISOString() } : row), { backup: false });
          next(); return;
        }
      }

      if (/^Bearer\s+/i.test(authorization) && modeAllows(config, 'bearer') && config.enableBearer && config.testBearerToken) {
        const token = authorization.replace(/^Bearer\s+/i, '').trim();
        if (constantTimeHashMatch(token, hashOpaque(config.testBearerToken, config.tokenPepper), config.tokenPepper)) {
          req.authContext = { userId: 'env-bearer', scopes: config.testBearerScopes, method: 'bearer' };
          next(); return;
        }
      }

      let apiKey = xApiKey;
      if (!apiKey && /^ApiKey\s+/i.test(authorization)) apiKey = authorization.replace(/^ApiKey\s+/i, '').trim();
      if (apiKey && modeAllows(config, 'api-key') && config.enableApiKey) {
        const keyHash = hashOpaque(apiKey, config.tokenPepper);
        const records = await stores.apiKeys.read();
        const found = records.find(row => safeStringEqual(row.hash, keyHash) && row.revokedAt === null && (!row.expiresAt || new Date(row.expiresAt) > now));
        if (found) {
          req.authContext = { userId: `api-key:${found.id}`, scopes: found.scopes, method: 'api-key' };
          await stores.apiKeys.update(rows => rows.map(row => row.id === found.id ? { ...row, lastUsedAt: now.toISOString() } : row), { backup: false });
          next(); return;
        }
      }

      if (/^Basic\s+/i.test(authorization) && modeAllows(config, 'basic') && config.enableBasic) {
        const credentials = parseBasic(authorization);
        if (credentials) {
          if (!req.secure && !localRequest(req)) { reject(res, config, 'HTTP Basic is accepted only over HTTPS (or loopback development).'); return; }
          const users = await stores.users.read();
          const user = users.find(item => item.username === credentials.username && item.disabledAt === null);
          if (user && await verifyPassword(credentials.password, user.passwordSalt, user.passwordHash)) {
            req.authContext = { userId: user.id, username: user.username, scopes: user.scopes, method: 'basic' };
            next(); return;
          }
        }
      }

      if (config.enableNoAuth && modeAllows(config, 'none') && localRequest(req)) {
        req.authContext = { userId: 'local-development', scopes: ['memory:read', 'memory:write'], method: 'none' };
        next(); return;
      }

      reject(res, config, authorization ? 'The supplied credential is invalid, expired, revoked, or lacks an enabled authentication mode.' : 'No supported credential was supplied.');
    } catch (error) {
      next(error);
    }
  };
}

export function requireToolScope(context: AuthContext | undefined, required: 'memory:read' | 'memory:write'): void {
  if (!context) throw new Error('Missing authentication context.');
  if (!hasScope(context, required)) throw new Error(`Insufficient scope. Required: ${required}.`);
}
