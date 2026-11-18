import express, { type ErrorRequestHandler } from 'express';
import helmet from 'helmet';
import { rateLimit } from 'express-rate-limit';
import { hostHeaderValidation } from '@modelcontextprotocol/express';
import { NodeStreamableHTTPServerTransport } from '@modelcontextprotocol/node';
import type { AppConfig } from './config/env.js';
import type { Stores } from './storage/stores.js';
import { MemoryRepository } from './storage/memory.repository.js';
import { createMcpServer } from './mcp/server.js';
import { createAuthMiddleware } from './auth/auth.middleware.js';
import type { AuthenticatedRequest } from './auth/auth.types.js';
import { createOAuthRouter } from './auth/oauth/oauth.routes.js';
import { isLoopbackRedirectUri } from './auth/oauth/redirect.service.js';
import { authorizationServerMetadata, protectedResourceMetadata } from './auth/oauth/metadata.js';
import { createAdminRouter } from './routes/admin.routes.js';
import { createAuthRouter } from './routes/auth.routes.js';

export function createApp(config: AppConfig, stores: Stores) {
  const app = express();
  const memoryRepository = new MemoryRepository(stores.memories);
  const baseHost = new URL(config.publicBaseUrl).hostname;
  const allowedHosts = [...new Set([baseHost, '127.0.0.1', 'localhost', '[::1]'])];

  if (config.trustProxy) app.set('trust proxy', 1);
  else app.set('trust proxy', false);

  app.use(hostHeaderValidation(allowedHosts));
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'none'"],
        formAction: [
          "'self'",
          (req) => {
            const requestUrl = new URL(req.url ?? '/', config.publicBaseUrl);
            return isLoopbackRedirectUri(requestUrl.searchParams.get('redirect_uri')) ? '*' : new URL(config.publicBaseUrl).protocol;
          }
        ],
        baseUri: ["'none'"],
        frameAncestors: ["'none'"],
        styleSrc: ["'self'", "'unsafe-inline'"]
      }
    },
    crossOriginResourcePolicy: { policy: 'cross-origin' }
  }));
  app.use(express.json({ limit: '64kb', strict: true }));
  app.use(express.urlencoded({ extended: false, limit: '32kb', parameterLimit: 100 }));

  const generalLimiter = rateLimit({ windowMs: 60_000, limit: 300, standardHeaders: 'draft-8', legacyHeaders: false });
  const authLimiter = rateLimit({ windowMs: 60_000, limit: 30, standardHeaders: 'draft-8', legacyHeaders: false });
  app.use(generalLimiter);

  // CORS for MCP and OAuth machine-to-machine endpoints (open to any origin)
  app.use((req, res, next) => {
    if (['/mcp', '/token', '/register', '/revoke'].includes(req.path) || req.path.startsWith('/.well-known/')) {
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type, MCP-Protocol-Version, MCP-Session-Id, Last-Event-ID, X-API-Key');
      res.setHeader('Access-Control-Expose-Headers', 'WWW-Authenticate, MCP-Session-Id, MCP-Protocol-Version');
    }
    if (req.method === 'OPTIONS') { res.status(204).end(); return; }
    next();
  });

  // CORS for frontend origin (credentials-aware)
  app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (origin === config.frontendUrl) {
      res.setHeader('Access-Control-Allow-Origin', config.frontendUrl);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, PUT, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-CSRF-Token, Authorization, X-API-Key');
    }
    if (req.method === 'OPTIONS') { res.status(204).end(); return; }
    next();
  });

  // JSON status endpoint
  app.get('/', (_req, res) => {
    res.json({ service: 'universal-mcp-memory-server', status: 'running', version: '1.0.0', mcpEndpoint: config.resource });
  });

  app.get('/health', (_req, res) => res.json({ status: 'ok', service: 'universal-mcp-memory-server', transport: 'streamable-http' }));

  app.get('/.well-known/oauth-authorization-server', (_req, res) => {
    if (!config.enableOAuth) { res.status(404).json({ error: 'oauth_disabled' }); return; }
    res.json(authorizationServerMetadata(config));
  });
  const sendProtectedResourceMetadata = (_req: express.Request, res: express.Response): void => {
    if (!config.enableOAuth) { res.status(404).json({ error: 'oauth_disabled' }); return; }
    res.json(protectedResourceMetadata(config));
  };
  app.get('/.well-known/oauth-protected-resource', sendProtectedResourceMetadata);
  // RFC 9728 path-aware discovery for the protected resource at /mcp.
  app.get('/.well-known/oauth-protected-resource/mcp', sendProtectedResourceMetadata);
  app.get('/mcp/.well-known/oauth-protected-resource', sendProtectedResourceMetadata);

  // Backward-compat redirect: OAuth clients that open /login are sent to the frontend login page
  app.get('/login', (req, res) => {
    const returnTo = typeof req.query['return_to'] === 'string' ? req.query['return_to'] : '';
    const dest = returnTo
      ? `${config.frontendUrl}/login?return_to=${encodeURIComponent(returnTo)}`
      : `${config.frontendUrl}/login`;
    res.redirect(302, dest);
  });

  // JSON auth API for the frontend SPA
  app.use('/auth', authLimiter, createAuthRouter(config, stores));

  app.use(['/register', '/token', '/revoke', '/authorize'], authLimiter);
  app.use((req, res, next) => {
    if (!config.enableOAuth && ['/register', '/token', '/revoke', '/authorize'].includes(req.path)) { res.status(404).json({ error: 'oauth_disabled' }); return; }
    next();
  });
  app.use(createOAuthRouter(config, stores));
  app.use('/admin', createAdminRouter(config, stores));

  const authenticateMcp = createAuthMiddleware(config, stores);
  const handleMcp = async (req: express.Request, res: express.Response, next: express.NextFunction): Promise<void> => {
    try {
      const authenticatedRequest = req as AuthenticatedRequest;
      if (!authenticatedRequest.authContext) { res.status(401).end(); return; }
      const server = createMcpServer(memoryRepository, authenticatedRequest.authContext);
      const transport = new NodeStreamableHTTPServerTransport({ sessionIdGenerator: undefined });
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (error) {
      next(error);
    }
  };

  app.post('/mcp', authLimiter, authenticateMcp, handleMcp);
  app.get('/mcp', authLimiter, authenticateMcp, handleMcp);
  app.delete('/mcp', authLimiter, authenticateMcp, handleMcp);
  app.all('/mcp', (_req, res) => res.status(405).setHeader('Allow', 'GET, POST, DELETE').end());

  const errorHandler: ErrorRequestHandler = (error: unknown, _req, res, _next) => {
    if (res.headersSent) return;
    const candidate = error as { status?: unknown; statusCode?: unknown };
    const statusCandidate = typeof candidate?.status === 'number' ? candidate.status : candidate?.statusCode;
    const status = typeof statusCandidate === 'number' && statusCandidate >= 400 && statusCandidate <= 599 ? statusCandidate : 500;
    // Deliberately do not log request headers, bodies, or credentials.
    if (status >= 500) console.error('[request-error] An internal request failure occurred.');
    const errorCode = status === 413 ? 'payload_too_large' : status >= 500 ? 'internal_server_error' : 'invalid_request';
    res.status(status).json({ error: errorCode });
  };
  app.use(errorHandler);
  return app;
}
