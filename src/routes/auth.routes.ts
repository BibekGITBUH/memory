import { Router } from 'express';
import { randomUUID, timingSafeEqual } from 'node:crypto';
import type { AppConfig } from '../config/env.js';
import type { Stores } from '../storage/stores.js';
import { getBrowserSession, createBrowserSession, clearBrowserSession } from '../auth/session.js';
import { authenticatePassword, registerUser, UsernameTakenError } from '../auth/users.service.js';
import { randomToken, hashOpaque } from '../utils/crypto.js';
import { authorizationResponseUrl } from '../auth/oauth/authorization-response.js';
import type { AuthorizationCode } from '../storage/schemas.js';
import { registerInputSchema } from '../storage/schemas.js';

export interface ConsentChallenge {
  clientId: string;
  clientName: string;
  redirectUri: string;
  state: string;
  scope: ('memory:read' | 'memory:write')[];
  codeChallenge: string;
  resource: string;
  expiresAt: number;
}

// In-memory consent challenge store (TTL: 5 minutes)
export const consentChallenges = new Map<string, ConsentChallenge>();

function safeStringField(body: unknown, key: string): string {
  const val = (body as Record<string, unknown>)?.[key];
  return typeof val === 'string' ? val : '';
}

export function createAuthRouter(config: AppConfig, stores: Stores) {
  const router = Router();

  // GET /auth/me - return current session info
  router.get('/me', async (req, res) => {
    const session = await getBrowserSession(req, stores, config);
    if (!session) { res.status(401).json({ authenticated: false }); return; }
    res.json({
      authenticated: true,
      csrf: session.csrf,
      user: {
        id: session.user.id,
        username: session.user.username,
        role: session.user.role,
        scopes: session.user.scopes
      }
    });
  });

  // POST /auth/register - register a new user and create a session
  router.post('/register', async (req, res) => {
    if (!config.enableRegistration) {
      res.status(403).json({
        error: 'registration_disabled',
        message: 'User registration is disabled on this server.'
      });
      return;
    }

    const parsed = registerInputSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({
        error: 'validation_error',
        message: parsed.error.issues[0]?.message ?? 'Invalid registration data.'
      });
      return;
    }

    try {
      const user = await registerUser(stores.users, parsed.data);
      createBrowserSession(res, user, config);
      res.status(201).json({
        authenticated: true,
        user: {
          id: user.id,
          username: user.username,
          role: user.role,
          scopes: user.scopes
        }
      });
    } catch (error) {
      if (error instanceof UsernameTakenError) {
        res.status(409).json({
          error: 'username_taken',
          message: error.message
        });
        return;
      }
      res.status(500).json({
        error: 'registration_failed',
        message: 'An internal error occurred during registration.'
      });
    }
  });

  // POST /auth/login - authenticate and set session cookie
  router.post('/login', async (req, res) => {
    const username = safeStringField(req.body, 'username');
    const password = safeStringField(req.body, 'password');
    if (!username || !password) { res.status(400).json({ error: 'username and password required' }); return; }
    const user = await authenticatePassword(stores.users, username, password);
    if (!user) { res.status(401).json({ error: 'invalid_credentials', message: 'Invalid username or password.' }); return; }
    createBrowserSession(res, user, config);
    res.json({
      authenticated: true,
      user: { id: user.id, username: user.username, role: user.role, scopes: user.scopes }
    });
  });

  // POST /auth/logout - clear session
  router.post('/logout', async (_req, res) => {
    clearBrowserSession(res, config);
    res.json({ ok: true });
  });

  // GET /auth/consent/:consentId - fetch pending consent challenge details
  router.get('/consent/:consentId', async (req, res) => {
    const consentId = req.params['consentId'] ?? '';
    const challenge = consentChallenges.get(consentId);
    if (!challenge || Date.now() > challenge.expiresAt) {
      consentChallenges.delete(consentId);
      res.status(404).json({ error: 'consent_not_found', message: 'Consent request not found or expired.' });
      return;
    }
    const session = await getBrowserSession(req, stores, config);
    if (!session) { res.status(401).json({ error: 'unauthenticated', message: 'Please log in to continue.' }); return; }
    res.json({
      consentId,
      clientName: challenge.clientName,
      scope: challenge.scope,
      resource: challenge.resource,
      user: { username: session.user.username, role: session.user.role },
      csrf: session.csrf
    });
  });

  // POST /auth/consent/:consentId - submit consent decision
  router.post('/consent/:consentId', async (req, res) => {
    const consentId = req.params['consentId'] ?? '';
    const challenge = consentChallenges.get(consentId);
    if (!challenge || Date.now() > challenge.expiresAt) {
      consentChallenges.delete(consentId);
      res.status(404).json({ error: 'consent_not_found', message: 'Consent request not found or expired.' });
      return;
    }
    const session = await getBrowserSession(req, stores, config);
    if (!session) { res.status(401).json({ error: 'unauthenticated' }); return; }
    const submittedCsrf = safeStringField(req.body, 'csrf');
    const left = Buffer.from(session.csrf);
    const right = Buffer.from(submittedCsrf);
    const csrfValid = left.length === right.length && timingSafeEqual(left, right);
    if (!csrfValid) { res.status(403).json({ error: 'csrf_failed' }); return; }
    const decision = safeStringField(req.body, 'decision');
    consentChallenges.delete(consentId);
    if (decision !== 'allow') {
      const redirectTo = authorizationResponseUrl(challenge.redirectUri, {
        error: 'access_denied',
        state: challenge.state,
        issuer: config.issuer
      });
      res.json({ redirectTo });
      return;
    }
    // Check user has the requested scopes
    const unavailable = challenge.scope.filter(s => !session.user.scopes.includes(s) && !session.user.scopes.includes('memory:write'));
    if (unavailable.length) {
      res.status(403).json({ error: 'insufficient_scope', message: `Account not authorized for: ${unavailable.join(', ')}` });
      return;
    }
    const code = randomToken(32);
    const now = new Date();
    const record: AuthorizationCode = {
      hash: hashOpaque(code, config.tokenPepper),
      clientId: challenge.clientId,
      userId: session.user.id,
      redirectUri: challenge.redirectUri,
      scope: challenge.scope,
      resource: challenge.resource,
      codeChallenge: challenge.codeChallenge,
      createdAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + config.authorizationCodeTtlSeconds * 1000).toISOString(),
      consumedAt: null
    };
    await stores.authorizationCodes.update(rows => [...rows, record]);
    const redirectTo = authorizationResponseUrl(challenge.redirectUri, {
      code,
      state: challenge.state,
      issuer: config.issuer
    });
    res.json({ redirectTo });
  });

  return router;
}
