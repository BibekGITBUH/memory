import { Router } from 'express';
import { randomUUID } from 'node:crypto';
import { z } from 'zod/v4';
import type { AppConfig } from '../config/env.js';
import type { Stores } from '../storage/stores.js';
import { getBrowserSession } from '../auth/session.js';
import { hashOpaque, randomToken, safeStringEqual } from '../utils/crypto.js';

const createSchema = z.object({
  name: z.string().trim().min(1).max(80),
  scopes: z.array(z.enum(['memory:read', 'memory:write'])).min(1).max(2),
  expiresInDays: z.number().int().min(1).max(3650).nullable().optional()
});

export function createAdminRouter(config: AppConfig, stores: Stores) {
  const router = Router();
  router.use(async (req, res, next) => {
    const session = await getBrowserSession(req, stores, config);
    if (!session || session.user.role !== 'admin') { res.status(401).json({ error: 'admin_session_required' }); return; }
    res.locals['adminUserId'] = session.user.id;
    res.locals['adminCsrf'] = session.csrf;
    next();
  });

  router.get('/session', (_req, res) => { res.json({ authenticated: true, csrf: res.locals['adminCsrf'] }); });

  router.get('/api-keys', async (_req, res) => {
    const rows = await stores.apiKeys.read();
    res.json(rows.map(({ hash: _hash, ...item }) => item));
  });

  router.post('/api-keys', async (req, res) => {
    const csrf = req.header('x-csrf-token') ?? (typeof req.body['csrf'] === 'string' ? req.body['csrf'] : '');
    if (!safeStringEqual(csrf, String(res.locals['adminCsrf'] ?? ''))) { res.status(403).json({ error: 'csrf_failed' }); return; }
    const parsed = createSchema.safeParse(req.body);
    if (!parsed.success) { res.status(400).json({ error: 'invalid_request', details: parsed.error.flatten() }); return; }
    const key = `mcp_${randomToken(32)}`;
    const now = new Date();
    const expiresAt = parsed.data.expiresInDays ? new Date(now.getTime() + parsed.data.expiresInDays * 86400_000).toISOString() : null;
    const record = {
      id: randomUUID(),
      name: parsed.data.name,
      hash: hashOpaque(key, config.tokenPepper),
      scopes: [...new Set(parsed.data.scopes)],
      createdAt: now.toISOString(),
      expiresAt,
      revokedAt: null,
      lastUsedAt: null
    };
    await stores.apiKeys.update(rows => [...rows, record]);
    res.status(201).json({ id: record.id, name: record.name, key, scopes: record.scopes, createdAt: record.createdAt, expiresAt, note: 'Copy this key now. It cannot be retrieved again.' });
  });

  router.delete('/api-keys/:id', async (req, res) => {
    const csrf = req.header('x-csrf-token') ?? (typeof req.body?.['csrf'] === 'string' ? req.body['csrf'] : '');
    if (!safeStringEqual(csrf, String(res.locals['adminCsrf'] ?? ''))) { res.status(403).json({ error: 'csrf_failed' }); return; }
    let revoked = false;
    const now = new Date().toISOString();
    await stores.apiKeys.update(rows => rows.map(row => {
      if (row.id !== req.params['id'] || row.revokedAt !== null) return row;
      revoked = true;
      return { ...row, revokedAt: now };
    }));
    res.status(revoked ? 200 : 404).json({ revoked });
  });

  router.get('/stats', async (_req, res) => {
    const [memories, keys] = await Promise.all([stores.memories.read(), stores.apiKeys.read()]);
    res.json({
      totalMemories: memories.length,
      activeApiKeys: keys.filter(k => k.revokedAt === null && (!k.expiresAt || new Date(k.expiresAt) > new Date())).length,
      totalApiKeys: keys.length
    });
  });

  router.get('/memories', async (req, res) => {
    const memories = await stores.memories.read();
    const page = Math.max(1, parseInt(String(req.query['page'] ?? '1'), 10));
    const limit = Math.min(100, Math.max(1, parseInt(String(req.query['limit'] ?? '20'), 10)));
    const search = typeof req.query['search'] === 'string' ? req.query['search'].toLowerCase() : '';
    const filtered = search ? memories.filter(m => m.content.toLowerCase().includes(search)) : memories;
    const start = (page - 1) * limit;
    res.json({ total: filtered.length, page, limit, memories: filtered.slice(start, start + limit) });
  });

  router.delete('/memories/:id', async (req, res) => {
    const id = req.params['id'] ?? '';
    let deleted = false;
    await stores.memories.update(rows => rows.filter(m => { if (m.id === id) { deleted = true; return false; } return true; }));
    res.status(deleted ? 200 : 404).json({ deleted });
  });

  return router;
}
