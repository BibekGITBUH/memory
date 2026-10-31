import { loadConfig, assertRuntimeConfig } from './config/env.js';
import { createStores } from './storage/stores.js';
import { ensureInitialAdmin } from './auth/users.service.js';
import { hashOpaque } from './utils/crypto.js';
import { randomUUID } from 'node:crypto';
import { createApp } from './app.js';

async function main(): Promise<void> {
  const config = loadConfig();
  assertRuntimeConfig(config);
  const stores = await createStores(config.dataDir);
  await ensureInitialAdmin(stores.users, config);

  if (config.testApiKey) {
    const hash = hashOpaque(config.testApiKey, config.tokenPepper);
    await stores.apiKeys.update(rows => {
      const existing = rows.find(row => row.id === '00000000-0000-4000-8000-000000000001');
      const record = {
        id: '00000000-0000-4000-8000-000000000001',
        name: 'Environment test API key',
        hash,
        scopes: config.testApiKeyScopes as ('memory:read' | 'memory:write')[],
        createdAt: existing?.createdAt ?? new Date().toISOString(),
        expiresAt: null,
        revokedAt: null,
        lastUsedAt: existing?.lastUsedAt ?? null
      };
      return [...rows.filter(row => row.id !== record.id), record];
    });
  }

  const app = createApp(config, stores);
  const httpServer = app.listen(config.port, config.host, () => {
    console.log(`MCP Memory Server listening on http://${config.host}:${config.port}`);
    console.log(`Public MCP resource: ${config.resource}`);
    console.log(`Authentication mode: ${config.authMode}`);
    if (config.enableNoAuth) console.warn('WARNING: local-development no-auth mode is enabled. Ensure only loopback requests can reach this server.');
  });
  const shutdown = (): void => {
    httpServer.close(() => process.exit(0));
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

main().catch(error => {
  console.error(error instanceof Error ? error.message : 'Startup failed.');
  process.exitCode = 1;
});
