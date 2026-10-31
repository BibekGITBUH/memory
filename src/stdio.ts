import { StdioServerTransport } from '@modelcontextprotocol/server/stdio';
import { loadConfig } from './config/env.js';
import { createStores } from './storage/stores.js';
import { MemoryRepository } from './storage/memory.repository.js';
import { createMcpServer } from './mcp/server.js';

async function main(): Promise<void> {
  const config = loadConfig();
  const stores = await createStores(config.dataDir);
  const repository = new MemoryRepository(stores.memories);
  const server = createMcpServer(repository, {
    userId: 'local-stdio',
    scopes: ['memory:read', 'memory:write'],
    method: 'none'
  });
  await server.connect(new StdioServerTransport());
}

main().catch(error => {
  console.error(error instanceof Error ? error.message : 'stdio server failed');
  process.exitCode = 1;
});
