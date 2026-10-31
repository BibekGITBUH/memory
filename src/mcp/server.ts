import { McpServer } from '@modelcontextprotocol/server';
import { z } from 'zod/v4';
import type { MemoryRepository } from '../storage/memory.repository.js';
import type { AuthContext } from '../auth/auth.types.js';
import { requireToolScope } from '../auth/auth.middleware.js';

export const MCP_TOOL_NAMES = ['create', 'delete', 'list'] as const;

export function createMcpServer(repository: MemoryRepository, authContext: AuthContext): McpServer {
  const server = new McpServer({ name: 'universal-mcp-memory-server', version: '1.0.0' });

  server.registerTool(
    'create',
    {
      description: 'Create and persist one memory. Requires memory:write.',
      inputSchema: z.object({ content: z.string().min(1).max(20000) })
    },
    async ({ content }) => {
      try {
        requireToolScope(authContext, 'memory:write');
        const memory = await repository.create(content);
        return { content: [{ type: 'text', text: JSON.stringify(memory, null, 2) }] };
      } catch (error) {
        return { isError: true, content: [{ type: 'text', text: error instanceof Error ? error.message : 'Memory creation failed.' }] };
      }
    }
  );

  server.registerTool(
    'delete',
    {
      description: 'Permanently delete one memory by its UUID. Requires memory:write.',
      inputSchema: z.object({ id: z.string().uuid() })
    },
    async ({ id }) => {
      try {
        requireToolScope(authContext, 'memory:write');
        const deleted = await repository.delete(id);
        return { content: [{ type: 'text', text: deleted ? `Memory ${id} was deleted.` : `Memory ${id} was not found.` }], ...(deleted ? {} : { isError: true }) };
      } catch (error) {
        return { isError: true, content: [{ type: 'text', text: error instanceof Error ? error.message : 'Memory deletion failed.' }] };
      }
    }
  );

  server.registerTool(
    'list',
    {
      description: 'List all memories with their UUID, content, and createdAt timestamp. Requires memory:read.',
      inputSchema: z.object({})
    },
    async () => {
      try {
        requireToolScope(authContext, 'memory:read');
        const memories = await repository.list();
        return { content: [{ type: 'text', text: JSON.stringify(memories, null, 2) }] };
      } catch (error) {
        return { isError: true, content: [{ type: 'text', text: error instanceof Error ? error.message : 'Memory listing failed.' }] };
      }
    }
  );

  return server;
}
