import type { AuthContext } from './auth.types.js';

export function hasScope(context: AuthContext, required: 'memory:read' | 'memory:write'): boolean {
  if (context.scopes.includes('memory:write')) return true;
  return context.scopes.includes(required);
}

export function assertScope(context: AuthContext, required: 'memory:read' | 'memory:write'): void {
  if (!hasScope(context, required)) {
    throw new Error(`Insufficient scope: this operation requires ${required}.`);
  }
}
