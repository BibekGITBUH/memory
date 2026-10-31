import { describe, it, expect } from 'vitest';
import { hasScope, assertScope } from '../src/auth/scopes.js';
import type { AuthContext } from '../src/auth/auth.types.js';

const readOnly: AuthContext = { userId: 'read-only', scopes: ['memory:read'], method: 'api-key' };
const writer: AuthContext = { userId: 'writer', scopes: ['memory:write'], method: 'oauth' };

describe('memory scope authorization', () => {
  it('allows list for memory:read', () => {
    expect(hasScope(readOnly, 'memory:read')).toBe(true);
    expect(() => assertScope(readOnly, 'memory:read')).not.toThrow();
  });
  it('blocks create/delete permissions for read-only credentials', () => {
    expect(hasScope(readOnly, 'memory:write')).toBe(false);
    expect(() => assertScope(readOnly, 'memory:write')).toThrow('memory:write');
  });
  it('treats memory:write as read plus write', () => {
    expect(hasScope(writer, 'memory:read')).toBe(true);
    expect(hasScope(writer, 'memory:write')).toBe(true);
  });
});
