import { describe, it, expect } from 'vitest';
import { memorySchema } from '../src/storage/schemas.js';

describe('JSON structure validation', () => {
  it('rejects a memory without UUID and timestamp', () => {
    expect(memorySchema.safeParse({ id: 'bad', content: 'x' }).success).toBe(false);
  });
  it('accepts the required memory record shape', () => {
    expect(memorySchema.safeParse({ id: '00000000-0000-4000-8000-000000000001', content: 'x', createdAt: '2026-01-01T00:00:00.000Z' }).success).toBe(true);
  });
});
