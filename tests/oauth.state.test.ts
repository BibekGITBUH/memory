import { describe, expect, it } from 'vitest';
import { isValidOAuthState } from '../src/auth/oauth/state.service.js';

describe('OAuth state validation', () => {
  it('accepts high-entropy states up to 8192 characters', () => {
    expect(isValidOAuthState('a'.repeat(16))).toBe(true);
    expect(isValidOAuthState('a'.repeat(8192))).toBe(true);
  });

  it('rejects missing, short, or oversized states', () => {
    expect(isValidOAuthState('')).toBe(false);
    expect(isValidOAuthState('a'.repeat(15))).toBe(false);
    expect(isValidOAuthState('a'.repeat(8193))).toBe(false);
  });
});
