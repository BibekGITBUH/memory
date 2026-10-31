import { describe, expect, it } from 'vitest';
import { authorizationResponseUrl } from '../src/auth/oauth/authorization-response.js';

describe('OAuth authorization responses', () => {
  it('includes state and issuer in consent denial responses and preserves callback query', () => {
    const url = new URL(authorizationResponseUrl('https://client.example/callback?existing=1', {
      error: 'access_denied',
      state: 'request-state',
      issuer: 'https://memory.example'
    }));

    expect(url.searchParams.get('existing')).toBe('1');
    expect(url.searchParams.get('error')).toBe('access_denied');
    expect(url.searchParams.get('state')).toBe('request-state');
    expect(url.searchParams.get('iss')).toBe('https://memory.example');
  });

  it('includes code, state, and issuer in successful authorization responses', () => {
    const url = new URL(authorizationResponseUrl('http://localhost:44489/callback', {
      code: 'authorization-code',
      state: 'request-state',
      issuer: 'https://memory.example'
    }));

    expect(url.searchParams.get('code')).toBe('authorization-code');
    expect(url.searchParams.get('state')).toBe('request-state');
    expect(url.searchParams.get('iss')).toBe('https://memory.example');
  });
});
