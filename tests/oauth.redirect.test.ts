import { describe, expect, it } from 'vitest';
import { isLoopbackRedirectUri, isValidRedirectUri, matchesRedirectUri } from '../src/auth/oauth/redirect.service.js';

describe('OAuth redirect URI validation', () => {
  it('accepts a dynamically allocated port for the same HTTP loopback callback', () => {
    expect(matchesRedirectUri('http://localhost/callback', 'http://localhost:44489/callback')).toBe(true);
    expect(matchesRedirectUri('http://127.0.0.1/callback', 'http://127.0.0.1:44489/callback')).toBe(true);
  });

  it('requires the loopback host, callback path, and query to remain unchanged', () => {
    expect(matchesRedirectUri('http://localhost/callback', 'http://attacker.example:44489/callback')).toBe(false);
    expect(matchesRedirectUri('http://localhost/callback', 'http://localhost:44489/other')).toBe(false);
    expect(matchesRedirectUri('http://localhost/callback?client=one', 'http://localhost:44489/callback?client=two')).toBe(false);
  });

  it('keeps HTTPS redirect URIs exact', () => {
    expect(matchesRedirectUri('https://claude.ai/api/mcp/auth_callback', 'https://claude.ai/api/mcp/auth_callback')).toBe(true);
    expect(matchesRedirectUri('https://claude.ai/api/mcp/auth_callback', 'https://claude.ai:44489/api/mcp/auth_callback')).toBe(false);
  });

  it('rejects unsafe and non-loopback HTTP redirect URIs', () => {
    expect(isValidRedirectUri('http://example.com/callback')).toBe(false);
    expect(isValidRedirectUri('http://user@localhost/callback')).toBe(false);
    expect(isValidRedirectUri('http://localhost/callback#fragment')).toBe(false);
  });

  it('identifies only HTTP loopback callbacks for the native-client consent policy', () => {
    expect(isLoopbackRedirectUri('http://localhost:44489/callback')).toBe(true);
    expect(isLoopbackRedirectUri('http://127.0.0.1/callback')).toBe(true);
    expect(isLoopbackRedirectUri('https://claude.ai/api/mcp/auth_callback')).toBe(false);
    expect(isLoopbackRedirectUri('http://example.com/callback')).toBe(false);
    expect(isLoopbackRedirectUri(null)).toBe(false);
  });
});
