import { describe, it, expect } from 'vitest';
import { randomBytes } from 'node:crypto';
import { sha256Base64Url } from '../src/utils/crypto.js';
import { validatePkce, verifyPkce } from '../src/auth/oauth/pkce.service.js';

describe('OAuth PKCE S256', () => {
  it('accepts only S256 and a valid challenge', () => {
    const verifier = randomBytes(32).toString('base64url');
    expect(validatePkce(sha256Base64Url(verifier), 'S256')).toBe(true);
    expect(validatePkce(sha256Base64Url(verifier), 'plain')).toBe(false);
  });
  it('verifies a code verifier against the challenge', () => {
    const verifier = randomBytes(32).toString('base64url');
    expect(verifyPkce(verifier, sha256Base64Url(verifier))).toBe(true);
    expect(verifyPkce(`${verifier}x`, sha256Base64Url(verifier))).toBe(false);
  });
});
