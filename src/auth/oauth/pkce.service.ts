import { sha256Base64Url } from '../../utils/crypto.js';

export function validatePkce(challenge: string, method: string): boolean {
  return method === 'S256' && /^[A-Za-z0-9_-]{43}$/.test(challenge);
}

export function verifyPkce(verifier: string, challenge: string): boolean {
  return /^[A-Za-z0-9._~-]{43,128}$/.test(verifier) && sha256Base64Url(verifier) === challenge;
}
