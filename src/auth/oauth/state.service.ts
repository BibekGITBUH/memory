const MIN_OAUTH_STATE_LENGTH = 16;
const MAX_OAUTH_STATE_LENGTH = 8192;

export function isValidOAuthState(value: string): boolean {
  return value.length >= MIN_OAUTH_STATE_LENGTH && value.length <= MAX_OAUTH_STATE_LENGTH;
}
