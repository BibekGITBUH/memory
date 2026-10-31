const loopbackHosts = new Set(['127.0.0.1', 'localhost', '[::1]']);

export function isLoopbackRedirectUri(value: string | null): boolean {
  if (!value) return false;
  try {
    const url = new URL(value);
    return url.protocol === 'http:' && loopbackHosts.has(url.hostname);
  } catch {
    return false;
  }
}

export function isValidRedirectUri(value: string): boolean {
  try {
    const url = new URL(value);
    if (url.hash || url.username || url.password) return false;
    if (url.protocol === 'https:') return true;
    return url.protocol === 'http:' && loopbackHosts.has(url.hostname);
  } catch {
    return false;
  }
}

export function matchesRedirectUri(registeredUri: string, requestedUri: string): boolean {
  if (!isValidRedirectUri(registeredUri) || !isValidRedirectUri(requestedUri)) return false;
  if (registeredUri === requestedUri) return true;

  const registered = new URL(registeredUri);
  const requested = new URL(requestedUri);
  return registered.protocol === 'http:'
    && requested.protocol === 'http:'
    && loopbackHosts.has(registered.hostname)
    && registered.hostname === requested.hostname
    && registered.pathname === requested.pathname
    && registered.search === requested.search;
}
