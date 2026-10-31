export function authorizationResponseUrl(
  redirectUri: string,
  parameters: { code?: string; error?: string; state: string; issuer: string }
): string {
  const redirect = new URL(redirectUri);
  if (parameters.code) redirect.searchParams.set('code', parameters.code);
  if (parameters.error) redirect.searchParams.set('error', parameters.error);
  redirect.searchParams.set('state', parameters.state);
  redirect.searchParams.set('iss', parameters.issuer);
  return redirect.toString();
}
