import type { AppConfig } from '../../config/env.js';

export function authorizationServerMetadata(config: AppConfig): Record<string, unknown> {
  return {
    issuer: config.issuer,
    authorization_endpoint: `${config.issuer}/authorize`,
    token_endpoint: `${config.issuer}/token`,
    registration_endpoint: `${config.issuer}/register`,
    revocation_endpoint: `${config.issuer}/revoke`,
    response_types_supported: ['code'],
    response_modes_supported: ['query'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none', 'client_secret_basic', 'client_secret_post', 'private_key_jwt'],
    token_endpoint_auth_signing_alg_values_supported: ['RS256', 'PS256', 'ES256', 'EdDSA'],
    scopes_supported: ['memory:read', 'memory:write'],
    client_id_metadata_document_supported: true,
    authorization_response_iss_parameter_supported: true
  };
}

export function protectedResourceMetadata(config: AppConfig): Record<string, unknown> {
  return {
    resource: config.resource,
    authorization_servers: config.enableOAuth ? [config.issuer] : [],
    bearer_methods_supported: ['header'],
    scopes_supported: ['memory:read', 'memory:write'],
    resource_documentation: config.issuer
  };
}
