import { describe, it, expect } from 'vitest';
import { authorizationServerMetadata, protectedResourceMetadata } from '../src/auth/oauth/metadata.js';
import type { AppConfig } from '../src/config/env.js';

const config = {
  enableOAuth: true,
  issuer: 'https://memory.example',
  publicBaseUrl: 'https://memory.example',
  resource: 'https://memory.example/mcp'
} as AppConfig;

describe('OAuth discovery metadata', () => {
  it('advertises authorization code, S256, DCR and CIMD', () => {
    const metadata = authorizationServerMetadata(config);
    expect(metadata['authorization_endpoint']).toBe('https://memory.example/authorize');
    expect(metadata['token_endpoint']).toBe('https://memory.example/token');
    expect(metadata['registration_endpoint']).toBe('https://memory.example/register');
    expect(metadata['code_challenge_methods_supported']).toEqual(['S256']);
    expect(metadata['client_id_metadata_document_supported']).toBe(true);
  });
  it('identifies the MCP resource and authorization server', () => {
    const metadata = protectedResourceMetadata(config);
    expect(metadata['resource']).toBe('https://memory.example/mcp');
    expect(metadata['authorization_servers']).toEqual(['https://memory.example']);
  });
});
