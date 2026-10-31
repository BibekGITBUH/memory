import 'dotenv/config';
import { z } from 'zod/v4';
import path from 'node:path';

const envSchema = z.object({
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  HOST: z.string().default('127.0.0.1'),
  PUBLIC_BASE_URL: z.string().default('http://127.0.0.1:3000'),
  DATA_DIR: z.string().default('./data'),
  ADMIN_USERNAME: z.string().default(''),
  ADMIN_PASSWORD: z.string().default(''),
  TOKEN_PEPPER: z.string().default(''),
  SESSION_SECRET: z.string().default(''),
  AUTH_MODE: z.enum(['oauth', 'bearer', 'api-key', 'basic', 'none', 'multi-auth']).default('multi-auth'),
  ENABLE_OAUTH: z.string().default('true'),
  ENABLE_BEARER: z.string().default('true'),
  ENABLE_API_KEY: z.string().default('true'),
  ENABLE_BASIC: z.string().default('true'),
  ENABLE_NO_AUTH: z.string().default('false'),
  TEST_BEARER_TOKEN: z.string().default(''),
  TEST_BEARER_SCOPES: z.string().default('memory:read,memory:write'),
  TEST_API_KEY: z.string().default(''),
  TEST_API_KEY_SCOPES: z.string().default('memory:read,memory:write'),
  OAUTH_ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().int().min(60).max(86400).default(3600),
  OAUTH_REFRESH_TOKEN_TTL_SECONDS: z.coerce.number().int().min(300).max(31536000).default(2592000),
  OAUTH_AUTHORIZATION_CODE_TTL_SECONDS: z.coerce.number().int().min(30).max(600).default(300),
  TRUST_PROXY: z.string().default('false'),
  CIMD_ALLOWED_HOSTS: z.string().default('')
});

function bool(value: string): boolean {
  return value.trim().toLowerCase() === 'true';
}

export type AuthMode = z.infer<typeof envSchema>['AUTH_MODE'];
export interface AppConfig {
  port: number;
  host: string;
  publicBaseUrl: string;
  issuer: string;
  resource: string;
  dataDir: string;
  adminUsername: string;
  adminPassword: string;
  tokenPepper: string;
  sessionSecret: string;
  authMode: AuthMode;
  enableOAuth: boolean;
  enableBearer: boolean;
  enableApiKey: boolean;
  enableBasic: boolean;
  enableNoAuth: boolean;
  testBearerToken: string;
  testBearerScopes: string[];
  testApiKey: string;
  testApiKeyScopes: string[];
  accessTokenTtlSeconds: number;
  refreshTokenTtlSeconds: number;
  authorizationCodeTtlSeconds: number;
  trustProxy: boolean;
  cimdAllowedHosts: string[];
}

export function loadConfig(): AppConfig {
  const parsed = envSchema.parse(process.env);
  const base = new URL(parsed.PUBLIC_BASE_URL);
  if (base.username || base.password) throw new Error('PUBLIC_BASE_URL must not contain username or password credentials.');
  if (base.protocol !== 'https:' && !(base.hostname === '127.0.0.1' || base.hostname === 'localhost' || base.hostname === '[::1]')) {
    throw new Error('PUBLIC_BASE_URL must use HTTPS except for loopback development URLs.');
  }
  if (base.pathname !== '/' || base.search || base.hash) throw new Error('PUBLIC_BASE_URL must be an origin only (for example https://memory.example), without a path, query, or fragment.');
  const publicBaseUrl = base.origin;
  const splitScopes = (value: string): string[] => [...new Set(value.split(/[,;]/).map(s => s.trim()).filter(Boolean))];
  return {
    port: parsed.PORT,
    host: parsed.HOST,
    publicBaseUrl,
    issuer: publicBaseUrl,
    resource: `${publicBaseUrl}/mcp`,
    dataDir: path.resolve(parsed.DATA_DIR),
    adminUsername: parsed.ADMIN_USERNAME,
    adminPassword: parsed.ADMIN_PASSWORD,
    tokenPepper: parsed.TOKEN_PEPPER,
    sessionSecret: parsed.SESSION_SECRET,
    authMode: parsed.AUTH_MODE,
    enableOAuth: bool(parsed.ENABLE_OAUTH) && (parsed.AUTH_MODE === 'oauth' || parsed.AUTH_MODE === 'multi-auth'),
    enableBearer: bool(parsed.ENABLE_BEARER),
    enableApiKey: bool(parsed.ENABLE_API_KEY),
    enableBasic: bool(parsed.ENABLE_BASIC),
    enableNoAuth: bool(parsed.ENABLE_NO_AUTH),
    testBearerToken: parsed.TEST_BEARER_TOKEN,
    testBearerScopes: splitScopes(parsed.TEST_BEARER_SCOPES),
    testApiKey: parsed.TEST_API_KEY,
    testApiKeyScopes: splitScopes(parsed.TEST_API_KEY_SCOPES),
    accessTokenTtlSeconds: parsed.OAUTH_ACCESS_TOKEN_TTL_SECONDS,
    refreshTokenTtlSeconds: parsed.OAUTH_REFRESH_TOKEN_TTL_SECONDS,
    authorizationCodeTtlSeconds: parsed.OAUTH_AUTHORIZATION_CODE_TTL_SECONDS,
    trustProxy: bool(parsed.TRUST_PROXY),
    cimdAllowedHosts: splitScopes(parsed.CIMD_ALLOWED_HOSTS).map(s => s.toLowerCase())
  };
}

export function assertRuntimeConfig(config: AppConfig): void {
  if (config.tokenPepper.length < 32 || config.sessionSecret.length < 32 || config.tokenPepper.startsWith('CHANGE_ME') || config.sessionSecret.startsWith('CHANGE_ME')) {
    throw new Error('TOKEN_PEPPER and SESSION_SECRET must each contain at least 32 characters. Generate random values; do not reuse passwords.');
  }
  if (config.enableNoAuth && !['127.0.0.1', 'localhost', '[::1]'].includes(new URL(config.publicBaseUrl).hostname)) {
    throw new Error('ENABLE_NO_AUTH is permitted only with a loopback PUBLIC_BASE_URL. It is never automatically enabled by Cloudflare Tunnel.');
  }
  if (config.enableNoAuth && process.env['NODE_ENV'] === 'production') {
    throw new Error('ENABLE_NO_AUTH is blocked in production, including multi-auth mode.');
  }
  const allowedScopes = new Set(['memory:read', 'memory:write']);
  if ([...config.testBearerScopes, ...config.testApiKeyScopes].some(scope => !allowedScopes.has(scope))) {
    throw new Error('TEST_BEARER_SCOPES and TEST_API_KEY_SCOPES may contain only memory:read and memory:write.');
  }
}
