import { z } from 'zod/v4';

export const scopeSchema = z.enum(['memory:read', 'memory:write']);
export const scopesSchema = z.array(scopeSchema).default(['memory:read']);

export const memorySchema = z.object({
  id: z.string().uuid(),
  content: z.string().min(1).max(20000),
  createdAt: z.string().datetime()
});
export type Memory = z.infer<typeof memorySchema>;

export const userSchema = z.object({
  id: z.string().uuid(),
  username: z.string().min(1),
  passwordSalt: z.string().min(16),
  passwordHash: z.string().min(64),
  role: z.enum(['admin', 'user']),
  scopes: scopesSchema,
  createdAt: z.string().datetime(),
  disabledAt: z.string().datetime().nullable().default(null)
});
export type User = z.infer<typeof userSchema>;

export const oauthClientSchema = z.object({
  clientId: z.string().min(1),
  clientName: z.string().min(1),
  redirectUris: z.array(z.string().url()).min(1),
  tokenEndpointAuthMethod: z.enum(['none', 'client_secret_basic', 'client_secret_post', 'private_key_jwt']),
  clientSecretHash: z.string().optional(),
  grantTypes: z.array(z.string()),
  responseTypes: z.array(z.string()),
  metadataDocument: z.boolean().default(false),
  metadata: z.record(z.string(), z.unknown()).optional(),
  createdAt: z.string().datetime(),
  disabledAt: z.string().datetime().nullable().default(null)
});
export type OAuthClient = z.infer<typeof oauthClientSchema>;

export const authorizationCodeSchema = z.object({
  hash: z.string().min(64),
  clientId: z.string(),
  userId: z.string().uuid(),
  redirectUri: z.string().url(),
  scope: z.array(scopeSchema),
  resource: z.string().url(),
  codeChallenge: z.string(),
  createdAt: z.string().datetime(),
  expiresAt: z.string().datetime(),
  consumedAt: z.string().datetime().nullable().default(null)
});
export type AuthorizationCode = z.infer<typeof authorizationCodeSchema>;

export const accessTokenSchema = z.object({
  hash: z.string().min(64),
  familyId: z.string().uuid(),
  clientId: z.string(),
  userId: z.string().uuid(),
  scope: z.array(scopeSchema),
  resource: z.string().url(),
  createdAt: z.string().datetime(),
  expiresAt: z.string().datetime(),
  revokedAt: z.string().datetime().nullable().default(null),
  lastUsedAt: z.string().datetime().nullable().default(null)
});
export type AccessTokenRecord = z.infer<typeof accessTokenSchema>;

export const refreshTokenSchema = z.object({
  hash: z.string().min(64),
  familyId: z.string().uuid(),
  clientId: z.string(),
  userId: z.string().uuid(),
  scope: z.array(scopeSchema),
  resource: z.string().url(),
  createdAt: z.string().datetime(),
  expiresAt: z.string().datetime(),
  usedAt: z.string().datetime().nullable().default(null),
  revokedAt: z.string().datetime().nullable().default(null)
});
export type RefreshTokenRecord = z.infer<typeof refreshTokenSchema>;

export const apiKeySchema = z.object({
  id: z.string().uuid(),
  name: z.string().min(1),
  hash: z.string().min(64),
  scopes: z.array(scopeSchema),
  createdAt: z.string().datetime(),
  expiresAt: z.string().datetime().nullable().default(null),
  revokedAt: z.string().datetime().nullable().default(null),
  lastUsedAt: z.string().datetime().nullable().default(null)
});
export type ApiKeyRecord = z.infer<typeof apiKeySchema>;

export const assertionSchema = z.object({
  hash: z.string().min(64),
  expiresAt: z.string().datetime()
});

export const arraySchemas = {
  memories: z.array(memorySchema),
  users: z.array(userSchema),
  oauthClients: z.array(oauthClientSchema),
  authorizationCodes: z.array(authorizationCodeSchema),
  accessTokens: z.array(accessTokenSchema),
  refreshTokens: z.array(refreshTokenSchema),
  apiKeys: z.array(apiKeySchema),
  assertions: z.array(assertionSchema)
};
