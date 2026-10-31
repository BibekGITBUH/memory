import path from 'node:path';
import { JsonStore } from './json-store.js';
import { arraySchemas } from './schemas.js';
import type { Memory, User, OAuthClient, AuthorizationCode, AccessTokenRecord, RefreshTokenRecord, ApiKeyRecord } from './schemas.js';
import { z } from 'zod/v4';

export interface Stores {
  memories: JsonStore<Memory[]>;
  users: JsonStore<User[]>;
  oauthClients: JsonStore<OAuthClient[]>;
  authorizationCodes: JsonStore<AuthorizationCode[]>;
  accessTokens: JsonStore<AccessTokenRecord[]>;
  refreshTokens: JsonStore<RefreshTokenRecord[]>;
  apiKeys: JsonStore<ApiKeyRecord[]>;
  assertions: JsonStore<{ hash: string; expiresAt: string }[]>;
}

export async function createStores(dataDir: string): Promise<Stores> {
  const stores: Stores = {
    memories: new JsonStore(path.join(dataDir, 'memories.json'), arraySchemas.memories, []),
    users: new JsonStore(path.join(dataDir, 'users.json'), arraySchemas.users, []),
    oauthClients: new JsonStore(path.join(dataDir, 'oauth-clients.json'), arraySchemas.oauthClients, []),
    authorizationCodes: new JsonStore(path.join(dataDir, 'authorization-codes.json'), arraySchemas.authorizationCodes, []),
    accessTokens: new JsonStore(path.join(dataDir, 'access-tokens.json'), arraySchemas.accessTokens, []),
    refreshTokens: new JsonStore(path.join(dataDir, 'refresh-tokens.json'), arraySchemas.refreshTokens, []),
    apiKeys: new JsonStore(path.join(dataDir, 'api-keys.json'), arraySchemas.apiKeys, []),
    assertions: new JsonStore(path.join(dataDir, 'oauth-assertions.json'), z.array(z.object({ hash: z.string(), expiresAt: z.string().datetime() })), [])
  };
  await Promise.all(Object.values(stores).map(store => store.initialize()));
  return stores;
}
