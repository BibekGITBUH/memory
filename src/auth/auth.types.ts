import type { Request } from 'express';
import type { User } from '../storage/schemas.js';

export type AuthMethod = 'oauth' | 'bearer' | 'api-key' | 'basic' | 'none';
export interface AuthContext {
  userId: string;
  username?: string;
  scopes: string[];
  method: AuthMethod;
  clientId?: string;
}
export interface AuthenticatedRequest extends Request {
  authContext?: AuthContext;
}
export interface BrowserSession {
  user: User;
  csrf: string;
  expiresAt: number;
}
