import { randomUUID } from 'node:crypto';
import type { AppConfig } from '../config/env.js';
import type { JsonStore } from '../storage/json-store.js';
import type { User } from '../storage/schemas.js';
import { hashPassword, verifyPassword } from '../utils/crypto.js';

export class UsernameTakenError extends Error {
  constructor(username: string) {
    super(`Username "${username}" is already taken.`);
    this.name = 'UsernameTakenError';
  }
}

export async function ensureInitialAdmin(store: JsonStore<User[]>, config: AppConfig): Promise<void> {
  const existing = await store.read();
  if (existing.length > 0) return;
  if (!config.adminUsername || config.adminPassword.length < 14 || config.adminPassword.startsWith('CHANGE_ME')) {
    throw new Error('First run: set ADMIN_USERNAME and a unique ADMIN_PASSWORD of at least 14 characters in .env.');
  }
  const password = await hashPassword(config.adminPassword);
  const admin: User = {
    id: randomUUID(),
    username: config.adminUsername,
    passwordSalt: password.salt,
    passwordHash: password.hash,
    role: 'admin',
    scopes: ['memory:read', 'memory:write'],
    createdAt: new Date().toISOString(),
    disabledAt: null
  };
  await store.update(current => current.length === 0 ? [admin] : current);
  console.log(`Created initial admin account "${config.adminUsername}" (password stored as a scrypt hash in users.json).`);
}


export async function registerUser(
  store: JsonStore<User[]>,
  input: { username: string; password: string }
): Promise<User> {
  const normalizedUsername = input.username.trim();
  const password = await hashPassword(input.password);
  const newUser: User = {
    id: randomUUID(),
    username: normalizedUsername,
    passwordSalt: password.salt,
    passwordHash: password.hash,
    role: 'user',
    scopes: ['memory:read', 'memory:write'],
    createdAt: new Date().toISOString(),
    disabledAt: null
  };

  // Atomic file lock via store.update ensures concurrent requests cannot create duplicate usernames
  await store.update(current => {
    const exists = current.some(
      user => user.username.toLowerCase() === normalizedUsername.toLowerCase()
    );
    if (exists) {
      throw new UsernameTakenError(normalizedUsername);
    }
    return [...current, newUser];
  });

  return newUser;
}

export async function authenticatePassword(store: JsonStore<User[]>, username: string, password: string): Promise<User | undefined> {
  const users = await store.read();
  const user = users.find(item => item.username === username && item.disabledAt === null);
  if (!user) {
    // Perform a dummy scrypt operation so unknown usernames do not return immediately.
    await verifyPassword(password, '00000000000000000000000000000000', '0'.repeat(128)).catch(() => false);
    return undefined;
  }
  return await verifyPassword(password, user.passwordSalt, user.passwordHash) ? user : undefined;
}
