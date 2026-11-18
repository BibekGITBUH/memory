import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { JsonStore } from '../src/storage/json-store.js';
import { arraySchemas, type User } from '../src/storage/schemas.js';
import { registerUser, authenticatePassword, UsernameTakenError } from '../src/auth/users.service.js';

describe('User Registration Service', () => {
    let tempDir: string;
    let userStore: JsonStore<User[]>;

    beforeEach(async () => {
        tempDir = await mkdtemp(path.join(tmpdir(), 'mcp-reg-test-'));
        userStore = new JsonStore(path.join(tempDir, 'users.json'), arraySchemas.users, []);
        await userStore.initialize();
    });

    afterEach(async () => {
        await rm(tempDir, { recursive: true, force: true });
    });

    it('registers a new user with role "user" and default scopes', async () => {
        const user = await registerUser(userStore, { username: 'alice', password: 'ValidPassword123!' });
        expect(user.id).toBeDefined();
        expect(user.username).toBe('alice');
        expect(user.role).toBe('user');
        expect(user.scopes).toEqual(['memory:read', 'memory:write']);

        const authenticated = await authenticatePassword(userStore, 'alice', 'ValidPassword123!');
        expect(authenticated?.id).toBe(user.id);
    });

    it('rejects case-insensitive duplicate usernames', async () => {
        await registerUser(userStore, { username: 'bob', password: 'ValidPassword123!' });
        await expect(registerUser(userStore, { username: 'Bob', password: 'DifferentPassword123!' }))
            .rejects.toThrow(UsernameTakenError);
    });
});