import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { z } from 'zod/v4';
import { mkdtemp, rm, readdir, readFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { JsonStore } from '../src/storage/json-store.js';
import { memorySchema, type Memory } from '../src/storage/schemas.js';
import { MemoryRepository } from '../src/storage/memory.repository.js';

let directory: string;
let repository: MemoryRepository;
beforeEach(async () => {
  directory = await mkdtemp(path.join(os.tmpdir(), 'mcp-memory-test-'));
  const store = new JsonStore<Memory[]>(path.join(directory, 'memories.json'), z.array(memorySchema), []);
  await store.initialize();
  repository = new MemoryRepository(store);
});

describe('MemoryRepository', () => {
  it('creates and lists a memory with UUID and timestamp', async () => {
    const saved = await repository.create('Remember this');
    expect(saved.id).toMatch(/^[0-9a-f-]{36}$/i);
    expect(new Date(saved.createdAt).toISOString()).toBe(saved.createdAt);
    await expect(repository.list()).resolves.toEqual([saved]);
  });

  it('deletes an existing memory and returns false for unknown IDs', async () => {
    const saved = await repository.create('delete me');
    await expect(repository.delete(saved.id)).resolves.toBe(true);
    await expect(repository.delete(saved.id)).resolves.toBe(false);
    await expect(repository.delete('not-a-uuid')).resolves.toBe(false);
    await expect(repository.list()).resolves.toEqual([]);
  });

  it('scrubs deleted memories from older local backup snapshots', async () => {
    const first = await repository.create('must be removed from backups');
    await repository.create('second memory creates a pre-write snapshot');
    const backupDir = path.join(directory, 'backups');
    const before = (await readdir(backupDir)).filter(name => name.startsWith('memories-') && name.endsWith('.json'));
    expect(before.length).toBeGreaterThan(0);
    await repository.delete(first.id);
    const after = (await readdir(backupDir)).filter(name => name.startsWith('memories-') && name.endsWith('.json'));
    for (const file of after) {
      const rows = JSON.parse(await readFile(path.join(backupDir, file), 'utf8')) as Memory[];
      expect(rows.some(row => row.id === first.id)).toBe(false);
    }
  });

  it('rejects empty content', async () => {
    await expect(repository.create('   ')).rejects.toThrow('must not be empty');
  });

  it('serializes concurrent writes without losing records', async () => {
    await Promise.all(Array.from({ length: 40 }, (_, index) => repository.create(`memory ${index}`)));
    const rows = await repository.list();
    expect(rows).toHaveLength(40);
    expect(new Set(rows.map(row => row.id)).size).toBe(40);
  });

  it('coordinates updates from two independent store instances', async () => {
    const secondStore = new JsonStore<Memory[]>(path.join(directory, 'memories.json'), z.array(memorySchema), []);
    await secondStore.initialize();
    const secondRepository = new MemoryRepository(secondStore);
    await Promise.all(Array.from({ length: 30 }, (_, index) =>
      index % 2 === 0 ? repository.create(`store-a ${index}`) : secondRepository.create(`store-b ${index}`)
    ));
    const rows = await repository.list();
    expect(rows).toHaveLength(30);
    expect(new Set(rows.map(row => row.id)).size).toBe(30);
  });
});

afterEach(async () => { await rm(directory, { recursive: true, force: true }); });
