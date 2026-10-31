import { randomUUID } from 'node:crypto';
import type { JsonStore } from './json-store.js';
import type { Memory } from './schemas.js';

export class MemoryRepository {
  constructor(private readonly store: JsonStore<Memory[]>) {}

  async create(content: string): Promise<Memory> {
    const clean = content.trim();
    if (!clean) throw new Error('content must not be empty');
    if (clean.length > 20000) throw new Error('content must be 20,000 characters or fewer');
    const memory: Memory = { id: randomUUID(), content: clean, createdAt: new Date().toISOString() };
    await this.store.update(current => [...current, memory]);
    return memory;
  }

  async delete(id: string): Promise<boolean> {
    let deleted = false;
    await this.store.update(current => {
      const next = current.filter(memory => memory.id !== id);
      deleted = next.length !== current.length;
      return next;
    }, {
      // Do not create a pre-delete snapshot that could restore the removed memory.
      backup: false,
      // Scrub the deleted UUID from every valid local memory snapshot while the store lock is held.
      transformBackups: rows => deleted ? rows.filter(memory => memory.id !== id) : rows
    });
    return deleted;
  }

  async list(): Promise<Memory[]> {
    return this.store.read();
  }
}
