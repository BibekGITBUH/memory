import { mkdir, readFile, copyFile, readdir, unlink } from 'node:fs/promises';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import lockfile from 'proper-lockfile';
import writeFileAtomic from 'write-file-atomic';
import type { z } from 'zod/v4';

export class JsonStore<T> {
  readonly filePath: string;
  private readonly schema: z.ZodType<T>;
  private readonly initialValue: T;
  private readonly backupDir: string;
  private readonly keepBackups: number;
  private queue: Promise<unknown> = Promise.resolve();

  constructor(filePath: string, schema: z.ZodType<T>, initialValue: T, keepBackups = 25) {
    this.filePath = filePath;
    this.schema = schema;
    this.initialValue = initialValue;
    this.backupDir = path.join(path.dirname(filePath), 'backups');
    this.keepBackups = keepBackups;
  }

  async initialize(): Promise<void> {
    await mkdir(path.dirname(this.filePath), { recursive: true });
    await mkdir(this.backupDir, { recursive: true });
    // The lock also protects first-run creation when two Node processes start together.
    const release = await lockfile.lock(this.filePath, {
      realpath: false,
      retries: { retries: 12, factor: 1.5, minTimeout: 20, maxTimeout: 500 },
      stale: 15000,
      update: 5000
    });
    try {
      try {
        await readFile(this.filePath, 'utf8');
        await this.read();
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
        await writeFileAtomic(this.filePath, JSON.stringify(this.initialValue, null, 2) + '\n', { encoding: 'utf8', fsync: true });
      }
    } finally {
      await release();
    }
  }

  async read(): Promise<T> {
    const raw = await readFile(this.filePath, 'utf8');
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw) as unknown;
    } catch {
      throw new Error(`Invalid JSON in ${this.filePath}. Original file was left untouched; restore from data/backups.`);
    }
    const result = this.schema.safeParse(parsed);
    if (!result.success) {
      throw new Error(`JSON schema validation failed for ${this.filePath}: ${result.error.message}`);
    }
    return result.data;
  }

  async update(
    mutator: (current: T) => T | Promise<T>,
    options: { backup?: boolean; transformBackups?: (value: T) => T } = {}
  ): Promise<T> {
    const run = async (): Promise<T> => {
      await this.initializeIfMissing();
      const release = await lockfile.lock(this.filePath, {
        realpath: false,
        retries: { retries: 12, factor: 1.5, minTimeout: 20, maxTimeout: 500 },
        stale: 15000,
        update: 5000
      });
      try {
        const current = await this.read();
        const next = this.schema.parse(await mutator(current));
        if (options.backup !== false) await this.makeBackup();
        // Complete backup transforms before replacing the live file. A failed scrub must not
        // report a successful permanent deletion while an older local snapshot still contains it.
        if (options.transformBackups) await this.transformBackups(options.transformBackups);
        await writeFileAtomic(this.filePath, JSON.stringify(next, null, 2) + '\n', {
          encoding: 'utf8',
          fsync: true
        });
        return next;
      } finally {
        await release();
      }
    };
    const operation = this.queue.then(run, run);
    this.queue = operation.catch(() => undefined);
    return operation;
  }

  private async initializeIfMissing(): Promise<void> {
    try {
      await readFile(this.filePath, 'utf8');
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      await this.initialize();
    }
  }

  private async transformBackups(transform: (value: T) => T): Promise<void> {
    const prefix = `${path.basename(this.filePath, '.json')}-`;
    const files = (await readdir(this.backupDir))
      .filter(name => name.startsWith(prefix) && name.endsWith('.json'));
    for (const name of files) {
      const target = path.join(this.backupDir, name);
      const raw = await readFile(target, 'utf8');
      let validated: T;
      try {
        const parsed: unknown = JSON.parse(raw);
        validated = this.schema.parse(parsed);
      } catch {
        // Preserve malformed snapshots for manual inspection rather than rewriting unknown data.
        continue;
      }
      const next = this.schema.parse(transform(validated));
      if (JSON.stringify(next) !== JSON.stringify(validated)) {
        await writeFileAtomic(target, JSON.stringify(next, null, 2) + '\n', { encoding: 'utf8', fsync: true });
      }
    }
  }

  private async makeBackup(): Promise<void> {
    try {
      await readFile(this.filePath, 'utf8');
    } catch {
      return;
    }
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupName = `${path.basename(this.filePath, '.json')}-${stamp}-${randomUUID().slice(0, 8)}.json`;
    await copyFile(this.filePath, path.join(this.backupDir, backupName));
    const files = (await readdir(this.backupDir))
      .filter(name => name.startsWith(`${path.basename(this.filePath, '.json')}-`) && name.endsWith('.json'))
      .sort();
    for (const oldFile of files.slice(0, Math.max(0, files.length - this.keepBackups))) {
      await unlink(path.join(this.backupDir, oldFile)).catch(() => undefined);
    }
  }
}
