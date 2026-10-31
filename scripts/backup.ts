import { mkdir, readdir, copyFile } from 'node:fs/promises';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import lockfile from 'proper-lockfile';
import { loadConfig } from '../src/config/env.js';

const config = loadConfig();
const backupDir = path.join(config.dataDir, 'backups');
await mkdir(backupDir, { recursive: true });
const files = (await readdir(config.dataDir)).filter(name => name.endsWith('.json'));
if (files.length === 0) {
  console.log('No JSON data files found yet. Start the server once to initialize them.');
} else {
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  for (const name of files) {
    const source = path.join(config.dataDir, name);
    const target = path.join(backupDir, `${name.replace(/\.json$/, '')}-manual-${stamp}-${randomUUID().slice(0, 8)}.json`);
    const release = await lockfile.lock(source, {
      realpath: false,
      retries: { retries: 12, factor: 1.5, minTimeout: 20, maxTimeout: 500 },
      stale: 15000,
      update: 5000
    });
    try {
      await copyFile(source, target);
    } finally {
      await release();
    }
  }
  console.log(`Backed up ${files.length} JSON files to ${backupDir}`);
}
