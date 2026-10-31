import { mkdir, readdir, copyFile, readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import writeFileAtomic from 'write-file-atomic';
import lockfile from 'proper-lockfile';
import { loadConfig } from '../src/config/env.js';
import { arraySchemas } from '../src/storage/schemas.js';

const config = loadConfig();
const targetName = process.argv[2];
const schemaByFile = new Map<string, { parse(value: unknown): unknown }>([
  ['memories.json', arraySchemas.memories], ['users.json', arraySchemas.users],
  ['oauth-clients.json', arraySchemas.oauthClients], ['authorization-codes.json', arraySchemas.authorizationCodes],
  ['access-tokens.json', arraySchemas.accessTokens], ['refresh-tokens.json', arraySchemas.refreshTokens],
  ['api-keys.json', arraySchemas.apiKeys], ['oauth-assertions.json', arraySchemas.assertions]
]);
if (!targetName || !schemaByFile.has(targetName)) {
  console.error('Usage: npm run restore -- memories.json [backup-file-name]');
  process.exit(1);
}

const backupDir = path.join(config.dataDir, 'backups');
await mkdir(backupDir, { recursive: true });
const target = path.join(config.dataDir, targetName);
const release = await lockfile.lock(target, {
  realpath: false,
  retries: { retries: 12, factor: 1.5, minTimeout: 20, maxTimeout: 500 },
  stale: 15000,
  update: 5000
});
try {
  // Use the same per-file lock as JsonStore so restore cannot race with a write or permanent delete.
  const prefix = targetName.replace(/\.json$/, '') + '-';
  const backups = (await readdir(backupDir)).filter(name => name.startsWith(prefix) && name.endsWith('.json'));
  const restorableBackups = backups.filter(name => !name.includes('-before-restore-'));
  const newestFirst = await Promise.all(restorableBackups.map(async name => ({
    name,
    modified: (await stat(path.join(backupDir, name))).mtimeMs
  })));
  newestFirst.sort((a, b) => a.modified - b.modified);
  const supplied = process.argv[3];
  const chosen = supplied ? backups.find(name => name === supplied) : newestFirst.at(-1)?.name;
  if (!chosen) throw new Error(`No matching backup found for ${targetName}.`);

  const raw = await readFile(path.join(backupDir, chosen), 'utf8');
  const parsed: unknown = JSON.parse(raw);
  schemaByFile.get(targetName)!.parse(parsed); // Refuse to restore structurally invalid JSON.

  try {
    await readFile(target, 'utf8');
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    await copyFile(target, path.join(backupDir, `${targetName.replace(/\.json$/, '')}-before-restore-${stamp}.json`));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }

  await writeFileAtomic(target, JSON.stringify(parsed, null, 2) + '\n', { encoding: 'utf8', fsync: true });
  console.log(`Restored ${targetName} from ${chosen}. The previous current file was backed up when present.`);
} finally {
  await release();
}
