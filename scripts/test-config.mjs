import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export default async function setup() {
  const directory = await mkdtemp(join(tmpdir(), 'vulnora-tests-'));
  const previous = process.env.VULNORA_CONFIG_DIR;
  process.env.VULNORA_CONFIG_DIR = directory;
  return async () => {
    if (previous === undefined) delete process.env.VULNORA_CONFIG_DIR;
    else process.env.VULNORA_CONFIG_DIR = previous;
    await rm(directory, { recursive: true, force: true });
  };
}
