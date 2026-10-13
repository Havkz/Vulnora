import { createServer } from 'node:net';
import { createHash } from 'node:crypto';
import { mkdir, realpath } from 'node:fs/promises';

/** OS-owned local lease: process death releases it without stale lock-file races. */
export async function acquireProjectLease(directory: string, id: string): Promise<() => Promise<void>> {
  if (!/^[\da-f]{8}-(?:[\da-f]{4}-){3}[\da-f]{12}$/i.test(id)) throw new Error('Invalid project ID.');
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const canonical = await realpath(directory);
  const key = createHash('sha256').update(`${process.platform === 'win32' ? canonical.toLowerCase() : canonical}/${id.toLowerCase()}`).digest('hex');
  // shortcut: leases protect one Windows/Linux host, shared projects across hosts need a distributed lock.
  const path = process.platform === 'win32' ? `\\\\.\\pipe\\vulnora-project-${key}`
    : process.platform === 'linux' ? `\0vulnora-project-${key}` : undefined;
  if (!path) throw new Error('Exclusive project execution is currently supported on Windows and Linux.');
  const server = createServer(socket => socket.destroy());
  try {
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(path, () => { server.removeListener('error', reject); resolve(); });
    });
  } catch (cause) {
    server.close();
    throw new Error('Could not acquire exclusive project access; another local process may already be using this project.', { cause });
  }
  server.unref();
  let closing: Promise<void> | undefined;
  return () => closing ||= new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
}
