import { access, stat } from 'node:fs/promises';
import { constants } from 'node:fs';
import { posix, win32 } from 'node:path';

/** Resolve only executable files on PATH; never invoke a shell or search the working directory. */
export async function commandPath(binary: string, platform = process.platform, env: NodeJS.ProcessEnv = process.env): Promise<string | undefined> {
  const windows = platform === 'win32';
  const path = windows ? win32 : posix;
  const extensions = windows && !path.extname(binary)
    ? (env.PATHEXT || '.COM;.EXE;.BAT;.CMD').split(';').filter(Boolean)
    : [''];
  for (const directory of (env.PATH || env.Path || env.path || '').split(windows ? ';' : ':')) {
    const trimmed = directory.trim().replace(/^"|"$/g, '');
    if (!path.isAbsolute(trimmed)) continue;
    for (const extension of extensions) {
      const candidate = path.join(trimmed, binary + extension);
      try {
        await access(candidate, windows ? constants.F_OK : constants.X_OK);
        if ((await stat(candidate)).isFile()) return candidate;
      } catch { /* Try the next PATH candidate. */ }
    }
  }
  return undefined;
}
