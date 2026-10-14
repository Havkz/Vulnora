import { constants, copyFileSync, existsSync, mkdirSync, readdirSync, statSync, chmodSync,
  writeFileSync, readFileSync, linkSync, unlinkSync, openSync, closeSync, fsyncSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, isAbsolute } from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';

/** Protect the dedicated settings directory, including atomic replacement files. */
export function protectConfigSecrets(directory: string): void {
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  if (process.platform !== 'win32') {
    chmodSync(directory, 0o700);
    for (const name of ['config.json', '.env']) {
      const file = join(directory, name);
      if (existsSync(file)) chmodSync(file, 0o600);
    }
    return;
  }
  const script = `
    $ErrorActionPreference = 'Stop'
    $identities = @([Security.Principal.WindowsIdentity]::GetCurrent().User,
      [Security.Principal.SecurityIdentifier]::new('S-1-5-18'),
      [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    foreach ($target in @($env:VULNORA_SETTINGS_ROOT, [IO.Path]::Combine($env:VULNORA_SETTINGS_ROOT, 'config.json'), [IO.Path]::Combine($env:VULNORA_SETTINGS_ROOT, '.env'))) {
      if ([IO.Directory]::Exists($target)) { $item = [IO.DirectoryInfo]::new($target); $inherit = 'ContainerInherit, ObjectInherit' }
      elseif ([IO.File]::Exists($target)) { $item = [IO.FileInfo]::new($target); $inherit = 'None' }
      else { continue }
      $acl = $item.GetAccessControl()
      $acl.SetAccessRuleProtection($true, $false)
      foreach ($rule in @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))) { $acl.RemoveAccessRuleSpecific($rule) }
      foreach ($identity in $identities) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($identity, 'FullControl', $inherit, 'None', 'Allow'))
      }
      $item.SetAccessControl($acl)
    }`;
  execFileSync('powershell.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand',
    Buffer.from(script, 'utf16le').toString('base64')], {
    windowsHide: true, timeout: 15000, stdio: 'pipe',
    env: { ...process.env, VULNORA_SETTINGS_ROOT: directory },
  });
}

/** Old environment names stay input-compatible; new names always take precedence. */
export function migrateEnvironment(env: NodeJS.ProcessEnv = process.env): void {
  for (const [key, value] of Object.entries(env)) {
    const renamed = key.replace(/^(?:TEMPEST|T3MP3ST)_/, 'VULNORA_');
    if (renamed !== key && env[renamed] === undefined) env[renamed] = value;
  }
}

export interface MigrationEntry { source: string; destination: string; sha256: string }

/** Copy only application data, never sandbox images, dependencies or provider credentials. */
export function migrateLegacyData(sources: string[], directory: string): MigrationEntry[] {
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const allowed = new Set(['config.json', '.env', 'projects', 'sessions', 'reports', 'history', 'scans', 'evidence']);
  const entries: MigrationEntry[] = [];
  function copy(source: string, destination: string): void {
    const stat = statSync(source, { throwIfNoEntry: false });
    if (!stat) return;
    if (stat.isDirectory()) {
      mkdirSync(destination, { recursive: true, mode: 0o700 });
      for (const child of readdirSync(source, { withFileTypes: true })) {
        if (child.isSymbolicLink()) continue;
        copy(join(source, child.name), join(destination, child.name));
      }
    } else if (stat.isFile() && !existsSync(destination)) {
      const temporary = `${destination}.${randomUUID()}.tmp`;
      try {
        copyFileSync(source, temporary, constants.COPYFILE_EXCL);
        chmodSync(temporary, 0o600);
        const fd = openSync(temporary, 'r+');
        try { fsyncSync(fd); } finally { closeSync(fd); }
        // Publish complete data without overwriting another process's existing settings.
        linkSync(temporary, destination);
      } catch (error) { if ((error as NodeJS.ErrnoException).code === 'EEXIST') return; throw error; }
      finally { if (existsSync(temporary)) unlinkSync(temporary); }
      entries.push({ source, destination, sha256: createHash('sha256').update(readFileSync(destination)).digest('hex') });
    }
  }
  for (const source of sources) {
    if (!existsSync(source) || source === directory) continue;
    for (const item of readdirSync(source, { withFileTypes: true })) {
      if (allowed.has(item.name) && !item.isSymbolicLink()) copy(join(source, item.name), join(directory, item.name));
    }
  }
  const marker = join(directory, 'migration-v1.json');
  if (!existsSync(marker)) writeFileSync(marker, JSON.stringify({ version: 1, createdAt: Date.now(), entries }, null, 2), { flag: 'wx', mode: 0o600 });
  return entries;
}

export function configDirectory(): string {
  migrateEnvironment();
  const configured = process.env.VULNORA_CONFIG_DIR;
  if (configured) {
    if (!isAbsolute(configured)) throw new Error('VULNORA_CONFIG_DIR must be an absolute path');
    // Explicit directories remain isolated, including test and portable installations.
    return configured;
  }
  const home = homedir();
  const directory = join(home, '.vulnora');
  const legacyConf = process.platform === 'win32'
    ? join(process.env.APPDATA || join(home, 'AppData', 'Roaming'), 't3mp3st-nodejs', 'Config')
    : process.platform === 'darwin' ? join(home, 'Library', 'Preferences', 't3mp3st-nodejs')
      : join(process.env.XDG_CONFIG_HOME || join(home, '.config'), 't3mp3st-nodejs');
  migrateLegacyData([join(home, '.t3mp3st'), legacyConf], directory);
  return directory;
}
