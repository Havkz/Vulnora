import { afterEach, describe, expect, it } from 'vitest';
import { mkdtemp, mkdir, readFile, writeFile, chmod, rm, copyFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const directories: string[] = [];
afterEach(async () => { for (const path of directories.splice(0)) await rm(path, { recursive: true, force: true }); });

describe('installed launcher', () => {
  it.skipIf(process.platform !== 'win32')('preserves existing Ollama services, stops its own service and accepts clean interruption', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'vulnora-launcher-')); directories.push(directory);
    await mkdir(join(directory, '.vulnora', 'sandbox'), { recursive: true });
    await copyFile('scripts/start-windows-vulnora.ps1', join(directory, 'start.ps1'));
    await writeFile(join(directory, 'setup-windows-arsenal.ps1'), '# Fixture installation already complete');
    await writeFile(join(directory, '.vulnora', 'sandbox', 'runtime.json'), JSON.stringify({
      distro: 'Fixture-Arsenal', user: 'fixture', appDirectory: '/home/fixture/release',
    }));
    const script = join(directory, 'check.ps1');
    await writeFile(script, `
$ErrorActionPreference = 'Stop'
$env:USERPROFILE = $PSScriptRoot
$env:OLLAMA_HOST = 'preserved-host'
$global:started = 0; $global:stopped = 0; $global:unavailable = $false; $global:exitCode = 0
function Invoke-RestMethod {
  if ($global:unavailable) { $global:unavailable = $false; throw 'Fixture API unavailable' }
  return @{ models = @() }
}
function Get-Command { return [pscustomobject]@{ Source = 'fixture-ollama.exe' } }
function Start-Process {
  param($FilePath, $ArgumentList, $WindowStyle, [switch]$PassThru)
  if ($env:OLLAMA_HOST -ne '127.0.0.1:11434' -or $WindowStyle -ne 'Hidden') { throw 'Unsafe service launch' }
  $global:started++; return [pscustomobject]@{ Id = 12345; HasExited = $false }
}
function Stop-Process { param($Id); if ($Id -ne 12345) { throw 'Stopped unowned process' }; $global:stopped++ }
function Start-Sleep { }
function wsl.exe {
  $global:invocation = @($args); $global:LASTEXITCODE = $global:exitCode
}
& (Join-Path $PSScriptRoot 'start.ps1') --help
if ($global:started -or $global:invocation[-1] -ne '--help') { throw 'Headless arguments not preserved' }
& (Join-Path $PSScriptRoot 'start.ps1') interactive
if ($global:started -or $global:stopped) { throw 'Existing service was touched' }
$global:unavailable = $true; $global:exitCode = 130
& (Join-Path $PSScriptRoot 'start.ps1') interactive
if ($global:started -ne 1 -or $global:stopped -ne 1 -or $env:OLLAMA_HOST -ne 'preserved-host') { throw 'Owned service lifecycle failed' }
if ($global:invocation -notcontains 'Fixture-Arsenal' -or $global:invocation -notcontains '/home/fixture/release/scripts/start-linux-vulnora.sh') { throw 'Wrong runtime' }
Write-Output 'WINDOWS_LAUNCHER_LIFECYCLE_OK'
`);
    const result = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-File', script], { encoding: 'utf8', windowsHide: true, timeout: 15000 });
    expect(result.stderr).toBe(''); expect(result.status).toBe(0);
    expect(result.stdout).toContain('WINDOWS_LAUNCHER_LIFECYCLE_OK');
  }, 20000);
  it.skipIf(process.platform === 'win32')('uses its release directory, retains user provider/model defaults and forwards arguments', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'vulnora-launcher-')); directories.push(directory);
    const scripts = join(directory, 'release', 'scripts'); const binaries = join(directory, '.local', 'bin');
    await mkdir(scripts, { recursive: true }); await mkdir(binaries, { recursive: true });
    await copyFile('scripts/start-linux-vulnora.sh', join(scripts, 'start.sh'));
    const capture = join(directory, 'capture'); const node = join(binaries, 'node');
    await writeFile(node, `#!/bin/bash
if [[ $1 == scripts/arsenal-doctor.mjs ]]; then echo '{"installed":23}'; exit "$FIXTURE_DOCTOR_EXIT"; fi
printf '%s\\n' "$PWD" "$VULNORA_DEFAULT_PROVIDER" "$VULNORA_LOCAL_MODEL" "$VULNORA_CONFIG_DIR" "$@" > "$FIXTURE_CAPTURE"
`);
    await chmod(node, 0o700);
    const env = { ...process.env, HOME: directory, VULNORA_DEFAULT_PROVIDER: 'local', VULNORA_LOCAL_MODEL: 'chosen:7b',
      VULNORA_CONFIG_DIR: join(directory, 'selected-config'), FIXTURE_CAPTURE: capture, FIXTURE_DOCTOR_EXIT: '0' };
    const args = [join(scripts, 'start.sh'), 'test', '--target', 'https://fixture.test/a b'];
    expect(spawnSync('bash', args, { cwd: tmpdir(), env }).status).toBe(0);
    expect((await readFile(capture, 'utf8')).trim().split('\n')).toEqual([
      join(directory, 'release'), 'local', 'chosen:7b', env.VULNORA_CONFIG_DIR,
      'dist/cli.js', 'test', '--target', 'https://fixture.test/a b',
    ]);
    await rm(capture);
    const failed = spawnSync('bash', args, { env: { ...env, FIXTURE_DOCTOR_EXIT: '1' }, encoding: 'utf8' });
    expect(failed.status).toBe(1); expect(failed.stderr).toContain('"installed":23');
    await expect(readFile(capture)).rejects.toMatchObject({ code: 'ENOENT' });
  });
});
