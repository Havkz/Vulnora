import { spawn, type ChildProcess } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import { commandPath } from '../command-path.js';

let owned: ChildProcess | undefined;
let starting: Promise<void> | undefined;

async function startOllama(signal?: AbortSignal | null): Promise<void> {
  if (starting) return starting;
  starting = (async () => {
    const powershell = process.env.VULNORA_OLLAMA_HOST_POWERSHELL;
    const helper = process.env.VULNORA_OLLAMA_HOST_HELPER;
    const command = powershell && helper ? powershell : await commandPath('ollama');
    if (!command) throw new Error('Ollama service is offline. Start ollama serve, or use the Windows Vulnora launcher.');
    const child = spawn(command, powershell && helper ? ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', helper] : ['serve'], {
      windowsHide: true, shell: false, stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, OLLAMA_HOST: '127.0.0.1:11434' },
    });
    owned = child;
    let failure: Error | undefined;
    child.on('error', error => { failure = error; });
    child.stderr?.resume(); child.stdout?.resume();
    try {
      const deadline = AbortSignal.any([AbortSignal.timeout(15000), ...(signal ? [signal] : [])]);
      for (;;) {
        deadline.throwIfAborted();
        if (failure) throw failure;
        try {
          const response = await fetch('http://127.0.0.1:11434/api/tags', { signal: AbortSignal.any([deadline, AbortSignal.timeout(1000)]) });
          if (response.ok) { await response.text(); return; }
        } catch { deadline.throwIfAborted(); }
        if (child.exitCode !== null || child.signalCode !== null) throw new Error('Ollama service could not start; check its local port and installation.');
        await delay(200, undefined, { signal: deadline });
      }
    } catch (error) { await stopOwnedOllama(); throw error; }
  })().finally(() => { starting = undefined; });
  return starting;
}

/** Start only an installed loopback Ollama service, and only after connection refusal. */
export async function fetchLocal(url: string, init?: RequestInit): Promise<Response> {
  try { return await fetch(url, init); }
  catch (error) {
    init?.signal?.throwIfAborted();
    const address = new URL(url);
    const cause = (error as { cause?: { code?: string; errors?: { code?: string }[] } }).cause;
    const refused = cause?.code === 'ECONNREFUSED' || (cause?.errors?.length && cause.errors.every(entry => entry.code === 'ECONNREFUSED'));
    if (!refused || address.protocol !== 'http:' || !['127.0.0.1', 'localhost'].includes(address.hostname)
      || address.port !== '11434' || !address.pathname.startsWith('/api/')) throw error;
    await startOllama(init?.signal);
    return fetch(url, init);
  }
}

export async function stopOwnedOllama(): Promise<void> {
  const child = owned; owned = undefined;
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  // The Windows helper owns the native process and releases it when its stdin closes.
  const host = !!process.env.VULNORA_OLLAMA_HOST_HELPER;
  await new Promise<void>(resolve => {
    const timer = setTimeout(() => { child.kill(); resolve(); }, 5000);
    child.once('exit', () => { clearTimeout(timer); resolve(); });
    if (host) child.stdin?.end(); else child.kill();
  });
}
