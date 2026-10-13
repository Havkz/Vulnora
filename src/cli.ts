#!/usr/bin/env node
import { TerminalInterrupted } from './ui/terminal.js';

try {
  if (process.argv.length === 2 || (process.argv.length === 3 && process.argv[2] === 'interactive')) {
    const { runInteractive } = await import('./ui/app.js');
    await runInteractive();
  } else await import('./commands.js');
} catch (error) {
  if (error instanceof TerminalInterrupted) process.exitCode = 130;
  else {
    console.error(`Vulnora: ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 1;
  }
}
