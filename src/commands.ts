import { Command } from 'commander';
import ora from 'ora';
import Table from 'cli-table3';
import { renderLogo, theme } from './ui/theme.js';
import { config, hasApiKey, AVAILABLE_MODELS } from './config/index.js';
import { LLMBackbone } from './llm/index.js';
import { createOllamaSession } from './llm/ollama-session.js';

function showBanner(): void { console.log('\n' + renderLogo(process.stdout.columns || 80).join('\n') + '\n'); }
function showError(message: string): void { console.log(theme.error('✗ ') + message); }
function showInfo(message: string): void { console.log(theme.active(message)); }
function showWarning(message: string): void { console.log(theme.warning(message)); }

const program = new Command();

program
  .name('vulnora')
  .description('Vulnora - persistent website and API security testing')
  .version('1.0.0');

program
  .command('interactive', { isDefault: true })
  .description('Start interactive mode')
  .action(async () => { const { runInteractive } = await import('./ui/app.js'); await runInteractive(); });

program
  .command('setup')
  .description('Run the setup wizard')
  .action(async () => {
    await import('./setup.js');
  });

program
  .command('status')
  .description('Show current configuration status')
  .action(() => {
    showBanner();
    const settings = config.getLLMConfig();

    console.log(theme.emphasis('Configuration Status:\n'));

    const table = new Table({
      style: { head: [], border: [] },
    });

    table.push(
      [theme.active('Default Provider'), settings.provider],
      [theme.active('Default Model'), settings.model],
      [theme.active('OpenRouter API Key'), hasApiKey('openrouter') ? theme.success('✓ Configured') : theme.error('✗ Not set')],
      [theme.active('Venice API Key'), hasApiKey('venice') ? theme.success('✓ Configured') : theme.error('✗ Not set')],
      [theme.active('Anthropic API Key'), hasApiKey('anthropic') ? theme.success('✓ Configured') : theme.error('✗ Not set')],
      [theme.active('OpenAI API Key'), hasApiKey('openai') ? theme.success('✓ Configured') : theme.error('✗ Not set')],
      [theme.active('DeepSeek API Key'), hasApiKey('deepseek') ? theme.success('✓ Configured') : theme.error('✗ Not set')],
      [theme.active('Config Path'), config.getConfigPath()],
    );

    console.log(table.toString());
    console.log('');
  });

program
  .command('test')
  .description('Test the LLM connection')
  .action(async () => {
    showBanner();

    const provider = config.getLLMConfig().provider;

    if (!['codex', 'local', 'local-agent', 'mock'].includes(provider) && !config.getLLMConfig().apiKey) {
      showError(`No API key configured for ${provider}`);
      showInfo('Run "npx vulnora setup" to configure API keys');
      process.exitCode = 1;
      return;
    }

    const spinner = ora(`Testing connection to ${provider}...`).start();

    try {
      const llm = new LLMBackbone(config.getLLMConfig());
      const response = await llm.prompt('Say "Connection successful!" and nothing else.');

      spinner.succeed('Connection successful!');
      console.log('');
      console.log(theme.active('Response:'), response);
      console.log('');
    } catch (error) {
      spinner.fail('Connection failed');
      showError(`${error instanceof Error ? error.message : String(error)}`);
      process.exitCode = 1;
    }
  });

program
  .command('models')
  .description('List available models')
  .action(() => {
    showBanner();

    const provider = config.get('defaultProvider');
    const models = AVAILABLE_MODELS[provider];

    console.log(theme.emphasis(`Available models for ${provider}:\n`));

    const table = new Table({
      head: [theme.active('Model ID'), theme.active('Name'), theme.active('Context')],
      style: { head: [], border: [] },
    });

    for (const model of models) {
      table.push([
        model.id,
        model.name,
        `${model.contextWindow.toLocaleString()} tokens`,
      ]);
    }

    console.log(table.toString());
    console.log('');
  });

// Wait for async commands so the model remains loaded until the CLI actually exits.
let ollamaSession: ReturnType<typeof createOllamaSession> | undefined;
program.hook('preAction', async (_program, command) => {
  if (command.name() !== 'test') return;
  ollamaSession = createOllamaSession(config.getLLMConfig());
  showInfo('Preparing configured local fallback...');
  await ollamaSession.start();
});

async function releaseOllama(): Promise<void> {
  try { await ollamaSession?.stop(); }
  catch (error) { showWarning(`Could not unload Ollama: ${error instanceof Error ? error.message : String(error)}`); }
}

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.once(signal, () => {
    if (process.argv.includes('interactive')) return;
    void releaseOllama().finally(() => process.exit(signal === 'SIGINT' ? 130 : 143));
  });
}

try { await program.parseAsync(); }
catch (error) {
  if (error instanceof Error && error.name === 'ExitPromptError') process.exitCode = 130;
  else {
    showError(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
} finally { await releaseOllama(); }
