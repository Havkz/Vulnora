import { Command, InvalidArgumentError, Option } from 'commander';
import ora from 'ora';
import Table from 'cli-table3';
import { renderLogo, theme } from './ui/theme.js';
import { config, hasApiKey, AVAILABLE_MODELS } from './config/index.js';
import { dirname, join } from 'node:path';
import { mkdir } from 'node:fs/promises';
import { ProviderSession, validateProvider } from './llm/provider-session.js';
import { stopOwnedOllama } from './llm/local-service.js';
import { CLI_PROVIDERS, resolveInference, type InferenceOptions } from './cli-inference.js';
import type { ProjectRecord, ScanningBehavior } from './projects/store.js';
import { normalizeAssessmentRules } from './projects/assessment.js';
import { validateProjectTarget } from './projects/targets.js';
import { formatProjectLog } from './ui/project-log.js';
import { redactSecrets } from './redact.js';
import { terminalText } from './ui/terminal.js';
import { createOllamaSession } from './llm/ollama-session.js';
import type { LLMProvider } from './types/index.js';

function showBanner(): void { console.log('\n' + renderLogo(process.stdout.columns || 80).join('\n') + '\n'); }
function showError(message: string): void { console.log(theme.error('✗ ') + terminalText(message)); }
function showInfo(message: string): void { console.log(theme.active(terminalText(message))); }

const program = new Command();

program
  .name('vulnora')
  .description('Vulnora - website pentesting tool')
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
  .command('fallback')
  .description('Show or update the saved fallback policy (safety refusals never switch models)')
  .option('--enabled <boolean>', 'Enable fallback', parseBoolean)
  .option('--on-api-error <boolean>', 'Switch on API or connection errors', parseBoolean)
  .option('--on-rate-limit <boolean>', 'Switch on rate limits or exhausted quota', parseBoolean)
  .option('--on-refusal <boolean>', 'Reevaluate technical or unclear refusals (default: false)', parseBoolean)
  .option('--provider <provider>', 'Fallback provider, such as local, codex or openai')
  .option('--model <model>', 'Fallback model ID (empty uses the provider default)')
  .action((options: { enabled?: boolean; onApiError?: boolean; onRateLimit?: boolean; onRefusal?: boolean; provider?: LLMProvider; model?: string }) => {
    if (Object.keys(options).length) config.setFallbackSettings(options);
    console.log(JSON.stringify(config.getFallbackSettings(), null, 2));
  });

function parseBoolean(value: string): boolean {
  if (value === 'true') return true;
  if (value === 'false') return false;
  throw new InvalidArgumentError('Expected true or false.');
}

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

inferenceOptions(program.command('test').description('Test only the selected provider; never use fallback'))
  .action(async (options: InferenceOptions) => {
    const selected = resolveInference(config, { ...options, fallbackEnabled: false });
    selected.fallbackChain = [];
    const spinner = ora(`Testing ${selected.provider}/${selected.cliModel || selected.model}...`).start();
    ollamaSession = createOllamaSession(selected);
    ollamaSession.retain();
    try {
      await validateProvider(selected, controller.signal, config.get('codex').command);
      spinner.succeed('Connection successful!');
    } catch (error) { spinner.fail('Connection failed'); throw error; }
  });

inferenceOptions(program.command('run [url]').description('Run or resume a persistent website assessment without menus'))
  .option('--name <name>', 'Project name (defaults to the target hostname)')
  .option('--resume <id>', 'Resume a saved project UUID; its target and intensity remain unchanged')
  .addOption(new Option('--intensity <mode>', 'Scanning behavior').choices(['auto', 'stealth', 'aggressive']))
  .option('--verbose', 'Show full command output')
  .option('--scope <host>', 'Additional authorized hostname or IP, including subdomains (repeatable)', collectOption, [])
  .option('--exclude <host>', 'Exclude a hostname/IP and its subdomains (repeatable)', collectOption, [])
  .option('--exclude-tool <id>', 'Exclude an exact tool ID (repeatable)', collectOption, [])
  .option('--rate-limit <number>', 'Maximum requests/sec per host (integer 1–1000; intensity may be slower)', Number)
  .option('--fallback-enabled <boolean>', 'Override fallback for this process', parseBoolean)
  .addOption(new Option('--fallback-provider <provider>', 'Fallback provider for this process').choices(CLI_PROVIDERS))
  .option('--fallback-model <model>', 'Fallback inference model ID')
  .option('--fallback-on-api-error <boolean>', 'Fallback on connection/API errors', parseBoolean)
  .option('--fallback-on-rate-limit <boolean>', 'Fallback on rate limits/quota', parseBoolean)
  .option('--fallback-on-refusal <boolean>', 'Reevaluate technical/unclear refusals only', parseBoolean)
  .action(async (url: string | undefined, options: InferenceOptions & { name?: string; resume?: string; intensity?: ScanningBehavior; verbose?: boolean; scope: string[]; exclude: string[]; excludeTool: string[]; rateLimit?: number }) => {
    if (options.resume && (url !== undefined || options.name !== undefined || options.intensity !== undefined || options.scope.length || options.exclude.length || options.excludeTool.length || options.rateLimit !== undefined)) {
      throw new Error('Use --resume <id> without a new target, name, intensity or assessment rules.');
    }
    if (!options.resume && !url) throw new Error('Provide a target URL or --resume <project-id>.');
    const assessment = normalizeAssessmentRules({ scopeHosts: options.scope, excludedHosts: options.exclude,
      excludedTools: options.excludeTool, requestsPerSecond: options.rateLimit }, url);
    const llm = resolveInference(config, options);
    const { ProjectStore } = await import('./projects/store.js');
    const { ProjectSession } = await import('./projects/session.js');
    const { runProject } = await import('./projects/run.js');
    const store = new ProjectStore(join(dirname(config.getConfigPath()), 'projects'));
    const target = url ? validateProjectTarget(url) : undefined;
    if (target && target.kind !== 'url') throw new Error('Use an explicit HTTP or HTTPS target URL.');
    controller.signal.throwIfAborted();
    await mkdir(store.directory, { recursive: true, mode: 0o700 });
    let project: ProjectRecord;
    if (options.resume) project = await store.load(options.resume);
    else {
      if (!target) throw new Error('Provide a target URL.');
      project = await store.create(options.name || target.hostname, target.input, options.intensity || 'auto', assessment);
    }
    showInfo(`Project ${project.id} · ${project.name}`);
    showInfo(`Resume: vulnora run --resume ${project.id}`);
    // Let runProject drain cancelled tool/model requests before releasing weights.
    providers = new ProviderSession(config, new AbortController().signal);
    const session = await ProjectSession.open(store, project.id, { llm });
    providers.track(session.command.llm);
    session.command.llm.on('request:provider', current => showInfo(`Provider: ${current.provider} · ${current.cliModel || current.model}`));
    const outcome = await runProject(session, controller.signal, event => {
      // Completed process events carry both the real invocation and its output.
      if (event.category === 'execution:started') return;
      const line = formatProjectLog(event, options.verbose, theme, process.stdout.columns || 120);
      if (line) console.log(line);
    });
    if (session.project.report) console.log(`Report: ${await store.exportReport(session.project)}`);
    if (outcome !== 'completed') {
      console.log(`Assessment ${outcome}; checkpoint retained. Open Vulnora to inspect pending recovery or missing coverage.`);
      process.exitCode = controller.signal.aborted ? interruptionCode : 2;
    }
  });

function collectOption(value: string, previous: string[]): string[] { return [...previous, value]; }

function inferenceOptions(command: Command): Command {
  return command.addOption(new Option('--provider <provider>', 'Inference provider (claude selects Claude Code)').choices(CLI_PROVIDERS))
    .option('--model <model>', 'Inference model ID; for CLI providers overrides only this Vulnora process')
    .addOption(new Option('--reasoning <effort>', 'Codex/Claude reasoning effort').choices(['low', 'medium', 'high', 'xhigh', 'max', 'ultra']));
}

program
  .command('models')
  .description('List provider models; local queries the actual server without loading weights')
  .addOption(new Option('--provider <provider>', 'Provider to list').choices(CLI_PROVIDERS))
  .action(async (options: { provider?: string }) => {
    showBanner();

    const provider = options.provider || config.getLLMConfig().provider;
    if (provider === 'local') {
      providers = new ProviderSession(config, controller.signal);
      const models = await providers.installedModels();
      console.log(models.length ? models.map(terminalText).join('\n') : 'No installed local models found. Add a model or configure its endpoint in Settings.');
      return;
    }
    const models = AVAILABLE_MODELS[provider === 'claude' ? 'local-agent' : provider as LLMProvider];

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

// Signals cancel work first; async command cleanup drains and saves before exit.
const controller = new AbortController();
let interruptionCode = 130;
let providers: ProviderSession | undefined;
let ollamaSession: ReturnType<typeof createOllamaSession> | undefined;
const interrupt = () => { interruptionCode = 130; controller.abort(); };
const terminate = () => { interruptionCode = 143; controller.abort(); };
program.hook('preAction', (_program, command) => {
  if (command.name() === 'interactive') return;
  process.once('SIGINT', interrupt);
  process.once('SIGTERM', terminate);
});

try { await program.parseAsync(); }
catch (error) {
  if (controller.signal.aborted) process.exitCode = interruptionCode;
  else if (error instanceof Error && error.name === 'ExitPromptError') process.exitCode = 130;
  else {
    showError(String(redactSecrets(error instanceof Error ? error.message : String(error))));
    process.exitCode = 1;
  }
} finally {
  try { await ollamaSession?.stop(); }
  catch (error) { showError(String(redactSecrets(String(error)))); process.exitCode = 1; }
  try { if (providers) await providers.close(); else await stopOwnedOllama(); }
  catch (error) { showError(String(redactSecrets(String(error)))); process.exitCode = 1; }
  process.off('SIGINT', interrupt); process.off('SIGTERM', terminate);
}
