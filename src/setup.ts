#!/usr/bin/env node
/**
 * VULNORA Setup Wizard
 *
 * Interactive setup for configuring API keys and settings.
 */

import inquirer from 'inquirer';
import boxen from 'boxen';
import ora from 'ora';
import { config, AVAILABLE_MODELS, hasApiKey, setApiKey } from './config/index.js';
import { LLMBackbone } from './llm/index.js';
import { renderLogo, theme } from './ui/theme.js';

// =============================================================================
// DISPLAY HELPERS
// =============================================================================

function showBanner(): void {
  console.log('\n' + renderLogo(process.stdout.columns || 80).join('\n') + '\n');
}

function showBox(title: string, content: string, borderColor: string = 'cyan'): void {
  console.log(
    boxen(content, {
      title,
      titleAlignment: 'center',
      padding: 1,
      margin: 1,
      borderStyle: 'round',
      borderColor: borderColor as any,
    })
  );
}

function showSuccess(message: string): void {
  console.log(theme.success('✓ ') + message);
}

function showError(message: string): void {
  console.log(theme.error('✗ ') + message);
}

function showInfo(message: string): void {
  console.log(theme.active('ℹ ') + message);
}

function showWarning(message: string): void {
  console.log(theme.warning(' ') + message);
}

// =============================================================================
// API KEY SETUP
// =============================================================================

async function setupOpenRouterKey(): Promise<boolean> {
  console.log('');
  showInfo('OpenRouter provides access to multiple AI models through a single API.');
  showInfo('Get your API key at: ' + theme.emphasis.underline('https://openrouter.ai/keys'));
  console.log('');

  const { apiKey } = await inquirer.prompt([
    {
      type: 'password',
      name: 'apiKey',
      message: 'Enter your OpenRouter API key:',
      mask: '*',
      validate: (input: string) => {
        if (!input || input.length < 10) {
          return 'Please enter a valid API key';
        }
        return true;
      },
    },
  ]);

  // Test the API key
  const spinner = ora('Testing API key...').start();

  try {
    const llm = new LLMBackbone({
      provider: 'openrouter',
      model: 'anthropic/claude-sonnet-4',
      apiKey,
      maxTokens: 10,
      temperature: 0,
    });

    await llm.prompt('Hello', undefined, { maxTokens: 10 });
    spinner.succeed('API key is valid!');

    setApiKey('openrouter', apiKey);
    showSuccess('OpenRouter API key saved successfully!');

    return true;
  } catch (error) {
    spinner.fail('API key validation failed');
    showError(`Error: ${error instanceof Error ? error.message : String(error)}`);
    return false;
  }
}

async function setupVeniceKey(): Promise<boolean> {
  console.log('');
  showInfo('Venice AI is an OpenAI-compatible, privacy-focused provider (uncensored models).');
  showInfo('Get your API key at: ' + theme.emphasis.underline('https://venice.ai/settings/api'));
  console.log('');

  const { apiKey } = await inquirer.prompt([
    {
      type: 'password',
      name: 'apiKey',
      message: 'Enter your Venice API key:',
      mask: '*',
      validate: (input: string) => {
        if (!input || input.length < 10) {
          return 'Please enter a valid API key';
        }
        return true;
      },
    },
  ]);

  // Test the API key
  const spinner = ora('Testing API key...').start();

  try {
    const llm = new LLMBackbone({
      provider: 'venice',
      model: 'llama-3.3-70b',
      apiKey,
      maxTokens: 10,
      temperature: 0,
    });

    await llm.prompt('Hello', undefined, { maxTokens: 10 });
    spinner.succeed('API key is valid!');

    setApiKey('venice', apiKey);
    showSuccess('Venice API key saved successfully!');

    return true;
  } catch (error) {
    spinner.fail('API key validation failed');
    showError(`Error: ${error instanceof Error ? error.message : String(error)}`);
    return false;
  }
}

async function setupAnthropicKey(): Promise<boolean> {
  console.log('');
  showInfo('Anthropic provides direct access to Claude models.');
  showInfo('Get your API key at: ' + theme.emphasis.underline('https://console.anthropic.com/'));
  console.log('');

  const { apiKey } = await inquirer.prompt([
    {
      type: 'password',
      name: 'apiKey',
      message: 'Enter your Anthropic API key:',
      mask: '*',
      validate: (input: string) => {
        if (!input || input.length < 10) {
          return 'Please enter a valid API key';
        }
        return true;
      },
    },
  ]);

  const spinner = ora('Testing API key...').start();

  try {
    const llm = new LLMBackbone({
      provider: 'anthropic',
      model: 'claude-sonnet-4-20250514',
      apiKey,
      maxTokens: 10,
      temperature: 0,
    });

    await llm.prompt('Hello', undefined, { maxTokens: 10 });
    spinner.succeed('API key is valid!');

    setApiKey('anthropic', apiKey);
    showSuccess('Anthropic API key saved successfully!');

    return true;
  } catch (error) {
    spinner.fail('API key validation failed');
    showError(`Error: ${error instanceof Error ? error.message : String(error)}`);
    return false;
  }
}

async function setupDeepSeekKey(): Promise<boolean> {
  console.log('');
  showInfo('DeepSeek provides OpenAI-compatible chat and reasoning models.');
  showInfo('Get your API key at: ' + theme.emphasis.underline('https://platform.deepseek.com/api_keys'));
  console.log('');

  const { apiKey } = await inquirer.prompt([
    {
      type: 'password',
      name: 'apiKey',
      message: 'Enter your DeepSeek API key:',
      mask: '*',
      validate: (input: string) => {
        if (!input || input.length < 10) {
          return 'Please enter a valid API key';
        }
        return true;
      },
    },
  ]);

  const spinner = ora('Testing API key...').start();

  try {
    const llm = new LLMBackbone({
      provider: 'deepseek',
      model: 'deepseek-chat',
      baseUrl: 'https://api.deepseek.com/v1',
      apiKey,
      maxTokens: 10,
      temperature: 0,
    });

    await llm.prompt('Hello', undefined, { maxTokens: 10 });
    spinner.succeed('API key is valid!');

    setApiKey('deepseek', apiKey);
    showSuccess('DeepSeek API key saved successfully!');

    return true;
  } catch (error) {
    spinner.fail('API key validation failed');
    showError(`Error: ${error instanceof Error ? error.message : String(error)}`);
    return false;
  }
}

async function setupOpenAIKey(): Promise<boolean> {
  console.log('');
  showInfo('OpenAI provides access to GPT models.');
  showInfo('Get your API key at: ' + theme.emphasis.underline('https://platform.openai.com/api-keys'));
  console.log('');

  const { apiKey } = await inquirer.prompt([
    {
      type: 'password',
      name: 'apiKey',
      message: 'Enter your OpenAI API key:',
      mask: '*',
      validate: (input: string) => {
        if (!input || input.length < 10) {
          return 'Please enter a valid API key';
        }
        return true;
      },
    },
  ]);

  const spinner = ora('Testing API key...').start();

  try {
    const llm = new LLMBackbone({
      provider: 'openai',
      model: 'gpt-4-turbo-preview',
      apiKey,
      maxTokens: 10,
      temperature: 0,
    });

    await llm.prompt('Hello', undefined, { maxTokens: 10 });
    spinner.succeed('API key is valid!');

    setApiKey('openai', apiKey);
    showSuccess('OpenAI API key saved successfully!');

    return true;
  } catch (error) {
    spinner.fail('API key validation failed');
    showError(`Error: ${error instanceof Error ? error.message : String(error)}`);
    return false;
  }
}

async function setupLiteLLMProxy(): Promise<boolean> {
  console.log('');
  showInfo('LiteLLM is an AI gateway proxy that routes to 100+ LLM providers.');
  showInfo('Docs: ' + theme.emphasis.underline('https://docs.litellm.ai/docs/proxy/quick_start'));
  console.log('');

  const { baseUrl } = await inquirer.prompt([
    {
      type: 'input',
      name: 'baseUrl',
      message: 'Enter your LiteLLM proxy base URL:',
      default: 'http://localhost:4000/v1',
      validate: (input: string) => {
        if (!input || !input.startsWith('http')) {
          return 'Please enter a valid URL (e.g. http://localhost:4000/v1)';
        }
        return true;
      },
    },
  ]);

  const { apiKey } = await inquirer.prompt([
    {
      type: 'password',
      name: 'apiKey',
      message: 'Enter your LiteLLM API key (leave blank if not required):',
      mask: '*',
    },
  ]);

  const { model } = await inquirer.prompt([
    {
      type: 'input',
      name: 'model',
      message: 'Enter the default model (uses LiteLLM model format, e.g. gpt-4o, anthropic/claude-sonnet-4-6):',
      default: 'gpt-4o',
    },
  ]);

  const spinner = ora('Testing LiteLLM proxy connection...').start();

  try {
    const llm = new LLMBackbone({
      provider: 'litellm',
      model,
      apiKey: apiKey || undefined,
      baseUrl,
      maxTokens: 10,
      temperature: 0,
    });

    await llm.prompt('Hello', undefined, { maxTokens: 10 });
    spinner.succeed('LiteLLM proxy connection successful!');

    config.set('litellm', { baseUrl, defaultModel: model });
    if (apiKey) setApiKey('litellm', apiKey);
    showSuccess('LiteLLM proxy configured successfully!');

    return true;
  } catch (error) {
    spinner.fail('LiteLLM proxy connection failed');
    showError(`Error: ${error instanceof Error ? error.message : String(error)}`);

    const { saveAnyway } = await inquirer.prompt([
      {
        type: 'confirm',
        name: 'saveAnyway',
        message: 'Save the configuration anyway? (proxy may not be running yet)',
        default: true,
      },
    ]);

    if (saveAnyway) {
      config.set('litellm', { baseUrl, defaultModel: model });
      if (apiKey) setApiKey('litellm', apiKey);
      showSuccess('LiteLLM proxy configuration saved.');
      return true;
    }
    return false;
  }
}

// =============================================================================
// MODEL SELECTION
// =============================================================================

async function selectDefaultModel(): Promise<void> {
  const provider = config.get('defaultProvider');
  const models = AVAILABLE_MODELS[provider];

  if (!models || models.length === 0) {
    showWarning('No models available for the current provider');
    return;
  }

  const { model } = await inquirer.prompt([
    {
      type: 'list',
      name: 'model',
      message: 'Select your default model:',
      choices: models.map(m => ({
        name: `${m.name} (${m.provider}) - ${m.contextWindow.toLocaleString()} tokens`,
        value: m.id,
      })),
      default: config.get('defaultModel'),
    },
  ]);

  config.setDefaultModel(provider, model);
  showSuccess(`Default model set to: ${model}`);
}

// =============================================================================
// MAIN SETUP FLOW
// =============================================================================

async function runSetup(): Promise<void> {
  showBanner();

  showBox(
    'Welcome to VULNORA Setup',
    `This wizard will help you configure VULNORA for first use.

You can use a local model with no API key, or add a key from one of these providers:
• ${theme.active('Local')} - Ollama / LM Studio / vLLM via VULNORA_LOCAL_BASE_URL
• ${theme.active('OpenRouter')} (recommended) - Access multiple models
• ${theme.active('Anthropic')} - Direct Claude access
• ${theme.active('OpenAI')} - GPT models
• ${theme.active('DeepSeek')} - OpenAI-compatible chat/reasoning models
• ${theme.active('LiteLLM')} - AI gateway proxy (100+ providers)

The setup will guide you through:
1. Adding API key(s), if you use a hosted provider
2. Selecting your default provider and model
3. Configuring basic settings`,
    'cyan'
  );

  // Check existing configuration
  const hasOpenRouter = hasApiKey('openrouter');
  const hasAnthropic = hasApiKey('anthropic');
  const hasOpenAI = hasApiKey('openai');
  const hasDeepSeek = hasApiKey('deepseek');
  const hasLiteLLM = config.hasLiteLLMProxy();

  if (hasOpenRouter || hasAnthropic || hasOpenAI || hasDeepSeek || hasLiteLLM) {
    console.log('');
    showInfo('Existing API keys detected:');
    if (hasOpenRouter) showSuccess('  OpenRouter: configured');
    if (hasAnthropic) showSuccess('  Anthropic: configured');
    if (hasOpenAI) showSuccess('  OpenAI: configured');
    if (hasDeepSeek) showSuccess('  DeepSeek: configured');
    if (hasLiteLLM) showSuccess('  LiteLLM Proxy: configured');
    console.log('');

    const { action } = await inquirer.prompt([
      {
        type: 'list',
        name: 'action',
        message: 'What would you like to do?',
        choices: [
          { name: 'Add/update API keys', value: 'keys' },
          { name: 'Change default provider/model', value: 'model' },
          { name: 'View current configuration', value: 'view' },
          { name: 'Reset all settings', value: 'reset' },
          { name: 'Exit', value: 'exit' },
        ],
      },
    ]);

    switch (action) {
      case 'keys':
        await setupApiKeys();
        break;
      case 'model':
        await setupProvider();
        await selectDefaultModel();
        break;
      case 'view':
        viewConfiguration();
        break;
      case 'reset':
        await resetConfiguration();
        break;
      case 'exit':
        return;
    }
  } else {
    // First-time setup
    await setupApiKeys();
    await setupProvider();
  }

  console.log('');
  showBox(
    'Setup Complete!',
    `VULNORA is now configured and ready to use.

Quick start:
${theme.active('npx vulnora')}        Start the interactive CLI
${theme.active('npx vulnora --help')} View all commands

Or use in your code:
${theme.muted(`import { createVulnora } from 'vulnora';
const vulnora = createVulnora({ name: 'My Operation' });`)}`,
    'green'
  );
}

async function setupApiKeys(): Promise<void> {
  const { providers } = await inquirer.prompt([
    {
      type: 'checkbox',
      name: 'providers',
      message: 'Which hosted API keys would you like to configure? Leave empty to use a local model only.',
      choices: [
        {
          name: `OpenRouter ${hasApiKey('openrouter') ? theme.success('(configured)') : theme.warning('(recommended)')}`,
          value: 'openrouter',
        },
        {
          name: `Venice ${hasApiKey('venice') ? theme.success('(configured)') : ''}`,
          value: 'venice',
        },
        {
          name: `Anthropic ${hasApiKey('anthropic') ? theme.success('(configured)') : ''}`,
          value: 'anthropic',
        },
        {
          name: `OpenAI ${hasApiKey('openai') ? theme.success('(configured)') : ''}`,
          value: 'openai',
        },
        {
          name: `DeepSeek ${hasApiKey('deepseek') ? theme.success('(configured)') : ''}`,
          value: 'deepseek',
        },
        {
          name: `LiteLLM Proxy ${config.hasLiteLLMProxy() ? theme.success('(configured)') : theme.muted('(100+ providers via gateway)')}`,
          value: 'litellm',
        },
      ],
    },
  ]);

  for (const provider of providers) {
    switch (provider) {
      case 'venice':
        await setupVeniceKey();
        break;
      case 'openrouter':
        await setupOpenRouterKey();
        break;
      case 'anthropic':
        await setupAnthropicKey();
        break;
      case 'openai':
        await setupOpenAIKey();
        break;
      case 'deepseek':
        await setupDeepSeekKey();
        break;
      case 'litellm':
        await setupLiteLLMProxy();
        break;
    }
  }
}

async function setupProvider(): Promise<void> {
  const configuredProviders = [];

  configuredProviders.push({ name: 'Local model (Ollama / LM Studio / vLLM, no API key)', value: 'local' });
  if (hasApiKey('openrouter')) configuredProviders.push({ name: 'OpenRouter', value: 'openrouter' });
  if (hasApiKey('venice')) configuredProviders.push({ name: 'Venice', value: 'venice' });
  if (hasApiKey('anthropic')) configuredProviders.push({ name: 'Anthropic', value: 'anthropic' });
  if (hasApiKey('openai')) configuredProviders.push({ name: 'OpenAI', value: 'openai' });
  if (hasApiKey('deepseek')) configuredProviders.push({ name: 'DeepSeek', value: 'deepseek' });
  if (config.hasLiteLLMProxy()) configuredProviders.push({ name: 'LiteLLM Proxy', value: 'litellm' });

  const { provider } = await inquirer.prompt([
    {
      type: 'list',
      name: 'provider',
      message: 'Select your default LLM provider:',
      choices: configuredProviders,
    },
  ]);

  config.setDefaultProvider(provider);
  showSuccess(`Default provider set to: ${provider}`);
}

function viewConfiguration(): void {
  const settings = config.getAll();

  console.log('');
  showInfo('Current Configuration:');
  console.log('');
  console.log(theme.active('  Default Provider: ') + settings.defaultProvider);
  console.log(theme.active('  Default Model: ') + settings.defaultModel);
  console.log(theme.active('  Max Tokens: ') + settings.maxTokens);
  console.log(theme.active('  Temperature: ') + settings.temperature);
  console.log('');
  console.log(theme.active('  API Keys:'));
  console.log('    OpenRouter: ' + (hasApiKey('openrouter') ? theme.success('configured') : theme.error('not set')));
  console.log('    Venice: ' + (hasApiKey('venice') ? theme.success('configured') : theme.error('not set')));
  console.log('    Anthropic: ' + (hasApiKey('anthropic') ? theme.success('configured') : theme.error('not set')));
  console.log('    OpenAI: ' + (hasApiKey('openai') ? theme.success('configured') : theme.error('not set')));
  console.log('    DeepSeek: ' + (hasApiKey('deepseek') ? theme.success('configured') : theme.error('not set')));
  console.log('    LiteLLM Proxy: ' + (config.hasLiteLLMProxy() ? theme.success('configured') : theme.error('not set')));
  console.log('');
  console.log(theme.active('  Config Path: ') + config.getConfigPath());
  console.log('');
}

async function resetConfiguration(): Promise<void> {
  const { confirm } = await inquirer.prompt([
    {
      type: 'confirm',
      name: 'confirm',
      message: 'Are you sure you want to reset all settings? This will remove all API keys.',
      default: false,
    },
  ]);

  if (confirm) {
    config.reset();
    showSuccess('All settings have been reset.');
  } else {
    showInfo('Reset cancelled.');
  }
}

// =============================================================================
// RUN
// =============================================================================

runSetup().catch(console.error);
