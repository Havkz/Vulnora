/**
 * VULNORA Configuration Management
 *
 * Handles API keys, settings, and persistent configuration.
 * Supports multiple LLM providers with easy key management.
 */

import Conf from 'conf';
import { homedir } from 'os';
import { dirname, join } from 'path';
import { existsSync, readFileSync, writeFileSync } from 'fs';
import type { LLMProvider, LLMConfig, FallbackEntry, OpsecLevel } from '../types/index.js';
import { configDirectory, migrateEnvironment, protectConfigSecrets } from './migration.js';
import { registerSecret } from '../redact.js';

export type ApiKeyProvider = 'openrouter' | 'venice' | 'anthropic' | 'openai' | 'xai' | 'gemini' | 'litellm' | 'deepseek' | 'local';

// =============================================================================
// CONFIGURATION SCHEMA
// =============================================================================

export interface VulnoraSettings {
  // API Keys
  apiKeys: {
    openrouter?: string;
    venice?: string;
    anthropic?: string;
    openai?: string;
    xai?: string;
    gemini?: string;
    deepseek?: string;
    litellm?: string;
    local?: string;
  };

  // Default LLM settings
  defaultProvider: LLMProvider;
  defaultModel: string;
  /** Explicit saved choices take precedence over inherited startup defaults. */
  userSelections: string[];

  scanningBehavior: 'auto' | 'stealth' | 'aggressive';
  local: { baseUrl: string; defaultModel: string };
  localAgent: { defaultModel: string };

  // OpenRouter specific
  openrouter: {
    baseUrl: string;
    defaultModel: string;
    siteUrl?: string;
    siteName?: string;
  };

  // Venice AI — OpenAI-compatible, privacy-focused (same wire shape as OpenRouter)
  venice: {
    baseUrl: string;
    defaultModel: string;
  };

  // Anthropic specific
  anthropic: {
    baseUrl: string;
    defaultModel: string;
  };

  // OpenAI specific
  openai: {
    baseUrl: string;
    defaultModel: string;
  };

  // xAI — Grok Build / Grok models (OpenAI-compatible API)
  xai: {
    baseUrl: string;
    defaultModel: string;
  };

  // LiteLLM AI gateway proxy — routes to 100+ LLM providers via unified API
  litellm: {
    baseUrl: string;
    defaultModel: string;
  };

  // Google Gemini — native Gemini API via its OpenAI-compatible endpoint
  gemini: {
    baseUrl: string;
    defaultModel: string;
  };

  // DeepSeek — OpenAI-compatible API
  deepseek: {
    baseUrl: string;
    defaultModel: string;
  };

  // Codex CLI/account subscription backend
  codex: {
    command: string;
    defaultModel: string;
  };

  // General settings
  maxTokens: number;
  temperature: number;
  timeout: number;

  // OPSEC defaults
  opsec: {
    level: OpsecLevel;
    maxDetectionEvents: number;
    cleanupOnComplete: boolean;
  };

  // UI preferences
  ui: {
    showBanner: boolean;
    colorOutput: boolean;
    verboseLogging: boolean;
  };
}

// =============================================================================
// DEFAULT CONFIGURATION
// =============================================================================

/** @deprecated Use VulnoraSettings. */
export type TempestSettings = VulnoraSettings;

const DEFAULT_SETTINGS: VulnoraSettings = {
  apiKeys: {},
  userSelections: [],

  defaultProvider: 'openrouter',
  defaultModel: 'anthropic/claude-opus-4.8',

  scanningBehavior: 'auto',
  local: { baseUrl: 'http://127.0.0.1:11434/api', defaultModel: '' },
  localAgent: { defaultModel: 'codex' },

  openrouter: {
    baseUrl: 'https://openrouter.ai/api/v1',
    defaultModel: 'anthropic/claude-opus-4.8',
    siteUrl: 'https://github.com/Havkz/Vulnora',
    siteName: 'VULNORA',
  },

  venice: {
    baseUrl: 'https://api.venice.ai/api/v1',
    defaultModel: 'llama-3.3-70b',
  },

  anthropic: {
    baseUrl: 'https://api.anthropic.com',
    defaultModel: 'claude-opus-4-8',
  },

  openai: {
    baseUrl: 'https://api.openai.com/v1',
    defaultModel: 'gpt-4-turbo-preview',
  },

  xai: {
    baseUrl: 'https://api.x.ai/v1',
    defaultModel: 'grok-build-0.1',
  },

  litellm: {
    baseUrl: 'http://localhost:4000/v1',
    defaultModel: 'gpt-4o',
  },

  // Gemini's OpenAI-compatible surface lives under /v1beta/openai. The OpenAIAdapter posts to
  // `${baseUrl}/chat/completions`, so the /openai path segment is REQUIRED here — without it,
  // requests hit /v1beta/chat/completions, which is not a valid Gemini endpoint.
  gemini: {
    baseUrl: 'https://generativelanguage.googleapis.com/v1beta/openai',
    defaultModel: 'gemini-2.5-flash',
  },

  deepseek: {
    baseUrl: 'https://api.deepseek.com/v1',
    defaultModel: 'deepseek-chat',
  },

  codex: {
    command: 'codex',
    defaultModel: 'codex-default',
  },

  maxTokens: 4096,
  temperature: 0.7,
  timeout: 60000,

  opsec: {
    level: 'covert',
    maxDetectionEvents: 3,
    cleanupOnComplete: true,
  },

  ui: {
    showBanner: true,
    colorOutput: true,
    verboseLogging: false,
  },
};

// =============================================================================
// MODEL REGISTRY
// =============================================================================

export interface ModelInfo {
  id: string;
  name: string;
  provider: string;
  contextWindow: number;
  maxOutput: number;
  pricing?: {
    prompt: number;
    completion: number;
  };
  capabilities: string[];
}

export const AVAILABLE_MODELS: Record<LLMProvider, ModelInfo[]> = {
  deterministic: [],
  venice: [
    {
      id: 'llama-3.3-70b',
      name: 'Llama 3.3 70B (Venice)',
      provider: 'Venice',
      contextWindow: 65536,
      maxOutput: 8192,
      capabilities: ['reasoning', 'code', 'analysis', 'uncensored', 'tools'],
    },
    {
      id: 'venice-uncensored',
      name: 'Venice Uncensored',
      provider: 'Venice',
      contextWindow: 32768,
      maxOutput: 8192,
      capabilities: ['reasoning', 'uncensored'],
    },
  ],

  openrouter: [
    // Anthropic (Feb 2026)
    {
      id: 'anthropic/claude-opus-4.8',
      name: 'Claude Opus 4.8',
      provider: 'Anthropic',
      contextWindow: 200000,
      maxOutput: 32000,
      capabilities: ['reasoning', 'code', 'analysis', 'vision', 'complex-tasks', 'agents', 'tools'],
    },
    {
      id: 'anthropic/claude-sonnet-4.5',
      name: 'Claude Sonnet 4.5',
      provider: 'Anthropic',
      contextWindow: 200000,
      maxOutput: 16384,
      capabilities: ['reasoning', 'code', 'analysis', 'vision', 'agents', 'tools'],
    },
    {
      id: 'anthropic/claude-haiku-4.5',
      name: 'Claude Haiku 4.5',
      provider: 'Anthropic',
      contextWindow: 200000,
      maxOutput: 8192,
      capabilities: ['reasoning', 'code', 'analysis', 'fast', 'tools'],
    },
    {
      id: 'anthropic/claude-sonnet-4',
      name: 'Claude Sonnet 4',
      provider: 'Anthropic',
      contextWindow: 200000,
      maxOutput: 8192,
      capabilities: ['reasoning', 'code', 'analysis', 'vision'],
    },
    // OpenAI
    {
      id: 'openai/gpt-4o',
      name: 'GPT-4o',
      provider: 'OpenAI',
      contextWindow: 128000,
      maxOutput: 4096,
      capabilities: ['reasoning', 'code', 'analysis', 'vision', 'fast'],
    },
    {
      id: 'openai/o1',
      name: 'o1',
      provider: 'OpenAI',
      contextWindow: 200000,
      maxOutput: 100000,
      capabilities: ['reasoning', 'code', 'analysis', 'complex-tasks'],
    },
    // Google (Dec 2025)
    {
      id: 'google/gemini-3.1-pro-preview',
      name: 'Gemini 3 Pro',
      provider: 'Google',
      contextWindow: 1000000,
      maxOutput: 8192,
      capabilities: ['reasoning', 'code', 'analysis', 'vision', 'multimodal'],
    },
    {
      id: 'google/gemini-3-flash-preview',
      name: 'Gemini 3 Flash',
      provider: 'Google',
      contextWindow: 1000000,
      maxOutput: 8192,
      capabilities: ['reasoning', 'code', 'analysis', 'vision', 'fast'],
    },
    {
      id: 'google/gemini-2.5-flash',
      name: 'Gemini 2.5 Flash',
      provider: 'Google',
      contextWindow: 1000000,
      maxOutput: 8192,
      capabilities: ['reasoning', 'code', 'analysis', 'vision'],
    },
    // xAI (Dec 2025)
    {
      id: 'x-ai/grok-4',
      name: 'Grok 4',
      provider: 'xAI',
      contextWindow: 256000,
      maxOutput: 8192,
      capabilities: ['reasoning', 'code', 'analysis', 'vision'],
    },
    {
      id: 'x-ai/grok-4-fast',
      name: 'Grok 4 Fast',
      provider: 'xAI',
      contextWindow: 2000000,
      maxOutput: 8192,
      capabilities: ['reasoning', 'code', 'analysis', 'fast'],
    },
    {
      id: 'x-ai/grok-4.1-fast',
      name: 'Grok 4.1 Fast',
      provider: 'xAI',
      contextWindow: 2000000,
      maxOutput: 8192,
      capabilities: ['reasoning', 'code', 'analysis', 'agents', 'tools'],
    },
    // Z.AI (Dec 2025)
    {
      id: 'z-ai/glm-4.7',
      name: 'GLM 4.7',
      provider: 'Z.AI',
      contextWindow: 203000,
      maxOutput: 8192,
      capabilities: ['reasoning', 'code', 'analysis', 'agents'],
    },
    // Meta
    {
      id: 'meta-llama/llama-3.3-70b',
      name: 'Llama 3.3 70B',
      provider: 'Meta',
      contextWindow: 131072,
      maxOutput: 4096,
      capabilities: ['reasoning', 'code', 'analysis'],
    },
    // DeepSeek (Dec 2025)
    {
      id: 'deepseek/deepseek-r1',
      name: 'DeepSeek R1',
      provider: 'DeepSeek',
      contextWindow: 64000,
      maxOutput: 8192,
      capabilities: ['reasoning', 'code', 'analysis', 'complex-tasks'],
    },
    {
      id: 'deepseek/deepseek-chat',
      name: 'DeepSeek V3',
      provider: 'DeepSeek',
      contextWindow: 64000,
      maxOutput: 8192,
      capabilities: ['reasoning', 'code', 'analysis'],
    },
    // Mistral
    {
      id: 'mistralai/mistral-large',
      name: 'Mistral Large',
      provider: 'Mistral',
      contextWindow: 128000,
      maxOutput: 4096,
      capabilities: ['reasoning', 'code', 'analysis'],
    },
  ],
  anthropic: [
    {
      id: 'claude-opus-4-8',
      name: 'Claude Opus 4.8',
      provider: 'Anthropic',
      contextWindow: 200000,
      maxOutput: 32000,
      capabilities: ['reasoning', 'code', 'analysis', 'vision', 'complex-tasks', 'agents', 'tools'],
    },
    {
      id: 'claude-sonnet-4-5-20250929',
      name: 'Claude Sonnet 4.5',
      provider: 'Anthropic',
      contextWindow: 200000,
      maxOutput: 16384,
      capabilities: ['reasoning', 'code', 'analysis', 'vision', 'agents', 'tools'],
    },
    {
      id: 'claude-haiku-4-5-20251001',
      name: 'Claude Haiku 4.5',
      provider: 'Anthropic',
      contextWindow: 200000,
      maxOutput: 8192,
      capabilities: ['reasoning', 'code', 'analysis', 'fast', 'tools'],
    },
    {
      id: 'claude-sonnet-4-20250514',
      name: 'Claude Sonnet 4',
      provider: 'Anthropic',
      contextWindow: 200000,
      maxOutput: 8192,
      capabilities: ['reasoning', 'code', 'analysis', 'vision'],
    },
  ],
  openai: [
    {
      id: 'gpt-4-turbo-preview',
      name: 'GPT-4 Turbo',
      provider: 'OpenAI',
      contextWindow: 128000,
      maxOutput: 4096,
      capabilities: ['reasoning', 'code', 'analysis', 'vision'],
    },
    {
      id: 'gpt-4o',
      name: 'GPT-4o',
      provider: 'OpenAI',
      contextWindow: 128000,
      maxOutput: 4096,
      capabilities: ['reasoning', 'code', 'analysis', 'vision', 'fast'],
    },
  ],
  litellm: [
    {
      id: 'gpt-4o',
      name: 'Any model via LiteLLM proxy (default: gpt-4o)',
      provider: 'LiteLLM',
      contextWindow: 128000,
      maxOutput: 4096,
      capabilities: ['reasoning', 'code', 'analysis', 'vision', 'tools'],
    },
  ],
  codex: [
    {
      id: 'codex-default',
      name: 'Codex Account Default',
      provider: 'Codex',
      contextWindow: 200000,
      maxOutput: 8192,
      capabilities: ['reasoning', 'code', 'analysis', 'agents', 'local-cli'],
    },
  ],
  mock: [
    {
      id: 'mock-model',
      name: 'Mock Model',
      provider: 'Mock',
      contextWindow: 100000,
      maxOutput: 4096,
      capabilities: ['testing'],
    },
  ],
  // Model IDs verified against xAI's published model list (docs.x.ai/docs/models, 2026-07-05):
  // grok-build-0.1 = coding model (256K ctx); grok-4.3 = general (1M ctx). Any current xAI
  // model id can be passed via config/CLI/model arg — these are just the curated defaults.
  xai: [
    {
      id: 'grok-build-0.1',
      name: 'Grok Build (grok-build-0.1, 256K)',
      provider: 'xAI',
      contextWindow: 256000,
      maxOutput: 8192,
      capabilities: ['reasoning', 'code', 'analysis', 'agents', 'tools'],
    },
    {
      id: 'grok-4.3',
      name: 'Grok 4.3 (general, 1M)',
      provider: 'xAI',
      contextWindow: 1000000,
      maxOutput: 8192,
      capabilities: ['reasoning', 'code', 'analysis', 'agents', 'tools'],
    },
  ],
  // Native Gemini model ids (bare, no `google/` prefix) for Google's OpenAI-compatible endpoint.
  // Distinct from the `google/gemini-*` ids under `openrouter`, which route through OpenRouter.
  gemini: [
    {
      id: 'gemini-2.5-flash',
      name: 'Gemini 2.5 Flash (native)',
      provider: 'Google',
      contextWindow: 1000000,
      maxOutput: 8192,
      capabilities: ['reasoning', 'code', 'analysis', 'vision', 'fast', 'tools'],
    },
    {
      id: 'gemini-2.5-pro',
      name: 'Gemini 2.5 Pro (native)',
      provider: 'Google',
      contextWindow: 1000000,
      maxOutput: 8192,
      capabilities: ['reasoning', 'code', 'analysis', 'vision', 'multimodal', 'tools'],
    },
    {
      id: 'gemini-2.0-flash',
      name: 'Gemini 2.0 Flash (native)',
      provider: 'Google',
      contextWindow: 1000000,
      maxOutput: 8192,
      capabilities: ['reasoning', 'code', 'analysis', 'vision', 'fast', 'tools'],
    },
  ],
  deepseek: [
    {
      id: 'deepseek-chat',
      name: 'DeepSeek V3 (native)',
      provider: 'DeepSeek',
      contextWindow: 64000,
      maxOutput: 8192,
      capabilities: ['reasoning', 'code', 'analysis', 'tools'],
    },
    {
      id: 'deepseek-reasoner',
      name: 'DeepSeek R1 (native)',
      provider: 'DeepSeek',
      contextWindow: 64000,
      maxOutput: 8192,
      capabilities: ['reasoning', 'code', 'analysis', 'complex-tasks'],
    },
  ],
  local: [
    {
      id: 'local-model',
      name: 'Local model (Ollama / LM Studio / vLLM — set VULNORA_LOCAL_MODEL)',
      provider: 'Local',
      contextWindow: 32000,
      maxOutput: 4096,
      capabilities: ['reasoning', 'code', 'tools'],
    },
  ],
  'local-agent': [
    // Connected local agent CLIs used AS the LLM backend — no API key (each uses its own login).
    // The chosen agent id (codex|claude|hermes) travels in the `model` field.
    {
      id: 'codex',
      name: 'Codex (local CLI)',
      provider: 'LocalAgent',
      contextWindow: 200000,
      maxOutput: 8192,
      capabilities: ['reasoning', 'code', 'analysis', 'agents', 'local-cli'],
    },
    {
      id: 'claude',
      name: 'Claude Code (local CLI)',
      provider: 'LocalAgent',
      contextWindow: 200000,
      maxOutput: 8192,
      capabilities: ['reasoning', 'code', 'analysis', 'agents', 'local-cli'],
    },
    {
      id: 'hermes',
      name: 'Hermes (local CLI)',
      provider: 'LocalAgent',
      contextWindow: 32000,
      maxOutput: 8192,
      capabilities: ['reasoning', 'code', 'agents', 'local-cli'],
    },
  ],
};

// =============================================================================
// CONFIGURATION MANAGER
// =============================================================================

class ConfigManager {
  private config: Conf<VulnoraSettings>;
  private envLoaded: boolean = false;

  constructor() {
    const directory = configDirectory();
    this.config = new Conf<VulnoraSettings>({
      projectName: 'vulnora',
      cwd: directory,
      defaults: DEFAULT_SETTINGS,
      configFileMode: 0o600,
    });

    if (process.platform !== 'win32' || Object.keys(this.config.get('apiKeys')).length || existsSync(join(directory, '.env'))) protectConfigSecrets(directory);

    this.loadEnvVariables();
  }

  /**
   * Load API keys from environment variables
   */
  private loadEnvVariables(): void {
    if (this.envLoaded) return;

    // Load only VULNORA-owned/home env files. Do NOT read process.cwd()/.env:
    // operators often run VULNORA inside target repos, and importing that repo's
    // secrets would contaminate this process with unrelated credentials.
    const envPaths = process.env.VULNORA_CONFIG_DIR ? [join(process.env.VULNORA_CONFIG_DIR, '.env')] : [
      join(homedir(), '.vulnora', '.env'),
      join(homedir(), '.env'),
    ];

    let envProvider: string | undefined;

    for (const envPath of envPaths) {
      if (existsSync(envPath)) {
        const envContent = readFileSync(envPath, 'utf-8');
        const lines = envContent.split('\n');
        // Validation variables added
        const VALID_PROVIDERS = ['openrouter', 'venice', 'anthropic', 'openai', 'xai', 'gemini', 'litellm', 'deepseek', 'local', 'codex', 'local-agent'];

        for (const line of lines) {
          const trimmed = line.trim();
          if (trimmed && !trimmed.startsWith('#')) {
            const [key, ...valueParts] = trimmed.split('=');
            const value = valueParts.join('=').replace(/^["']|["']$/g, '');
            // Real env vars take precedence over the .env file (standard dotenv
            // semantics): only fill a key that is not already set. This also lets a
            // caller force an UNCONFIGURED server (e.g. arsenal:smoke) by exporting an
            // empty OPENROUTER_API_KEY= — the .env file no longer clobbers it.
            if (key && value && process.env[key] === undefined) {
              process.env[key] = value;

              // Track LLM_PROVIDER for default provider
              if (key === 'LLM_PROVIDER' && VALID_PROVIDERS.includes(value.toLowerCase())) {
                envProvider = value.toLowerCase();
              }
            }
          }
        }
        // Set VULNORA_DEFAULT_PROVIDER if LLM_PROVIDER found
        if (envProvider && !process.env.VULNORA_DEFAULT_PROVIDER) {
          process.env.VULNORA_DEFAULT_PROVIDER = envProvider;
        }
        break;
      }
    }

    migrateEnvironment();
    // Environment variables (including values loaded from ~/.vulnora/.env above)
    // are intentionally process-local defaults, so do not persist them into
    // Conf's apiKeys store as a side effect. Explicit saved choices take precedence.
    // (XAI_API_KEY / Grok Build follows the same safe path — see the envVarMap in getApiKey.)
    this.envLoaded = true;
  }

  /**
   * Get all settings
   */
  getAll(): VulnoraSettings {
    return this.config.store;
  }

  /**
   * Get a specific setting
   */
  get<K extends keyof VulnoraSettings>(key: K): VulnoraSettings[K] {
    return this.config.get(key);
  }

  /**
   * Set a specific setting
   */
  set<K extends keyof VulnoraSettings>(key: K, value: VulnoraSettings[K]): void {
    this.config.set(key, value);
  }

  /**
   * Set an API key for a provider
   */
  setApiKey(provider: ApiKeyProvider, key: string): void {
    protectConfigSecrets(dirname(this.getConfigPath()));
    const apiKeys = this.config.get('apiKeys');
    apiKeys[provider] = key;
    this.config.set({ apiKeys, userSelections: this.selections(`apiKey:${provider}`) });
    registerSecret(key);
  }

  /**
   * Get an API key for a provider
   */
  getApiKey(provider: ApiKeyProvider): string | undefined {
    if (/^(1|true|yes|on)$/i.test((process.env.VULNORA_FORCE_UNCONFIGURED || '').trim())) return undefined;
    if (this.selected(`apiKey:${provider}`)) return this.config.get('apiKeys')[provider];
    // Environment supplies defaults until the user explicitly replaces a key.
    // local provider: a self-hosted/OpenAI-compatible server MAY require a bearer
    // (Zhipu/z.ai, Together, etc.) — accept VULNORA_LOCAL_API_KEY or provider-specific vars.
    if (provider === 'local') {
      const localKey = process.env.VULNORA_LOCAL_API_KEY?.trim() || process.env.ZAI_API_KEY?.trim() || process.env.ZHIPUAI_API_KEY?.trim();
      if (localKey) return localKey;
      return this.config.get('apiKeys')[provider];
    }
    const envVarMap = {
      openrouter: 'OPENROUTER_API_KEY',
      venice: 'VENICE_API_KEY',
      anthropic: 'ANTHROPIC_API_KEY',
      openai: 'OPENAI_API_KEY',
      xai: 'XAI_API_KEY',
      gemini: 'GEMINI_API_KEY',
      deepseek: 'DEEPSEEK_API_KEY',
      litellm: 'LITELLM_API_KEY',
    };

    // Force a fully UNCONFIGURED server (no key from env OR the saved store) — used by
    // arsenal:smoke so the key-required / fail-closed paths are exercisable. Gated behind
    // an explicit flag so a normal operator's STORED key is NEVER silently disabled by an
    // empty exported env var (round-2 code-sweep regression fix).

    const envKey = process.env[envVarMap[provider]];
    if (envKey) return envKey;   // a non-empty env var wins; empty/unset falls through

    // Otherwise fall back to the stored config
    return this.config.get('apiKeys')[provider];
  }

  /**
   * Check if a provider has a valid API key configured
   */
  hasApiKey(provider: ApiKeyProvider): boolean {
    const key = this.getApiKey(provider);
    return !!key && key.length > 10;
  }

  /**
   * Remove an API key
   */
  removeApiKey(provider: ApiKeyProvider): void {
    const apiKeys = this.config.get('apiKeys');
    delete apiKeys[provider];
    this.config.set({ apiKeys, userSelections: this.selections().filter(value => value !== `apiKey:${provider}`) });
  }

  /**
   * Check if a LiteLLM proxy is configured (base URL set via env or config)
   */
  hasLiteLLMProxy(): boolean {
    const envUrl = process.env.LITELLM_BASE_URL?.trim();
    if (envUrl) return true;
    const storedUrl = this.config.get('litellm')?.baseUrl;
    return !!storedUrl && storedUrl !== 'http://localhost:4000/v1';
  }

  /**
   * Get configured providers (those with API keys)
   */
  getConfiguredProviders(): LLMProvider[] {
    const providers: LLMProvider[] = [];

    if (this.hasApiKey('openrouter')) providers.push('openrouter');
    if (this.hasApiKey('venice')) providers.push('venice');
    if (this.hasApiKey('anthropic')) providers.push('anthropic');
    if (this.hasApiKey('openai')) providers.push('openai');
    if (this.hasApiKey('xai')) providers.push('xai');
    if (this.hasLiteLLMProxy()) providers.push('litellm');
    if (this.hasApiKey('gemini')) providers.push('gemini');
    if (this.hasApiKey('deepseek')) providers.push('deepseek');

    // Codex uses the local Codex CLI/account auth instead of API-key storage.
    providers.push('codex');

    // Mock and local are always available
    providers.push('mock', 'local');

    return providers;
  }

  /**
   * Get the LLM configuration for the default or specified provider
   */
  getLLMConfig(provider?: LLMProvider, model?: string): LLMConfig {
    let actualProvider = provider;

    if (!actualProvider) {
      const envProvider = process.env.VULNORA_DEFAULT_PROVIDER?.trim();
      if (envProvider && !this.selected('provider')) {
        actualProvider = envProvider as LLMProvider;
      } else {
        actualProvider = this.config.get('defaultProvider');
      }
    }

    let apiKey: string | undefined;
    let baseUrl: string | undefined;
    let actualModel: string;

    switch (actualProvider) {
      case 'openrouter':
        apiKey = this.getApiKey('openrouter');
        baseUrl = this.config.get('openrouter').baseUrl;
        actualModel = model || this.config.get('openrouter').defaultModel;
        break;
      case 'venice':
        apiKey = this.getApiKey('venice');
        baseUrl = this.config.get('venice').baseUrl;
        actualModel = model || this.config.get('venice').defaultModel;
        break;
      case 'anthropic':
        apiKey = this.getApiKey('anthropic');
        baseUrl = this.config.get('anthropic').baseUrl;
        actualModel = model || this.config.get('anthropic').defaultModel;
        break;
      case 'openai':
        apiKey = this.getApiKey('openai');
        baseUrl = this.config.get('openai').baseUrl;
        actualModel = model || this.config.get('openai').defaultModel;
        break;
      case 'xai':
        // Grok Build / Grok — xAI's OpenAI-compatible API (native tool-calling).
        apiKey = this.getApiKey('xai');
        baseUrl = this.config.get('xai').baseUrl;
        actualModel = model || this.config.get('xai').defaultModel;
        break;
      case 'litellm':
        apiKey = this.getApiKey('litellm');
        baseUrl = process.env.LITELLM_BASE_URL?.trim() || this.config.get('litellm').baseUrl;
        actualModel = model || (this.selected('model:litellm') ? this.config.get('litellm').defaultModel : undefined)
          || process.env.LITELLM_MODEL?.trim() || this.config.get('litellm').defaultModel;
        break;
      case 'gemini':
        // Google Gemini via its OpenAI-compatible endpoint (native tool-calling).
        apiKey = this.getApiKey('gemini');
        baseUrl = this.config.get('gemini').baseUrl;
        actualModel = model || this.config.get('gemini').defaultModel;
        break;
      case 'deepseek':
        // DeepSeek native API is OpenAI-compatible.
        apiKey = this.getApiKey('deepseek');
        baseUrl = this.config.get('deepseek').baseUrl;
        actualModel = model || this.config.get('deepseek').defaultModel;
        break;
      case 'codex':
        actualModel = model || this.config.get('codex').defaultModel;
        break;
      case 'local-agent':
        actualModel = model || this.config.get('localAgent').defaultModel;
        break;
      case 'mock':
        actualModel = 'mock-model';
        break;
      case 'deterministic':
        actualModel = 'evidence-only';
        break;
      case 'local':
        // Self-hosted, usually keyless. Defaults to Ollama; point VULNORA_LOCAL_BASE_URL at
        // any OpenAI-compatible server (LM Studio :1234/v1, vLLM :8000/v1, llama.cpp, Zhipu/z.ai
        // /api/paas/v4) and VULNORA_LOCAL_MODEL at the model tag you're serving.
        // Some OpenAI-compatible servers require a real bearer (Zhipu, Together, etc.) —
        // VULNORA_LOCAL_API_KEY (or a provider-specific env like ZAI_API_KEY) provides it.
        baseUrl = process.env.VULNORA_LOCAL_BASE_URL?.trim() || this.config.get('local').baseUrl;
        // Placeholder ids from AVAILABLE_MODELS / the static UI are not real served model tags.
        // Treat them as unset so VULNORA_LOCAL_MODEL (or the llama3 default) wins; a real tag
        // passed in still takes priority.
        actualModel = (model && !['local-model', 'local/ollama'].includes(model) ? model : undefined)
          || (this.selected('model:local') ? this.config.get('local').defaultModel : undefined)
          || process.env.VULNORA_LOCAL_MODEL?.trim() || this.config.get('local').defaultModel || 'llama3';
        apiKey = this.getApiKey('local');
        break;
      default:
        throw new Error(`Unknown provider: ${actualProvider}`);
    }

    return {
      provider: actualProvider,
      model: actualModel,
      apiKey,
      baseUrl,
      maxTokens: this.config.get('maxTokens'),
      temperature: this.config.get('temperature'),
      timeout: this.config.get('timeout'),
      fallbackChain: this.buildFallbackChain(actualProvider),
    };
  }

  /**
   * Opt-in model fallback ladder. When VULNORA_MODEL_FALLBACK is set, any primary-
   * model failure that the model can't self-recover from — a refusal, an empty 200,
   * or a hard error that survives same-model retries (rate-limit, 5xx, timeout, dead
   * key, missing model, context blowout) — escalates across the OTHER configured
   * providers in priority order (openrouter → venice → anthropic → openai), each with its own
   * key/model. VULNORA_MODEL_FALLBACK=local selects the configured local/Ollama
   * model as the sole fallback. OFF by default (no surprise model-switching). On a refusal the real
   * authorization context is restated — honest escalation, no jailbreak prompts
   * (see LLMBackbone.chat).
   */
  private buildFallbackChain(primary: LLMProvider): FallbackEntry[] {
    const flag = (process.env.VULNORA_MODEL_FALLBACK || '').trim().toLowerCase();
    if (!flag || ['0', 'false', 'off', 'no'].includes(flag)) return [];
    const chain: FallbackEntry[] = [];
    if (['local', 'ollama'].includes(flag)) {
      if (primary !== 'local') {
        const local = this.getLLMConfig('local');
        chain.push({
          provider: 'local',
          model: local.model,
          apiKey: local.apiKey,
          baseUrl: local.baseUrl,
        });
      }
      return chain;
    }
    const add = (p: 'openrouter' | 'venice' | 'anthropic' | 'openai' | 'xai' | 'gemini' | 'litellm' | 'deepseek') => {
      if (p === primary) return;
      if (p === 'litellm' ? !this.hasLiteLLMProxy() : !this.hasApiKey(p)) return;
      chain.push({
        provider: p,
        model: this.config.get(p).defaultModel,
        apiKey: this.getApiKey(p),
        baseUrl: this.config.get(p).baseUrl,
      });
    };
    add('openrouter');
    add('venice');
    add('litellm');
    add('anthropic');
    add('openai');
    add('xai');
    add('gemini');
    add('deepseek');
    return chain;
  }

  /**
   * Set the default provider
   */
  setDefaultProvider(provider: LLMProvider): void {
    this.config.set({ defaultProvider: provider, defaultModel: this.getLLMConfig(provider).model,
      userSelections: this.selections('provider') });
  }

  /**
   * Set the default model for a provider
   */
  setDefaultModel(provider: LLMProvider, model: string): void {
    const changes: Partial<VulnoraSettings> = { userSelections: this.selections(`model:${provider}`) };
    if (provider !== 'mock' && provider !== 'deterministic') {
      const key = provider === 'local-agent' ? 'localAgent' : provider;
      if (!Object.hasOwn(DEFAULT_SETTINGS, key)) throw new Error(`Unknown provider: ${provider}`);
      Object.assign(changes, { [key]: { ...this.config.get(key), defaultModel: model } });
    }
    if (this.config.get('defaultProvider') === provider) changes.defaultModel = model;
    this.config.set(changes);
  }

  /**
   * Reset to default settings
   */
  reset(): void {
    this.config.clear();
  }

  private selections(key?: string): string[] {
    const saved = this.config.get('userSelections');
    const values = Array.isArray(saved) ? saved.filter(value => typeof value === 'string') : [];
    return [...new Set([...values, ...(key ? [key] : [])])];
  }

  private selected(key: string): boolean { return this.selections().includes(key); }

  /**
   * Get the config file path
   */
  getConfigPath(): string {
    return this.config.path;
  }

  /**
   * Export configuration to a file
   */
  exportConfig(filePath: string): void {
    const settings = this.getAll();
    // Remove sensitive data
    const safeSettings = {
      ...settings,
      apiKeys: {
        openrouter: settings.apiKeys.openrouter ? '***REDACTED***' : undefined,
        venice: settings.apiKeys.venice ? '***REDACTED***' : undefined,
        anthropic: settings.apiKeys.anthropic ? '***REDACTED***' : undefined,
        openai: settings.apiKeys.openai ? '***REDACTED***' : undefined,
        xai: settings.apiKeys.xai ? '***REDACTED***' : undefined,
        gemini: settings.apiKeys.gemini ? '***REDACTED***' : undefined,
        deepseek: settings.apiKeys.deepseek ? '***REDACTED***' : undefined,
        litellm: settings.apiKeys.litellm ? '***REDACTED***' : undefined,
      },
    };
    writeFileSync(filePath, JSON.stringify(safeSettings, null, 2));
  }

  /**
   * Create a .env template file
   */
  createEnvTemplate(filePath: string = join(process.cwd(), '.env.template')): void {
    const template = `# VULNORA Environment Configuration
# Save this file as ~/.vulnora/.env and fill in your API keys
# The setup script writes the same VULNORA-owned file.

# OpenRouter API Key (recommended - access to multiple models)
# Get your key at: https://openrouter.ai/keys
OPENROUTER_API_KEY=

# Venice API Key
# Get your key at: https://venice.ai
VENICE_API_KEY=

# Anthropic API Key (direct Claude access)
# Get your key at: https://console.anthropic.com/
ANTHROPIC_API_KEY=

# OpenAI API Key
# Get your key at: https://platform.openai.com/api-keys
OPENAI_API_KEY=

# xAI API Key
# Get your key at: https://console.x.ai/
XAI_API_KEY=

# LiteLLM Proxy (AI gateway — 100+ providers via single API)
# Docs: https://docs.litellm.ai/docs/proxy/quick_start
LITELLM_BASE_URL=http://localhost:4000/v1
LITELLM_API_KEY=
LITELLM_MODEL=gpt-4o

# Google Gemini API Key (direct Gemini API via its OpenAI-compatible endpoint)
# Get your key at: https://aistudio.google.com/apikey
GEMINI_API_KEY=

# DeepSeek API Key (direct DeepSeek API via its OpenAI-compatible endpoint)
# Get your key at: https://platform.deepseek.com/api_keys
DEEPSEEK_API_KEY=

# Local model (Ollama / LM Studio / vLLM / llama.cpp, or any OpenAI-compatible server)
# Point VULNORA_LOCAL_BASE_URL at the server root (Ollama default shown below).
# For an OpenAI-compatible server, use a versioned path: LM Studio :1234/v1,
# vLLM :8000/v1, or e.g. Zhipu/z.ai /api/paas/v4 — any /vN path speaks the
# OpenAI wire (/chat/completions, choices[]); otherwise the Ollama native format is used.
# Most local servers are keyless; if yours requires a bearer (Zhipu, Together, …)
# set VULNORA_LOCAL_API_KEY (ZAI_API_KEY / ZHIPUAI_API_KEY are accepted as aliases).
VULNORA_LOCAL_BASE_URL=http://localhost:11434/api
VULNORA_LOCAL_MODEL=llama3
VULNORA_LOCAL_API_KEY=
`;
    writeFileSync(filePath, template);
  }
}

// =============================================================================
// SINGLETON EXPORT
// =============================================================================

export const config = new ConfigManager();

// Helper functions for quick access
export const getApiKey = (provider: ApiKeyProvider) => config.getApiKey(provider);
export const setApiKey = (provider: ApiKeyProvider, key: string) => config.setApiKey(provider, key);
export const hasApiKey = (provider: ApiKeyProvider) => config.hasApiKey(provider);
export const getLLMConfig = (provider?: LLMProvider, model?: string) => config.getLLMConfig(provider, model);
export const getConfiguredProviders = () => config.getConfiguredProviders();
