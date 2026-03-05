// ---------------------------------------------------------------------------
// @vulnhunter/core - AI Client Factory
// ---------------------------------------------------------------------------

import type { IAIClient } from "./interface.js";
import type { AIClientConfig, AIProvider } from "./types.js";
import { VulnHunterAIError } from "./types.js";

/**
 * Creates an AI client for the specified provider. Uses lazy dynamic imports
 * so that unused provider SDKs (openai, @google/generative-ai) are never loaded.
 */
export async function createAIClient(config: AIClientConfig): Promise<IAIClient> {
  switch (config.provider) {
    case "anthropic": {
      const { AnthropicProvider } = await import("./providers/anthropic.js");
      return new AnthropicProvider(config);
    }
    case "openai": {
      const { OpenAIProvider } = await import("./providers/openai.js");
      return new OpenAIProvider(config);
    }
    case "google": {
      const { GoogleProvider } = await import("./providers/google.js");
      return new GoogleProvider(config);
    }
    case "deepseek": {
      const { DeepSeekProvider } = await import("./providers/deepseek.js");
      return new DeepSeekProvider(config);
    }
    case "ollama": {
      const { OllamaProvider } = await import("./providers/ollama.js");
      return new OllamaProvider(config);
    }
    default:
      throw new VulnHunterAIError(
        `Unsupported AI provider: "${config.provider}". ` +
        `Supported: anthropic, openai, google, deepseek, ollama`,
        { code: "invalid_provider", retryable: false },
      );
  }
}

/**
 * Creates an AI client from environment variables.
 *
 * Reads:
 *  - `AI_PROVIDER`   — provider name (default: "anthropic")
 *  - `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / `GOOGLE_AI_API_KEY` / `DEEPSEEK_API_KEY`
 *  - `AI_MODEL`      — optional model override
 *  - `AI_MAX_TOKENS`  — optional max output tokens
 *  - `AI_BASE_URL`   — optional custom endpoint
 */
export async function createAIClientFromEnv(): Promise<IAIClient> {
  const provider = (process.env.AI_PROVIDER ?? "anthropic") as AIProvider;

  const apiKeyMap: Record<AIProvider, string | undefined> = {
    anthropic: process.env.ANTHROPIC_API_KEY,
    openai: process.env.OPENAI_API_KEY,
    google: process.env.GOOGLE_AI_API_KEY,
    deepseek: process.env.DEEPSEEK_API_KEY,
    ollama: process.env.OLLAMA_API_KEY ?? "ollama",
  };

  const apiKey = apiKeyMap[provider];
  if (!apiKey && provider !== "ollama") {
    throw new VulnHunterAIError(
      `Missing API key for provider "${provider}". ` +
      `Set the appropriate environment variable (e.g. ANTHROPIC_API_KEY, OPENAI_API_KEY).`,
      { code: "missing_api_key", retryable: false },
    );
  }

  const model = process.env.AI_MODEL || undefined;
  const maxTokens = process.env.AI_MAX_TOKENS ? Number(process.env.AI_MAX_TOKENS) : undefined;
  const baseUrl = process.env.AI_BASE_URL || undefined;

  return createAIClient({
    provider,
    apiKey,
    model,
    maxTokens,
    baseUrl,
  });
}
