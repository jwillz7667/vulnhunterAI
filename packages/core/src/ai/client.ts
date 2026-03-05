// ---------------------------------------------------------------------------
// @vulnhunter/core - Backward-Compatible Anthropic Client
// ---------------------------------------------------------------------------
// This module preserves the original `AnthropicClient` class as a thin wrapper
// around `AnthropicProvider` so that existing code using
// `new AnthropicClient(config)` continues to work without changes.

import { AnthropicProvider } from "./providers/anthropic.js";

// Re-export types from their canonical location for backward compatibility
export { VulnHunterAIError } from "./types.js";
export type { TokenUsage, TokenUsageSnapshot } from "./types.js";

// ---------------------------------------------------------------------------
// Legacy configuration type (kept for backward compat)
// ---------------------------------------------------------------------------

export interface AnthropicClientConfig {
  apiKey: string;
  model?: string;
  maxTokens?: number;
  /** Requests per minute to the Anthropic API (default: 50). */
  rateLimitRpm?: number;
  /** Maximum retries on transient errors (default: 3). */
  maxRetries?: number;
  /** Base delay in ms for exponential backoff (default: 1000). */
  retryBaseDelayMs?: number;
  /** Maximum delay in ms for exponential backoff (default: 60000). */
  retryMaxDelayMs?: number;
}

// ---------------------------------------------------------------------------
// AnthropicClient — backward-compatible wrapper
// ---------------------------------------------------------------------------

export class AnthropicClient extends AnthropicProvider {
  constructor(config: AnthropicClientConfig) {
    super({
      provider: "anthropic",
      apiKey: config.apiKey,
      model: config.model,
      maxTokens: config.maxTokens,
      rateLimitRpm: config.rateLimitRpm,
      maxRetries: config.maxRetries,
      retryBaseDelayMs: config.retryBaseDelayMs,
      retryMaxDelayMs: config.retryMaxDelayMs,
    });
  }
}
