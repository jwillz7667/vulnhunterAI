// ---------------------------------------------------------------------------
// @vulnhunter/core - Provider-Agnostic AI Types
// ---------------------------------------------------------------------------

/**
 * Supported AI providers. Each maps to a concrete provider implementation.
 */
export type AIProvider = "anthropic" | "openai" | "google" | "deepseek" | "ollama";

/**
 * Provider-agnostic chat message. Replaces Anthropic's `MessageParam`.
 */
export interface ChatMessage {
  role: "user" | "assistant";
  content: string;
}

/**
 * Provider-agnostic tool definition using JSON Schema for parameters.
 * Replaces Anthropic's `Tool` type.
 */
export interface ToolDefinition {
  name: string;
  description: string;
  parameters: Record<string, unknown>;
}

/**
 * Provider-agnostic tool call returned by the model.
 * Replaces Anthropic's `ToolUseBlock`.
 */
export interface ToolCall {
  id: string;
  name: string;
  arguments: Record<string, unknown>;
}

/**
 * Provider-agnostic chat response.
 */
export interface ChatResponse {
  content: string;
  toolCalls: ToolCall[];
  usage: TokenUsage;
}

/**
 * Token usage for a single request.
 */
export interface TokenUsage {
  inputTokens: number;
  outputTokens: number;
  cacheCreationInputTokens: number;
  cacheReadInputTokens: number;
}

/**
 * Snapshot of cumulative and per-request token usage.
 */
export interface TokenUsageSnapshot {
  /** Lifetime totals across all requests made by this client. */
  lifetime: TokenUsage;
  /** Usage from the most recent request. */
  lastRequest: TokenUsage;
  /** Total number of API calls made. */
  totalRequests: number;
}

/**
 * Unified configuration for creating any AI provider client.
 */
export interface AIClientConfig {
  provider: AIProvider;
  apiKey?: string;
  model?: string;
  maxTokens?: number;
  /** Requests per minute (default: 50). */
  rateLimitRpm?: number;
  /** Maximum retries on transient errors (default: 3). */
  maxRetries?: number;
  /** Base delay in ms for exponential backoff (default: 1000). */
  retryBaseDelayMs?: number;
  /** Maximum delay in ms for exponential backoff (default: 60000). */
  retryMaxDelayMs?: number;
  /** Custom base URL for the provider API. */
  baseUrl?: string;
}

// ---------------------------------------------------------------------------
// Custom Error
// ---------------------------------------------------------------------------

export class VulnHunterAIError extends Error {
  public readonly code: string;
  public readonly statusCode?: number;
  public readonly retryable: boolean;

  constructor(
    message: string,
    opts: { code: string; statusCode?: number; retryable?: boolean; cause?: Error },
  ) {
    super(message, { cause: opts.cause });
    this.name = "VulnHunterAIError";
    this.code = opts.code;
    this.statusCode = opts.statusCode;
    this.retryable = opts.retryable ?? false;
  }
}
