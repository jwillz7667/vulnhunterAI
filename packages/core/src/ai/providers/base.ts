// ---------------------------------------------------------------------------
// @vulnhunter/core - Base AI Provider
// ---------------------------------------------------------------------------

import type { IAIClient } from "../interface.js";
import type {
  AIProvider,
  AIClientConfig,
  ChatMessage,
  ChatResponse,
  TokenUsage,
  TokenUsageSnapshot,
  ToolDefinition,
  VulnHunterAIError,
} from "../types.js";
import { VulnHunterAIError as AIError } from "../types.js";
import { createLogger } from "../../utils/logger.js";
import { withRetry } from "../../utils/retry.js";
import { RateLimiter } from "../../utils/rate-limiter.js";

const log = createLogger("ai:provider");

const RETRYABLE_ERROR_MESSAGES = [
  "overloaded",
  "rate_limit",
  "timeout",
  "ECONNRESET",
  "ETIMEDOUT",
  "socket hang up",
];

/**
 * Abstract base class for all AI providers. Handles token tracking,
 * rate limiting, retry logic, and the `analyze()` convenience method.
 *
 * Subclasses implement `_doChat()` and `_doStream()` with provider-specific SDK calls.
 */
export abstract class BaseAIProvider implements IAIClient {
  public readonly provider: AIProvider;
  public readonly modelId: string;

  protected readonly maxTokens: number;
  protected readonly maxRetries: number;
  protected readonly retryBaseDelayMs: number;
  protected readonly retryMaxDelayMs: number;
  protected readonly rateLimiter: RateLimiter;
  protected readonly baseUrl?: string;

  private lifetimeUsage: TokenUsage = {
    inputTokens: 0,
    outputTokens: 0,
    cacheCreationInputTokens: 0,
    cacheReadInputTokens: 0,
  };
  private lastRequestUsage: TokenUsage = {
    inputTokens: 0,
    outputTokens: 0,
    cacheCreationInputTokens: 0,
    cacheReadInputTokens: 0,
  };
  private totalRequests = 0;

  constructor(config: AIClientConfig) {
    this.provider = config.provider;
    this.modelId = config.model ?? this.getDefaultModel();
    this.maxTokens = config.maxTokens ?? 8192;
    this.maxRetries = config.maxRetries ?? 3;
    this.retryBaseDelayMs = config.retryBaseDelayMs ?? 1000;
    this.retryMaxDelayMs = config.retryMaxDelayMs ?? 60_000;
    this.baseUrl = config.baseUrl;

    const rpm = config.rateLimitRpm ?? 50;
    this.rateLimiter = new RateLimiter(rpm / 60);

    log.info(
      { provider: this.provider, model: this.modelId, maxTokens: this.maxTokens, rpm },
      "AI provider initialised",
    );
  }

  // -------------------------------------------------------------------------
  // Abstract methods — subclasses must implement
  // -------------------------------------------------------------------------

  protected abstract getDefaultModel(): string;

  protected abstract _doChat(
    messages: ChatMessage[],
    systemPrompt: string,
    tools?: ToolDefinition[],
  ): Promise<ChatResponse>;

  protected abstract _doStream(
    messages: ChatMessage[],
    systemPrompt: string,
    onDelta?: (delta: string) => void,
  ): Promise<{ content: string; usage: TokenUsage }>;

  // -------------------------------------------------------------------------
  // Public API (IAIClient)
  // -------------------------------------------------------------------------

  async chat(
    messages: ChatMessage[],
    systemPrompt: string,
    tools?: ToolDefinition[],
  ): Promise<ChatResponse> {
    return this.executeWithRetry(async () => {
      await this.rateLimiter.acquire();

      log.debug(
        { provider: this.provider, messageCount: messages.length, hasTools: !!(tools && tools.length) },
        "Sending chat request",
      );

      const response = await this._doChat(messages, systemPrompt, tools);
      this.trackUsage(response.usage);

      log.debug(
        {
          inputTokens: response.usage.inputTokens,
          outputTokens: response.usage.outputTokens,
          toolCallCount: response.toolCalls.length,
        },
        "Chat response received",
      );

      return response;
    });
  }

  async stream(
    messages: ChatMessage[],
    systemPrompt: string,
    onDelta?: (delta: string) => void,
  ): Promise<{ content: string; usage: TokenUsage }> {
    return this.executeWithRetry(async () => {
      await this.rateLimiter.acquire();

      log.debug({ provider: this.provider, messageCount: messages.length }, "Starting stream request");

      const result = await this._doStream(messages, systemPrompt, onDelta);
      this.trackUsage(result.usage);

      log.debug(
        {
          inputTokens: result.usage.inputTokens,
          outputTokens: result.usage.outputTokens,
          contentLength: result.content.length,
        },
        "Stream completed",
      );

      return result;
    });
  }

  async analyze(
    prompt: string,
    context?: string,
  ): Promise<{ content: string; usage: TokenUsage }> {
    const systemPrompt =
      context ??
      "You are a senior security researcher. Analyse the provided information and respond precisely.";

    const messages: ChatMessage[] = [{ role: "user", content: prompt }];
    const result = await this.chat(messages, systemPrompt);
    return { content: result.content, usage: result.usage };
  }

  getUsage(): TokenUsageSnapshot {
    return {
      lifetime: { ...this.lifetimeUsage },
      lastRequest: { ...this.lastRequestUsage },
      totalRequests: this.totalRequests,
    };
  }

  resetUsage(): void {
    this.lifetimeUsage = {
      inputTokens: 0,
      outputTokens: 0,
      cacheCreationInputTokens: 0,
      cacheReadInputTokens: 0,
    };
    this.lastRequestUsage = {
      inputTokens: 0,
      outputTokens: 0,
      cacheCreationInputTokens: 0,
      cacheReadInputTokens: 0,
    };
    this.totalRequests = 0;
  }

  // -------------------------------------------------------------------------
  // Protected helpers available to subclasses
  // -------------------------------------------------------------------------

  protected toVulnHunterError(error: unknown): VulnHunterAIError {
    if (error instanceof AIError) return error;
    const err = error instanceof Error ? error : new Error(String(error));
    return new AIError(err.message, {
      code: "unknown",
      retryable: false,
      cause: err,
    });
  }

  // -------------------------------------------------------------------------
  // Private
  // -------------------------------------------------------------------------

  private trackUsage(usage: TokenUsage): void {
    this.lastRequestUsage = { ...usage };
    this.lifetimeUsage.inputTokens += usage.inputTokens;
    this.lifetimeUsage.outputTokens += usage.outputTokens;
    this.lifetimeUsage.cacheCreationInputTokens += usage.cacheCreationInputTokens;
    this.lifetimeUsage.cacheReadInputTokens += usage.cacheReadInputTokens;
    this.totalRequests++;
  }

  private async executeWithRetry<T>(fn: () => Promise<T>): Promise<T> {
    try {
      return await withRetry(fn, {
        maxRetries: this.maxRetries,
        baseDelayMs: this.retryBaseDelayMs,
        maxDelayMs: this.retryMaxDelayMs,
        backoffFactor: 2,
        retryableErrors: RETRYABLE_ERROR_MESSAGES,
      });
    } catch (error) {
      throw this.toVulnHunterError(error);
    }
  }
}
