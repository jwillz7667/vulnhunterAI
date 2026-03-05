// ---------------------------------------------------------------------------
// @vulnhunter/core - AI Client Interface
// ---------------------------------------------------------------------------

import type {
  AIProvider,
  ChatMessage,
  ChatResponse,
  TokenUsage,
  TokenUsageSnapshot,
  ToolDefinition,
} from "./types.js";

/**
 * Provider-agnostic interface for all AI clients.
 * Agents and engines program against this interface so any provider
 * (Anthropic, OpenAI, Google, DeepSeek, Ollama) can be swapped via config.
 */
export interface IAIClient {
  readonly provider: AIProvider;
  readonly modelId: string;

  /**
   * Send a chat completion request with optional tool definitions.
   */
  chat(
    messages: ChatMessage[],
    systemPrompt: string,
    tools?: ToolDefinition[],
  ): Promise<ChatResponse>;

  /**
   * Stream a chat completion. Yields text deltas via the callback.
   */
  stream(
    messages: ChatMessage[],
    systemPrompt: string,
    onDelta?: (delta: string) => void,
  ): Promise<{ content: string; usage: TokenUsage }>;

  /**
   * High-level convenience: send a single prompt with optional context
   * and receive the assistant's text response.
   */
  analyze(
    prompt: string,
    context?: string,
  ): Promise<{ content: string; usage: TokenUsage }>;

  /**
   * Returns current token usage statistics.
   */
  getUsage(): TokenUsageSnapshot;

  /**
   * Resets lifetime usage counters.
   */
  resetUsage(): void;
}
