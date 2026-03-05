// ---------------------------------------------------------------------------
// @vulnhunter/core - Anthropic Provider
// ---------------------------------------------------------------------------

import Anthropic from "@anthropic-ai/sdk";
import type { MessageParam, Tool } from "@anthropic-ai/sdk/resources/messages";
import { BaseAIProvider } from "./base.js";
import type {
  AIClientConfig,
  ChatMessage,
  ChatResponse,
  TokenUsage,
  ToolDefinition,
  ToolCall,
} from "../types.js";
import { VulnHunterAIError } from "../types.js";

const RETRYABLE_STATUS_CODES = new Set([429, 500, 502, 503, 529]);

export class AnthropicProvider extends BaseAIProvider {
  private readonly sdk: Anthropic;

  constructor(config: AIClientConfig) {
    super(config);
    this.sdk = new Anthropic({
      apiKey: config.apiKey,
      ...(config.baseUrl ? { baseURL: config.baseUrl } : {}),
    });
  }

  /**
   * Exposes the underlying Anthropic SDK for advanced use cases.
   */
  get raw(): Anthropic {
    return this.sdk;
  }

  // -------------------------------------------------------------------------
  // Abstract implementations
  // -------------------------------------------------------------------------

  protected getDefaultModel(): string {
    return "claude-opus-4-6";
  }

  protected async _doChat(
    messages: ChatMessage[],
    systemPrompt: string,
    tools?: ToolDefinition[],
  ): Promise<ChatResponse> {
    const anthropicMessages = this.toAnthropicMessages(messages);
    const anthropicTools = tools ? this.toAnthropicTools(tools) : undefined;

    const params: Anthropic.Messages.MessageCreateParamsNonStreaming = {
      model: this.modelId,
      max_tokens: this.maxTokens,
      system: systemPrompt,
      messages: anthropicMessages,
      ...(anthropicTools && anthropicTools.length > 0 ? { tools: anthropicTools } : {}),
    };

    try {
      const response = await this.sdk.messages.create(params);

      const textBlocks = response.content.filter(
        (block): block is Anthropic.Messages.TextBlock => block.type === "text",
      );
      const content = textBlocks.map((b) => b.text).join("");

      const toolUseBlocks = response.content.filter(
        (block): block is Anthropic.Messages.ToolUseBlock => block.type === "tool_use",
      );
      const toolCalls = this.fromAnthropicToolCalls(toolUseBlocks);

      const usage = this.extractUsage(response.usage);

      return { content, toolCalls, usage };
    } catch (error) {
      throw this.mapError(error);
    }
  }

  protected async _doStream(
    messages: ChatMessage[],
    systemPrompt: string,
    onDelta?: (delta: string) => void,
  ): Promise<{ content: string; usage: TokenUsage }> {
    const anthropicMessages = this.toAnthropicMessages(messages);

    try {
      const stream = this.sdk.messages.stream({
        model: this.modelId,
        max_tokens: this.maxTokens,
        system: systemPrompt,
        messages: anthropicMessages,
      });

      let accumulated = "";
      stream.on("text", (text) => {
        accumulated += text;
        onDelta?.(text);
      });

      const finalMessage = await stream.finalMessage();
      const usage = this.extractUsage(finalMessage.usage);

      return { content: accumulated, usage };
    } catch (error) {
      throw this.mapError(error);
    }
  }

  // -------------------------------------------------------------------------
  // Translation helpers
  // -------------------------------------------------------------------------

  private toAnthropicMessages(messages: ChatMessage[]): MessageParam[] {
    return messages.map((m) => ({
      role: m.role,
      content: m.content,
    }));
  }

  private toAnthropicTools(tools: ToolDefinition[]): Tool[] {
    return tools.map((t) => ({
      name: t.name,
      description: t.description,
      input_schema: t.parameters as Tool["input_schema"],
    }));
  }

  private fromAnthropicToolCalls(blocks: Anthropic.Messages.ToolUseBlock[]): ToolCall[] {
    return blocks.map((b) => ({
      id: b.id,
      name: b.name,
      arguments: b.input as Record<string, unknown>,
    }));
  }

  private extractUsage(usage: Anthropic.Messages.Usage): TokenUsage {
    const cacheUsage = usage as Anthropic.Messages.Usage & {
      cache_creation_input_tokens?: number;
      cache_read_input_tokens?: number;
    };

    return {
      inputTokens: usage.input_tokens,
      outputTokens: usage.output_tokens,
      cacheCreationInputTokens: cacheUsage.cache_creation_input_tokens ?? 0,
      cacheReadInputTokens: cacheUsage.cache_read_input_tokens ?? 0,
    };
  }

  private mapError(error: unknown): VulnHunterAIError {
    if (error instanceof VulnHunterAIError) return error;

    if (error instanceof Anthropic.APIError) {
      return new VulnHunterAIError(error.message, {
        code: `anthropic_${error.status}`,
        statusCode: error.status,
        retryable: RETRYABLE_STATUS_CODES.has(error.status),
        cause: error,
      });
    }

    return this.toVulnHunterError(error);
  }
}
