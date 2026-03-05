// ---------------------------------------------------------------------------
// @vulnhunter/core - OpenAI Provider
// ---------------------------------------------------------------------------

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

const RETRYABLE_STATUS_CODES = new Set([429, 500, 502, 503]);

/**
 * OpenAI provider. Also serves as the base for DeepSeek and Ollama since
 * they expose OpenAI-compatible APIs.
 */
export class OpenAIProvider extends BaseAIProvider {
  private sdk: any; // Lazily loaded OpenAI instance
  private sdkLoaded = false;

  constructor(config: AIClientConfig) {
    super(config);
  }

  protected getDefaultModel(): string {
    return "gpt-4o";
  }

  // -------------------------------------------------------------------------
  // Lazy SDK initialization (so `openai` is only imported when used)
  // -------------------------------------------------------------------------

  private async getSDK(): Promise<any> {
    if (!this.sdkLoaded) {
      try {
        const { default: OpenAI } = await import("openai");
        this.sdk = new OpenAI({
          apiKey: (this as any).apiKey ?? process.env.OPENAI_API_KEY,
          ...(this.baseUrl ? { baseURL: this.baseUrl } : {}),
        });
        this.sdkLoaded = true;
      } catch {
        throw new VulnHunterAIError(
          'OpenAI SDK not installed. Run: npm install openai',
          { code: "missing_dependency", retryable: false },
        );
      }
    }
    return this.sdk;
  }

  // -------------------------------------------------------------------------
  // Abstract implementations
  // -------------------------------------------------------------------------

  protected async _doChat(
    messages: ChatMessage[],
    systemPrompt: string,
    tools?: ToolDefinition[],
  ): Promise<ChatResponse> {
    const client = await this.getSDK();

    const openaiMessages = [
      { role: "system" as const, content: systemPrompt },
      ...messages.map((m) => ({
        role: m.role as "user" | "assistant",
        content: m.content,
      })),
    ];

    const openaiTools = tools && tools.length > 0
      ? tools.map((t) => ({
          type: "function" as const,
          function: {
            name: t.name,
            description: t.description,
            parameters: t.parameters,
          },
        }))
      : undefined;

    try {
      const response = await client.chat.completions.create({
        model: this.modelId,
        max_tokens: this.maxTokens,
        messages: openaiMessages,
        ...(openaiTools ? { tools: openaiTools } : {}),
      });

      const choice = response.choices[0];
      const content = choice?.message?.content ?? "";

      const toolCalls: ToolCall[] = (choice?.message?.tool_calls ?? []).map(
        (tc: any) => ({
          id: tc.id,
          name: tc.function.name,
          arguments: JSON.parse(tc.function.arguments || "{}"),
        }),
      );

      const usage = this.extractOpenAIUsage(response.usage);

      return { content, toolCalls, usage };
    } catch (error) {
      throw this.mapOpenAIError(error);
    }
  }

  protected async _doStream(
    messages: ChatMessage[],
    systemPrompt: string,
    onDelta?: (delta: string) => void,
  ): Promise<{ content: string; usage: TokenUsage }> {
    const client = await this.getSDK();

    const openaiMessages = [
      { role: "system" as const, content: systemPrompt },
      ...messages.map((m) => ({
        role: m.role as "user" | "assistant",
        content: m.content,
      })),
    ];

    try {
      const stream = await client.chat.completions.create({
        model: this.modelId,
        max_tokens: this.maxTokens,
        messages: openaiMessages,
        stream: true,
        stream_options: { include_usage: true },
      });

      let accumulated = "";
      let usage: TokenUsage = {
        inputTokens: 0,
        outputTokens: 0,
        cacheCreationInputTokens: 0,
        cacheReadInputTokens: 0,
      };

      for await (const chunk of stream) {
        const delta = chunk.choices?.[0]?.delta?.content;
        if (delta) {
          accumulated += delta;
          onDelta?.(delta);
        }
        if (chunk.usage) {
          usage = this.extractOpenAIUsage(chunk.usage);
        }
      }

      return { content: accumulated, usage };
    } catch (error) {
      throw this.mapOpenAIError(error);
    }
  }

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------

  private extractOpenAIUsage(usage: any): TokenUsage {
    return {
      inputTokens: usage?.prompt_tokens ?? 0,
      outputTokens: usage?.completion_tokens ?? 0,
      cacheCreationInputTokens: 0,
      cacheReadInputTokens: 0,
    };
  }

  private mapOpenAIError(error: unknown): VulnHunterAIError {
    if (error instanceof VulnHunterAIError) return error;

    if (error && typeof error === "object" && "status" in error) {
      const status = (error as any).status as number;
      return new VulnHunterAIError((error as any).message ?? "OpenAI API error", {
        code: `openai_${status}`,
        statusCode: status,
        retryable: RETRYABLE_STATUS_CODES.has(status),
        cause: error instanceof Error ? error : new Error(String(error)),
      });
    }

    return this.toVulnHunterError(error);
  }
}
