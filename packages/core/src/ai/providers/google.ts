// ---------------------------------------------------------------------------
// @vulnhunter/core - Google Gemini Provider
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

/**
 * Google Gemini provider using the @google/generative-ai SDK.
 */
export class GoogleProvider extends BaseAIProvider {
  private sdk: any; // Lazily loaded GenerativeModel instance
  private sdkLoaded = false;
  private readonly apiKey: string;

  constructor(config: AIClientConfig) {
    super(config);
    this.apiKey = config.apiKey ?? process.env.GOOGLE_AI_API_KEY ?? "";
  }

  protected getDefaultModel(): string {
    return "gemini-2.0-flash";
  }

  // -------------------------------------------------------------------------
  // Lazy SDK initialization
  // -------------------------------------------------------------------------

  private async getModel(systemPrompt: string, tools?: ToolDefinition[]): Promise<any> {
    if (!this.sdkLoaded) {
      try {
        await import("@google/generative-ai");
        this.sdkLoaded = true;
      } catch {
        throw new VulnHunterAIError(
          'Google AI SDK not installed. Run: npm install @google/generative-ai',
          { code: "missing_dependency", retryable: false },
        );
      }
    }

    const { GoogleGenerativeAI } = await import("@google/generative-ai");
    const genAI = new GoogleGenerativeAI(this.apiKey);

    const toolDeclarations = tools && tools.length > 0
      ? [{
          functionDeclarations: tools.map((t) => ({
            name: t.name,
            description: t.description,
            parameters: t.parameters as any,
          })),
        }]
      : undefined;

    return genAI.getGenerativeModel({
      model: this.modelId,
      systemInstruction: systemPrompt,
      ...(toolDeclarations ? { tools: toolDeclarations as any } : {}),
      generationConfig: {
        maxOutputTokens: this.maxTokens,
      },
    });
  }

  // -------------------------------------------------------------------------
  // Abstract implementations
  // -------------------------------------------------------------------------

  protected async _doChat(
    messages: ChatMessage[],
    systemPrompt: string,
    tools?: ToolDefinition[],
  ): Promise<ChatResponse> {
    try {
      const model = await this.getModel(systemPrompt, tools);
      const geminiContents = this.toGeminiContents(messages);

      const result = await model.generateContent({ contents: geminiContents });
      const response = result.response;

      const content = response.text() ?? "";

      // Extract tool calls from function call parts
      const toolCalls: ToolCall[] = [];
      const candidates = response.candidates ?? [];
      for (const candidate of candidates) {
        for (const part of candidate.content?.parts ?? []) {
          if (part.functionCall) {
            toolCalls.push({
              id: `fc_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
              name: part.functionCall.name,
              arguments: part.functionCall.args ?? {},
            });
          }
        }
      }

      const usage = this.extractGeminiUsage(response.usageMetadata);

      return { content, toolCalls, usage };
    } catch (error) {
      throw this.mapGeminiError(error);
    }
  }

  protected async _doStream(
    messages: ChatMessage[],
    systemPrompt: string,
    onDelta?: (delta: string) => void,
  ): Promise<{ content: string; usage: TokenUsage }> {
    try {
      const model = await this.getModel(systemPrompt);
      const geminiContents = this.toGeminiContents(messages);

      const result = await model.generateContentStream({ contents: geminiContents });

      let accumulated = "";
      let usage: TokenUsage = {
        inputTokens: 0,
        outputTokens: 0,
        cacheCreationInputTokens: 0,
        cacheReadInputTokens: 0,
      };

      for await (const chunk of result.stream) {
        const text = chunk.text();
        if (text) {
          accumulated += text;
          onDelta?.(text);
        }
        if (chunk.usageMetadata) {
          usage = this.extractGeminiUsage(chunk.usageMetadata);
        }
      }

      return { content: accumulated, usage };
    } catch (error) {
      throw this.mapGeminiError(error);
    }
  }

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------

  private toGeminiContents(messages: ChatMessage[]): any[] {
    return messages.map((m) => ({
      role: m.role === "assistant" ? "model" : "user",
      parts: [{ text: m.content }],
    }));
  }

  private extractGeminiUsage(metadata: any): TokenUsage {
    return {
      inputTokens: metadata?.promptTokenCount ?? 0,
      outputTokens: metadata?.candidatesTokenCount ?? 0,
      cacheCreationInputTokens: 0,
      cacheReadInputTokens: 0,
    };
  }

  private mapGeminiError(error: unknown): VulnHunterAIError {
    if (error instanceof VulnHunterAIError) return error;

    if (error && typeof error === "object" && "status" in error) {
      const status = (error as any).status as number;
      return new VulnHunterAIError((error as any).message ?? "Google AI API error", {
        code: `google_${status}`,
        statusCode: status,
        retryable: status === 429 || status >= 500,
        cause: error instanceof Error ? error : new Error(String(error)),
      });
    }

    return this.toVulnHunterError(error);
  }
}
