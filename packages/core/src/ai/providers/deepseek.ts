// ---------------------------------------------------------------------------
// @vulnhunter/core - DeepSeek Provider
// ---------------------------------------------------------------------------
// Thin wrapper around OpenAIProvider — DeepSeek uses the same API
// with a different base URL and default model.

import { OpenAIProvider } from "./openai.js";
import type { AIClientConfig } from "../types.js";

export class DeepSeekProvider extends OpenAIProvider {
  constructor(config: AIClientConfig) {
    super({
      ...config,
      baseUrl: config.baseUrl ?? "https://api.deepseek.com",
      model: config.model ?? "deepseek-chat",
    });
  }

  protected override getDefaultModel(): string {
    return "deepseek-chat";
  }
}
