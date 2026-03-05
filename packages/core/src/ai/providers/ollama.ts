// ---------------------------------------------------------------------------
// @vulnhunter/core - Ollama Provider
// ---------------------------------------------------------------------------
// Thin wrapper around OpenAIProvider — Ollama exposes an OpenAI-compatible
// API at localhost:11434/v1 by default.

import { OpenAIProvider } from "./openai.js";
import type { AIClientConfig } from "../types.js";

export class OllamaProvider extends OpenAIProvider {
  constructor(config: AIClientConfig) {
    super({
      ...config,
      apiKey: config.apiKey ?? "ollama",
      baseUrl: config.baseUrl ?? "http://localhost:11434/v1",
      model: config.model ?? "llama3.1:latest",
    });
  }

  protected override getDefaultModel(): string {
    return "llama3.1:latest";
  }
}
