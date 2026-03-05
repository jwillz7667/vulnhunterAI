// Types
export * from "./types/index.js";

// AI Engine — Provider-agnostic interface, types, and factory
export type { IAIClient } from "./ai/interface.js";
export type {
  AIProvider,
  AIClientConfig,
  ChatMessage,
  ChatResponse,
  ToolDefinition,
  ToolCall,
} from "./ai/types.js";
export { createAIClient, createAIClientFromEnv } from "./ai/factory.js";

// AI Engine — Providers
export { AnthropicProvider } from "./ai/providers/anthropic.js";
export { OpenAIProvider } from "./ai/providers/openai.js";
export { GoogleProvider } from "./ai/providers/google.js";
export { DeepSeekProvider } from "./ai/providers/deepseek.js";
export { OllamaProvider } from "./ai/providers/ollama.js";

// AI Engine — Legacy client (backward compat)
export { AnthropicClient } from "./ai/client.js";

// AI Engine — Agents
export { CoordinatorAgent } from "./ai/agents/coordinator.js";
export { SolverAgent } from "./ai/agents/solver.js";
export { AnalyzerAgent } from "./ai/agents/analyzer.js";
export { ReporterAgent } from "./ai/agents/reporter.js";
export { ExploitChainEngine } from "./ai/chains.js";

// Database
export { prisma } from "./db/index.js";

// Services
export { executeScanWithPersistence } from "./services/scan-service.js";
export type { ScanCallbacks, ScanExecutionResult } from "./services/scan-service.js";

// Utilities
export { logger, createLogger } from "./utils/logger.js";
export { RateLimiter } from "./utils/rate-limiter.js";
export { withRetry } from "./utils/retry.js";
export { generateId, generateUUID, hashString } from "./utils/crypto.js";
export { sendRequest, buildUrl, parseHeaders } from "./utils/http.js";
export type { HttpRequest, HttpResponse } from "./utils/http.js";
