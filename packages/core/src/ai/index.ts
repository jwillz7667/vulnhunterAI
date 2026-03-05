// ---------------------------------------------------------------------------
// @vulnhunter/core - AI Engine Barrel Export
// ---------------------------------------------------------------------------

// Provider-agnostic types
export {
  VulnHunterAIError,
} from "./types.js";
export type {
  AIProvider,
  AIClientConfig,
  ChatMessage,
  ChatResponse,
  ToolDefinition,
  ToolCall,
  TokenUsage,
  TokenUsageSnapshot,
} from "./types.js";

// Interface
export type { IAIClient } from "./interface.js";

// Factory
export { createAIClient, createAIClientFromEnv } from "./factory.js";

// Providers
export {
  BaseAIProvider,
  AnthropicProvider,
  OpenAIProvider,
  GoogleProvider,
  DeepSeekProvider,
  OllamaProvider,
} from "./providers/index.js";

// Legacy client (backward compat)
export { AnthropicClient } from "./client.js";
export type { AnthropicClientConfig } from "./client.js";

// Agents
export {
  CoordinatorAgent,
  SolverAgent,
  AnalyzerAgent,
  ReporterAgent,
} from "./agents/index.js";

export type {
  TestPayload,
  AnalysisResult,
  SolverResult,
  SolverConfig,
  CorrelationResult,
  DetectedChain,
  FalsePositiveAnalysis,
  ImpactAssessment,
  StaticFinding,
  DynamicFinding,
  SASTDASTCorrelation,
  BugBountyPlatform,
  VulnerabilityNarrative,
  RemediationGuidance,
  ExecutiveSummary,
  PlatformSubmission,
} from "./agents/index.js";

// Exploit Chain Engine
export { ExploitChainEngine } from "./chains.js";

// Prompts
export {
  COORDINATOR_SYSTEM_PROMPT,
  SOLVER_SYSTEM_PROMPT,
  ANALYZER_SYSTEM_PROMPT,
  REPORTER_SYSTEM_PROMPT,
} from "./prompts/index.js";
