// =============================================================================
// @vulnhunter/core - Type Definitions Barrel Export
// =============================================================================
// All types, enums, interfaces, and Zod schemas are re-exported from this file.
// Consumers should import from "@vulnhunter/core/types" or from this index.
// =============================================================================

// ---------------------------------------------------------------------------
// Vulnerability types & schemas
// ---------------------------------------------------------------------------
export {
  // Enums
  Severity,
  VulnerabilityCategory,
  // Zod schemas
  SeveritySchema,
  VulnerabilityCategorySchema,
  HttpRequestSchema,
  HttpResponseSchema,
  EvidenceSchema,
  VulnerabilitySchema,
  FindingSchema,
  ExploitStepSchema,
  ExploitChainSchema,
  // Constants
  SEVERITY_WEIGHT,
} from "./vulnerability";

export type {
  // Interfaces
  HttpRequest,
  HttpResponse,
  Evidence,
  Vulnerability,
  Finding,
  ExploitStep,
  ExploitChain,
  // Zod inferred input types
  VulnerabilityInput,
  FindingInput,
  ExploitChainInput,
} from "./vulnerability";

// ---------------------------------------------------------------------------
// Target types & schemas
// ---------------------------------------------------------------------------
export {
  // Enums
  TargetType,
  AuthenticationType,
  // Zod schemas
  TargetTypeSchema,
  AuthenticationTypeSchema,
  BasicCredentialsSchema,
  BearerCredentialsSchema,
  CookieCredentialsSchema,
  OAuthCredentialsSchema,
  APIKeyCredentialsSchema,
  CustomCredentialsSchema,
  AuthenticationSchema,
  ScopeEntrySchema,
  ScopeSchema,
  TargetMetadataSchema,
  TargetSchema,
} from "./target";

export type {
  // Interfaces
  BasicCredentials,
  BearerCredentials,
  CookieCredentials,
  OAuthCredentials,
  APIKeyCredentials,
  CustomCredentials,
  Authentication,
  ScopeEntry,
  Scope,
  TargetMetadata,
  Target,
  // Zod inferred input types
  TargetInput,
  ScopeInput,
  AuthenticationInput,
} from "./target";

// ---------------------------------------------------------------------------
// Scan types & schemas
// ---------------------------------------------------------------------------
export {
  // Enums
  ScanType,
  ScanStatus,
  // Zod schemas
  ScanTypeSchema,
  ScanStatusSchema,
  ScanModuleConfigSchema,
  ScanOptionsSchema,
  ScanConfigSchema,
  ScanStatisticsSchema,
  ScanResultSchema,
  ScanProgressSchema,
} from "./scan";

export type {
  // Interfaces
  ScanModuleConfig,
  ScanOptions,
  ScanConfig,
  ScanStatistics,
  ScanResult,
  ScanProgress,
  // Zod inferred input types
  ScanConfigInput,
  ScanOptionsInput,
  ScanResultInput,
  ScanProgressInput,
} from "./scan";

// ---------------------------------------------------------------------------
// Report types & schemas
// ---------------------------------------------------------------------------
export {
  // Enums
  ReportFormat,
  ComplianceFramework,
  ComplianceControlStatus,
  // Zod schemas
  ReportFormatSchema,
  ComplianceFrameworkSchema,
  ComplianceControlStatusSchema,
  ComplianceControlSchema,
  ComplianceMappingSchema,
  ReportConfigSchema,
  ReportStatisticsSchema,
  ReportSchema,
} from "./report";

export type {
  // Interfaces
  ComplianceControl,
  ComplianceMapping,
  ReportConfig,
  ReportStatistics,
  Report,
  // Zod inferred input types
  ReportInput,
  ReportConfigInput,
  ComplianceMappingInput,
} from "./report";

// ---------------------------------------------------------------------------
// Agent types & schemas
// ---------------------------------------------------------------------------
export {
  // Enums
  AgentRole,
  AgentTaskStatus,
  MessageRole,
  // Zod schemas
  AgentRoleSchema,
  AgentTaskStatusSchema,
  MessageRoleSchema,
  ToolCallSchema,
  ToolResultSchema,
  AgentMessageSchema,
  AgentTaskResultSchema,
  AgentTaskSchema,
  AttackPhaseSchema,
  AttackPlanSchema,
  MemorizedPatternSchema,
  SuccessfulPayloadSchema,
  TechniquesByTargetSchema,
  AgentMemorySchema,
} from "./agent";

export type {
  // Interfaces
  ToolCall,
  ToolResult,
  AgentMessage,
  AgentTask,
  AgentTaskResult,
  AttackPhase,
  AttackPlan,
  MemorizedPattern,
  SuccessfulPayload,
  TechniquesByTarget,
  AgentMemory,
  // Zod inferred input types
  AgentTaskInput,
  AgentMessageInput,
  AttackPlanInput,
  AgentMemoryInput,
} from "./agent";

// ---------------------------------------------------------------------------
// Bounty types & schemas
// ---------------------------------------------------------------------------
export {
  // Enums
  BountyPlatform,
  SubmissionStatus,
  // Zod schemas
  BountyPlatformSchema,
  SubmissionStatusSchema,
  BountyRangeSchema,
  ProgramStatisticsSchema,
  BountyProgramSchema,
  SubmissionTimelineEntrySchema,
  SubmissionSchema,
} from "./bounty";

export type {
  // Interfaces
  BountyRange,
  ProgramStatistics,
  BountyProgram,
  Submission,
  SubmissionTimelineEntry,
  // Zod inferred input types
  BountyProgramInput,
  SubmissionInput,
} from "./bounty";
