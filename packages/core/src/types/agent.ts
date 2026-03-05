import { z } from "zod";
import { type ScanType, ScanTypeSchema } from "./scan";

// ---------------------------------------------------------------------------
// Agent Role
// ---------------------------------------------------------------------------

export enum AgentRole {
  Coordinator = "coordinator",
  Solver = "solver",
  Analyzer = "analyzer",
  Reporter = "reporter",
}

export const AgentRoleSchema = z.nativeEnum(AgentRole);

// ---------------------------------------------------------------------------
// Agent Task Status
// ---------------------------------------------------------------------------

export enum AgentTaskStatus {
  Pending = "pending",
  Running = "running",
  Completed = "completed",
  Failed = "failed",
  Cancelled = "cancelled",
}

export const AgentTaskStatusSchema = z.nativeEnum(AgentTaskStatus);

// ---------------------------------------------------------------------------
// Tool Call / Tool Result (Anthropic Claude function-calling interface)
// ---------------------------------------------------------------------------

/** A tool/function call requested by the agent. */
export interface ToolCall {
  /** Unique ID for this tool call (used to correlate results). */
  id: string;
  /** Fully-qualified tool name, e.g. "scanner:xss:reflected". */
  name: string;
  /** JSON-serializable arguments passed to the tool. */
  arguments: Record<string, unknown>;
}

export const ToolCallSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  arguments: z.record(z.unknown()),
});

/** The result returned by a tool after execution. */
export interface ToolResult {
  /** The tool call ID this result corresponds to. */
  toolCallId: string;
  /** Whether the tool execution succeeded. */
  success: boolean;
  /** The output data from the tool. */
  output: unknown;
  /** Error message if the tool failed. */
  error?: string;
  /** Execution time in milliseconds. */
  durationMs?: number;
}

export const ToolResultSchema = z.object({
  toolCallId: z.string().min(1),
  success: z.boolean(),
  output: z.unknown(),
  error: z.string().optional(),
  durationMs: z.number().nonnegative().optional(),
});

// ---------------------------------------------------------------------------
// Agent Message
// ---------------------------------------------------------------------------

/** Role of a message in the agent conversation. */
export enum MessageRole {
  System = "system",
  User = "user",
  Assistant = "assistant",
  Tool = "tool",
}

export const MessageRoleSchema = z.nativeEnum(MessageRole);

/** A single message in the agent's conversation history. */
export interface AgentMessage {
  /** Who produced this message. */
  role: MessageRole;
  /** Text content of the message. */
  content: string;
  /** Tool calls made by the assistant in this message (assistant role only). */
  toolCalls?: ToolCall[];
  /** Tool results being reported (tool role only). */
  toolResults?: ToolResult[];
  /** ISO-8601 timestamp. */
  timestamp: string;
  /** Token usage for this message (for cost tracking). */
  tokenUsage?: {
    inputTokens: number;
    outputTokens: number;
  };
}

export const AgentMessageSchema = z.object({
  role: MessageRoleSchema,
  content: z.string(),
  toolCalls: z.array(ToolCallSchema).optional(),
  toolResults: z.array(ToolResultSchema).optional(),
  timestamp: z.string().datetime(),
  tokenUsage: z
    .object({
      inputTokens: z.number().int().nonnegative(),
      outputTokens: z.number().int().nonnegative(),
    })
    .optional(),
});

// ---------------------------------------------------------------------------
// Agent Task
// ---------------------------------------------------------------------------

/** A discrete unit of work assigned to an agent. */
export interface AgentTask {
  /** Unique identifier (UUID v4). */
  id: string;
  /** Which agent role should handle this task. */
  role: AgentRole;
  /** The target value (URL, endpoint, etc.) this task operates on. */
  target: string;
  /** Natural-language instruction describing what the agent should do. */
  instruction: string;
  /** Additional context (prior findings, reconnaissance data, etc.). */
  context: Record<string, unknown>;
  /** ID of the parent task that spawned this one (for task trees). */
  parentTaskId?: string;
  /** Current execution status. */
  status: AgentTaskStatus;
  /** The result produced by the agent (null until completed). */
  result?: AgentTaskResult;
  /** Full conversation history for this task. */
  messages: AgentMessage[];
  /** Maximum number of LLM iterations allowed for this task. */
  maxIterations: number;
  /** Current iteration count. */
  currentIteration: number;
  /** ISO-8601 timestamp of task creation. */
  createdAt: string;
  /** ISO-8601 timestamp of last status change. */
  updatedAt: string;
}

/** The structured output produced when an agent task completes. */
export interface AgentTaskResult {
  /** Whether the task objective was achieved. */
  success: boolean;
  /** Summary of what was accomplished or why it failed. */
  summary: string;
  /** Findings produced by this task (if any). */
  findingIds: string[];
  /** Sub-tasks spawned during execution. */
  childTaskIds: string[];
  /** Arbitrary structured data produced by the agent. */
  data?: Record<string, unknown>;
}

export const AgentTaskResultSchema = z.object({
  success: z.boolean(),
  summary: z.string(),
  findingIds: z.array(z.string().uuid()),
  childTaskIds: z.array(z.string().uuid()),
  data: z.record(z.unknown()).optional(),
});

export const AgentTaskSchema = z.object({
  id: z.string().uuid(),
  role: AgentRoleSchema,
  target: z.string().min(1),
  instruction: z.string().min(1),
  context: z.record(z.unknown()),
  parentTaskId: z.string().uuid().optional(),
  status: AgentTaskStatusSchema,
  result: AgentTaskResultSchema.optional(),
  messages: z.array(AgentMessageSchema),
  maxIterations: z.number().int().positive().default(20),
  currentIteration: z.number().int().nonnegative().default(0),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
});

// ---------------------------------------------------------------------------
// Attack Plan
// ---------------------------------------------------------------------------

/** A single phase in a multi-phase attack plan. */
export interface AttackPhase {
  /** Phase name, e.g. "Reconnaissance", "Active Exploitation", "Post-Exploitation". */
  name: string;
  /** Description of the phase objective. */
  description: string;
  /** Scanner/exploiter modules to execute in this phase. */
  modules: string[];
  /** Specific endpoints to target in this phase. */
  endpoints: string[];
  /** Estimated duration in seconds. */
  estimatedDurationSec?: number;
  /** Phase dependencies (names of phases that must complete first). */
  dependsOn: string[];
  /** Priority (1 = highest). */
  priority: number;
}

export const AttackPhaseSchema = z.object({
  name: z.string().min(1),
  description: z.string().min(1),
  modules: z.array(z.string()),
  endpoints: z.array(z.string()),
  estimatedDurationSec: z.number().int().positive().optional(),
  dependsOn: z.array(z.string()).default([]),
  priority: z.number().int().positive().default(1),
});

/** An AI-generated attack plan for a target. */
export interface AttackPlan {
  /** Unique identifier (UUID v4). */
  id: string;
  /** The target this plan was generated for. */
  target: string;
  /** Type of scan this plan is designed for. */
  scanType: ScanType;
  /** Ordered list of attack phases. */
  phases: AttackPhase[];
  /** High-level rationale for the chosen attack strategy. */
  rationale: string;
  /** Estimated total duration in seconds. */
  estimatedTotalDurationSec: number;
  /** ISO-8601 timestamp of when the plan was generated. */
  generatedAt: string;
  /** Which AI model generated this plan. */
  generatedBy: string;
}

export const AttackPlanSchema = z.object({
  id: z.string().uuid(),
  target: z.string().min(1),
  scanType: ScanTypeSchema,
  phases: z.array(AttackPhaseSchema).min(1),
  rationale: z.string().min(1),
  estimatedTotalDurationSec: z.number().int().positive(),
  generatedAt: z.string().datetime(),
  generatedBy: z.string().min(1),
});

// ---------------------------------------------------------------------------
// Agent Memory
// ---------------------------------------------------------------------------

/** A remembered attack pattern or technique. */
export interface MemorizedPattern {
  /** The pattern or technique identifier. */
  name: string;
  /** Description of the pattern. */
  description: string;
  /** How many times this pattern has been successfully used. */
  successCount: number;
  /** How many times this pattern was attempted. */
  attemptCount: number;
  /** Success rate (0.0 - 1.0). */
  successRate: number;
  /** Target types this pattern works best against. */
  effectiveAgainst: string[];
  /** ISO-8601 timestamp of last successful use. */
  lastUsed?: string;
}

export const MemorizedPatternSchema = z.object({
  name: z.string().min(1),
  description: z.string().min(1),
  successCount: z.number().int().nonnegative(),
  attemptCount: z.number().int().nonnegative(),
  successRate: z.number().min(0).max(1),
  effectiveAgainst: z.array(z.string()),
  lastUsed: z.string().datetime().optional(),
});

/** A payload that has successfully triggered a vulnerability. */
export interface SuccessfulPayload {
  /** The raw payload string. */
  payload: string;
  /** Category of vulnerability this payload targets. */
  category: string;
  /** Target type this payload was effective against. */
  targetType: string;
  /** Technologies/frameworks this payload works against. */
  effectiveTechnologies: string[];
  /** How many times this payload has worked. */
  successCount: number;
  /** ISO-8601 timestamp of last successful use. */
  lastUsed: string;
}

export const SuccessfulPayloadSchema = z.object({
  payload: z.string().min(1),
  category: z.string().min(1),
  targetType: z.string().min(1),
  effectiveTechnologies: z.array(z.string()),
  successCount: z.number().int().positive(),
  lastUsed: z.string().datetime(),
});

/** Effective techniques mapped by target type / technology. */
export interface TechniquesByTarget {
  /** The target type or technology identifier. */
  targetIdentifier: string;
  /** Ranked list of effective techniques (most effective first). */
  techniques: string[];
  /** Notes about the target's behaviour or quirks. */
  notes?: string;
}

export const TechniquesByTargetSchema = z.object({
  targetIdentifier: z.string().min(1),
  techniques: z.array(z.string()).min(1),
  notes: z.string().optional(),
});

/**
 * Persistent memory for the AI agent, allowing it to learn from
 * past scanning sessions and improve over time.
 */
export interface AgentMemory {
  /** Unique identifier (UUID v4). */
  id: string;
  /** Recognized attack patterns and their effectiveness. */
  patterns: MemorizedPattern[];
  /** Payloads that have successfully triggered vulnerabilities. */
  successfulPayloads: SuccessfulPayload[];
  /** Effective techniques organized by target type/technology. */
  effectiveTechniques: TechniquesByTarget[];
  /** Total number of scans this memory has been used across. */
  totalScans: number;
  /** Total number of findings produced using this memory. */
  totalFindings: number;
  /** ISO-8601 timestamp of when this memory was last updated. */
  lastUpdated: string;
}

export const AgentMemorySchema = z.object({
  id: z.string().uuid(),
  patterns: z.array(MemorizedPatternSchema),
  successfulPayloads: z.array(SuccessfulPayloadSchema),
  effectiveTechniques: z.array(TechniquesByTargetSchema),
  totalScans: z.number().int().nonnegative(),
  totalFindings: z.number().int().nonnegative(),
  lastUpdated: z.string().datetime(),
});

// ---------------------------------------------------------------------------
// Inferred types from Zod
// ---------------------------------------------------------------------------

export type AgentTaskInput = z.input<typeof AgentTaskSchema>;
export type AgentMessageInput = z.input<typeof AgentMessageSchema>;
export type AttackPlanInput = z.input<typeof AttackPlanSchema>;
export type AgentMemoryInput = z.input<typeof AgentMemorySchema>;
