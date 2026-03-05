import { randomUUID } from "node:crypto";
import type { ChatMessage, TokenUsage } from "../types.js";
import type { IAIClient } from "../interface.js";
import { createLogger } from "../../utils/logger.js";
import {
  COORDINATOR_SYSTEM_PROMPT,
  buildCoordinatorPlanPrompt,
  buildCoordinatorSynthesisPrompt,
} from "../prompts/coordinator.js";

import type { Target, TargetMetadata } from "../../types/target.js";
import type { ScanConfig, ScanResult } from "../../types/scan.js";
import type {
  AttackPlan,
  AttackPhase,
  AgentTask,
  AgentMemory,
} from "../../types/agent.js";
import { AgentRole as AgentRoleEnum, AgentTaskStatus } from "../../types/agent.js";
import type {
  VulnerabilityCategory,
  Vulnerability,
  Finding,
  Severity,
  ExploitChain,
} from "../../types/vulnerability.js";
import { VulnerabilityCategory as VulnCat } from "../../types/vulnerability.js";

// ---------------------------------------------------------------------------
// Local types for coordinator-internal data that no longer lives on the
// domain-level AgentTask / AgentMemory shapes.
// ---------------------------------------------------------------------------

/** Result returned by a solver agent after testing a single task. */
interface SolverResult {
  taskId: string;
  found: boolean;
  severity?: Severity;
  category?: VulnerabilityCategory;
  description: string;
  payload?: string;
  request?: { method: string; url: string; headers: Record<string, string>; body?: string };
  response?: { statusCode: number; headers: Record<string, string>; body?: string };
  confidence: number;
  remediation?: string;
  cweId?: string;
  cvssScore?: number;
  cvssVector?: string;
  references: string[];
  tokensUsed: { input: number; output: number };
}

/** Internal memory fact used by the coordinator during a scan session. */
interface MemoryFact {
  category: string;
  content: string;
  confidence: number;
  recordedAt: string;
}

/** Coordinator-internal working memory (not the persisted AgentMemory). */
interface CoordinatorMemory {
  facts: MemoryFact[];
  attemptedPayloads: Map<string, string[]>;
  testedEndpoints: Map<string, string[]>;
  observations: string[];
  tokenUsage: { input: number; output: number };
}

/** Coordinator-internal task representation (richer than the domain AgentTask). */
interface CoordinatorTask {
  id: string;
  scanId: string;
  assignedRole: typeof AgentRoleEnum.Solver;
  vulnerabilityType: VulnerabilityCategory;
  endpoint: string;
  method: string;
  parameters: EndpointParameter[];
  context: string;
  priority: number;
  status: AgentTaskStatus;
  difficulty: number;
  parentTaskId?: string;
  createdAt: string;
  completedAt?: string;
}

interface EndpointParameter {
  name: string;
  type: "query" | "path" | "body" | "header" | "cookie";
  dataType?: string;
  required?: boolean;
  sampleValue?: string;
}

/** Internal attack plan phase that carries ordered tasks. */
interface CoordinatorAttackPhase {
  order: number;
  name: string;
  description: string;
  tasks: CoordinatorTask[];
  estimatedDurationSec: number;
}

/** Internal attack plan that carries coordinator-specific fields. */
interface CoordinatorAttackPlan {
  id: string;
  scanId: string;
  targetId: string;
  strategy: string;
  phases: CoordinatorAttackPhase[];
  totalEstimatedDurationSec: number;
  prioritizedCategories: VulnerabilityCategory[];
  detectedTechnologies: string[];
  createdAt: string;
}

// ---------------------------------------------------------------------------
// Logger
// ---------------------------------------------------------------------------

const log = createLogger("ai:coordinator");

// ---------------------------------------------------------------------------
// Internal JSON shapes returned by the LLM
// ---------------------------------------------------------------------------

interface LLMAttackPlanResponse {
  strategy: string;
  phases: Array<{
    order: number;
    name: string;
    description: string;
    tasks: Array<{
      vulnerabilityType: string;
      endpoint: string;
      method: string;
      parameters?: Array<{ name: string; type: string; dataType?: string; sampleValue?: string }>;
      context: string;
      priority: number;
      difficulty: number;
    }>;
    estimatedDurationSec: number;
  }>;
  prioritizedCategories: string[];
  detectedTechnologies: string[];
}

interface LLMSynthesisResponse {
  summary: string;
  criticalFindings: Array<{
    id: string;
    title: string;
    severity: string;
    recommendation: string;
  }>;
  exploitChains: Array<{
    name: string;
    steps: Array<{ vulnerabilityId: string; outcome: string }>;
    combinedSeverity: string;
  }>;
  riskScore: number;
  recommendations: string[];
}

// ---------------------------------------------------------------------------
// CoordinatorAgent
// ---------------------------------------------------------------------------

export class CoordinatorAgent {
  private readonly client: IAIClient;
  private readonly scanId: string;
  private memory: CoordinatorMemory;
  private conversationHistory: ChatMessage[] = [];

  constructor(params: { client: IAIClient; scanId: string }) {
    this.client = params.client;
    this.scanId = params.scanId;

    this.memory = {
      facts: [],
      attemptedPayloads: new Map(),
      testedEndpoints: new Map(),
      observations: [],
      tokenUsage: { input: 0, output: 0 },
    };

    log.info({ scanId: this.scanId }, "CoordinatorAgent initialised");
  }

  // -----------------------------------------------------------------------
  // createAttackPlan
  // -----------------------------------------------------------------------

  /**
   * Analyses the target and scan configuration to produce a structured,
   * phased attack plan with prioritised tasks for solver agents.
   */
  async createAttackPlan(target: Target, config: ScanConfig): Promise<CoordinatorAttackPlan> {
    log.info({ targetId: target.id, targetValue: target.value }, "Creating attack plan");

    const prompt = buildCoordinatorPlanPrompt({
      targetName: target.name,
      targetValue: target.value,
      targetType: target.type,
      technologies: target.metadata?.technologies ?? [],
      scope: {
        inScope: target.scope?.inScope.map((s) => s.pattern) ?? [target.value],
        outOfScope: target.scope?.outOfScope.map((s) => s.pattern) ?? [],
      },
      scanType: config.scanType,
      endpoints: undefined, // Will be populated after recon phase
      previousFindings: undefined,
    });

    const userMessage: ChatMessage = { role: "user", content: prompt };
    this.conversationHistory.push(userMessage);

    const response = await this.client.chat(
      this.conversationHistory,
      COORDINATOR_SYSTEM_PROMPT
    );

    this.trackTokens(response.usage);

    // Store assistant response in conversation history for multi-turn context
    this.conversationHistory.push({ role: "assistant", content: response.content });

    const parsed = this.parseJSON<LLMAttackPlanResponse>(response.content);

    // Convert LLM response to typed AttackPlan
    const plan = this.buildAttackPlan(parsed, target, config);

    this.addFact("strategy", parsed.strategy, 90);
    if (parsed.detectedTechnologies.length > 0) {
      this.addFact(
        "technology",
        `Detected technologies: ${parsed.detectedTechnologies.join(", ")}`,
        80
      );
    }

    log.info(
      {
        planId: plan.id,
        phaseCount: plan.phases.length,
        totalTasks: plan.phases.reduce((sum, p) => sum + p.tasks.length, 0),
        estimatedDuration: plan.totalEstimatedDurationSec,
      },
      "Attack plan created"
    );

    return plan;
  }

  // -----------------------------------------------------------------------
  // assignTasks
  // -----------------------------------------------------------------------

  /**
   * Extracts individual tasks from the attack plan, ordered by phase and priority.
   * Returns a flat list of AgentTasks ready for solver agents to execute.
   */
  assignTasks(plan: CoordinatorAttackPlan): CoordinatorTask[] {
    const tasks: CoordinatorTask[] = [];

    for (const phase of plan.phases.sort((a, b) => a.order - b.order)) {
      const phaseTasks = phase.tasks.sort((a: CoordinatorTask, b: CoordinatorTask) => a.priority - b.priority);
      tasks.push(...phaseTasks);
    }

    log.info(
      {
        planId: plan.id,
        totalTasks: tasks.length,
        byCategory: this.countBy(tasks, (t) => t.vulnerabilityType),
      },
      "Tasks assigned from attack plan"
    );

    return tasks;
  }

  // -----------------------------------------------------------------------
  // synthesizeResults
  // -----------------------------------------------------------------------

  /**
   * Combines all solver results into a coherent assessment. Uses the LLM to
   * produce an overall summary, identify critical findings, detect potential
   * exploit chains, and generate prioritised recommendations.
   */
  async synthesizeResults(
    solverResults: SolverResult[],
    target: Target
  ): Promise<{
    summary: string;
    criticalFindings: Array<{ id: string; title: string; severity: string; recommendation: string }>;
    exploitChains: Array<{
      name: string;
      steps: Array<{ vulnerabilityId: string; outcome: string }>;
      combinedSeverity: string;
    }>;
    riskScore: number;
    recommendations: string[];
    usage: TokenUsage;
  }> {
    log.info(
      {
        totalResults: solverResults.length,
        foundCount: solverResults.filter((r) => r.found).length,
      },
      "Synthesising solver results"
    );

    const findings = solverResults
      .filter((r) => r.found)
      .map((r) => ({
        title: r.description.slice(0, 120),
        severity: r.severity ?? "info",
        category: r.category ?? "information_disclosure",
        endpoint: r.request?.url ?? "unknown",
        confidence: r.confidence,
      }));

    const errors = solverResults
      .filter((r) => !r.found && r.confidence < 10)
      .map((r) => r.description)
      .slice(0, 10); // Limit error list to avoid token overflow

    const prompt = buildCoordinatorSynthesisPrompt({
      targetName: target.name,
      totalTasks: solverResults.length,
      completedTasks: solverResults.length,
      findings,
      errors,
    });

    const userMessage: ChatMessage = { role: "user", content: prompt };
    this.conversationHistory.push(userMessage);

    const response = await this.client.chat(
      this.conversationHistory,
      COORDINATOR_SYSTEM_PROMPT
    );

    this.trackTokens(response.usage);
    this.conversationHistory.push({ role: "assistant", content: response.content });

    const parsed = this.parseJSON<LLMSynthesisResponse>(response.content);

    log.info(
      {
        riskScore: parsed.riskScore,
        criticalCount: parsed.criticalFindings.length,
        chainCount: parsed.exploitChains.length,
        recommendationCount: parsed.recommendations.length,
      },
      "Results synthesised"
    );

    return {
      summary: parsed.summary,
      criticalFindings: parsed.criticalFindings,
      exploitChains: parsed.exploitChains,
      riskScore: parsed.riskScore,
      recommendations: parsed.recommendations,
      usage: response.usage,
    };
  }

  // -----------------------------------------------------------------------
  // Memory access
  // -----------------------------------------------------------------------

  getMemory(): CoordinatorMemory {
    return this.memory;
  }

  // -----------------------------------------------------------------------
  // Private helpers
  // -----------------------------------------------------------------------

  private buildAttackPlan(
    raw: LLMAttackPlanResponse,
    target: Target,
    config: ScanConfig
  ): CoordinatorAttackPlan {
    const planId = randomUUID();
    const now = new Date().toISOString();

    const phases: CoordinatorAttackPhase[] = raw.phases.map((phase) => ({
      order: phase.order,
      name: phase.name,
      description: phase.description,
      estimatedDurationSec: phase.estimatedDurationSec,
      tasks: phase.tasks.map((task) => ({
        id: randomUUID(),
        scanId: this.scanId,
        assignedRole: AgentRoleEnum.Solver as typeof AgentRoleEnum.Solver,
        vulnerabilityType: this.resolveVulnCategory(task.vulnerabilityType),
        endpoint: task.endpoint,
        method: task.method,
        parameters: (task.parameters ?? []).map((p) => ({
          name: p.name,
          type: p.type as "query" | "path" | "body" | "header" | "cookie",
          dataType: p.dataType,
          sampleValue: p.sampleValue,
        })),
        context: task.context,
        priority: task.priority,
        status: AgentTaskStatus.Pending,
        difficulty: task.difficulty,
        createdAt: now,
      })),
    }));

    return {
      id: planId,
      scanId: this.scanId,
      targetId: target.id,
      strategy: raw.strategy,
      phases,
      totalEstimatedDurationSec: phases.reduce(
        (sum, p) => sum + p.estimatedDurationSec,
        0
      ),
      prioritizedCategories: raw.prioritizedCategories.map((c) =>
        this.resolveVulnCategory(c)
      ),
      detectedTechnologies: raw.detectedTechnologies,
      createdAt: now,
    };
  }

  /**
   * Maps a free-form vulnerability type string from the LLM to the
   * VulnerabilityCategory enum. Falls back to APIVuln for unrecognised types.
   */
  private resolveVulnCategory(raw: string): VulnerabilityCategory {
    const normalised = raw.toLowerCase().replace(/[^a-z_]/g, "");
    const mapping: Record<string, VulnerabilityCategory> = {
      xss: VulnCat.XSS,
      crosssitescripting: VulnCat.XSS,
      sqli: VulnCat.SQLi,
      sqlinjection: VulnCat.SQLi,
      ssrf: VulnCat.SSRF,
      serversiderequestforgery: VulnCat.SSRF,
      idor: VulnCat.IDOR,
      insecuredirectobjectreference: VulnCat.IDOR,
      auth_bypass: VulnCat.AuthBypass,
      authbypass: VulnCat.AuthBypass,
      authenticationbypass: VulnCat.AuthBypass,
      cors: VulnCat.CORS,
      header_misconfig: VulnCat.HeaderMisconfig,
      headermisconfig: VulnCat.HeaderMisconfig,
      api_vuln: VulnCat.APIVuln,
      apivuln: VulnCat.APIVuln,
      graphql: VulnCat.GraphQL,
      rce: VulnCat.RCE,
      remotecodeexecution: VulnCat.RCE,
      lfi: VulnCat.LFI,
      localfileinclusion: VulnCat.LFI,
      open_redirect: VulnCat.OpenRedirect,
      openredirect: VulnCat.OpenRedirect,
      xxe: VulnCat.XXE,
      deserialization: VulnCat.Deserialization,
      cryptographic: VulnCat.Cryptographic,
      information_disclosure: VulnCat.InformationDisclosure,
      informationdisclosure: VulnCat.InformationDisclosure,
      business_logic: VulnCat.BusinessLogic,
      businesslogic: VulnCat.BusinessLogic,
      smart_contract: VulnCat.SmartContract,
      smartcontract: VulnCat.SmartContract,
    };

    return mapping[normalised] ?? VulnCat.APIVuln;
  }

  /**
   * Safely parse a JSON string from LLM output. Handles markdown fences
   * and trailing content after the JSON block.
   */
  private parseJSON<T>(text: string): T {
    // Strip markdown code fences if present
    let cleaned = text.trim();
    const jsonFenceRegex = /```(?:json)?\s*\n?([\s\S]*?)\n?\s*```/;
    const fenceMatch = cleaned.match(jsonFenceRegex);
    if (fenceMatch) {
      cleaned = fenceMatch[1].trim();
    }

    // Try to extract JSON object or array from surrounding text
    const jsonStartObj = cleaned.indexOf("{");
    const jsonStartArr = cleaned.indexOf("[");
    let jsonStart = -1;
    if (jsonStartObj === -1) jsonStart = jsonStartArr;
    else if (jsonStartArr === -1) jsonStart = jsonStartObj;
    else jsonStart = Math.min(jsonStartObj, jsonStartArr);

    if (jsonStart > 0) {
      cleaned = cleaned.slice(jsonStart);
    }

    // Find the matching closing bracket
    const openChar = cleaned[0];
    const closeChar = openChar === "{" ? "}" : "]";
    let depth = 0;
    let jsonEnd = -1;
    let inString = false;
    let escape = false;

    for (let i = 0; i < cleaned.length; i++) {
      const ch = cleaned[i];
      if (escape) {
        escape = false;
        continue;
      }
      if (ch === "\\") {
        escape = true;
        continue;
      }
      if (ch === '"') {
        inString = !inString;
        continue;
      }
      if (inString) continue;
      if (ch === openChar) depth++;
      if (ch === closeChar) {
        depth--;
        if (depth === 0) {
          jsonEnd = i;
          break;
        }
      }
    }

    if (jsonEnd > 0) {
      cleaned = cleaned.slice(0, jsonEnd + 1);
    }

    try {
      return JSON.parse(cleaned) as T;
    } catch (err) {
      log.error({ text: text.slice(0, 500) }, "Failed to parse LLM JSON response");
      throw new Error(
        `CoordinatorAgent: Failed to parse LLM response as JSON. ` +
          `Excerpt: ${cleaned.slice(0, 200)}...`
      );
    }
  }

  private trackTokens(usage: TokenUsage): void {
    this.memory.tokenUsage.input += usage.inputTokens;
    this.memory.tokenUsage.output += usage.outputTokens;
  }

  private addFact(category: string, content: string, confidence: number): void {
    this.memory.facts.push({
      category,
      content,
      confidence,
      recordedAt: new Date().toISOString(),
    });
  }

  private countBy<T>(items: T[], keyFn: (item: T) => string): Record<string, number> {
    const counts: Record<string, number> = {};
    for (const item of items) {
      const key = keyFn(item);
      counts[key] = (counts[key] ?? 0) + 1;
    }
    return counts;
  }
}
