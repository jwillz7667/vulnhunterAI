import { randomUUID } from "node:crypto";
import type { ChatMessage, TokenUsage } from "../types.js";
import type { IAIClient } from "../interface.js";
import { createLogger } from "../../utils/logger.js";
import {
  SOLVER_SYSTEM_PROMPT,
  buildPayloadGenerationPrompt,
  buildResponseAnalysisPrompt,
} from "../prompts/solver.js";

import type { AgentTask } from "../../types/agent.js";
import type {
  Vulnerability,
  Finding,
  Severity,
  VulnerabilityCategory,
  HttpRequest,
  HttpResponse,
  Evidence,
} from "../../types/vulnerability.js";
import {
  Severity as SeverityEnum,
  VulnerabilityCategory as VulnCat,
} from "../../types/vulnerability.js";

// ---------------------------------------------------------------------------
// Logger
// ---------------------------------------------------------------------------

const log = createLogger("ai:solver");

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** A generated test payload ready to be sent to the target. */
export interface TestPayload {
  value: string;
  technique: string;
  description: string;
  encoding: string;
  injectionPoint: string;
}

/** Result of analysing a single HTTP response against a payload. */
export interface AnalysisResult {
  vulnerable: boolean;
  confidence: number;
  severity: Severity;
  category: VulnerabilityCategory;
  title: string;
  description: string;
  evidence: string;
  cweId?: string;
  cvssScore?: number;
  cvssVector?: string;
  remediation?: string;
  references: string[];
}

/** Full result returned after executing a solver task. */
export interface SolverResult {
  taskId: string;
  found: boolean;
  severity?: Severity;
  category?: VulnerabilityCategory;
  title?: string;
  description: string;
  payload?: string;
  request?: HttpRequest;
  response?: HttpResponse;
  confidence: number;
  remediation?: string;
  cweId?: string;
  cvssScore?: number;
  cvssVector?: string;
  references: string[];
  tokensUsed: { input: number; output: number };
}

/** Configuration for the solver agent. */
export interface SolverConfig {
  /** Technologies detected on the target, used for context-aware payloads. */
  technologies: string[];
  /** Maximum payloads to generate per task. */
  maxPayloads: number;
  /** Minimum confidence to consider a finding valid. */
  minConfidence: number;
  /** HTTP requester function -- injected by the caller so the solver is transport-agnostic. */
  sendRequest: (request: HttpRequest) => Promise<HttpResponse>;
  /** Optional: baseline response for differential analysis. */
  getBaseline?: (endpoint: string, method: string) => Promise<HttpResponse | undefined>;
}

// ---------------------------------------------------------------------------
// LLM response shapes
// ---------------------------------------------------------------------------

interface LLMPayloadResponse {
  payloads: Array<{
    value: string;
    technique: string;
    description: string;
    encoding: string;
    injectionPoint: string;
  }>;
}

interface LLMAnalysisResponse {
  vulnerable: boolean;
  confidence: number;
  severity?: string;
  category?: string;
  title?: string;
  description: string;
  evidence?: string;
  cweId?: string;
  cvssScore?: number;
  cvssVector?: string;
  remediation?: string;
  references?: string[];
}

// ---------------------------------------------------------------------------
// SolverAgent
// ---------------------------------------------------------------------------

export class SolverAgent {
  private readonly client: IAIClient;
  private readonly config: SolverConfig;
  private readonly conversationHistory: ChatMessage[] = [];
  private tokenUsage = { input: 0, output: 0 };

  constructor(params: { client: IAIClient; config: SolverConfig }) {
    this.client = params.client;
    this.config = params.config;
  }

  // -----------------------------------------------------------------------
  // execute
  // -----------------------------------------------------------------------

  /**
   * Runs the assigned security test against a specific endpoint.
   * 1. Generates payloads using AI.
   * 2. Sends each payload to the target.
   * 3. Analyses responses to determine vulnerability presence.
   * 4. Returns a structured SolverResult.
   */
  async execute(task: AgentTask): Promise<SolverResult> {
    const module = (task.context as Record<string, unknown>).module as string | undefined;
    const vulnType = module ?? "api_vuln";

    log.info(
      { taskId: task.id, target: task.target, vulnType },
      "Solver executing task"
    );

    // 1. Generate payloads
    const payloads = await this.generatePayloads(vulnType, {
      endpoint: task.target,
      method: "GET",
      parameters: [],
      instruction: task.instruction,
    });

    if (payloads.length === 0) {
      log.warn({ taskId: task.id }, "No payloads generated");
      return this.buildNegativeResult(task.id, "No payloads could be generated for this test.");
    }

    // 2. Get baseline response for differential analysis
    let baseline: HttpResponse | undefined;
    if (this.config.getBaseline) {
      try {
        baseline = await this.config.getBaseline(task.target, "GET");
      } catch {
        log.debug({ taskId: task.id }, "Baseline request failed, proceeding without");
      }
    }

    // 3. Test each payload
    let bestResult: SolverResult | undefined;

    for (const payload of payloads) {
      try {
        const request = this.buildRequest(task.target, "GET", payload);
        const response = await this.config.sendRequest(request);

        const analysis = await this.analyzeResponse({
          vulnType,
          endpoint: task.target,
          payload: payload.value,
          request,
          response,
          baseline,
        });

        if (analysis.vulnerable && analysis.confidence >= this.config.minConfidence) {
          const result: SolverResult = {
            taskId: task.id,
            found: true,
            severity: this.resolveSeverity(analysis.severity ?? "medium"),
            category: this.resolveCategory(analysis.category ?? vulnType),
            title: analysis.title,
            description: analysis.description,
            payload: payload.value,
            request,
            response,
            confidence: analysis.confidence,
            remediation: analysis.remediation,
            cweId: analysis.cweId,
            cvssScore: analysis.cvssScore,
            cvssVector: analysis.cvssVector,
            references: analysis.references,
            tokensUsed: { ...this.tokenUsage },
          };

          // Keep the highest-confidence result
          if (!bestResult || result.confidence > bestResult.confidence) {
            bestResult = result;
          }

          // If very high confidence, no need to test remaining payloads
          if (analysis.confidence >= 90) {
            log.info(
              {
                taskId: task.id,
                confidence: analysis.confidence,
                payload: payload.value.slice(0, 80),
              },
              "High-confidence vulnerability found, stopping payload iteration"
            );
            break;
          }
        }
      } catch (err) {
        log.warn(
          { taskId: task.id, payload: payload.value.slice(0, 60), error: String(err) },
          "Payload test failed"
        );
      }
    }

    if (bestResult) {
      log.info(
        {
          taskId: task.id,
          severity: bestResult.severity,
          confidence: bestResult.confidence,
        },
        "Solver found vulnerability"
      );
      return bestResult;
    }

    log.info({ taskId: task.id }, "No vulnerability found");
    return this.buildNegativeResult(
      task.id,
      `No ${vulnType} vulnerability detected at ${task.target} after testing ${payloads.length} payloads.`
    );
  }

  // -----------------------------------------------------------------------
  // generatePayloads
  // -----------------------------------------------------------------------

  /**
   * Uses AI to generate context-aware test payloads for a specific
   * vulnerability type and endpoint.
   */
  async generatePayloads(
    vulnType: string,
    context: {
      endpoint: string;
      method: string;
      parameters: Array<{ name: string; type: string; dataType?: string; sampleValue?: string }>;
      instruction: string;
      previousAttempts?: string[];
    }
  ): Promise<TestPayload[]> {
    log.debug({ vulnType, endpoint: context.endpoint }, "Generating payloads");

    const prompt = buildPayloadGenerationPrompt({
      vulnerabilityType: vulnType,
      endpoint: context.endpoint,
      method: context.method,
      parameters: context.parameters,
      technologies: this.config.technologies,
      context: context.instruction,
      previousAttempts: context.previousAttempts,
    });

    const messages: ChatMessage[] = [{ role: "user", content: prompt }];

    const response = await this.client.chat(messages, SOLVER_SYSTEM_PROMPT);
    this.accumulateTokens(response.usage);

    try {
      const parsed = this.parseJSON<LLMPayloadResponse>(response.content);
      const payloads = (parsed.payloads ?? []).slice(0, this.config.maxPayloads);

      log.debug(
        { vulnType, count: payloads.length },
        "Payloads generated"
      );

      return payloads;
    } catch (err) {
      log.error(
        { vulnType, error: String(err) },
        "Failed to parse payload generation response"
      );
      return [];
    }
  }

  // -----------------------------------------------------------------------
  // analyzeResponse
  // -----------------------------------------------------------------------

  /**
   * Uses AI to determine whether an HTTP response indicates that a
   * vulnerability was successfully triggered by the payload.
   */
  async analyzeResponse(params: {
    vulnType: string;
    endpoint: string;
    payload: string;
    request: HttpRequest;
    response: HttpResponse;
    baseline?: HttpResponse;
  }): Promise<AnalysisResult> {
    log.debug(
      { vulnType: params.vulnType, endpoint: params.endpoint, status: params.response.statusCode },
      "Analysing response"
    );

    const prompt = buildResponseAnalysisPrompt({
      vulnerabilityType: params.vulnType,
      endpoint: params.endpoint,
      payload: params.payload,
      request: {
        method: params.request.method,
        url: params.request.url,
        headers: params.request.headers,
        body: params.request.body,
      },
      response: {
        statusCode: params.response.statusCode,
        headers: params.response.headers,
        body: params.response.body,
        responseTimeMs: params.response.responseTimeMs,
      },
      baselineResponse: params.baseline
        ? {
            statusCode: params.baseline.statusCode,
            headers: params.baseline.headers,
            body: params.baseline.body,
            responseTimeMs: params.baseline.responseTimeMs,
          }
        : undefined,
    });

    const messages: ChatMessage[] = [{ role: "user", content: prompt }];

    const response = await this.client.chat(messages, SOLVER_SYSTEM_PROMPT);
    this.accumulateTokens(response.usage);

    try {
      const parsed = this.parseJSON<LLMAnalysisResponse>(response.content);

      return {
        vulnerable: parsed.vulnerable,
        confidence: Math.min(100, Math.max(0, parsed.confidence)),
        severity: this.resolveSeverity(parsed.severity ?? "info"),
        category: this.resolveCategory(parsed.category ?? params.vulnType),
        title: parsed.title ?? `Potential ${params.vulnType} at ${params.endpoint}`,
        description: parsed.description,
        evidence: parsed.evidence ?? "",
        cweId: parsed.cweId,
        cvssScore: parsed.cvssScore,
        cvssVector: parsed.cvssVector,
        remediation: parsed.remediation,
        references: parsed.references ?? [],
      };
    } catch (err) {
      log.error({ error: String(err) }, "Failed to parse analysis response");
      return {
        vulnerable: false,
        confidence: 0,
        severity: SeverityEnum.Info,
        category: this.resolveCategory(params.vulnType),
        title: "",
        description: "Analysis failed: could not parse LLM response",
        evidence: "",
        references: [],
      };
    }
  }

  // -----------------------------------------------------------------------
  // Private helpers
  // -----------------------------------------------------------------------

  private buildRequest(
    endpoint: string,
    method: string,
    payload: TestPayload
  ): HttpRequest {
    const url = new URL(endpoint);

    // Inject payload based on injection point
    const injectionPoint = payload.injectionPoint.toLowerCase();

    if (injectionPoint.includes("query") || injectionPoint.includes("parameter")) {
      // Extract the parameter name from "query parameter 'xyz'" patterns
      const paramMatch = payload.injectionPoint.match(/['"](\w+)['"]/);
      const paramName = paramMatch?.[1] ?? "q";
      url.searchParams.set(paramName, payload.value);
    }

    const headers: Record<string, string> = {
      "User-Agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
      Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Accept-Language": "en-US,en;q=0.5",
    };

    if (injectionPoint.includes("header")) {
      const headerMatch = payload.injectionPoint.match(/['"]([^'"]+)['"]/);
      const headerName = headerMatch?.[1] ?? "X-Custom-Header";
      headers[headerName] = payload.value;
    }

    let body: string | undefined;
    if (
      injectionPoint.includes("body") &&
      (method === "POST" || method === "PUT" || method === "PATCH")
    ) {
      headers["Content-Type"] = "application/x-www-form-urlencoded";
      const paramMatch = payload.injectionPoint.match(/['"](\w+)['"]/);
      const paramName = paramMatch?.[1] ?? "input";
      body = `${encodeURIComponent(paramName)}=${encodeURIComponent(payload.value)}`;
    }

    return {
      method,
      url: url.toString(),
      headers,
      body,
    };
  }

  private buildNegativeResult(taskId: string, description: string): SolverResult {
    return {
      taskId,
      found: false,
      description,
      confidence: 0,
      references: [],
      tokensUsed: { ...this.tokenUsage },
    };
  }

  private resolveSeverity(raw: string): Severity {
    const normalised = raw.toLowerCase().trim();
    const map: Record<string, Severity> = {
      critical: SeverityEnum.Critical,
      high: SeverityEnum.High,
      medium: SeverityEnum.Medium,
      low: SeverityEnum.Low,
      info: SeverityEnum.Info,
      informational: SeverityEnum.Info,
    };
    return map[normalised] ?? SeverityEnum.Info;
  }

  private resolveCategory(raw: string): VulnerabilityCategory {
    const normalised = raw.toLowerCase().replace(/[^a-z_]/g, "");
    const map: Record<string, VulnerabilityCategory> = {
      xss: VulnCat.XSS,
      sqli: VulnCat.SQLi,
      sqlinjection: VulnCat.SQLi,
      ssrf: VulnCat.SSRF,
      idor: VulnCat.IDOR,
      authbypass: VulnCat.AuthBypass,
      auth_bypass: VulnCat.AuthBypass,
      cors: VulnCat.CORS,
      headermisconfig: VulnCat.HeaderMisconfig,
      header_misconfig: VulnCat.HeaderMisconfig,
      apivuln: VulnCat.APIVuln,
      api_vuln: VulnCat.APIVuln,
      graphql: VulnCat.GraphQL,
      rce: VulnCat.RCE,
      lfi: VulnCat.LFI,
      openredirect: VulnCat.OpenRedirect,
      open_redirect: VulnCat.OpenRedirect,
      xxe: VulnCat.XXE,
      deserialization: VulnCat.Deserialization,
      cryptographic: VulnCat.Cryptographic,
      informationdisclosure: VulnCat.InformationDisclosure,
      information_disclosure: VulnCat.InformationDisclosure,
      businesslogic: VulnCat.BusinessLogic,
      business_logic: VulnCat.BusinessLogic,
      smartcontract: VulnCat.SmartContract,
      smart_contract: VulnCat.SmartContract,
    };
    return map[normalised] ?? VulnCat.APIVuln;
  }

  private accumulateTokens(usage: TokenUsage): void {
    this.tokenUsage.input += usage.inputTokens;
    this.tokenUsage.output += usage.outputTokens;
  }

  /**
   * Robustly extract JSON from LLM output, handling fences and surrounding text.
   */
  private parseJSON<T>(text: string): T {
    let cleaned = text.trim();

    const jsonFenceRegex = /```(?:json)?\s*\n?([\s\S]*?)\n?\s*```/;
    const fenceMatch = cleaned.match(jsonFenceRegex);
    if (fenceMatch) {
      cleaned = fenceMatch[1].trim();
    }

    const jsonStartObj = cleaned.indexOf("{");
    const jsonStartArr = cleaned.indexOf("[");
    let jsonStart = -1;
    if (jsonStartObj === -1) jsonStart = jsonStartArr;
    else if (jsonStartArr === -1) jsonStart = jsonStartObj;
    else jsonStart = Math.min(jsonStartObj, jsonStartArr);

    if (jsonStart > 0) {
      cleaned = cleaned.slice(jsonStart);
    }

    if (cleaned.length === 0 || (cleaned[0] !== "{" && cleaned[0] !== "[")) {
      throw new Error(`SolverAgent: No JSON found in LLM response`);
    }

    const openChar = cleaned[0];
    const closeChar = openChar === "{" ? "}" : "]";
    let depth = 0;
    let jsonEnd = -1;
    let inString = false;
    let escape = false;

    for (let i = 0; i < cleaned.length; i++) {
      const ch = cleaned[i];
      if (escape) { escape = false; continue; }
      if (ch === "\\") { escape = true; continue; }
      if (ch === '"') { inString = !inString; continue; }
      if (inString) continue;
      if (ch === openChar) depth++;
      if (ch === closeChar) {
        depth--;
        if (depth === 0) { jsonEnd = i; break; }
      }
    }

    if (jsonEnd > 0) {
      cleaned = cleaned.slice(0, jsonEnd + 1);
    }

    return JSON.parse(cleaned) as T;
  }
}
