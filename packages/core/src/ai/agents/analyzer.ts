import type { ChatMessage, TokenUsage } from "../types.js";
import type { IAIClient } from "../interface.js";
import { createLogger } from "../../utils/logger.js";
import {
  ANALYZER_SYSTEM_PROMPT,
  buildCorrelationPrompt,
  buildExploitChainPrompt,
  buildFalsePositivePrompt,
  buildSASTDASTCorrelationPrompt,
  buildImpactAssessmentPrompt,
} from "../prompts/analyzer.js";

import type {
  Finding,
  Vulnerability,
  ExploitChain,
  ExploitStep,
  Severity,
} from "../../types/vulnerability.js";
import {
  Severity as SeverityEnum,
  SEVERITY_WEIGHT,
} from "../../types/vulnerability.js";

// ---------------------------------------------------------------------------
// Logger
// ---------------------------------------------------------------------------

const log = createLogger("ai:analyzer");

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Result of correlating two or more findings. */
export interface CorrelationResult {
  findingIds: string[];
  relationship: string;
  description: string;
  mergedSeverity: Severity;
  mergedConfidence: number;
}

/** Result of exploit chain detection. */
export interface DetectedChain {
  name: string;
  steps: Array<{ order: number; vulnerabilityId: string; outcome: string }>;
  feasibility: number;
  impact: number;
  combinedScore: number;
  combinedSeverity: Severity;
  narrative: string;
}

/** Result of false-positive analysis for a single finding. */
export interface FalsePositiveAnalysis {
  findingId: string;
  isFalsePositive: boolean;
  confidence: number;
  reason: string;
}

/** Result of impact assessment. */
export interface ImpactAssessment {
  confidentiality: string;
  integrity: string;
  availability: string;
  businessImpact: string;
  exploitability: string;
  adjustedSeverity: Severity;
  cvssScore: number;
  cvssVector: string;
  narrative: string;
}

/** A SAST finding for correlation purposes. */
export interface StaticFinding {
  id: string;
  title: string;
  filePath: string;
  lineNumber: number;
  category: string;
  severity: string;
  codeSnippet: string;
}

/** A DAST finding for correlation purposes. */
export interface DynamicFinding {
  id: string;
  title: string;
  endpoint: string;
  category: string;
  severity: string;
  confidence: number;
}

/** Result of SAST/DAST correlation. */
export interface SASTDASTCorrelation {
  staticFindingId: string;
  dynamicFindingId?: string;
  correlated: boolean;
  adjustedConfidence: number;
  explanation: string;
}

// ---------------------------------------------------------------------------
// LLM response shapes
// ---------------------------------------------------------------------------

interface LLMCorrelationResponse {
  correlations: Array<{
    findingIds: string[];
    relationship: string;
    description: string;
    mergedSeverity: string;
    mergedConfidence: number;
  }>;
}

interface LLMChainResponse {
  chains: Array<{
    name: string;
    steps: Array<{ order: number; vulnerabilityId: string; outcome: string }>;
    feasibility: number;
    impact: number;
    combinedScore: number;
    combinedSeverity: string;
    narrative: string;
  }>;
}

interface LLMFalsePositiveResponse {
  analysis: Array<{
    findingId: string;
    isFalsePositive: boolean;
    confidence: number;
    reason: string;
  }>;
}

interface LLMImpactResponse {
  confidentiality: string;
  integrity: string;
  availability: string;
  businessImpact: string;
  exploitability: string;
  adjustedSeverity: string;
  cvssScore: number;
  cvssVector: string;
  narrative: string;
}

interface LLMSASTDASTResponse {
  correlations: Array<{
    staticFindingId: string;
    dynamicFindingId?: string;
    correlated: boolean;
    adjustedConfidence: number;
    explanation: string;
  }>;
}

// ---------------------------------------------------------------------------
// AnalyzerAgent
// ---------------------------------------------------------------------------

export class AnalyzerAgent {
  private readonly client: IAIClient;
  private tokenUsage = { input: 0, output: 0 };

  constructor(params: { client: IAIClient }) {
    this.client = params.client;
    log.info("AnalyzerAgent initialised");
  }

  // -----------------------------------------------------------------------
  // correlateFindings
  // -----------------------------------------------------------------------

  /**
   * Identifies relationships between vulnerabilities: same root cause,
   * same component, overlapping attack surface, or related impact.
   * Returns correlation groups with merged severity and confidence.
   */
  async correlateFindings(findings: Finding[]): Promise<CorrelationResult[]> {
    if (findings.length < 2) return [];

    log.info({ findingCount: findings.length }, "Correlating findings");

    const summaries = findings.map((f) => ({
      id: f.vulnerability.id,
      title: f.vulnerability.title,
      severity: f.vulnerability.severity,
      category: f.vulnerability.category,
      endpoint: f.vulnerability.endpoint ?? f.vulnerability.target,
      description: f.vulnerability.description.slice(0, 300),
      confidence: f.confidence,
      cweId: f.vulnerability.cweId,
    }));

    const prompt = buildCorrelationPrompt(summaries);
    const messages: ChatMessage[] = [{ role: "user", content: prompt }];

    const response = await this.client.chat(messages, ANALYZER_SYSTEM_PROMPT);
    this.accumulateTokens(response.usage);

    const parsed = this.parseJSON<LLMCorrelationResponse>(response.content);

    const results: CorrelationResult[] = parsed.correlations.map((c) => ({
      findingIds: c.findingIds,
      relationship: c.relationship,
      description: c.description,
      mergedSeverity: this.resolveSeverity(c.mergedSeverity),
      mergedConfidence: Math.min(100, Math.max(0, c.mergedConfidence)),
    }));

    log.info(
      { correlationCount: results.length },
      "Finding correlation complete"
    );

    return results;
  }

  // -----------------------------------------------------------------------
  // detectExploitChains
  // -----------------------------------------------------------------------

  /**
   * Identifies compound vulnerability chains where multiple lower-severity
   * findings can be combined into a higher-impact attack.
   */
  async detectExploitChains(findings: Finding[]): Promise<DetectedChain[]> {
    if (findings.length < 2) return [];

    log.info({ findingCount: findings.length }, "Detecting exploit chains");

    const summaries = findings.map((f) => ({
      id: f.vulnerability.id,
      title: f.vulnerability.title,
      severity: f.vulnerability.severity,
      category: f.vulnerability.category,
      endpoint: f.vulnerability.endpoint ?? f.vulnerability.target,
      description: f.vulnerability.description.slice(0, 400),
    }));

    const prompt = buildExploitChainPrompt(summaries);
    const messages: ChatMessage[] = [{ role: "user", content: prompt }];

    const response = await this.client.chat(messages, ANALYZER_SYSTEM_PROMPT);
    this.accumulateTokens(response.usage);

    const parsed = this.parseJSON<LLMChainResponse>(response.content);

    const chains: DetectedChain[] = parsed.chains.map((c) => ({
      name: c.name,
      steps: c.steps.map((s, idx) => ({
        order: s.order ?? idx + 1,
        vulnerabilityId: s.vulnerabilityId,
        outcome: s.outcome,
      })),
      feasibility: Math.min(10, Math.max(1, c.feasibility)),
      impact: Math.min(10, Math.max(1, c.impact)),
      combinedScore: Math.min(10, Math.max(0, c.combinedScore)),
      combinedSeverity: this.resolveSeverity(c.combinedSeverity),
      narrative: c.narrative,
    }));

    log.info(
      { chainCount: chains.length },
      "Exploit chain detection complete"
    );

    return chains;
  }

  // -----------------------------------------------------------------------
  // assessImpact
  // -----------------------------------------------------------------------

  /**
   * Performs a deep impact assessment on a single finding, evaluating
   * CIA triad impact, business consequences, and exploitability.
   * Returns an adjusted severity and CVSS score.
   */
  async assessImpact(
    finding: Finding,
    context: { technologies: string[]; targetType: string; hasAuthentication: boolean }
  ): Promise<ImpactAssessment> {
    log.info(
      { findingId: finding.vulnerability.id, title: finding.vulnerability.title },
      "Assessing impact"
    );

    const prompt = buildImpactAssessmentPrompt({
      title: finding.vulnerability.title,
      severity: finding.vulnerability.severity,
      category: finding.vulnerability.category,
      description: finding.vulnerability.description,
      endpoint: finding.vulnerability.endpoint ?? finding.vulnerability.target,
      technologies: context.technologies,
      targetType: context.targetType,
      hasAuthentication: context.hasAuthentication,
    });

    const messages: ChatMessage[] = [{ role: "user", content: prompt }];

    const response = await this.client.chat(messages, ANALYZER_SYSTEM_PROMPT);
    this.accumulateTokens(response.usage);

    const parsed = this.parseJSON<LLMImpactResponse>(response.content);

    const result: ImpactAssessment = {
      confidentiality: parsed.confidentiality,
      integrity: parsed.integrity,
      availability: parsed.availability,
      businessImpact: parsed.businessImpact,
      exploitability: parsed.exploitability,
      adjustedSeverity: this.resolveSeverity(parsed.adjustedSeverity),
      cvssScore: Math.min(10, Math.max(0, parsed.cvssScore)),
      cvssVector: parsed.cvssVector,
      narrative: parsed.narrative,
    };

    log.info(
      {
        findingId: finding.vulnerability.id,
        adjustedSeverity: result.adjustedSeverity,
        cvssScore: result.cvssScore,
      },
      "Impact assessment complete"
    );

    return result;
  }

  // -----------------------------------------------------------------------
  // eliminateFalsePositives
  // -----------------------------------------------------------------------

  /**
   * AI-powered false positive reduction. Reviews each finding's evidence,
   * response context, and technology stack to determine which findings
   * are genuine and which are noise.
   */
  async eliminateFalsePositives(findings: Finding[]): Promise<FalsePositiveAnalysis[]> {
    if (findings.length === 0) return [];

    log.info(
      { findingCount: findings.length },
      "Eliminating false positives"
    );

    // Process in batches of 10 to stay within token limits
    const batchSize = 10;
    const allResults: FalsePositiveAnalysis[] = [];

    for (let i = 0; i < findings.length; i += batchSize) {
      const batch = findings.slice(i, i + batchSize);

      const summaries = batch.map((f) => ({
        id: f.vulnerability.id,
        title: f.vulnerability.title,
        category: f.vulnerability.category,
        endpoint: f.vulnerability.endpoint ?? f.vulnerability.target,
        payload: f.vulnerability.evidence?.payload ?? "(no payload)",
        responseContentType: f.vulnerability.response?.headers["content-type"],
        responseBody: f.vulnerability.response?.body?.slice(0, 500),
        responseStatusCode: f.vulnerability.response?.statusCode,
        confidence: f.confidence,
      }));

      const prompt = buildFalsePositivePrompt(summaries);
      const messages: ChatMessage[] = [{ role: "user", content: prompt }];

      const response = await this.client.chat(messages, ANALYZER_SYSTEM_PROMPT);
      this.accumulateTokens(response.usage);

      const parsed = this.parseJSON<LLMFalsePositiveResponse>(response.content);

      for (const item of parsed.analysis) {
        allResults.push({
          findingId: item.findingId,
          isFalsePositive: item.isFalsePositive,
          confidence: Math.min(100, Math.max(0, item.confidence)),
          reason: item.reason,
        });
      }
    }

    const fpCount = allResults.filter((r) => r.isFalsePositive).length;
    log.info(
      { total: findings.length, falsePositives: fpCount, truePositives: findings.length - fpCount },
      "False positive elimination complete"
    );

    return allResults;
  }

  // -----------------------------------------------------------------------
  // correlateSASTDAST
  // -----------------------------------------------------------------------

  /**
   * Correlates static analysis (code-level) findings with dynamic analysis
   * (runtime) findings. Increases confidence when both SAST and DAST
   * confirm the same issue; decreases confidence for uncorroborated findings.
   */
  async correlateSASTDAST(
    staticFindings: StaticFinding[],
    dynamicFindings: DynamicFinding[]
  ): Promise<SASTDASTCorrelation[]> {
    if (staticFindings.length === 0 && dynamicFindings.length === 0) return [];

    log.info(
      {
        staticCount: staticFindings.length,
        dynamicCount: dynamicFindings.length,
      },
      "Correlating SAST and DAST findings"
    );

    const prompt = buildSASTDASTCorrelationPrompt({
      staticFindings,
      dynamicFindings,
    });

    const messages: ChatMessage[] = [{ role: "user", content: prompt }];

    const response = await this.client.chat(messages, ANALYZER_SYSTEM_PROMPT);
    this.accumulateTokens(response.usage);

    const parsed = this.parseJSON<LLMSASTDASTResponse>(response.content);

    const results: SASTDASTCorrelation[] = parsed.correlations.map((c) => ({
      staticFindingId: c.staticFindingId,
      dynamicFindingId: c.dynamicFindingId,
      correlated: c.correlated,
      adjustedConfidence: Math.min(100, Math.max(0, c.adjustedConfidence)),
      explanation: c.explanation,
    }));

    log.info(
      {
        totalCorrelations: results.length,
        correlated: results.filter((r) => r.correlated).length,
      },
      "SAST/DAST correlation complete"
    );

    return results;
  }

  // -----------------------------------------------------------------------
  // Token usage
  // -----------------------------------------------------------------------

  getTokenUsage(): { input: number; output: number } {
    return { ...this.tokenUsage };
  }

  // -----------------------------------------------------------------------
  // Private helpers
  // -----------------------------------------------------------------------

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

  private accumulateTokens(usage: TokenUsage): void {
    this.tokenUsage.input += usage.inputTokens;
    this.tokenUsage.output += usage.outputTokens;
  }

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
      throw new Error(`AnalyzerAgent: No JSON found in LLM response`);
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

    try {
      return JSON.parse(cleaned) as T;
    } catch (err) {
      log.error({ text: text.slice(0, 500) }, "Failed to parse LLM JSON response");
      throw new Error(
        `AnalyzerAgent: Failed to parse LLM response as JSON. Excerpt: ${cleaned.slice(0, 200)}...`
      );
    }
  }
}
