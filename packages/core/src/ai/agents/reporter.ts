import type { ChatMessage, TokenUsage } from "../types.js";
import type { IAIClient } from "../interface.js";
import { createLogger } from "../../utils/logger.js";
import {
  REPORTER_SYSTEM_PROMPT,
  buildNarrativePrompt,
  buildRemediationPrompt,
  buildExecutiveSummaryPrompt,
  buildPlatformFormatPrompt,
} from "../prompts/reporter.js";

import type { Vulnerability, Finding, Severity } from "../../types/vulnerability.js";
import type { ScanResult } from "../../types/scan.js";
import { Severity as SeverityEnum, SEVERITY_WEIGHT } from "../../types/vulnerability.js";

// ---------------------------------------------------------------------------
// Logger
// ---------------------------------------------------------------------------

const log = createLogger("ai:reporter");

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type BugBountyPlatform = "hackerone" | "bugcrowd" | "intigriti";

/** Generated narrative for a single vulnerability. */
export interface VulnerabilityNarrative {
  vulnerabilityId: string;
  narrative: string;
  tokensUsed: { input: number; output: number };
}

/** Generated remediation guidance for a single vulnerability. */
export interface RemediationGuidance {
  vulnerabilityId: string;
  guidance: string;
  tokensUsed: { input: number; output: number };
}

/** Generated executive summary for a scan. */
export interface ExecutiveSummary {
  scanId: string;
  summary: string;
  tokensUsed: { input: number; output: number };
}

/** Vulnerability formatted for a specific bug bounty platform. */
export interface PlatformSubmission {
  vulnerabilityId: string;
  platform: BugBountyPlatform;
  formattedReport: string;
  tokensUsed: { input: number; output: number };
}

// ---------------------------------------------------------------------------
// ReporterAgent
// ---------------------------------------------------------------------------

export class ReporterAgent {
  private readonly client: IAIClient;
  private readonly technologies: string[];
  private totalTokenUsage = { input: 0, output: 0 };

  constructor(params: { client: IAIClient; technologies?: string[] }) {
    this.client = params.client;
    this.technologies = params.technologies ?? [];
    log.info("ReporterAgent initialised");
  }

  // -----------------------------------------------------------------------
  // generateNarrative
  // -----------------------------------------------------------------------

  /**
   * Creates a detailed, human-readable narrative for a vulnerability.
   * Includes explanation, reproduction steps, impact analysis, and references.
   */
  async generateNarrative(vulnerability: Vulnerability): Promise<VulnerabilityNarrative> {
    log.info(
      { vulnId: vulnerability.id, title: vulnerability.title },
      "Generating narrative"
    );

    const prompt = buildNarrativePrompt({
      title: vulnerability.title,
      severity: vulnerability.severity,
      category: vulnerability.category,
      endpoint: vulnerability.endpoint ?? vulnerability.target,
      description: vulnerability.description,
      payload: vulnerability.evidence?.payload,
      evidence: vulnerability.evidence?.description,
      request: vulnerability.request,
      response: vulnerability.response
        ? {
            statusCode: vulnerability.response.statusCode,
            headers: vulnerability.response.headers,
            body: vulnerability.response.body,
          }
        : undefined,
      technologies: this.technologies,
      cweId: vulnerability.cweId,
      cvssScore: vulnerability.cvssScore,
      cvssVector: vulnerability.cvssVector,
    });

    const messages: ChatMessage[] = [{ role: "user", content: prompt }];
    const response = await this.client.chat(messages, REPORTER_SYSTEM_PROMPT);
    this.accumulateTokens(response.usage);

    log.debug(
      { vulnId: vulnerability.id, contentLength: response.content.length },
      "Narrative generated"
    );

    return {
      vulnerabilityId: vulnerability.id,
      narrative: response.content,
      tokensUsed: { input: response.usage.inputTokens, output: response.usage.outputTokens },
    };
  }

  // -----------------------------------------------------------------------
  // suggestRemediation
  // -----------------------------------------------------------------------

  /**
   * Provides specific, actionable remediation guidance with code examples
   * tailored to the target's technology stack.
   */
  async suggestRemediation(vulnerability: Vulnerability): Promise<RemediationGuidance> {
    log.info(
      { vulnId: vulnerability.id, title: vulnerability.title },
      "Generating remediation guidance"
    );

    const prompt = buildRemediationPrompt({
      title: vulnerability.title,
      category: vulnerability.category,
      endpoint: vulnerability.endpoint ?? vulnerability.target,
      description: vulnerability.description,
      technologies: this.technologies,
      cweId: vulnerability.cweId,
    });

    const messages: ChatMessage[] = [{ role: "user", content: prompt }];
    const response = await this.client.chat(messages, REPORTER_SYSTEM_PROMPT);
    this.accumulateTokens(response.usage);

    log.debug(
      { vulnId: vulnerability.id, contentLength: response.content.length },
      "Remediation guidance generated"
    );

    return {
      vulnerabilityId: vulnerability.id,
      guidance: response.content,
      tokensUsed: { input: response.usage.inputTokens, output: response.usage.outputTokens },
    };
  }

  // -----------------------------------------------------------------------
  // writeExecutiveSummary
  // -----------------------------------------------------------------------

  /**
   * Generates an executive summary of the entire scan result for
   * non-technical stakeholders (CISOs, CTOs, board members).
   */
  async writeExecutiveSummary(scanResult: ScanResult): Promise<ExecutiveSummary> {
    log.info(
      { scanId: scanResult.id, findingCount: scanResult.findings.length },
      "Writing executive summary"
    );

    const severityCounts = this.countBySeverity(scanResult.findings);

    // Get top findings sorted by severity weight
    const topFindings = scanResult.findings
      .slice()
      .sort(
        (a, b) =>
          (SEVERITY_WEIGHT[b.vulnerability.severity as Severity] ?? 0) -
          (SEVERITY_WEIGHT[a.vulnerability.severity as Severity] ?? 0)
      )
      .slice(0, 5)
      .map((f) => ({
        title: f.vulnerability.title,
        severity: f.vulnerability.severity,
        impact: f.vulnerability.description.slice(0, 150),
      }));

    // Calculate scan duration in minutes
    const durationMs = scanResult.endTime
      ? new Date(scanResult.endTime).getTime() - new Date(scanResult.startTime).getTime()
      : 0;
    const durationMinutes = Math.max(1, Math.round(durationMs / 60_000));

    // Count exploit chains from stats
    const exploitChainCount = scanResult.stats.exploitChainsFound ?? 0;

    const prompt = buildExecutiveSummaryPrompt({
      targetName: scanResult.target,
      scanType: scanResult.scanType,
      totalFindings: scanResult.findings.length,
      criticalCount: severityCounts.critical,
      highCount: severityCounts.high,
      mediumCount: severityCounts.medium,
      lowCount: severityCounts.low,
      infoCount: severityCounts.info,
      exploitChainCount,
      topFindings,
      scanDurationMinutes: durationMinutes,
    });

    const messages: ChatMessage[] = [{ role: "user", content: prompt }];
    const response = await this.client.chat(messages, REPORTER_SYSTEM_PROMPT);
    this.accumulateTokens(response.usage);

    log.debug(
      { scanId: scanResult.id, contentLength: response.content.length },
      "Executive summary generated"
    );

    return {
      scanId: scanResult.id,
      summary: response.content,
      tokensUsed: { input: response.usage.inputTokens, output: response.usage.outputTokens },
    };
  }

  // -----------------------------------------------------------------------
  // formatForPlatform
  // -----------------------------------------------------------------------

  /**
   * Formats a vulnerability for submission to a specific bug bounty platform
   * (HackerOne, Bugcrowd, or Intigriti) following platform-specific templates.
   */
  async formatForPlatform(
    vulnerability: Vulnerability,
    platform: BugBountyPlatform
  ): Promise<PlatformSubmission> {
    log.info(
      { vulnId: vulnerability.id, platform },
      "Formatting for platform"
    );

    const prompt = buildPlatformFormatPrompt({
      platform,
      title: vulnerability.title,
      severity: vulnerability.severity,
      category: vulnerability.category,
      endpoint: vulnerability.endpoint ?? vulnerability.target,
      description: vulnerability.description,
      payload: vulnerability.evidence?.payload,
      evidence: vulnerability.evidence?.description,
      request: vulnerability.request,
      response: vulnerability.response
        ? {
            statusCode: vulnerability.response.statusCode,
            headers: vulnerability.response.headers,
            body: vulnerability.response.body,
          }
        : undefined,
      cweId: vulnerability.cweId,
      cvssScore: vulnerability.cvssScore,
      remediation: vulnerability.remediation,
    });

    const messages: ChatMessage[] = [{ role: "user", content: prompt }];
    const response = await this.client.chat(messages, REPORTER_SYSTEM_PROMPT);
    this.accumulateTokens(response.usage);

    log.debug(
      { vulnId: vulnerability.id, platform, contentLength: response.content.length },
      "Platform formatting complete"
    );

    return {
      vulnerabilityId: vulnerability.id,
      platform,
      formattedReport: response.content,
      tokensUsed: { input: response.usage.inputTokens, output: response.usage.outputTokens },
    };
  }

  // -----------------------------------------------------------------------
  // Batch operations
  // -----------------------------------------------------------------------

  /**
   * Generates narratives for multiple vulnerabilities in sequence.
   * Useful for building complete reports.
   */
  async generateNarratives(vulnerabilities: Vulnerability[]): Promise<VulnerabilityNarrative[]> {
    const results: VulnerabilityNarrative[] = [];
    for (const vuln of vulnerabilities) {
      const narrative = await this.generateNarrative(vuln);
      results.push(narrative);
    }
    return results;
  }

  /**
   * Generates remediation guidance for multiple vulnerabilities in sequence.
   */
  async suggestRemediations(vulnerabilities: Vulnerability[]): Promise<RemediationGuidance[]> {
    const results: RemediationGuidance[] = [];
    for (const vuln of vulnerabilities) {
      const remediation = await this.suggestRemediation(vuln);
      results.push(remediation);
    }
    return results;
  }

  // -----------------------------------------------------------------------
  // Token usage
  // -----------------------------------------------------------------------

  getTokenUsage(): { input: number; output: number } {
    return { ...this.totalTokenUsage };
  }

  // -----------------------------------------------------------------------
  // Private helpers
  // -----------------------------------------------------------------------

  private countBySeverity(
    findings: Finding[]
  ): Record<"critical" | "high" | "medium" | "low" | "info", number> {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of findings) {
      const sev = f.vulnerability.severity.toLowerCase();
      if (sev in counts) {
        counts[sev as keyof typeof counts]++;
      }
    }
    return counts;
  }

  private accumulateTokens(usage: TokenUsage): void {
    this.totalTokenUsage.input += usage.inputTokens;
    this.totalTokenUsage.output += usage.outputTokens;
  }
}
