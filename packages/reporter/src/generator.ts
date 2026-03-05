import { createLogger } from "@vulnhunter/core";
import { calculateCvss, estimateCvss, type CvssResult } from "./cvss.js";
import { getCweForCategory, getCweById } from "./cwe-mapper.js";
import { mapToCompliance, type ComplianceResult } from "./compliance.js";
import { generateMarkdown } from "./formats/markdown.js";
import { generateHtml } from "./formats/html.js";
import { generateJson } from "./formats/json.js";

const log = createLogger("reporter");

export interface ReportVulnerability {
  id: string;
  title: string;
  description: string;
  severity: string;
  category: string;
  cvssScore?: number;
  cvssVector?: string;
  cweId?: string;
  endpoint?: string;
  method?: string;
  parameter?: string;
  evidence?: Record<string, unknown>;
  request?: string;
  response?: string;
  remediation?: string;
  references?: string[];
  confirmed: boolean;
  falsePositive: boolean;
  module: string;
  confidence: number;
}

export interface ReportConfig {
  format: "json" | "markdown" | "html" | "pdf";
  title?: string;
  includeEvidence: boolean;
  includeRemediation: boolean;
  includeRawHttp: boolean;
  executiveSummary: boolean;
  complianceFrameworks: string[];
  minimumSeverity?: string;
  excludeFalsePositives: boolean;
}

export interface ReportStatistics {
  totalVulnerabilities: number;
  confirmedVulnerabilities: number;
  bySeverity: Record<string, number>;
  byCategory: Record<string, number>;
  averageCvss: number;
  riskScore: number;
  exploitChains: number;
}

export interface GeneratedReport {
  id: string;
  title: string;
  format: string;
  content: string;
  statistics: ReportStatistics;
  complianceResults: ComplianceResult[];
  generatedAt: string;
}

const DEFAULT_CONFIG: ReportConfig = {
  format: "markdown",
  includeEvidence: true,
  includeRemediation: true,
  includeRawHttp: false,
  executiveSummary: true,
  complianceFrameworks: ["owasp_top10"],
  excludeFalsePositives: true,
};

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export class ReportGenerator {
  generate(
    scanId: string,
    vulnerabilities: ReportVulnerability[],
    config: Partial<ReportConfig> = {}
  ): GeneratedReport {
    const cfg = { ...DEFAULT_CONFIG, ...config };

    log.info(
      { scanId, vulnCount: vulnerabilities.length, format: cfg.format },
      "Generating report"
    );

    // Filter vulnerabilities
    let filtered = [...vulnerabilities];
    if (cfg.excludeFalsePositives) {
      filtered = filtered.filter((v) => !v.falsePositive);
    }
    if (cfg.minimumSeverity) {
      const minOrder = SEVERITY_ORDER[cfg.minimumSeverity] ?? 4;
      filtered = filtered.filter(
        (v) => (SEVERITY_ORDER[v.severity] ?? 4) <= minOrder
      );
    }

    // Sort by severity
    filtered.sort(
      (a, b) =>
        (SEVERITY_ORDER[a.severity] ?? 4) - (SEVERITY_ORDER[b.severity] ?? 4)
    );

    // Enrich with CVSS and CWE data
    const enriched = filtered.map((v) => this.enrichVulnerability(v));

    // Calculate statistics
    const statistics = this.calculateStatistics(enriched);

    // Generate compliance mappings
    const complianceResults = cfg.complianceFrameworks.map((framework) =>
      mapToCompliance(
        framework,
        enriched.map((v) => ({
          id: v.id,
          category: v.category,
          severity: v.severity,
          cweId: v.cweId,
        }))
      )
    );

    // Generate executive summary
    const executiveSummary = cfg.executiveSummary
      ? this.generateExecutiveSummary(statistics, complianceResults)
      : undefined;

    // Render content in requested format
    const title = cfg.title || `VulnHunter Security Assessment Report`;
    let content: string;

    switch (cfg.format) {
      case "json":
        content = generateJson({
          title,
          scanId,
          executiveSummary,
          vulnerabilities: enriched,
          statistics,
          complianceResults,
          config: cfg,
          generatedAt: new Date().toISOString(),
        });
        break;
      case "html":
        content = generateHtml({
          title,
          scanId,
          executiveSummary,
          vulnerabilities: enriched,
          statistics,
          complianceResults,
          config: cfg,
          generatedAt: new Date().toISOString(),
        });
        break;
      case "markdown":
      default:
        content = generateMarkdown({
          title,
          scanId,
          executiveSummary,
          vulnerabilities: enriched,
          statistics,
          complianceResults,
          config: cfg,
          generatedAt: new Date().toISOString(),
        });
        break;
    }

    const report: GeneratedReport = {
      id: crypto.randomUUID(),
      title,
      format: cfg.format,
      content,
      statistics,
      complianceResults,
      generatedAt: new Date().toISOString(),
    };

    log.info(
      {
        reportId: report.id,
        format: cfg.format,
        vulnCount: enriched.length,
        contentLength: content.length,
      },
      "Report generated"
    );

    return report;
  }

  private enrichVulnerability(vuln: ReportVulnerability): ReportVulnerability {
    // Add CWE if missing
    if (!vuln.cweId) {
      const cwe = getCweForCategory(vuln.category);
      if (cwe) vuln.cweId = cwe.id;
    }

    // Add CVSS score if missing
    if (!vuln.cvssScore) {
      let cvss: CvssResult;
      if (vuln.cvssVector) {
        const { parseVector } = require("./cvss.js");
        cvss = calculateCvss(parseVector(vuln.cvssVector));
      } else {
        cvss = estimateCvss(vuln.category, vuln.confirmed);
      }
      vuln.cvssScore = cvss.score;
      vuln.cvssVector = cvss.vector;
    }

    // Add remediation if missing
    if (!vuln.remediation) {
      vuln.remediation = this.getDefaultRemediation(vuln.category);
    }

    // Add references if missing
    if (!vuln.references || vuln.references.length === 0) {
      const cwe = vuln.cweId ? getCweById(vuln.cweId) : getCweForCategory(vuln.category);
      vuln.references = cwe ? [cwe.url] : [];
    }

    return vuln;
  }

  private calculateStatistics(vulns: ReportVulnerability[]): ReportStatistics {
    const bySeverity: Record<string, number> = {};
    const byCategory: Record<string, number> = {};
    let totalCvss = 0;

    for (const v of vulns) {
      bySeverity[v.severity] = (bySeverity[v.severity] || 0) + 1;
      byCategory[v.category] = (byCategory[v.category] || 0) + 1;
      totalCvss += v.cvssScore || 0;
    }

    const averageCvss = vulns.length > 0 ? totalCvss / vulns.length : 0;
    const riskScore = this.calculateRiskScore(vulns);

    return {
      totalVulnerabilities: vulns.length,
      confirmedVulnerabilities: vulns.filter((v) => v.confirmed).length,
      bySeverity,
      byCategory,
      averageCvss: Math.round(averageCvss * 10) / 10,
      riskScore,
      exploitChains: 0,
    };
  }

  private calculateRiskScore(vulns: ReportVulnerability[]): number {
    if (vulns.length === 0) return 0;

    const weights: Record<string, number> = {
      critical: 40,
      high: 25,
      medium: 10,
      low: 3,
      info: 1,
    };

    let totalWeight = 0;
    for (const v of vulns) {
      const baseWeight = weights[v.severity] || 1;
      const confirmedMultiplier = v.confirmed ? 1.5 : 1;
      totalWeight += baseWeight * confirmedMultiplier;
    }

    // Normalize to 0-100, cap at 100
    return Math.min(100, Math.round(totalWeight));
  }

  private generateExecutiveSummary(
    stats: ReportStatistics,
    compliance: ComplianceResult[]
  ): string {
    const critical = stats.bySeverity["critical"] || 0;
    const high = stats.bySeverity["high"] || 0;
    const medium = stats.bySeverity["medium"] || 0;
    const low = stats.bySeverity["low"] || 0;

    let riskLevel: string;
    if (critical > 0) riskLevel = "CRITICAL";
    else if (high > 0) riskLevel = "HIGH";
    else if (medium > 0) riskLevel = "MODERATE";
    else if (low > 0) riskLevel = "LOW";
    else riskLevel = "MINIMAL";

    let summary = `This security assessment identified ${stats.totalVulnerabilities} vulnerabilities `;
    summary += `(${critical} critical, ${high} high, ${medium} medium, ${low} low). `;
    summary += `Overall risk level: ${riskLevel} (score: ${stats.riskScore}/100). `;

    if (stats.confirmedVulnerabilities > 0) {
      summary += `${stats.confirmedVulnerabilities} vulnerabilities were confirmed through exploit validation. `;
    }

    if (critical > 0) {
      summary += `Immediate action is required to address ${critical} critical severity finding(s). `;
    }

    for (const cr of compliance) {
      summary += `${cr.framework} compliance score: ${cr.overallScore}%. `;
    }

    return summary;
  }

  private getDefaultRemediation(category: string): string {
    const remediations: Record<string, string> = {
      xss: "Implement output encoding/escaping for all user-controlled data. Use Content Security Policy (CSP) headers. Adopt a template engine with auto-escaping enabled.",
      sqli: "Use parameterized queries or prepared statements. Implement an ORM. Validate and sanitize all user input. Apply principle of least privilege to database accounts.",
      ssrf: "Validate and whitelist allowed URLs/domains. Block requests to internal/private IP ranges. Disable unnecessary URL schemes. Use a dedicated service for URL fetching.",
      idor: "Implement proper authorization checks on all object references. Use indirect references (UUIDs) instead of sequential IDs. Verify user permissions server-side.",
      auth_bypass: "Implement multi-factor authentication. Use well-tested authentication libraries. Validate JWTs properly including algorithm verification. Enforce strong session management.",
      cors: "Restrict Access-Control-Allow-Origin to trusted domains. Never reflect arbitrary origins. Avoid using credentials with wildcard origins.",
      header_misconfig: "Implement all recommended security headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.",
      rce: "Never pass user input to system commands. Use safe APIs instead of shell execution. Implement strict input validation. Run applications with minimal privileges.",
      lfi: "Validate and sanitize file paths. Use a whitelist of allowed files. Avoid passing user input to file operations. Implement chroot or container isolation.",
      open_redirect: "Validate redirect URLs against a whitelist of allowed domains. Use relative paths for redirects. Warn users before redirecting to external sites.",
      information_disclosure: "Remove sensitive information from error messages, headers, and responses. Disable debug mode in production. Use generic error pages.",
      dependency: "Update vulnerable dependencies to patched versions. Enable automated dependency scanning in CI/CD. Use lock files to pin dependency versions.",
      cryptographic: "Use current cryptographic algorithms (AES-256-GCM, SHA-256+). Avoid deprecated algorithms (MD5, SHA-1, DES). Use established cryptographic libraries.",
      ssl_tls: "Disable TLS 1.0 and 1.1. Enable TLS 1.2+ with strong cipher suites. Implement HSTS. Use valid certificates from trusted CAs.",
      smart_contract: "Follow check-effects-interactions pattern. Use SafeMath for arithmetic operations. Implement access control modifiers. Conduct formal verification.",
    };

    return remediations[category] || "Review and remediate according to security best practices for this vulnerability class.";
  }
}
