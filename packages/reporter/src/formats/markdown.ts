import type { ReportVulnerability, ReportConfig, ReportStatistics } from "../generator.js";
import type { ComplianceResult } from "../compliance.js";

export interface MarkdownReportData {
  title: string;
  scanId: string;
  executiveSummary?: string;
  vulnerabilities: ReportVulnerability[];
  statistics: ReportStatistics;
  complianceResults: ComplianceResult[];
  config: ReportConfig;
  generatedAt: string;
}

export function generateMarkdown(data: MarkdownReportData): string {
  const lines: string[] = [];

  // Header
  lines.push(`# ${data.title}`);
  lines.push("");
  lines.push(`**Generated:** ${new Date(data.generatedAt).toLocaleString()}`);
  lines.push(`**Scan ID:** ${data.scanId}`);
  lines.push(`**Tool:** VulnHunter AI v1.0.0`);
  lines.push("");
  lines.push("---");
  lines.push("");

  // Executive Summary
  if (data.executiveSummary) {
    lines.push("## Executive Summary");
    lines.push("");
    lines.push(data.executiveSummary);
    lines.push("");
  }

  // Statistics
  lines.push("## Summary Statistics");
  lines.push("");
  lines.push(`| Metric | Value |`);
  lines.push(`|--------|-------|`);
  lines.push(`| Total Vulnerabilities | ${data.statistics.totalVulnerabilities} |`);
  lines.push(`| Confirmed | ${data.statistics.confirmedVulnerabilities} |`);
  lines.push(`| Average CVSS | ${data.statistics.averageCvss} |`);
  lines.push(`| Risk Score | ${data.statistics.riskScore}/100 |`);
  lines.push("");

  // Severity breakdown
  lines.push("### Severity Distribution");
  lines.push("");
  lines.push("| Severity | Count |");
  lines.push("|----------|-------|");
  for (const [severity, count] of Object.entries(data.statistics.bySeverity)) {
    const icon = getSeverityIcon(severity);
    lines.push(`| ${icon} ${severity.toUpperCase()} | ${count} |`);
  }
  lines.push("");

  // Category breakdown
  if (Object.keys(data.statistics.byCategory).length > 0) {
    lines.push("### Vulnerability Categories");
    lines.push("");
    lines.push("| Category | Count |");
    lines.push("|----------|-------|");
    for (const [category, count] of Object.entries(data.statistics.byCategory)) {
      lines.push(`| ${formatCategory(category)} | ${count} |`);
    }
    lines.push("");
  }

  // Vulnerabilities
  lines.push("## Vulnerabilities");
  lines.push("");

  for (const vuln of data.vulnerabilities) {
    const icon = getSeverityIcon(vuln.severity);
    lines.push(`### ${icon} ${vuln.title}`);
    lines.push("");
    lines.push(`**Severity:** ${vuln.severity.toUpperCase()} | **CVSS:** ${vuln.cvssScore || "N/A"} | **CWE:** ${vuln.cweId || "N/A"} | **Confidence:** ${vuln.confidence}%`);
    if (vuln.confirmed) lines.push("**Status:** CONFIRMED");
    lines.push("");
    lines.push(`**Category:** ${formatCategory(vuln.category)}`);
    if (vuln.endpoint) {
      lines.push(`**Endpoint:** \`${vuln.method || "GET"} ${vuln.endpoint}\``);
    }
    if (vuln.parameter) {
      lines.push(`**Parameter:** \`${vuln.parameter}\``);
    }
    lines.push("");

    // Description
    lines.push("#### Description");
    lines.push("");
    lines.push(vuln.description);
    lines.push("");

    // Evidence
    if (data.config.includeEvidence && vuln.evidence) {
      lines.push("#### Evidence");
      lines.push("");
      lines.push("```");
      lines.push(JSON.stringify(vuln.evidence, null, 2));
      lines.push("```");
      lines.push("");
    }

    // Raw HTTP
    if (data.config.includeRawHttp && (vuln.request || vuln.response)) {
      if (vuln.request) {
        lines.push("#### HTTP Request");
        lines.push("");
        lines.push("```http");
        lines.push(vuln.request);
        lines.push("```");
        lines.push("");
      }
      if (vuln.response) {
        lines.push("#### HTTP Response");
        lines.push("");
        lines.push("```http");
        lines.push(vuln.response.slice(0, 2000));
        lines.push("```");
        lines.push("");
      }
    }

    // Remediation
    if (data.config.includeRemediation && vuln.remediation) {
      lines.push("#### Remediation");
      lines.push("");
      lines.push(vuln.remediation);
      lines.push("");
    }

    // References
    if (vuln.references && vuln.references.length > 0) {
      lines.push("#### References");
      lines.push("");
      for (const ref of vuln.references) {
        lines.push(`- ${ref}`);
      }
      lines.push("");
    }

    if (vuln.cvssVector) {
      lines.push(`**CVSS Vector:** \`${vuln.cvssVector}\``);
      lines.push("");
    }

    lines.push("---");
    lines.push("");
  }

  // Compliance
  if (data.complianceResults.length > 0) {
    lines.push("## Compliance Mapping");
    lines.push("");

    for (const result of data.complianceResults) {
      lines.push(`### ${result.framework} ${result.version}`);
      lines.push("");
      lines.push(`**Overall Score:** ${result.overallScore}%`);
      lines.push("");
      lines.push(`${result.summary}`);
      lines.push("");
      lines.push("| Control | Name | Status | Findings |");
      lines.push("|---------|------|--------|----------|");

      for (const control of result.controls) {
        const statusIcon = getStatusIcon(control.status);
        lines.push(
          `| ${control.id} | ${control.name} | ${statusIcon} ${control.status} | ${control.findingIds.length} |`
        );
      }
      lines.push("");
    }
  }

  // Footer
  lines.push("---");
  lines.push("");
  lines.push("*Report generated by VulnHunter AI - Autonomous Security Research Platform*");

  return lines.join("\n");
}

function getSeverityIcon(severity: string): string {
  switch (severity.toLowerCase()) {
    case "critical": return "[CRITICAL]";
    case "high": return "[HIGH]";
    case "medium": return "[MEDIUM]";
    case "low": return "[LOW]";
    case "info": return "[INFO]";
    default: return "[?]";
  }
}

function getStatusIcon(status: string): string {
  switch (status) {
    case "pass": return "[PASS]";
    case "fail": return "[FAIL]";
    case "partial": return "[PARTIAL]";
    case "not_applicable": return "[N/A]";
    default: return "[?]";
  }
}

function formatCategory(category: string): string {
  return category
    .split("_")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}
