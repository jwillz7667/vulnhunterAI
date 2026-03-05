// =============================================================================
// @vulnhunter/cli - Report Command
// =============================================================================
// Generates, views, and exports security assessment reports from completed
// scans. Supports JSON, Markdown, and HTML output formats with optional
// compliance framework mapping (OWASP Top 10, PCI-DSS, NIST, SOC 2, ISO 27001).
//
// Usage:
//   vulnhunter report <scan-id>
//   vulnhunter report <scan-id> --format html --compliance owasp,pci-dss
//   vulnhunter report <scan-id> --output ./reports/assessment.html
// =============================================================================

import { Command } from "commander";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import type {
  ScanResult,
  Finding,
  Severity,
  ScanStatistics,
} from "@vulnhunter/core";
import { ScanProgressDisplay } from "../ui/progress.js";
import { renderVulnerabilityTable, renderSeveritySummary } from "../ui/table.js";
import { getConfigValue } from "./config.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const REPORT_CACHE_DIR = path.join(os.homedir(), ".vulnhunter", "reports");
const SCAN_CACHE_DIR = path.join(os.homedir(), ".vulnhunter", "scans");

const SUPPORTED_FORMATS = ["json", "markdown", "html"] as const;
type ReportFormat = (typeof SUPPORTED_FORMATS)[number];

const COMPLIANCE_FRAMEWORKS = [
  "owasp",
  "pci-dss",
  "nist",
  "soc2",
  "iso27001",
] as const;
type ComplianceFramework = (typeof COMPLIANCE_FRAMEWORKS)[number];

// ---------------------------------------------------------------------------
// Compliance Framework Definitions
// ---------------------------------------------------------------------------

interface ComplianceControl {
  id: string;
  name: string;
  description: string;
  status: "pass" | "fail" | "partial" | "not_applicable";
  relatedFindings: string[];
}

interface ComplianceReport {
  framework: string;
  frameworkLabel: string;
  overallScore: number;
  totalControls: number;
  passedControls: number;
  failedControls: number;
  partialControls: number;
  controls: ComplianceControl[];
}

/**
 * Returns the full set of controls for a given compliance framework and
 * maps scan findings to each control. A control "fails" if at least one
 * finding maps to its vulnerability categories; "passes" if none do.
 */
function buildComplianceReport(
  framework: ComplianceFramework,
  findings: Finding[],
): ComplianceReport {
  const definitions = getFrameworkDefinition(framework);
  const findingCategories = new Set(
    findings.map((f) => f.vulnerability.category),
  );

  const controls: ComplianceControl[] = definitions.controls.map((ctrl) => {
    const relatedFindings = findings
      .filter((f) => ctrl.categories.includes(f.vulnerability.category as string))
      .map((f) => f.vulnerability.id);

    let status: ComplianceControl["status"];
    if (relatedFindings.length === 0) {
      status = "pass";
    } else if (
      relatedFindings.length > 0 &&
      findings.some(
        (f) =>
          ctrl.categories.includes(f.vulnerability.category as string) &&
          (f.vulnerability.severity === "critical" ||
            f.vulnerability.severity === "high"),
      )
    ) {
      status = "fail";
    } else {
      status = "partial";
    }

    return {
      id: ctrl.id,
      name: ctrl.name,
      description: ctrl.description,
      status,
      relatedFindings,
    };
  });

  const passedControls = controls.filter((c) => c.status === "pass").length;
  const failedControls = controls.filter((c) => c.status === "fail").length;
  const partialControls = controls.filter((c) => c.status === "partial").length;
  const totalControls = controls.length;
  const overallScore =
    totalControls > 0
      ? Math.round(((passedControls + partialControls * 0.5) / totalControls) * 100)
      : 100;

  return {
    framework,
    frameworkLabel: definitions.label,
    overallScore,
    totalControls,
    passedControls,
    failedControls,
    partialControls,
    controls,
  };
}

interface FrameworkDefinition {
  label: string;
  controls: Array<{
    id: string;
    name: string;
    description: string;
    categories: string[];
  }>;
}

function getFrameworkDefinition(framework: ComplianceFramework): FrameworkDefinition {
  switch (framework) {
    case "owasp":
      return {
        label: "OWASP Top 10 (2021)",
        controls: [
          { id: "A01:2021", name: "Broken Access Control", description: "Failures in access control enforcement", categories: ["idor", "auth_bypass", "cors"] },
          { id: "A02:2021", name: "Cryptographic Failures", description: "Failures related to cryptography", categories: ["cryptographic", "information_disclosure"] },
          { id: "A03:2021", name: "Injection", description: "SQL, NoSQL, OS, LDAP injection", categories: ["sqli", "rce", "xxe", "lfi"] },
          { id: "A04:2021", name: "Insecure Design", description: "Risks related to design and architectural flaws", categories: ["business_logic"] },
          { id: "A05:2021", name: "Security Misconfiguration", description: "Missing or incorrect security configurations", categories: ["header_misconfig", "cors"] },
          { id: "A06:2021", name: "Vulnerable Components", description: "Using components with known vulnerabilities", categories: ["information_disclosure"] },
          { id: "A07:2021", name: "Auth Failures", description: "Authentication and session management failures", categories: ["auth_bypass"] },
          { id: "A08:2021", name: "Data Integrity Failures", description: "Software and data integrity failures", categories: ["deserialization"] },
          { id: "A09:2021", name: "Logging Failures", description: "Security logging and monitoring failures", categories: [] },
          { id: "A10:2021", name: "SSRF", description: "Server-Side Request Forgery", categories: ["ssrf"] },
        ],
      };
    case "pci-dss":
      return {
        label: "PCI DSS v4.0",
        controls: [
          { id: "6.2.4", name: "Software Engineering Practices", description: "Prevent common software attacks", categories: ["sqli", "xss", "rce", "lfi", "xxe"] },
          { id: "6.3.1", name: "Known Vulnerabilities", description: "Identify and manage known vulnerabilities", categories: ["information_disclosure"] },
          { id: "6.4.1", name: "Public-Facing Web Apps", description: "Protect public-facing web applications", categories: ["xss", "sqli", "ssrf", "cors"] },
          { id: "8.3.1", name: "Authentication", description: "Strong authentication mechanisms", categories: ["auth_bypass"] },
          { id: "2.2.7", name: "Encrypted Transmission", description: "Encrypt all non-console administrative access", categories: ["cryptographic"] },
          { id: "11.3.1", name: "Vulnerability Scanning", description: "Internal vulnerability scans performed quarterly", categories: [] },
        ],
      };
    case "nist":
      return {
        label: "NIST Cybersecurity Framework v2.0",
        controls: [
          { id: "ID.RA-01", name: "Asset Vulnerabilities", description: "Vulnerabilities of organizational assets are identified", categories: ["information_disclosure", "header_misconfig"] },
          { id: "PR.AC-01", name: "Access Control", description: "Identities and credentials are managed", categories: ["auth_bypass", "idor"] },
          { id: "PR.DS-01", name: "Data Protection", description: "Data at rest and in transit is protected", categories: ["cryptographic", "information_disclosure"] },
          { id: "PR.IP-12", name: "Vulnerability Management", description: "A vulnerability management plan is developed and implemented", categories: [] },
          { id: "DE.CM-08", name: "Vulnerability Scans", description: "Vulnerability scans are performed", categories: [] },
          { id: "PR.AC-07", name: "Users and Devices", description: "Users, devices and other assets are authenticated", categories: ["auth_bypass"] },
        ],
      };
    case "soc2":
      return {
        label: "SOC 2 Type II",
        controls: [
          { id: "CC6.1", name: "Logical Access", description: "Logical access security over information assets", categories: ["auth_bypass", "idor"] },
          { id: "CC6.6", name: "System Boundaries", description: "Security measures against threats outside system boundaries", categories: ["ssrf", "xss", "sqli", "rce"] },
          { id: "CC6.7", name: "Data Transmission", description: "Restrict transmission of data to authorized parties", categories: ["cryptographic", "cors"] },
          { id: "CC7.1", name: "Vulnerability Detection", description: "Detection of vulnerabilities and anomalies", categories: ["information_disclosure"] },
          { id: "CC8.1", name: "Change Management", description: "Authorization, design, development, testing of changes", categories: [] },
        ],
      };
    case "iso27001":
      return {
        label: "ISO 27001:2022",
        controls: [
          { id: "A.8.8", name: "Technical Vulnerability Management", description: "Information about technical vulnerabilities shall be obtained", categories: ["information_disclosure"] },
          { id: "A.8.9", name: "Configuration Management", description: "Configurations shall be established and managed", categories: ["header_misconfig", "cors"] },
          { id: "A.8.12", name: "Data Leakage Prevention", description: "Data leakage prevention measures shall be applied", categories: ["information_disclosure", "cryptographic"] },
          { id: "A.8.24", name: "Use of Cryptography", description: "Rules for cryptography shall be defined and implemented", categories: ["cryptographic"] },
          { id: "A.8.25", name: "Secure Development Lifecycle", description: "Rules for secure development shall be established", categories: ["sqli", "xss", "rce", "ssrf", "lfi"] },
          { id: "A.8.26", name: "Application Security Requirements", description: "Security requirements shall be identified for applications", categories: ["auth_bypass", "idor", "business_logic"] },
          { id: "A.8.28", name: "Secure Coding", description: "Secure coding principles shall be applied", categories: ["sqli", "xss", "rce", "lfi", "xxe", "deserialization"] },
        ],
      };
    default:
      return { label: framework, controls: [] };
  }
}

// ---------------------------------------------------------------------------
// Scan Data Retrieval (Cache + Prisma DB)
// ---------------------------------------------------------------------------

/**
 * Retrieves scan results by ID. First checks the local cache directory
 * (~/.vulnhunter/scans/), then queries the Prisma database.
 */
async function loadScanResult(scanId: string): Promise<ScanResult> {
  // Check local cache first
  const cachePath = path.join(SCAN_CACHE_DIR, `${scanId}.json`);
  if (fs.existsSync(cachePath)) {
    return JSON.parse(fs.readFileSync(cachePath, "utf-8"));
  }

  // Load from database
  const { prisma } = await import("@vulnhunter/core");
  const scan = await prisma.scan.findUnique({
    where: { id: scanId },
    include: { target: true, vulnerabilities: true },
  });

  if (!scan) {
    throw new Error(
      `Scan "${scanId}" not found. Run 'vulnhunter scan <target>' first or check the scan ID.`,
    );
  }

  // Convert DB records to Finding[]
  const findings: Finding[] = scan.vulnerabilities.map((v) => ({
    vulnerability: {
      id: v.id,
      title: v.title,
      description: v.description,
      severity: v.severity.toLowerCase() as Severity,
      category: v.category.toLowerCase() as any,
      cvssScore: v.cvssScore ?? 0,
      cvssVector: v.cvssVector ?? "",
      cweId: v.cweId ?? undefined,
      target: scan.target.value,
      endpoint: v.endpoint ?? undefined,
      evidence: { description: (v.evidence as string) ?? "" },
      remediation: v.remediation ?? undefined,
      references:
        typeof v.references === "string"
          ? JSON.parse(v.references)
          : (v.references as string[]) ?? [],
      confirmed: v.confirmed,
      falsePositive: v.falsePositive,
      discoveredAt: v.createdAt.toISOString(),
    },
    module: v.module,
    confidence: v.confidence,
    timestamp: v.createdAt.toISOString(),
  }));

  const findingsBySeverity: Record<Severity, number> = {
    critical: scan.criticalCount,
    high: scan.highCount,
    medium: scan.mediumCount,
    low: scan.lowCount,
    info: scan.infoCount,
  } as Record<Severity, number>;

  const findingsByCategory: Record<string, number> = {};
  for (const f of findings) {
    const cat = f.vulnerability.category;
    findingsByCategory[cat] = (findingsByCategory[cat] || 0) + 1;
  }

  return {
    id: scan.id,
    target: scan.target.value,
    status: scan.status.toLowerCase() as any,
    scanType: scan.type.toLowerCase() as any,
    config: {
      target: scan.target.value,
      scanType: scan.type.toLowerCase() as any,
      options: (scan.config as any) ?? {},
    },
    startTime: (scan.startedAt ?? scan.createdAt).toISOString(),
    endTime: scan.completedAt?.toISOString() ?? new Date().toISOString(),
    findings,
    stats: {
      totalRequests: 0,
      endpointsDiscovered: 0,
      findingsBySeverity,
      findingsByCategory,
      confirmedFindings: findings.filter((f) => f.vulnerability.confirmed).length,
      falsePositives: findings.filter((f) => f.vulnerability.falsePositive).length,
      exploitChainsFound: 0,
      durationMs: (scan.duration ?? 0) * 1000,
      modulesCompleted: [],
      modulesFailed: [],
    },
  };
}

// ---------------------------------------------------------------------------
// Report Generators
// ---------------------------------------------------------------------------

interface FullReport {
  id: string;
  scanId: string;
  format: ReportFormat;
  title: string;
  generatedAt: string;
  target: string;
  executiveSummary: string;
  scanResult: ScanResult;
  complianceReports: ComplianceReport[];
  content: string;
}

/**
 * Builds the executive summary paragraph from scan statistics.
 */
function buildExecutiveSummary(result: ScanResult, complianceReports: ComplianceReport[]): string {
  const stats = result.stats;
  const crit = stats.findingsBySeverity["critical" as Severity] || 0;
  const high = stats.findingsBySeverity["high" as Severity] || 0;
  const med = stats.findingsBySeverity["medium" as Severity] || 0;
  const low = stats.findingsBySeverity["low" as Severity] || 0;
  const total = result.findings.length;

  let riskLevel: string;
  if (crit > 0) riskLevel = "CRITICAL";
  else if (high > 0) riskLevel = "HIGH";
  else if (med > 0) riskLevel = "MODERATE";
  else if (low > 0) riskLevel = "LOW";
  else riskLevel = "MINIMAL";

  let summary = `This security assessment of ${result.target} identified ${total} vulnerabilities `;
  summary += `(${crit} critical, ${high} high, ${med} medium, ${low} low). `;
  summary += `Overall risk level: ${riskLevel}. `;
  summary += `The scan completed in ${(stats.durationMs / 1000).toFixed(1)} seconds, `;
  summary += `testing ${stats.endpointsDiscovered} endpoints with ${stats.totalRequests} requests. `;

  if (stats.confirmedFindings > 0) {
    summary += `${stats.confirmedFindings} of ${total} vulnerabilities were confirmed through exploit validation. `;
  }

  if (stats.exploitChainsFound > 0) {
    summary += `${stats.exploitChainsFound} exploit chain(s) were identified combining multiple vulnerabilities. `;
  }

  if (crit > 0) {
    summary += `Immediate action is required to address ${crit} critical finding(s). `;
  }

  for (const cr of complianceReports) {
    summary += `${cr.frameworkLabel} compliance score: ${cr.overallScore}%. `;
  }

  return summary;
}

/**
 * Generates a Markdown report string.
 */
function generateMarkdownReport(report: FullReport): string {
  const { scanResult: result, complianceReports } = report;
  const lines: string[] = [];

  lines.push(`# ${report.title}`);
  lines.push("");
  lines.push(`**Generated:** ${report.generatedAt}`);
  lines.push(`**Target:** ${result.target}`);
  lines.push(`**Scan ID:** ${result.id}`);
  lines.push(`**Scan Type:** ${result.scanType}`);
  lines.push(`**Duration:** ${(result.stats.durationMs / 1000).toFixed(1)}s`);
  lines.push("");

  // Executive summary
  lines.push("## Executive Summary");
  lines.push("");
  lines.push(report.executiveSummary);
  lines.push("");

  // Statistics table
  lines.push("## Summary Statistics");
  lines.push("");
  lines.push("| Metric | Value |");
  lines.push("|--------|-------|");
  lines.push(`| Total Findings | ${result.findings.length} |`);
  lines.push(`| Confirmed | ${result.stats.confirmedFindings} |`);
  lines.push(`| Requests Sent | ${result.stats.totalRequests} |`);
  lines.push(`| Endpoints Discovered | ${result.stats.endpointsDiscovered} |`);
  lines.push(`| Exploit Chains | ${result.stats.exploitChainsFound} |`);
  lines.push("");

  // Severity breakdown
  lines.push("### Findings by Severity");
  lines.push("");
  lines.push("| Severity | Count |");
  lines.push("|----------|-------|");
  for (const [sev, count] of Object.entries(result.stats.findingsBySeverity)) {
    lines.push(`| ${sev.toUpperCase()} | ${count} |`);
  }
  lines.push("");

  // Compliance
  if (complianceReports.length > 0) {
    lines.push("## Compliance Mapping");
    lines.push("");

    for (const cr of complianceReports) {
      lines.push(`### ${cr.frameworkLabel}`);
      lines.push("");
      lines.push(`**Overall Score:** ${cr.overallScore}% (${cr.passedControls}/${cr.totalControls} controls passing)`);
      lines.push("");
      lines.push("| Control | Name | Status | Findings |");
      lines.push("|---------|------|--------|----------|");
      for (const ctrl of cr.controls) {
        const statusEmoji = ctrl.status === "pass" ? "PASS" : ctrl.status === "fail" ? "FAIL" : ctrl.status === "partial" ? "PARTIAL" : "N/A";
        lines.push(`| ${ctrl.id} | ${ctrl.name} | ${statusEmoji} | ${ctrl.relatedFindings.length} |`);
      }
      lines.push("");
    }
  }

  // Detailed findings
  lines.push("## Detailed Findings");
  lines.push("");

  const severityOrder: Record<string, number> = {
    critical: 0, high: 1, medium: 2, low: 3, info: 4,
  };

  const sorted = [...result.findings].sort(
    (a, b) =>
      (severityOrder[a.vulnerability.severity] ?? 5) -
      (severityOrder[b.vulnerability.severity] ?? 5),
  );

  for (const f of sorted) {
    const v = f.vulnerability;
    lines.push(`### ${v.severity.toUpperCase()}: ${v.title}`);
    lines.push("");
    lines.push(`- **Category:** ${v.category}`);
    lines.push(`- **CVSS:** ${v.cvssScore}`);
    lines.push(`- **CWE:** ${v.cweId || "N/A"}`);
    lines.push(`- **Endpoint:** \`${v.endpoint || v.target}\``);
    lines.push(`- **Confidence:** ${f.confidence}%`);
    lines.push(`- **Confirmed:** ${v.confirmed ? "Yes" : "No"}`);
    lines.push("");
    lines.push(`**Description:** ${v.description}`);
    if (v.remediation) {
      lines.push("");
      lines.push(`**Remediation:** ${v.remediation}`);
    }
    if (v.references && v.references.length > 0) {
      lines.push("");
      lines.push("**References:**");
      for (const ref of v.references) {
        lines.push(`- ${ref}`);
      }
    }
    lines.push("");
    lines.push("---");
    lines.push("");
  }

  return lines.join("\n");
}

/**
 * Generates an HTML report string with inline CSS styling.
 */
function generateHtmlReport(report: FullReport): string {
  const { scanResult: result, complianceReports } = report;

  const severityColors: Record<string, string> = {
    critical: "#dc2626",
    high: "#ea580c",
    medium: "#ca8a04",
    low: "#2563eb",
    info: "#6b7280",
  };

  const severityOrder: Record<string, number> = {
    critical: 0, high: 1, medium: 2, low: 3, info: 4,
  };

  const sorted = [...result.findings].sort(
    (a, b) =>
      (severityOrder[a.vulnerability.severity] ?? 5) -
      (severityOrder[b.vulnerability.severity] ?? 5),
  );

  const findingsHtml = sorted.map((f) => {
    const v = f.vulnerability;
    const color = severityColors[v.severity] || "#6b7280";
    return `
      <div class="finding" style="border-left: 4px solid ${color}; margin-bottom: 24px; padding: 16px; background: #fafafa; border-radius: 4px;">
        <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px;">
          <span class="severity-badge" style="background: ${color}; color: white; padding: 2px 10px; border-radius: 4px; font-weight: bold; font-size: 12px; text-transform: uppercase;">${v.severity}</span>
          <h3 style="margin: 0; font-size: 16px;">${escapeHtml(v.title)}</h3>
        </div>
        <table style="font-size: 14px; margin-bottom: 8px;">
          <tr><td style="padding-right: 16px; color: #666;"><strong>Category:</strong></td><td>${escapeHtml(v.category)}</td></tr>
          <tr><td style="padding-right: 16px; color: #666;"><strong>CVSS:</strong></td><td>${v.cvssScore}</td></tr>
          <tr><td style="padding-right: 16px; color: #666;"><strong>CWE:</strong></td><td>${escapeHtml(v.cweId || "N/A")}</td></tr>
          <tr><td style="padding-right: 16px; color: #666;"><strong>Endpoint:</strong></td><td><code>${escapeHtml(v.endpoint || v.target)}</code></td></tr>
          <tr><td style="padding-right: 16px; color: #666;"><strong>Confidence:</strong></td><td>${f.confidence}%</td></tr>
          <tr><td style="padding-right: 16px; color: #666;"><strong>Confirmed:</strong></td><td>${v.confirmed ? "Yes" : "No"}</td></tr>
        </table>
        <p style="margin: 8px 0;"><strong>Description:</strong> ${escapeHtml(v.description)}</p>
        ${v.remediation ? `<p style="margin: 8px 0; color: #166534; background: #dcfce7; padding: 8px; border-radius: 4px;"><strong>Remediation:</strong> ${escapeHtml(v.remediation)}</p>` : ""}
      </div>`;
  }).join("\n");

  const complianceHtml = complianceReports.map((cr) => {
    const controlRows = cr.controls.map((ctrl) => {
      const statusColor = ctrl.status === "pass" ? "#16a34a" : ctrl.status === "fail" ? "#dc2626" : "#ca8a04";
      return `<tr>
        <td style="padding: 8px; border-bottom: 1px solid #eee;">${escapeHtml(ctrl.id)}</td>
        <td style="padding: 8px; border-bottom: 1px solid #eee;">${escapeHtml(ctrl.name)}</td>
        <td style="padding: 8px; border-bottom: 1px solid #eee; color: ${statusColor}; font-weight: bold;">${ctrl.status.toUpperCase()}</td>
        <td style="padding: 8px; border-bottom: 1px solid #eee;">${ctrl.relatedFindings.length}</td>
      </tr>`;
    }).join("\n");

    return `
      <div class="compliance-section" style="margin-bottom: 32px;">
        <h3>${escapeHtml(cr.frameworkLabel)}</h3>
        <p><strong>Overall Score:</strong> ${cr.overallScore}% (${cr.passedControls}/${cr.totalControls} controls passing)</p>
        <table style="width: 100%; border-collapse: collapse; font-size: 14px;">
          <thead><tr style="background: #f3f4f6;">
            <th style="text-align: left; padding: 8px;">Control</th>
            <th style="text-align: left; padding: 8px;">Name</th>
            <th style="text-align: left; padding: 8px;">Status</th>
            <th style="text-align: left; padding: 8px;">Findings</th>
          </tr></thead>
          <tbody>${controlRows}</tbody>
        </table>
      </div>`;
  }).join("\n");

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(report.title)}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 960px; margin: 0 auto; padding: 40px 20px; color: #1a1a1a; line-height: 1.6; }
    h1 { border-bottom: 3px solid #0ea5e9; padding-bottom: 12px; }
    h2 { color: #0369a1; margin-top: 40px; border-bottom: 1px solid #e5e7eb; padding-bottom: 8px; }
    code { background: #f3f4f6; padding: 2px 6px; border-radius: 3px; font-size: 13px; }
    .meta-table td { padding: 4px 16px 4px 0; }
    .summary-box { background: #eff6ff; border: 1px solid #bfdbfe; padding: 20px; border-radius: 8px; margin: 20px 0; }
  </style>
</head>
<body>
  <h1>${escapeHtml(report.title)}</h1>
  <table class="meta-table">
    <tr><td><strong>Generated:</strong></td><td>${report.generatedAt}</td></tr>
    <tr><td><strong>Target:</strong></td><td>${escapeHtml(result.target)}</td></tr>
    <tr><td><strong>Scan ID:</strong></td><td><code>${escapeHtml(result.id)}</code></td></tr>
    <tr><td><strong>Type:</strong></td><td>${result.scanType}</td></tr>
    <tr><td><strong>Duration:</strong></td><td>${(result.stats.durationMs / 1000).toFixed(1)}s</td></tr>
  </table>

  <h2>Executive Summary</h2>
  <div class="summary-box">
    <p>${escapeHtml(report.executiveSummary)}</p>
  </div>

  <h2>Summary Statistics</h2>
  <table style="width: 100%; border-collapse: collapse; font-size: 14px;">
    <thead><tr style="background: #f3f4f6;">
      <th style="text-align: left; padding: 8px;">Severity</th>
      <th style="text-align: left; padding: 8px;">Count</th>
    </tr></thead>
    <tbody>
      ${Object.entries(result.stats.findingsBySeverity).map(([sev, count]) => `
        <tr><td style="padding: 8px; border-bottom: 1px solid #eee; color: ${severityColors[sev] || "#666"}; font-weight: bold;">${sev.toUpperCase()}</td><td style="padding: 8px; border-bottom: 1px solid #eee;">${count}</td></tr>
      `).join("")}
    </tbody>
  </table>

  ${complianceReports.length > 0 ? `<h2>Compliance Mapping</h2>${complianceHtml}` : ""}

  <h2>Detailed Findings (${result.findings.length})</h2>
  ${findingsHtml}

  <footer style="margin-top: 60px; padding-top: 20px; border-top: 1px solid #e5e7eb; color: #9ca3af; font-size: 12px;">
    Generated by VulnHunter AI Security Platform | ${report.generatedAt}
  </footer>
</body>
</html>`;
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// ---------------------------------------------------------------------------
// Command Registration
// ---------------------------------------------------------------------------

/**
 * Registers the `report` command with Commander.
 */
export function registerReportCommand(program: Command): void {
  program
    .command("report <scan-id>")
    .description("Generate or view a security report from a completed scan")
    .option(
      "-f, --format <format>",
      `Report format: ${SUPPORTED_FORMATS.join(", ")}`,
      getConfigValue<string>("output.format") || "markdown",
    )
    .option(
      "-c, --compliance <frameworks>",
      `Compliance frameworks (comma-separated): ${COMPLIANCE_FRAMEWORKS.join(", ")}`,
    )
    .option("-o, --output <path>", "Save report to file")
    .option("--title <title>", "Custom report title")
    .option("--no-summary", "Omit executive summary")
    .option("--no-remediation", "Omit remediation recommendations")
    .option(
      "--min-severity <severity>",
      "Minimum severity to include: critical, high, medium, low, info",
      "info",
    )
    .action(async (scanId: string, opts: Record<string, unknown>) => {
      const chalk = (await import("chalk")).default;

      const format = (opts.format as string) || "markdown";
      const complianceArg = opts.compliance as string | undefined;
      const complianceFrameworks: ComplianceFramework[] = complianceArg
        ? (complianceArg.split(",").map((f) => f.trim().toLowerCase()) as ComplianceFramework[])
            .filter((f) => (COMPLIANCE_FRAMEWORKS as readonly string[]).includes(f))
        : [];

      // Validate format
      if (!(SUPPORTED_FORMATS as readonly string[]).includes(format)) {
        console.error(
          chalk.red(`\n  Error: Unsupported format "${format}". Use: ${SUPPORTED_FORMATS.join(", ")}\n`),
        );
        process.exit(1);
      }

      console.log();
      console.log(chalk.cyan.bold("  VulnHunter AI - Report Generator"));
      console.log(chalk.gray("  " + "\u2500".repeat(50)));
      console.log(chalk.white(`  Scan ID:    ${chalk.cyan(scanId)}`));
      console.log(chalk.white(`  Format:     ${chalk.yellow(format)}`));
      if (complianceFrameworks.length > 0) {
        console.log(chalk.white(`  Compliance: ${chalk.yellow(complianceFrameworks.join(", "))}`));
      }
      if (opts.output) {
        console.log(chalk.white(`  Output:     ${chalk.yellow(String(opts.output))}`));
      }
      console.log(chalk.gray("  " + "\u2500".repeat(50)));
      console.log();

      const progress = new ScanProgressDisplay();
      await progress.start("Loading scan results...");

      try {
        // Load scan data
        await progress.update({
          phase: "load",
          module: "data_retrieval",
          progressPercent: 10,
          message: `Loading scan results for ${scanId}`,
          findingsCount: 0,
          endpointsTested: 0,
          requestsSent: 0,
        });

        const scanResult = await loadScanResult(scanId);

        // Filter findings by minimum severity
        const severityOrder: Record<string, number> = {
          critical: 0, high: 1, medium: 2, low: 3, info: 4,
        };
        const minSev = opts.minSeverity as string || "info";
        const minSevOrder = severityOrder[minSev] ?? 4;

        const filteredFindings = scanResult.findings.filter(
          (f) => (severityOrder[f.vulnerability.severity] ?? 4) <= minSevOrder,
        );

        const filteredResult: ScanResult = {
          ...scanResult,
          findings: filteredFindings,
        };

        await progress.update({
          phase: "generate",
          module: "report_engine",
          progressPercent: 30,
          message: `Processing ${filteredFindings.length} findings...`,
          findingsCount: filteredFindings.length,
          endpointsTested: 0,
          requestsSent: 0,
        });

        // Build compliance reports
        const complianceReports: ComplianceReport[] = [];
        for (let i = 0; i < complianceFrameworks.length; i++) {
          const fw = complianceFrameworks[i]!;
          await progress.update({
            phase: "compliance",
            module: fw,
            progressPercent: 40 + Math.round((i / complianceFrameworks.length) * 20),
            message: `Mapping findings to ${fw} framework...`,
            findingsCount: filteredFindings.length,
            endpointsTested: 0,
            requestsSent: 0,
          });

          complianceReports.push(buildComplianceReport(fw, filteredFindings));
          await new Promise((r) => setTimeout(r, 300));
        }

        // Build the executive summary
        const executiveSummary = opts.summary !== false
          ? buildExecutiveSummary(filteredResult, complianceReports)
          : "";

        // Generate report
        await progress.update({
          phase: "render",
          module: `format:${format}`,
          progressPercent: 70,
          message: `Rendering ${format} report...`,
          findingsCount: filteredFindings.length,
          endpointsTested: 0,
          requestsSent: 0,
        });

        const reportTitle = (opts.title as string) ||
          `VulnHunter Security Assessment - ${filteredResult.target}`;

        const report: FullReport = {
          id: crypto.randomUUID(),
          scanId,
          format: format as ReportFormat,
          title: reportTitle,
          generatedAt: new Date().toISOString(),
          target: filteredResult.target,
          executiveSummary,
          scanResult: filteredResult,
          complianceReports,
          content: "",
        };

        // Render content in the requested format
        switch (format) {
          case "json":
            report.content = JSON.stringify(
              {
                id: report.id,
                scanId: report.scanId,
                title: report.title,
                generatedAt: report.generatedAt,
                target: report.target,
                executiveSummary: report.executiveSummary,
                statistics: filteredResult.stats,
                findings: filteredFindings.map((f) => ({
                  ...f.vulnerability,
                  module: f.module,
                  confidence: f.confidence,
                })),
                complianceReports,
              },
              null,
              2,
            );
            break;
          case "html":
            report.content = generateHtmlReport(report);
            break;
          case "markdown":
          default:
            report.content = generateMarkdownReport(report);
            break;
        }

        await new Promise((r) => setTimeout(r, 300));

        await progress.complete(
          `Report generated | ${format} | ${filteredFindings.length} findings | ${complianceReports.length} compliance frameworks`,
        );

        // Display summary in the terminal regardless of format
        console.log();
        console.log(chalk.cyan.bold("  Report Summary"));
        console.log(chalk.gray("  " + "\u2500".repeat(50)));
        console.log(chalk.white(`  Report ID:  ${chalk.cyan(report.id)}`));
        console.log(chalk.white(`  Target:     ${chalk.cyan.bold(filteredResult.target)}`));
        console.log(chalk.white(`  Findings:   ${chalk.yellow.bold(String(filteredFindings.length))}`));
        console.log(chalk.white(`  Confirmed:  ${chalk.green(String(filteredResult.stats.confirmedFindings))}`));
        console.log(chalk.white(`  Format:     ${chalk.yellow(format)}`));
        console.log();

        // Show severity summary
        if (filteredFindings.length > 0) {
          await renderSeveritySummary(filteredFindings);
        }

        // Show compliance scores
        if (complianceReports.length > 0) {
          console.log(chalk.cyan.bold("  Compliance Scores"));
          const Table = (await import("cli-table3")).default;
          const compTable = new Table({
            head: [
              chalk.white.bold("Framework"),
              chalk.white.bold("Score"),
              chalk.white.bold("Passed"),
              chalk.white.bold("Failed"),
              chalk.white.bold("Partial"),
            ],
            colWidths: [28, 10, 10, 10, 10],
            style: { head: [], border: ["gray"] },
          });

          for (const cr of complianceReports) {
            const scoreColor = cr.overallScore >= 80
              ? chalk.green.bold
              : cr.overallScore >= 50
                ? chalk.yellow.bold
                : chalk.red.bold;

            compTable.push([
              chalk.cyan(cr.frameworkLabel),
              scoreColor(`${cr.overallScore}%`),
              chalk.green(String(cr.passedControls)),
              chalk.red(String(cr.failedControls)),
              chalk.yellow(String(cr.partialControls)),
            ]);
          }
          console.log(compTable.toString());
          console.log();
        }

        // Write output file
        if (opts.output) {
          const outputPath = path.resolve(opts.output as string);
          const dir = path.dirname(outputPath);
          if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
          }
          fs.writeFileSync(outputPath, report.content, "utf-8");
          console.log(chalk.green(`  \u2713 Report saved to ${outputPath}`));
          console.log(chalk.gray(`    Size: ${(Buffer.byteLength(report.content) / 1024).toFixed(1)} KB\n`));
        } else {
          // If no output file specified, print to stdout for json/markdown
          if (format === "json" || format === "markdown") {
            console.log(chalk.gray("  " + "\u2500".repeat(50)));
            console.log();
            console.log(report.content);
          } else {
            console.log(
              chalk.gray(`\n  Use --output <path> to save the ${format} report to a file.\n`),
            );
          }
        }
      } catch (err: any) {
        await progress.error(err.message || "Report generation failed");
        process.exit(1);
      }
    });
}
