import type { ReportVulnerability, ReportConfig, ReportStatistics } from "../generator.js";
import type { ComplianceResult } from "../compliance.js";

export interface HtmlReportData {
  title: string;
  scanId: string;
  executiveSummary?: string;
  vulnerabilities: ReportVulnerability[];
  statistics: ReportStatistics;
  complianceResults: ComplianceResult[];
  config: ReportConfig;
  generatedAt: string;
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function severityColor(severity: string): string {
  switch (severity.toLowerCase()) {
    case "critical": return "#dc2626";
    case "high": return "#ea580c";
    case "medium": return "#d97706";
    case "low": return "#2563eb";
    case "info": return "#6b7280";
    default: return "#6b7280";
  }
}

function statusColor(status: string): string {
  switch (status) {
    case "pass": return "#16a34a";
    case "fail": return "#dc2626";
    case "partial": return "#d97706";
    default: return "#6b7280";
  }
}

export function generateHtml(data: HtmlReportData): string {
  const vulnRows = data.vulnerabilities
    .map(
      (v) => `
    <div class="vuln-card" style="border-left: 4px solid ${severityColor(v.severity)};">
      <div class="vuln-header">
        <span class="severity-badge" style="background: ${severityColor(v.severity)};">${escapeHtml(v.severity.toUpperCase())}</span>
        <h3>${escapeHtml(v.title)}</h3>
        ${v.confirmed ? '<span class="confirmed-badge">CONFIRMED</span>' : ""}
      </div>
      <div class="vuln-meta">
        <span>CVSS: ${v.cvssScore ?? "N/A"}</span>
        <span>CWE: ${escapeHtml(v.cweId || "N/A")}</span>
        <span>Confidence: ${v.confidence}%</span>
        ${v.endpoint ? `<span>Endpoint: <code>${escapeHtml(v.method || "GET")} ${escapeHtml(v.endpoint)}</code></span>` : ""}
      </div>
      <p>${escapeHtml(v.description)}</p>
      ${
        data.config.includeRemediation && v.remediation
          ? `<div class="remediation"><h4>Remediation</h4><p>${escapeHtml(v.remediation)}</p></div>`
          : ""
      }
      ${
        v.references && v.references.length > 0
          ? `<div class="references"><h4>References</h4><ul>${v.references.map((r) => `<li><a href="${escapeHtml(r)}" target="_blank">${escapeHtml(r)}</a></li>`).join("")}</ul></div>`
          : ""
      }
    </div>`
    )
    .join("\n");

  const complianceSections = data.complianceResults
    .map(
      (cr) => `
    <div class="compliance-section">
      <h3>${escapeHtml(cr.framework)} ${escapeHtml(cr.version)}</h3>
      <div class="score-bar">
        <div class="score-fill" style="width: ${cr.overallScore}%; background: ${cr.overallScore >= 80 ? "#16a34a" : cr.overallScore >= 50 ? "#d97706" : "#dc2626"};">
          ${cr.overallScore}%
        </div>
      </div>
      <p>${escapeHtml(cr.summary)}</p>
      <table>
        <thead><tr><th>Control</th><th>Name</th><th>Status</th><th>Findings</th></tr></thead>
        <tbody>
          ${cr.controls
            .map(
              (c) =>
                `<tr><td>${escapeHtml(c.id)}</td><td>${escapeHtml(c.name)}</td><td><span style="color: ${statusColor(c.status)}; font-weight: bold;">${escapeHtml(c.status.toUpperCase())}</span></td><td>${c.findingIds.length}</td></tr>`
            )
            .join("")}
        </tbody>
      </table>
    </div>`
    )
    .join("\n");

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(data.title)}</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; line-height: 1.6; }
    .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
    header { background: linear-gradient(135deg, #1e293b, #0f172a); padding: 2rem; border-bottom: 2px solid #334155; margin-bottom: 2rem; }
    header h1 { font-size: 2rem; background: linear-gradient(135deg, #38bdf8, #818cf8); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    header .meta { color: #94a3b8; margin-top: 0.5rem; }
    .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
    .stat-card { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 1.5rem; text-align: center; }
    .stat-card .value { font-size: 2rem; font-weight: bold; color: #38bdf8; }
    .stat-card .label { color: #94a3b8; font-size: 0.875rem; }
    .severity-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 0.5rem; margin-bottom: 2rem; }
    .severity-item { text-align: center; padding: 1rem; border-radius: 8px; background: #1e293b; border: 1px solid #334155; }
    .severity-item .count { font-size: 1.5rem; font-weight: bold; }
    .executive-summary { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 1.5rem; margin-bottom: 2rem; }
    .executive-summary h2 { margin-bottom: 1rem; color: #38bdf8; }
    .vuln-card { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 1.5rem; margin-bottom: 1rem; }
    .vuln-header { display: flex; align-items: center; gap: 1rem; margin-bottom: 1rem; }
    .vuln-header h3 { flex: 1; }
    .severity-badge { padding: 0.25rem 0.75rem; border-radius: 4px; color: white; font-weight: bold; font-size: 0.75rem; }
    .confirmed-badge { background: #16a34a; padding: 0.25rem 0.75rem; border-radius: 4px; color: white; font-size: 0.75rem; }
    .vuln-meta { display: flex; gap: 1rem; flex-wrap: wrap; color: #94a3b8; font-size: 0.875rem; margin-bottom: 1rem; }
    .remediation { background: #0f172a; border-radius: 4px; padding: 1rem; margin-top: 1rem; }
    .remediation h4 { color: #16a34a; margin-bottom: 0.5rem; }
    .references { margin-top: 1rem; }
    .references h4 { color: #38bdf8; margin-bottom: 0.5rem; }
    .references a { color: #818cf8; }
    code { background: #334155; padding: 0.125rem 0.375rem; border-radius: 3px; font-size: 0.875rem; }
    h2 { color: #38bdf8; margin: 2rem 0 1rem; padding-bottom: 0.5rem; border-bottom: 1px solid #334155; }
    table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
    th, td { padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid #334155; }
    th { background: #0f172a; color: #94a3b8; font-weight: 600; }
    .compliance-section { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 1.5rem; margin-bottom: 1rem; }
    .compliance-section h3 { margin-bottom: 1rem; }
    .score-bar { background: #334155; border-radius: 4px; height: 2rem; margin-bottom: 1rem; overflow: hidden; }
    .score-fill { height: 100%; display: flex; align-items: center; justify-content: center; color: white; font-weight: bold; border-radius: 4px; transition: width 0.3s; }
    footer { text-align: center; color: #64748b; margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #334155; }
  </style>
</head>
<body>
  <header>
    <div class="container">
      <h1>${escapeHtml(data.title)}</h1>
      <div class="meta">
        Generated: ${new Date(data.generatedAt).toLocaleString()} | Scan ID: ${escapeHtml(data.scanId)} | VulnHunter AI v1.0.0
      </div>
    </div>
  </header>
  <div class="container">
    ${
      data.executiveSummary
        ? `<div class="executive-summary"><h2>Executive Summary</h2><p>${escapeHtml(data.executiveSummary)}</p></div>`
        : ""
    }

    <div class="stats-grid">
      <div class="stat-card"><div class="value">${data.statistics.totalVulnerabilities}</div><div class="label">Total Vulnerabilities</div></div>
      <div class="stat-card"><div class="value">${data.statistics.confirmedVulnerabilities}</div><div class="label">Confirmed</div></div>
      <div class="stat-card"><div class="value">${data.statistics.averageCvss}</div><div class="label">Average CVSS</div></div>
      <div class="stat-card"><div class="value">${data.statistics.riskScore}</div><div class="label">Risk Score</div></div>
    </div>

    <div class="severity-grid">
      ${["critical", "high", "medium", "low", "info"]
        .map(
          (s) => `
        <div class="severity-item">
          <div class="count" style="color: ${severityColor(s)};">${data.statistics.bySeverity[s] || 0}</div>
          <div>${s.toUpperCase()}</div>
        </div>`
        )
        .join("")}
    </div>

    <h2>Vulnerabilities</h2>
    ${vulnRows}

    ${complianceSections ? `<h2>Compliance</h2>${complianceSections}` : ""}

    <footer>
      <p>VulnHunter AI - Autonomous Security Research Platform</p>
    </footer>
  </div>
</body>
</html>`;
}
