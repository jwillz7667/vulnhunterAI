import type { ReportVulnerability, ReportConfig, ReportStatistics } from "../generator.js";
import type { ComplianceResult } from "../compliance.js";

export interface JsonReportData {
  title: string;
  scanId: string;
  executiveSummary?: string;
  vulnerabilities: ReportVulnerability[];
  statistics: ReportStatistics;
  complianceResults: ComplianceResult[];
  config: ReportConfig;
  generatedAt: string;
}

export function generateJson(data: JsonReportData): string {
  const report = {
    meta: {
      tool: "VulnHunter AI",
      version: "1.0.0",
      generatedAt: data.generatedAt,
      format: "json",
      scanId: data.scanId,
    },
    title: data.title,
    executiveSummary: data.executiveSummary,
    statistics: data.statistics,
    vulnerabilities: data.vulnerabilities.map((v) => ({
      id: v.id,
      title: v.title,
      description: v.description,
      severity: v.severity,
      category: v.category,
      cvss: {
        score: v.cvssScore,
        vector: v.cvssVector,
      },
      cwe: v.cweId,
      location: {
        endpoint: v.endpoint,
        method: v.method,
        parameter: v.parameter,
      },
      evidence: data.config.includeEvidence ? v.evidence : undefined,
      http: data.config.includeRawHttp
        ? { request: v.request, response: v.response }
        : undefined,
      remediation: data.config.includeRemediation ? v.remediation : undefined,
      references: v.references,
      metadata: {
        confirmed: v.confirmed,
        falsePositive: v.falsePositive,
        module: v.module,
        confidence: v.confidence,
      },
    })),
    compliance: data.complianceResults,
  };

  return JSON.stringify(report, null, 2);
}
