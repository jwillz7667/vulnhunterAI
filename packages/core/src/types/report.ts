import { z } from "zod";
import {
  type Vulnerability,
  VulnerabilitySchema,
  type Severity,
  SeveritySchema,
} from "./vulnerability";
import { type ScanStatistics, ScanStatisticsSchema } from "./scan";

// ---------------------------------------------------------------------------
// Report Format
// ---------------------------------------------------------------------------

export enum ReportFormat {
  JSON = "json",
  Markdown = "markdown",
  HTML = "html",
  PDF = "pdf",
}

export const ReportFormatSchema = z.nativeEnum(ReportFormat);

// ---------------------------------------------------------------------------
// Compliance Framework
// ---------------------------------------------------------------------------

export enum ComplianceFramework {
  OWASP_Top10 = "owasp_top10",
  NIST = "nist",
  PCI_DSS = "pci_dss",
  SOC2 = "soc2",
  ISO27001 = "iso27001",
}

export const ComplianceFrameworkSchema = z.nativeEnum(ComplianceFramework);

// ---------------------------------------------------------------------------
// Compliance Control Status
// ---------------------------------------------------------------------------

export enum ComplianceControlStatus {
  Pass = "pass",
  Fail = "fail",
  NotApplicable = "not_applicable",
  Partial = "partial",
}

export const ComplianceControlStatusSchema = z.nativeEnum(ComplianceControlStatus);

// ---------------------------------------------------------------------------
// Compliance Mapping
// ---------------------------------------------------------------------------

/** Mapping of a single compliance control to its scan findings. */
export interface ComplianceControl {
  /** Framework-specific control identifier, e.g. "A01:2021" for OWASP. */
  id: string;
  /** Human-readable control name, e.g. "Broken Access Control". */
  name: string;
  /** Description of the control requirement. */
  description?: string;
  /** Whether the target passes, fails, or partially meets this control. */
  status: ComplianceControlStatus;
  /** IDs of findings that relate to this control. */
  findingIds: string[];
}

export const ComplianceControlSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  description: z.string().optional(),
  status: ComplianceControlStatusSchema,
  findingIds: z.array(z.string().uuid()),
});

/** Top-level compliance mapping for a single framework. */
export interface ComplianceMapping {
  /** Which compliance framework this mapping targets. */
  framework: ComplianceFramework;
  /** Overall compliance score as a percentage (0-100). */
  overallScore: number;
  /** Individual control assessments. */
  controls: ComplianceControl[];
}

export const ComplianceMappingSchema = z.object({
  framework: ComplianceFrameworkSchema,
  overallScore: z.number().min(0).max(100),
  controls: z.array(ComplianceControlSchema),
});

// ---------------------------------------------------------------------------
// Report Configuration
// ---------------------------------------------------------------------------

/** Configuration for generating a report from scan results. */
export interface ReportConfig {
  /** Desired output format. */
  format: ReportFormat;
  /** Whether to include evidence (screenshots, payloads, HTTP traces). */
  includeEvidence: boolean;
  /** Whether to include remediation recommendations. */
  includeRemediation: boolean;
  /** Whether to include raw HTTP request/response pairs. */
  includeRawHttp: boolean;
  /** Compliance frameworks to map findings against. */
  complianceFrameworks: ComplianceFramework[];
  /** Whether to generate an executive summary section. */
  executiveSummary: boolean;
  /** Optional custom report title override. */
  title?: string;
  /** Optional custom branding logo URL for HTML/PDF reports. */
  logoUrl?: string;
  /** Minimum severity to include in the report. */
  minimumSeverity?: Severity;
  /** Exclude false positives from the report. */
  excludeFalsePositives: boolean;
  /** Custom CSS for HTML reports. */
  customCss?: string;
  /** Custom footer text. */
  footerText?: string;
}

export const ReportConfigSchema = z.object({
  format: ReportFormatSchema,
  includeEvidence: z.boolean().default(true),
  includeRemediation: z.boolean().default(true),
  includeRawHttp: z.boolean().default(false),
  complianceFrameworks: z.array(ComplianceFrameworkSchema).default([]),
  executiveSummary: z.boolean().default(true),
  title: z.string().max(500).optional(),
  logoUrl: z.string().url().optional(),
  minimumSeverity: SeveritySchema.optional(),
  excludeFalsePositives: z.boolean().default(true),
  customCss: z.string().optional(),
  footerText: z.string().optional(),
});

// ---------------------------------------------------------------------------
// Report Statistics
// ---------------------------------------------------------------------------

/** Summarised statistics for the report. */
export interface ReportStatistics {
  /** Breakdown of vulnerabilities by severity. */
  vulnerabilitiesBySeverity: Record<Severity, number>;
  /** Breakdown of vulnerabilities by category. */
  vulnerabilitiesByCategory: Record<string, number>;
  /** Total number of vulnerabilities. */
  totalVulnerabilities: number;
  /** Total number of confirmed vulnerabilities. */
  confirmedVulnerabilities: number;
  /** Total number of exploit chains. */
  exploitChains: number;
  /** Overall risk score (0-100). */
  riskScore: number;
  /** Underlying scan statistics. */
  scanStats: ScanStatistics;
}

export const ReportStatisticsSchema = z.object({
  vulnerabilitiesBySeverity: z.record(SeveritySchema, z.number().int().nonnegative()),
  vulnerabilitiesByCategory: z.record(z.number().int().nonnegative()),
  totalVulnerabilities: z.number().int().nonnegative(),
  confirmedVulnerabilities: z.number().int().nonnegative(),
  exploitChains: z.number().int().nonnegative(),
  riskScore: z.number().min(0).max(100),
  scanStats: ScanStatisticsSchema,
});

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

/** A generated security report. */
export interface Report {
  /** Unique identifier (UUID v4). */
  id: string;
  /** ID of the scan this report was generated from. */
  scanId: string;
  /** Output format of this report. */
  format: ReportFormat;
  /** Report title. */
  title: string;
  /** Executive summary text (if enabled). */
  summary?: string;
  /** Vulnerabilities included in this report. */
  vulnerabilities: Vulnerability[];
  /** Aggregate statistics. */
  statistics: ReportStatistics;
  /** Compliance framework mappings (if any frameworks were configured). */
  complianceMappings: ComplianceMapping[];
  /** The configuration used to generate this report. */
  config: ReportConfig;
  /** ISO-8601 timestamp of when the report was generated. */
  generatedAt: string;
  /** File path or URL where the rendered report is stored (for HTML/PDF). */
  outputPath?: string;
  /** Size of the rendered report in bytes. */
  fileSizeBytes?: number;
}

export const ReportSchema = z.object({
  id: z.string().uuid(),
  scanId: z.string().uuid(),
  format: ReportFormatSchema,
  title: z.string().min(1).max(500),
  summary: z.string().optional(),
  vulnerabilities: z.array(VulnerabilitySchema),
  statistics: ReportStatisticsSchema,
  complianceMappings: z.array(ComplianceMappingSchema),
  config: ReportConfigSchema,
  generatedAt: z.string().datetime(),
  outputPath: z.string().optional(),
  fileSizeBytes: z.number().int().nonnegative().optional(),
});

// ---------------------------------------------------------------------------
// Inferred types from Zod
// ---------------------------------------------------------------------------

export type ReportInput = z.input<typeof ReportSchema>;
export type ReportConfigInput = z.input<typeof ReportConfigSchema>;
export type ComplianceMappingInput = z.input<typeof ComplianceMappingSchema>;
