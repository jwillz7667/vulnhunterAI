import { z } from "zod";
import { type Finding, FindingSchema, type Severity, SeveritySchema } from "./vulnerability";
import { AuthenticationSchema, type Authentication } from "./target";

// ---------------------------------------------------------------------------
// Scan Type
// ---------------------------------------------------------------------------

export enum ScanType {
  Full = "full",
  Recon = "recon",
  Web = "web",
  Code = "code",
  Network = "network",
  Cloud = "cloud",
  SmartContract = "smart_contract",
}

export const ScanTypeSchema = z.nativeEnum(ScanType);

// ---------------------------------------------------------------------------
// Scan Status
// ---------------------------------------------------------------------------

export enum ScanStatus {
  Queued = "queued",
  Running = "running",
  Paused = "paused",
  Completed = "completed",
  Failed = "failed",
  Cancelled = "cancelled",
}

export const ScanStatusSchema = z.nativeEnum(ScanStatus);

// ---------------------------------------------------------------------------
// Scan Module Configuration
// ---------------------------------------------------------------------------

/**
 * Fine-grained enable/disable and configuration for individual scanner
 * modules. When `enabled` is false the module is skipped entirely.
 */
export interface ScanModuleConfig {
  /** Module identifier, e.g. "xss", "sqli", "ssrf", "recon:subdomain". */
  name: string;
  /** Whether this module should run. Defaults to true. */
  enabled: boolean;
  /** Module-specific options (payload lists, wordlists, thresholds, etc.). */
  options?: Record<string, unknown>;
}

export const ScanModuleConfigSchema = z.object({
  name: z.string().min(1),
  enabled: z.boolean().default(true),
  options: z.record(z.unknown()).optional(),
});

// ---------------------------------------------------------------------------
// Scan Options
// ---------------------------------------------------------------------------

/** Global options that apply to the entire scan. */
export interface ScanOptions {
  /** Maximum crawl/traversal depth from the initial target. */
  maxDepth: number;
  /** Maximum HTTP requests per second to stay under rate limits / avoid detection. */
  rateLimit: number;
  /** Per-request timeout in milliseconds. */
  requestTimeoutMs: number;
  /** Overall scan timeout in milliseconds (0 = no limit). */
  scanTimeoutMs: number;
  /** Maximum number of concurrent requests / threads. */
  maxConcurrency: number;
  /** Custom HTTP headers to include on every request. */
  customHeaders?: Record<string, string>;
  /** User-Agent string override. */
  userAgent?: string;
  /** Proxy URL (supports HTTP, HTTPS, SOCKS5). */
  proxy?: string;
  /** Follow redirects up to this many hops (0 = do not follow). */
  maxRedirects: number;
  /** Whether to accept and store cookies during the scan. */
  enableCookies: boolean;
  /** Minimum severity level to report (findings below this are dropped). */
  minimumSeverity?: Severity;
  /** Authentication to use for the target. Overrides target-level auth if set. */
  authentication?: Authentication;
  /** Restrict scanning to these URL path prefixes. Empty = no restriction. */
  scopeRestrictions: string[];
  /** Specific modules to enable/disable/configure. */
  enabledModules: ScanModuleConfig[];
  /** Enable AI-powered payload generation and mutation. */
  aiPayloadGeneration: boolean;
  /** Enable automatic exploit chain detection. */
  exploitChainDetection: boolean;
  /** Custom wordlist URLs or local paths for fuzzing. */
  wordlists?: string[];
  /** Tags applied to every finding produced by this scan. */
  tags?: string[];
}

export const ScanOptionsSchema = z.object({
  maxDepth: z.number().int().min(1).max(100).default(10),
  rateLimit: z.number().int().min(1).max(1000).default(10),
  requestTimeoutMs: z.number().int().min(1000).max(120_000).default(30_000),
  scanTimeoutMs: z.number().int().min(0).default(300_000),
  maxConcurrency: z.number().int().min(1).max(100).default(10),
  customHeaders: z.record(z.string()).optional(),
  userAgent: z.string().optional(),
  proxy: z.string().url().optional(),
  maxRedirects: z.number().int().min(0).max(20).default(5),
  enableCookies: z.boolean().default(true),
  minimumSeverity: SeveritySchema.optional(),
  authentication: AuthenticationSchema.optional(),
  scopeRestrictions: z.array(z.string()).default([]),
  enabledModules: z.array(ScanModuleConfigSchema).default([]),
  aiPayloadGeneration: z.boolean().default(true),
  exploitChainDetection: z.boolean().default(true),
  wordlists: z.array(z.string()).optional(),
  tags: z.array(z.string()).optional(),
});

// ---------------------------------------------------------------------------
// Scan Config
// ---------------------------------------------------------------------------

/** Top-level configuration object passed when starting a new scan. */
export interface ScanConfig {
  /** The target value (URL, domain, IP, CIDR, repo URL, contract address). */
  target: string;
  /** Type of scan to perform. */
  scanType: ScanType;
  /** Scan-level options. */
  options: ScanOptions;
}

export const ScanConfigSchema = z.object({
  target: z.string().min(1),
  scanType: ScanTypeSchema,
  options: ScanOptionsSchema,
});

// ---------------------------------------------------------------------------
// Scan Statistics
// ---------------------------------------------------------------------------

/** Aggregate statistics for a completed (or in-progress) scan. */
export interface ScanStatistics {
  /** Total number of HTTP requests sent. */
  totalRequests: number;
  /** Total number of unique endpoints discovered. */
  endpointsDiscovered: number;
  /** Breakdown of findings by severity. */
  findingsBySeverity: Record<Severity, number>;
  /** Breakdown of findings by category. */
  findingsByCategory: Record<string, number>;
  /** Number of findings that were confirmed true positives. */
  confirmedFindings: number;
  /** Number of findings flagged as false positives. */
  falsePositives: number;
  /** Total number of exploit chains identified. */
  exploitChainsFound: number;
  /** Scan duration in milliseconds. */
  durationMs: number;
  /** Modules that completed successfully. */
  modulesCompleted: string[];
  /** Modules that failed during the scan. */
  modulesFailed: string[];
}

export const ScanStatisticsSchema = z.object({
  totalRequests: z.number().int().nonnegative(),
  endpointsDiscovered: z.number().int().nonnegative(),
  findingsBySeverity: z.record(SeveritySchema, z.number().int().nonnegative()),
  findingsByCategory: z.record(z.number().int().nonnegative()),
  confirmedFindings: z.number().int().nonnegative(),
  falsePositives: z.number().int().nonnegative(),
  exploitChainsFound: z.number().int().nonnegative(),
  durationMs: z.number().int().nonnegative(),
  modulesCompleted: z.array(z.string()),
  modulesFailed: z.array(z.string()),
});

// ---------------------------------------------------------------------------
// Scan Result
// ---------------------------------------------------------------------------

/** The complete result of a scan, including all findings and statistics. */
export interface ScanResult {
  /** Unique identifier (UUID v4). */
  id: string;
  /** The scanned target value. */
  target: string;
  /** Current scan status. */
  status: ScanStatus;
  /** The scan type that was executed. */
  scanType: ScanType;
  /** The configuration used for this scan. */
  config: ScanConfig;
  /** ISO-8601 timestamp of scan start. */
  startTime: string;
  /** ISO-8601 timestamp of scan completion (null if still running). */
  endTime?: string;
  /** All findings produced during the scan. */
  findings: Finding[];
  /** Aggregate statistics. */
  stats: ScanStatistics;
  /** Error message if the scan failed. */
  error?: string;
}

export const ScanResultSchema = z.object({
  id: z.string().uuid(),
  target: z.string().min(1),
  status: ScanStatusSchema,
  scanType: ScanTypeSchema,
  config: ScanConfigSchema,
  startTime: z.string().datetime(),
  endTime: z.string().datetime().optional(),
  findings: z.array(FindingSchema),
  stats: ScanStatisticsSchema,
  error: z.string().optional(),
});

// ---------------------------------------------------------------------------
// Scan Progress
// ---------------------------------------------------------------------------

/**
 * Real-time progress updates emitted during a scan.
 * Published over WebSocket / SSE / BullMQ events.
 */
export interface ScanProgress {
  /** The scan ID this progress update belongs to. */
  scanId: string;
  /** Current high-level phase (e.g. "recon", "active_scan", "reporting"). */
  phase: string;
  /** Module currently executing. */
  module: string;
  /** Overall progress as a percentage (0-100). */
  progressPercent: number;
  /** Human-readable status message. */
  message: string;
  /** Running count of findings discovered so far. */
  findingsCount: number;
  /** Endpoints tested so far. */
  endpointsTested: number;
  /** Requests sent so far. */
  requestsSent: number;
  /** ISO-8601 timestamp of this progress event. */
  timestamp: string;
}

export const ScanProgressSchema = z.object({
  scanId: z.string().uuid(),
  phase: z.string().min(1),
  module: z.string().min(1),
  progressPercent: z.number().min(0).max(100),
  message: z.string(),
  findingsCount: z.number().int().nonnegative(),
  endpointsTested: z.number().int().nonnegative(),
  requestsSent: z.number().int().nonnegative(),
  timestamp: z.string().datetime(),
});

// ---------------------------------------------------------------------------
// Inferred types from Zod
// ---------------------------------------------------------------------------

export type ScanConfigInput = z.input<typeof ScanConfigSchema>;
export type ScanOptionsInput = z.input<typeof ScanOptionsSchema>;
export type ScanResultInput = z.input<typeof ScanResultSchema>;
export type ScanProgressInput = z.input<typeof ScanProgressSchema>;
