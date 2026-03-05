import { z } from "zod";
import { type Severity, SeveritySchema } from "./vulnerability";
import { type Scope, ScopeSchema } from "./target";

// ---------------------------------------------------------------------------
// Bounty Platform
// ---------------------------------------------------------------------------

export enum BountyPlatform {
  HackerOne = "hackerone",
  Bugcrowd = "bugcrowd",
}

export const BountyPlatformSchema = z.nativeEnum(BountyPlatform);

// ---------------------------------------------------------------------------
// Submission Status
// ---------------------------------------------------------------------------

export enum SubmissionStatus {
  Draft = "draft",
  Submitted = "submitted",
  Triaged = "triaged",
  Accepted = "accepted",
  Duplicate = "duplicate",
  Informative = "informative",
  Resolved = "resolved",
  NotApplicable = "not_applicable",
}

export const SubmissionStatusSchema = z.nativeEnum(SubmissionStatus);

// ---------------------------------------------------------------------------
// Bounty Range
// ---------------------------------------------------------------------------

/** Min/max bounty payout for a severity level. */
export interface BountyRange {
  severity: Severity;
  /** Minimum payout in USD. */
  minUsd: number;
  /** Maximum payout in USD. */
  maxUsd: number;
}

export const BountyRangeSchema = z.object({
  severity: SeveritySchema,
  minUsd: z.number().nonnegative(),
  maxUsd: z.number().nonnegative(),
});

// ---------------------------------------------------------------------------
// Program Statistics
// ---------------------------------------------------------------------------

/** Historical statistics for a bounty program. */
export interface ProgramStatistics {
  /** Total number of reports submitted to this program. */
  totalReports: number;
  /** Total bounties paid out in USD. */
  totalBountiesPaidUsd: number;
  /** Average bounty payout in USD. */
  averagePayoutUsd: number;
  /** Average time to first response in hours. */
  averageResponseTimeHours: number;
  /** Average time to triage in hours. */
  averageTriageTimeHours: number;
  /** Average time to bounty payout in hours. */
  averageBountyTimeHours: number;
  /** Percentage of reports resolved (0-100). */
  resolutionRate: number;
  /** Number of researchers who have been rewarded. */
  rewardedResearchers: number;
}

export const ProgramStatisticsSchema = z.object({
  totalReports: z.number().int().nonnegative(),
  totalBountiesPaidUsd: z.number().nonnegative(),
  averagePayoutUsd: z.number().nonnegative(),
  averageResponseTimeHours: z.number().nonnegative(),
  averageTriageTimeHours: z.number().nonnegative(),
  averageBountyTimeHours: z.number().nonnegative(),
  resolutionRate: z.number().min(0).max(100),
  rewardedResearchers: z.number().int().nonnegative(),
});

// ---------------------------------------------------------------------------
// Bounty Program
// ---------------------------------------------------------------------------

/** A bug bounty program on a supported platform. */
export interface BountyProgram {
  /** Unique identifier (UUID v4). */
  id: string;
  /** The platform hosting this program. */
  platform: BountyPlatform;
  /** Program name, e.g. "GitHub Bug Bounty". */
  name: string;
  /** Handle/slug on the platform. */
  handle: string;
  /** URL to the program page on the bounty platform. */
  url: string;
  /** Program scope (what assets are in/out of scope). */
  scope: Scope;
  /** Payout ranges by severity. */
  bountyRanges: BountyRange[];
  /** Historical program statistics. */
  statistics: ProgramStatistics;
  /** Whether the program is currently accepting submissions. */
  active: boolean;
  /** Whether the program is managed (private/invite-only). */
  managed: boolean;
  /** Whether the program has a safe harbor policy. */
  safeHarbor: boolean;
  /** Program-specific policy URL. */
  policyUrl?: string;
  /** Maximum severity accepted by the program. */
  maxSeverity?: Severity;
  /** Required disclosure type. */
  disclosurePolicy?: "full" | "coordinated" | "none";
  /** Asset types accepted (web, mobile, api, hardware, etc.). */
  assetTypes: string[];
  /** ISO-8601 timestamp of when the program was launched. */
  launchedAt?: string;
  /** ISO-8601 timestamp of last sync from the platform API. */
  lastSyncedAt: string;
}

export const BountyProgramSchema = z.object({
  id: z.string().uuid(),
  platform: BountyPlatformSchema,
  name: z.string().min(1),
  handle: z.string().min(1),
  url: z.string().url(),
  scope: ScopeSchema,
  bountyRanges: z.array(BountyRangeSchema),
  statistics: ProgramStatisticsSchema,
  active: z.boolean(),
  managed: z.boolean(),
  safeHarbor: z.boolean(),
  policyUrl: z.string().url().optional(),
  maxSeverity: SeveritySchema.optional(),
  disclosurePolicy: z.enum(["full", "coordinated", "none"]).optional(),
  assetTypes: z.array(z.string()),
  launchedAt: z.string().datetime().optional(),
  lastSyncedAt: z.string().datetime(),
});

// ---------------------------------------------------------------------------
// Submission
// ---------------------------------------------------------------------------

/** A vulnerability report submitted to a bounty program. */
export interface Submission {
  /** Unique identifier (UUID v4). */
  id: string;
  /** ID of the bounty program this submission targets. */
  programId: string;
  /** ID of the vulnerability being reported. */
  vulnerabilityId: string;
  /** Current submission status on the platform. */
  status: SubmissionStatus;
  /** Report title as submitted. */
  title: string;
  /** Full report body (Markdown). */
  reportBody: string;
  /** Severity claimed in the submission. */
  claimedSeverity: Severity;
  /** Severity assigned by the triage team (if triaged). */
  assignedSeverity?: Severity;
  /** Bounty reward in USD (null until awarded). */
  rewardUsd?: number;
  /** URL to the report on the bounty platform. */
  reportUrl?: string;
  /** Platform-specific report ID (e.g. HackerOne report number). */
  platformReportId?: string;
  /** Triage analyst or team assigned to this report. */
  assignedTo?: string;
  /** Comments/timeline entries from the platform. */
  timeline: SubmissionTimelineEntry[];
  /** ISO-8601 timestamp of submission. */
  submittedAt: string;
  /** ISO-8601 timestamp of last status change. */
  updatedAt: string;
  /** ISO-8601 timestamp of resolution (if resolved). */
  resolvedAt?: string;
}

/** A single timeline entry on a submission (comment, status change, etc.). */
export interface SubmissionTimelineEntry {
  /** Type of timeline event. */
  type: "comment" | "status_change" | "bounty_awarded" | "severity_change" | "assignment";
  /** Who made the change (username or "system"). */
  actor: string;
  /** Human-readable message. */
  message: string;
  /** ISO-8601 timestamp. */
  timestamp: string;
  /** Additional metadata for this event. */
  metadata?: Record<string, unknown>;
}

export const SubmissionTimelineEntrySchema = z.object({
  type: z.enum([
    "comment",
    "status_change",
    "bounty_awarded",
    "severity_change",
    "assignment",
  ]),
  actor: z.string().min(1),
  message: z.string(),
  timestamp: z.string().datetime(),
  metadata: z.record(z.unknown()).optional(),
});

export const SubmissionSchema = z.object({
  id: z.string().uuid(),
  programId: z.string().uuid(),
  vulnerabilityId: z.string().uuid(),
  status: SubmissionStatusSchema,
  title: z.string().min(1).max(500),
  reportBody: z.string().min(1),
  claimedSeverity: SeveritySchema,
  assignedSeverity: SeveritySchema.optional(),
  rewardUsd: z.number().nonnegative().optional(),
  reportUrl: z.string().url().optional(),
  platformReportId: z.string().optional(),
  assignedTo: z.string().optional(),
  timeline: z.array(SubmissionTimelineEntrySchema),
  submittedAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
  resolvedAt: z.string().datetime().optional(),
});

// ---------------------------------------------------------------------------
// Inferred types from Zod
// ---------------------------------------------------------------------------

export type BountyProgramInput = z.input<typeof BountyProgramSchema>;
export type SubmissionInput = z.input<typeof SubmissionSchema>;
