// =============================================================================
// Shared Scan Execution Service
// =============================================================================
// Central service used by API routes, MCP server, and CLI to execute scans
// with database persistence. Bridges the scanner engine with Prisma storage.
// =============================================================================

import { prisma } from "../db/index.js";
import type { ScanConfig, ScanProgress, ScanResult, Finding, Severity } from "../types/index.js";
import { ScanStatus } from "../types/index.js";
import { createLogger } from "../utils/logger.js";

const log = createLogger("scan-service");

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ScanCallbacks {
  onProgress?: (progress: ScanProgress) => void;
  onFinding?: (finding: Finding) => void;
  onComplete?: (result: ScanResult) => void;
  onError?: (error: Error) => void;
}

export interface ScanExecutionResult {
  scanId: string;
  result: ScanResult;
}

// ---------------------------------------------------------------------------
// Severity mapping: core enum values -> Prisma string values
// ---------------------------------------------------------------------------

function toDbSeverity(severity: Severity): string {
  return severity.toUpperCase();
}

function toDbCategory(category: string): string {
  return category.toUpperCase().replace(/_/g, "_");
}

// ---------------------------------------------------------------------------
// Main Execution Function
// ---------------------------------------------------------------------------

/**
 * Executes a scan with full database persistence.
 *
 * 1. Upserts the Target record
 * 2. Creates a Scan record (QUEUED -> RUNNING)
 * 3. Calls createFullEngine() from @vulnhunter/scanner
 * 4. Iterates the engine's AsyncGenerator
 * 5. Updates Scan progress in DB on each event
 * 6. Converts each Finding to a Prisma Vulnerability record
 * 7. Updates Scan to COMPLETED with final stats
 */
export async function executeScanWithPersistence(
  config: ScanConfig,
  callbacks: ScanCallbacks = {},
): Promise<ScanExecutionResult> {
  // Lazy import to avoid circular deps
  const { createFullEngine } = await import("@vulnhunter/scanner");

  // 1. Upsert Target
  const target = await prisma.target.upsert({
    where: { id: config.target },
    update: { updatedAt: new Date() },
    create: {
      name: config.target,
      type: detectTargetType(config.target),
      value: config.target,
      scopeIncludes: JSON.stringify(config.options.scopeRestrictions || []),
      scopeExcludes: "[]",
      tags: JSON.stringify(config.options.tags || []),
    },
  });

  // 2. Create Scan record
  const scan = await prisma.scan.create({
    data: {
      targetId: target.id,
      type: config.scanType.toUpperCase(),
      status: "QUEUED",
      config: JSON.parse(JSON.stringify(config)),
      progress: 0,
    },
  });

  const scanId = scan.id;
  log.info({ scanId, target: config.target }, "Scan created in database");

  // Update to RUNNING
  await prisma.scan.update({
    where: { id: scanId },
    data: { status: "RUNNING", startedAt: new Date() },
  });

  try {
    // 3. Create engine with all modules
    const engine = await createFullEngine();

    // 4. Execute scan via AsyncGenerator
    const gen = engine.executeScan(config);
    let result: ScanResult | undefined;

    while (true) {
      const { value, done } = await gen.next();

      if (done) {
        // The return value of the generator is the ScanResult
        result = value as ScanResult;
        break;
      }

      // value is ScanProgress
      const progress = value as ScanProgress;
      callbacks.onProgress?.(progress);

      // 5. Update progress in DB (throttled to avoid excessive writes)
      await prisma.scan.update({
        where: { id: scanId },
        data: {
          progress: Math.round(progress.progressPercent),
          currentPhase: `${progress.phase}: ${progress.module}`,
        },
      });
    }

    if (!result) {
      throw new Error("Scan completed without producing a result");
    }

    // 6. Persist findings as Vulnerability records
    const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

    for (const finding of result.findings) {
      const vuln = finding.vulnerability;
      const sevKey = vuln.severity as string;
      if (sevKey in severityCounts) {
        severityCounts[sevKey as keyof typeof severityCounts]++;
      }

      callbacks.onFinding?.(finding);

      await prisma.vulnerability.create({
        data: {
          scanId,
          title: vuln.title,
          description: vuln.description,
          severity: toDbSeverity(vuln.severity),
          category: toDbCategory(vuln.category),
          cvssScore: vuln.cvssScore,
          cvssVector: vuln.cvssVector ?? null,
          cweId: vuln.cweId ?? null,
          endpoint: vuln.endpoint ?? null,
          method: vuln.request?.method ?? null,
          parameter: null,
          evidence: vuln.evidence ? JSON.parse(JSON.stringify(vuln.evidence)) : null,
          request: vuln.request ? `${vuln.request.method} ${vuln.request.url}\n${Object.entries(vuln.request.headers).map(([k, v]) => `${k}: ${v}`).join("\n")}${vuln.request.body ? `\n\n${vuln.request.body}` : ""}` : null,
          response: vuln.response ? `HTTP ${vuln.response.statusCode}\n${Object.entries(vuln.response.headers).map(([k, v]) => `${k}: ${v}`).join("\n")}${vuln.response.body ? `\n\n${vuln.response.body.slice(0, 10000)}` : ""}` : null,
          remediation: vuln.remediation ?? null,
          references: JSON.stringify(vuln.references || []),
          confirmed: vuln.confirmed,
          falsePositive: vuln.falsePositive,
          module: finding.module,
          confidence: finding.confidence,
          rawData: finding.rawData ? JSON.parse(JSON.stringify(finding.rawData)) : null,
        },
      });
    }

    // 7. Update scan to COMPLETED
    const endTime = new Date();
    const duration = result.stats.durationMs
      ? Math.round(result.stats.durationMs / 1000)
      : Math.round((endTime.getTime() - (scan.startedAt?.getTime() ?? scan.createdAt.getTime())) / 1000);

    await prisma.scan.update({
      where: { id: scanId },
      data: {
        status: result.status === ScanStatus.Failed ? "FAILED" : "COMPLETED",
        progress: 100,
        currentPhase: "complete",
        completedAt: endTime,
        duration,
        findingsCount: result.findings.length,
        criticalCount: severityCounts.critical,
        highCount: severityCounts.high,
        mediumCount: severityCounts.medium,
        lowCount: severityCounts.low,
        infoCount: severityCounts.info,
      },
    });

    log.info(
      { scanId, findings: result.findings.length, duration },
      "Scan completed and persisted",
    );

    callbacks.onComplete?.(result);

    return { scanId, result };
  } catch (error) {
    const errMsg = error instanceof Error ? error.message : String(error);
    log.error({ scanId, error: errMsg }, "Scan execution failed");

    await prisma.scan.update({
      where: { id: scanId },
      data: {
        status: "FAILED",
        completedAt: new Date(),
        currentPhase: `error: ${errMsg.slice(0, 200)}`,
      },
    });

    callbacks.onError?.(error instanceof Error ? error : new Error(errMsg));
    throw error;
  }
}

// ---------------------------------------------------------------------------
// Helper: Detect target type from input string
// ---------------------------------------------------------------------------

function detectTargetType(target: string): string {
  if (target.startsWith("http://") || target.startsWith("https://")) return "URL";
  if (/^\d+\.\d+\.\d+\.\d+\/\d+$/.test(target)) return "CIDR";
  if (/^\d+\.\d+\.\d+\.\d+$/.test(target)) return "IP";
  if (target.startsWith("0x") || target.endsWith(".sol")) return "SMART_CONTRACT";
  if (target.includes("github.com") || target.includes("gitlab.com")) return "REPOSITORY";
  return "DOMAIN";
}
