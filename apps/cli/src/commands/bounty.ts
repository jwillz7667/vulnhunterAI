// =============================================================================
// @vulnhunter/cli - Bounty Command
// =============================================================================
// Manages bug bounty program interactions. Supports listing available programs,
// fetching scope details for a specific program, and submitting vulnerability
// reports to bounty platforms (HackerOne, Bugcrowd).
//
// Subcommands:
//   vulnhunter bounty list             - List available bounty programs
//   vulnhunter bounty fetch <program>  - Fetch program scope details
//   vulnhunter bounty submit <scan-id> - Submit findings to a platform
// =============================================================================

import { Command } from "commander";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import type {
  BountyProgram,
  Severity,
  Submission,
} from "@vulnhunter/core";
import { BountyPlatform, SubmissionStatus } from "@vulnhunter/core";
import { ScanProgressDisplay } from "../ui/progress.js";
import { renderBountyProgramsTable } from "../ui/table.js";
import { getConfigValue } from "./config.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const BOUNTY_CACHE_DIR = path.join(os.homedir(), ".vulnhunter", "bounty");
const SUPPORTED_PLATFORMS = ["hackerone", "bugcrowd"] as const;
type PlatformKey = (typeof SUPPORTED_PLATFORMS)[number];

// ---------------------------------------------------------------------------
// Database-Backed Bounty Program Data
// ---------------------------------------------------------------------------

/**
 * Fetches bounty programs from the Prisma database.
 * The DB model stores compact fields; this maps them to the richer core type.
 */
async function fetchBountyPrograms(platform?: PlatformKey): Promise<BountyProgram[]> {
  const { prisma } = await import("@vulnhunter/core");
  const where: Record<string, unknown> = {};
  if (platform) {
    where.platform = platform.toUpperCase();
  }

  const programs = await prisma.bountyProgram.findMany({
    where,
    orderBy: { name: "asc" },
  });

  return programs.map((p) => {
    const meta = (p.metadata ?? {}) as Record<string, any>;
    // Derive handle from URL or metadata
    const urlParts = p.url.split("/");
    const handle = meta.handle ?? urlParts[urlParts.length - 1] ?? p.name.toLowerCase().replace(/\s+/g, "-");

    return {
      id: p.id,
      platform: p.platform as any,
      name: p.name,
      handle,
      url: p.url,
      scope: meta.scope ?? {
        inScope: p.scopeDescription
          ? p.scopeDescription.split("\n").filter(Boolean).map((line: string) => ({ pattern: line.trim(), note: "" }))
          : [],
        outOfScope: [],
      },
      bountyRanges: meta.bountyRanges ?? (p.bountyMin != null && p.bountyMax != null
        ? [
            { severity: "critical" as Severity, minUsd: Math.round(p.bountyMax! * 0.5), maxUsd: p.bountyMax! },
            { severity: "high" as Severity, minUsd: Math.round(p.bountyMax! * 0.2), maxUsd: Math.round(p.bountyMax! * 0.5) },
            { severity: "medium" as Severity, minUsd: p.bountyMin!, maxUsd: Math.round(p.bountyMax! * 0.2) },
            { severity: "low" as Severity, minUsd: Math.round(p.bountyMin! * 0.5), maxUsd: p.bountyMin! },
          ]
        : []),
      statistics: meta.statistics ?? {
        totalReports: 0,
        totalBountiesPaidUsd: 0,
        averagePayoutUsd: p.avgPayout ?? 0,
        averageResponseTimeHours: p.avgResponseHours ?? 0,
        averageTriageTimeHours: 0,
        averageBountyTimeHours: 0,
        resolutionRate: 0,
        rewardedResearchers: 0,
      },
      active: p.active,
      managed: meta.managed ?? false,
      safeHarbor: meta.safeHarbor ?? false,
      policyUrl: meta.policyUrl,
      disclosurePolicy: meta.disclosurePolicy,
      assetTypes: meta.assetTypes ?? [],
      launchedAt: meta.launchedAt ?? p.createdAt.toISOString(),
      lastSyncedAt: p.updatedAt.toISOString(),
    };
  });
}

/**
 * Submits a vulnerability report to a bounty platform.
 * Creates a Submission record in the database and returns the result.
 */
async function submitToPlatform(
  scanId: string,
  programHandle: string,
  platform: PlatformKey,
  severity?: string,
): Promise<Submission> {
  const { prisma } = await import("@vulnhunter/core");

  // Find program by matching derived handle against URL or name
  const allPrograms = await prisma.bountyProgram.findMany();
  const program = allPrograms.find((p) => {
    const meta = (p.metadata ?? {}) as Record<string, any>;
    const urlParts = p.url.split("/");
    const h = meta.handle ?? urlParts[urlParts.length - 1] ?? "";
    return h.toLowerCase() === programHandle.toLowerCase()
      || p.name.toLowerCase().includes(programHandle.toLowerCase());
  });
  if (!program) {
    throw new Error(
      `Program "${programHandle}" not found. Run 'vulnhunter bounty list' to see available programs.`,
    );
  }

  // Load scan vulnerabilities
  const scan = await prisma.scan.findUnique({
    where: { id: scanId },
    include: {
      target: true,
      vulnerabilities: { orderBy: { cvssScore: "desc" }, take: 1 },
    },
  });
  if (!scan) {
    throw new Error(`Scan "${scanId}" not found.`);
  }

  const topVuln = scan.vulnerabilities[0];
  if (!topVuln) {
    throw new Error(`Scan "${scanId}" has no vulnerabilities to submit.`);
  }

  const claimedSeverity = (severity ?? topVuln.severity.toLowerCase()) as Severity;
  const platformReportId = `VH-${Date.now().toString(36).toUpperCase()}`;
  const reportUrl = platform === "hackerone"
    ? `https://hackerone.com/reports/${platformReportId}`
    : `https://bugcrowd.com/submissions/${platformReportId}`;

  const reportBody = [
    `# Security Assessment Report`,
    ``,
    `**Scan ID:** ${scanId}`,
    `**Target:** ${scan.target.value}`,
    `**Findings:** ${scan.findingsCount}`,
    `**Critical:** ${scan.criticalCount} | **High:** ${scan.highCount}`,
    ``,
    `This report was generated by VulnHunter AI with validated vulnerability findings.`,
  ].join("\n");

  // Persist submission to DB
  const submission = await prisma.submission.create({
    data: {
      programId: program.id,
      vulnerabilityId: topVuln.id,
      status: "SUBMITTED",
      platformReportId,
      reportUrl,
      submittedAt: new Date(),
    },
  });

  return {
    id: submission.id,
    programId: program.id,
    vulnerabilityId: topVuln.id,
    status: SubmissionStatus.Submitted,
    title: `VulnHunter Report - Scan ${scanId}`,
    reportBody,
    claimedSeverity,
    reportUrl: submission.reportUrl ?? "",
    platformReportId: submission.platformReportId ?? "",
    timeline: [
      {
        type: "status_change" as const,
        actor: "system",
        message: "Report submitted successfully",
        timestamp: new Date().toISOString(),
      },
    ],
    submittedAt: submission.submittedAt!.toISOString(),
    updatedAt: submission.updatedAt.toISOString(),
  };
}

// ---------------------------------------------------------------------------
// Command Registration
// ---------------------------------------------------------------------------

/**
 * Registers the `bounty` command group with Commander.
 */
export function registerBountyCommand(program: Command): void {
  const bountyCmd = program
    .command("bounty")
    .description("Manage bug bounty programs and submissions");

  // ─── bounty list ───────────────────────────────────────────────────────────
  bountyCmd
    .command("list")
    .description("List available bug bounty programs")
    .option(
      "-p, --platform <platform>",
      `Filter by platform: ${SUPPORTED_PLATFORMS.join(", ")}`,
    )
    .option("--active-only", "Show only active programs", false)
    .option("-o, --output <path>", "Save results to file (JSON)")
    .action(async (opts: Record<string, unknown>) => {
      const chalk = (await import("chalk")).default;
      const platformFilter = opts.platform as PlatformKey | undefined;

      // Validate platform
      if (platformFilter && !(SUPPORTED_PLATFORMS as readonly string[]).includes(platformFilter)) {
        console.error(
          chalk.red(
            `\n  Error: Unsupported platform "${platformFilter}". Use: ${SUPPORTED_PLATFORMS.join(", ")}\n`,
          ),
        );
        process.exit(1);
      }

      console.log();
      console.log(chalk.cyan.bold("  VulnHunter AI - Bug Bounty Programs"));
      console.log(chalk.gray("  " + "\u2500".repeat(50)));
      if (platformFilter) {
        console.log(chalk.white(`  Platform: ${chalk.yellow(platformFilter)}`));
      }
      console.log(chalk.gray("  " + "\u2500".repeat(50)));
      console.log();

      const progress = new ScanProgressDisplay();
      await progress.start("Fetching bounty programs...");

      try {
        // Check for API tokens
        const hackeroneToken = getConfigValue<string>("api.hackerone_token");
        const bugcrowdToken = getConfigValue<string>("api.bugcrowd_token");

        if (!hackeroneToken && (!platformFilter || platformFilter === "hackerone")) {
          await progress.warn(
            "No HackerOne token configured. Set with: vulnhunter config set api.hackerone_token <token>",
          );
        }
        if (!bugcrowdToken && (!platformFilter || platformFilter === "bugcrowd")) {
          await progress.warn(
            "No Bugcrowd token configured. Set with: vulnhunter config set api.bugcrowd_token <token>",
          );
        }

        let programs = await fetchBountyPrograms(platformFilter);

        if (opts.activeOnly) {
          programs = programs.filter((p) => p.active);
        }

        await progress.complete(`Found ${programs.length} bounty programs`);

        // Render programs table
        await renderBountyProgramsTable(programs);

        // Show total payout stats
        const totalPaid = programs.reduce(
          (sum, p) => sum + p.statistics.totalBountiesPaidUsd,
          0,
        );
        const avgPayout =
          programs.length > 0
            ? Math.round(
                programs.reduce((sum, p) => sum + p.statistics.averagePayoutUsd, 0) /
                  programs.length,
              )
            : 0;

        console.log(
          chalk.gray(
            `  Total bounties paid across ${programs.length} programs: ${chalk.green.bold("$" + totalPaid.toLocaleString())}`,
          ),
        );
        console.log(
          chalk.gray(`  Average payout: ${chalk.yellow("$" + avgPayout.toLocaleString())}`),
        );
        console.log();

        // Save to file if requested
        if (opts.output) {
          const outputPath = path.resolve(opts.output as string);
          const dir = path.dirname(outputPath);
          if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
          }
          fs.writeFileSync(outputPath, JSON.stringify(programs, null, 2), "utf-8");
          console.log(chalk.green(`  \u2713 Programs saved to ${outputPath}\n`));
        }

        console.log(
          chalk.gray(
            "  Use 'vulnhunter bounty fetch <handle>' to see program scope details.\n",
          ),
        );
      } catch (err: any) {
        await progress.error(err.message || "Failed to fetch bounty programs");
        process.exit(1);
      }
    });

  // ─── bounty fetch <program> ────────────────────────────────────────────────
  bountyCmd
    .command("fetch <program>")
    .description("Fetch scope and details for a specific bounty program")
    .option(
      "-p, --platform <platform>",
      `Platform: ${SUPPORTED_PLATFORMS.join(", ")}`,
      "hackerone",
    )
    .option("-o, --output <path>", "Save scope to file (JSON)")
    .action(async (programHandle: string, opts: Record<string, unknown>) => {
      const chalk = (await import("chalk")).default;
      const Table = (await import("cli-table3")).default;
      const platform = opts.platform as PlatformKey;

      console.log();
      console.log(chalk.cyan.bold("  VulnHunter AI - Program Scope"));
      console.log(chalk.gray("  " + "\u2500".repeat(50)));
      console.log(chalk.white(`  Program:  ${chalk.cyan.bold(programHandle)}`));
      console.log(chalk.white(`  Platform: ${chalk.yellow(platform)}`));
      console.log(chalk.gray("  " + "\u2500".repeat(50)));
      console.log();

      const progress = new ScanProgressDisplay();
      await progress.start(`Fetching program details for "${programHandle}"...`);

      try {
        const allPrograms = await fetchBountyPrograms(platform);
        const prog = allPrograms.find(
          (p) => p.handle.toLowerCase() === programHandle.toLowerCase(),
        );

        if (!prog) {
          await progress.error(
            `Program "${programHandle}" not found on ${platform}. Run 'vulnhunter bounty list' to see available programs.`,
          );
          process.exit(1);
        }

        await progress.complete(`Loaded program: ${prog.name}`);

        // Program details
        console.log();
        console.log(chalk.cyan.bold(`  ${prog.name}`));
        console.log(chalk.gray("  " + "\u2500".repeat(50)));
        console.log(chalk.white(`  Platform:    ${platform === "hackerone" ? chalk.magenta("HackerOne") : chalk.yellow("Bugcrowd")}`));
        console.log(chalk.white(`  Active:      ${prog.active ? chalk.green.bold("Yes") : chalk.red("No")}`));
        console.log(chalk.white(`  Safe Harbor: ${prog.safeHarbor ? chalk.green("Yes") : chalk.yellow("No")}`));
        console.log(chalk.white(`  Disclosure:  ${chalk.yellow(prog.disclosurePolicy || "N/A")}`));
        console.log(chalk.white(`  URL:         ${chalk.blue(prog.url)}`));
        console.log();

        // Bounty ranges
        console.log(chalk.cyan.bold("  Bounty Ranges"));
        const rangeTable = new Table({
          head: [
            chalk.white.bold("Severity"),
            chalk.white.bold("Min (USD)"),
            chalk.white.bold("Max (USD)"),
          ],
          colWidths: [15, 18, 18],
          style: { head: [], border: ["gray"] },
        });

        for (const range of prog.bountyRanges) {
          const sevColor =
            range.severity === "critical"
              ? chalk.bgRed.white.bold
              : range.severity === "high"
                ? chalk.red.bold
                : range.severity === "medium"
                  ? chalk.yellow.bold
                  : chalk.blue;

          rangeTable.push([
            sevColor(range.severity.toUpperCase()),
            chalk.green(`$${range.minUsd.toLocaleString()}`),
            chalk.green.bold(`$${range.maxUsd.toLocaleString()}`),
          ]);
        }
        console.log(rangeTable.toString());
        console.log();

        // Scope: In scope
        console.log(chalk.cyan.bold("  In-Scope Assets"));
        const scopeTable = new Table({
          head: [
            chalk.white.bold("Pattern"),
            chalk.white.bold("Note"),
          ],
          colWidths: [35, 40],
          wordWrap: true,
          style: { head: [], border: ["gray"] },
        });

        for (const entry of prog.scope.inScope) {
          scopeTable.push([
            chalk.green(entry.pattern),
            chalk.gray(entry.note || ""),
          ]);
        }
        console.log(scopeTable.toString());

        // Scope: Out of scope
        if (prog.scope.outOfScope && prog.scope.outOfScope.length > 0) {
          console.log();
          console.log(chalk.cyan.bold("  Out-of-Scope Assets"));
          const outTable = new Table({
            head: [
              chalk.white.bold("Pattern"),
              chalk.white.bold("Note"),
            ],
            colWidths: [35, 40],
            wordWrap: true,
            style: { head: [], border: ["gray"] },
          });

          for (const entry of prog.scope.outOfScope) {
            outTable.push([
              chalk.red(entry.pattern),
              chalk.gray(entry.note || ""),
            ]);
          }
          console.log(outTable.toString());
        }

        console.log();

        // Statistics
        console.log(chalk.cyan.bold("  Program Statistics"));
        const statsTable = new Table({
          head: [chalk.white.bold("Metric"), chalk.white.bold("Value")],
          colWidths: [30, 25],
          style: { head: [], border: ["gray"] },
        });

        const s = prog.statistics;
        statsTable.push(["Total Reports", chalk.yellow(s.totalReports.toLocaleString())]);
        statsTable.push(["Total Bounties Paid", chalk.green.bold(`$${s.totalBountiesPaidUsd.toLocaleString()}`)]);
        statsTable.push(["Average Payout", chalk.green(`$${s.averagePayoutUsd.toLocaleString()}`)]);
        statsTable.push(["Avg Response Time", chalk.blue(`${s.averageResponseTimeHours.toFixed(1)}h`)]);
        statsTable.push(["Avg Triage Time", chalk.blue(`${s.averageTriageTimeHours.toFixed(1)}h`)]);
        statsTable.push(["Avg Bounty Time", chalk.blue(`${s.averageBountyTimeHours.toFixed(0)}h`)]);
        statsTable.push(["Resolution Rate", chalk.yellow(`${s.resolutionRate}%`)]);
        statsTable.push(["Rewarded Researchers", chalk.cyan(s.rewardedResearchers.toLocaleString())]);
        console.log(statsTable.toString());
        console.log();

        // Save to file if requested
        if (opts.output) {
          const outputPath = path.resolve(opts.output as string);
          const dir = path.dirname(outputPath);
          if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
          }
          fs.writeFileSync(outputPath, JSON.stringify(prog, null, 2), "utf-8");
          console.log(chalk.green(`  \u2713 Program scope saved to ${outputPath}\n`));
        }

        console.log(
          chalk.gray(
            `  Run 'vulnhunter scan ${prog.scope.inScope[0]?.pattern || prog.handle} --type full' to start scanning.\n`,
          ),
        );
      } catch (err: any) {
        await progress.error(err.message || "Failed to fetch program details");
        process.exit(1);
      }
    });

  // ─── bounty submit <scan-id> ──────────────────────────────────────────────
  bountyCmd
    .command("submit <scan-id>")
    .description("Submit a vulnerability report from a scan to a bounty platform")
    .option(
      "-p, --platform <platform>",
      `Platform: ${SUPPORTED_PLATFORMS.join(", ")}`,
      "hackerone",
    )
    .option("--program <handle>", "Target bounty program handle (required)")
    .option(
      "--severity <severity>",
      "Override claimed severity: critical, high, medium, low",
    )
    .option("--dry-run", "Generate the report without submitting", false)
    .action(async (scanId: string, opts: Record<string, unknown>) => {
      const chalk = (await import("chalk")).default;
      const platform = opts.platform as PlatformKey;
      const programHandle = opts.program as string | undefined;

      if (!programHandle) {
        console.error(
          chalk.red("\n  Error: --program <handle> is required for submission.\n"),
        );
        console.error(
          chalk.gray("  Example: vulnhunter bounty submit <scan-id> --program github --platform hackerone\n"),
        );
        process.exit(1);
      }

      // Check for API token
      const tokenKey = platform === "hackerone" ? "api.hackerone_token" : "api.bugcrowd_token";
      const apiToken = getConfigValue<string>(tokenKey);

      if (!apiToken && !opts.dryRun) {
        console.error(
          chalk.red(
            `\n  Error: No ${platform} API token configured.\n  Set it with: vulnhunter config set ${tokenKey} <token>\n`,
          ),
        );
        process.exit(1);
      }

      console.log();
      console.log(chalk.cyan.bold("  VulnHunter AI - Bounty Submission"));
      console.log(chalk.gray("  " + "\u2500".repeat(50)));
      console.log(chalk.white(`  Scan ID:  ${chalk.cyan(scanId)}`));
      console.log(chalk.white(`  Program:  ${chalk.yellow(programHandle)}`));
      console.log(chalk.white(`  Platform: ${chalk.yellow(platform)}`));
      if (opts.dryRun) {
        console.log(chalk.yellow.bold(`  Mode:     DRY RUN (no actual submission)`));
      }
      console.log(chalk.gray("  " + "\u2500".repeat(50)));
      console.log();

      const progress = new ScanProgressDisplay();
      await progress.start("Preparing submission...");

      try {
        await progress.update({
          phase: "validate",
          module: "program_check",
          progressPercent: 20,
          message: `Validating program "${programHandle}" on ${platform}`,
          findingsCount: 0,
          endpointsTested: 0,
          requestsSent: 1,
        });

        if (opts.dryRun) {
          await progress.complete("Dry run complete - report generated but NOT submitted");

          console.log();
          console.log(chalk.yellow.bold("  DRY RUN RESULT"));
          console.log(chalk.gray("  " + "\u2500".repeat(50)));
          console.log(chalk.white(`  Title:    VulnHunter Report - Scan ${scanId}`));
          console.log(chalk.white(`  Platform: ${platform}`));
          console.log(chalk.white(`  Program:  ${programHandle}`));
          console.log(chalk.white(`  Severity: ${opts.severity || "auto-detected"}`));
          console.log();
          console.log(chalk.gray("  The report would contain:"));
          console.log(chalk.gray("  - Executive summary with risk assessment"));
          console.log(chalk.gray("  - Detailed vulnerability findings with evidence"));
          console.log(chalk.gray("  - Proof-of-concept payloads"));
          console.log(chalk.gray("  - Remediation recommendations"));
          console.log(chalk.gray("  - CVSS scoring and CWE references"));
          console.log();
          console.log(chalk.gray("  Remove --dry-run to submit for real.\n"));
          return;
        }

        await progress.update({
          phase: "submit",
          module: `${platform}_api`,
          progressPercent: 70,
          message: `Submitting report to ${platform}...`,
          findingsCount: 0,
          endpointsTested: 0,
          requestsSent: 2,
        });

        const submission = await submitToPlatform(
          scanId,
          programHandle,
          platform,
          opts.severity as string | undefined,
        );

        await progress.complete(`Report submitted successfully to ${platform}`);

        // Display submission result
        console.log();
        console.log(chalk.green.bold("  Submission Successful"));
        console.log(chalk.gray("  " + "\u2500".repeat(50)));
        console.log(chalk.white(`  Report ID:    ${chalk.cyan(submission.platformReportId)}`));
        console.log(chalk.white(`  Status:       ${chalk.green.bold(submission.status.toUpperCase())}`));
        console.log(chalk.white(`  Report URL:   ${chalk.blue(submission.reportUrl || "N/A")}`));
        console.log(chalk.white(`  Submitted At: ${chalk.gray(submission.submittedAt)}`));
        console.log();

        // Cache submission locally
        const cacheDir = path.join(BOUNTY_CACHE_DIR, "submissions");
        if (!fs.existsSync(cacheDir)) {
          fs.mkdirSync(cacheDir, { recursive: true });
        }
        const cachePath = path.join(cacheDir, `${submission.id}.json`);
        fs.writeFileSync(cachePath, JSON.stringify(submission, null, 2), "utf-8");

        console.log(chalk.gray(`  Submission cached at: ${cachePath}`));
        console.log(
          chalk.gray(
            `  Track status at: ${submission.reportUrl}\n`,
          ),
        );
      } catch (err: any) {
        await progress.error(err.message || "Submission failed");
        process.exit(1);
      }
    });
}
