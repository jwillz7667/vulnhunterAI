// =============================================================================
// @vulnhunter/cli - Monitor Command
// =============================================================================
// Implements continuous security monitoring for a target. Runs scans at a
// configurable interval, detects changes between scans (new findings,
// resolved findings, severity changes), and sends notifications via
// Slack, Discord, or email webhooks.
//
// Usage:
//   vulnhunter monitor <target>
//   vulnhunter monitor <target> --interval 12h --notify slack,email
//   vulnhunter monitor <target> --interval 1h --type web
// =============================================================================

import { Command } from "commander";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import type {
  ScanConfig,
  ScanProgress,
  ScanResult,
  ScanType,
  Finding,
  Severity,
} from "@vulnhunter/core";
import { ScanProgressDisplay } from "../ui/progress.js";
import { renderSeveritySummary, renderVulnerabilityTable } from "../ui/table.js";
import { refreshDashboard, type DashboardState } from "../ui/dashboard.js";
import { getConfigValue } from "./config.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MONITOR_STATE_DIR = path.join(os.homedir(), ".vulnhunter", "monitor");
const NOTIFICATION_CHANNELS = ["slack", "discord", "email"] as const;
type NotificationChannel = (typeof NOTIFICATION_CHANNELS)[number];

// ---------------------------------------------------------------------------
// Interval Parsing
// ---------------------------------------------------------------------------

/**
 * Parses a human-readable interval string into milliseconds.
 * Supports: "30m", "1h", "12h", "24h", "1d", "7d"
 */
function parseInterval(interval: string): number {
  const match = interval.match(/^(\d+(?:\.\d+)?)\s*(m|min|h|hr|hours?|d|days?)$/i);
  if (!match) {
    throw new Error(
      `Invalid interval "${interval}". Use format: 30m, 1h, 12h, 24h, 1d, 7d`,
    );
  }

  const value = parseFloat(match[1]!);
  const unit = match[2]!.toLowerCase();

  switch (unit) {
    case "m":
    case "min":
      return Math.max(value * 60_000, 60_000); // minimum 1 minute
    case "h":
    case "hr":
    case "hour":
    case "hours":
      return value * 3_600_000;
    case "d":
    case "day":
    case "days":
      return value * 86_400_000;
    default:
      return value * 3_600_000; // default to hours
  }
}

/**
 * Formats milliseconds into a human-readable string.
 */
function formatDuration(ms: number): string {
  if (ms < 60_000) return `${Math.round(ms / 1000)}s`;
  if (ms < 3_600_000) return `${Math.round(ms / 60_000)}m`;
  if (ms < 86_400_000) return `${(ms / 3_600_000).toFixed(1)}h`;
  return `${(ms / 86_400_000).toFixed(1)}d`;
}

// ---------------------------------------------------------------------------
// Change Detection
// ---------------------------------------------------------------------------

interface MonitorState {
  target: string;
  lastScanId: string;
  lastScanTime: string;
  lastFindings: Finding[];
  scanCount: number;
  totalNewFindings: number;
  totalResolvedFindings: number;
}

interface ChangeReport {
  newFindings: Finding[];
  resolvedFindings: Finding[];
  changedSeverity: Array<{
    findingId: string;
    title: string;
    oldSeverity: string;
    newSeverity: string;
  }>;
  totalCurrent: number;
  totalPrevious: number;
}

/**
 * Compares two sets of findings and produces a change report.
 * Findings are matched by vulnerability title + endpoint combination.
 */
function detectChanges(
  previousFindings: Finding[],
  currentFindings: Finding[],
): ChangeReport {
  // Build lookup maps by a composite key of title + endpoint
  const makeKey = (f: Finding) =>
    `${f.vulnerability.title}::${f.vulnerability.endpoint || f.vulnerability.target}`;

  const previousMap = new Map<string, Finding>();
  for (const f of previousFindings) {
    previousMap.set(makeKey(f), f);
  }

  const currentMap = new Map<string, Finding>();
  for (const f of currentFindings) {
    currentMap.set(makeKey(f), f);
  }

  // New findings: in current but not in previous
  const newFindings: Finding[] = [];
  for (const [key, finding] of currentMap) {
    if (!previousMap.has(key)) {
      newFindings.push(finding);
    }
  }

  // Resolved findings: in previous but not in current
  const resolvedFindings: Finding[] = [];
  for (const [key, finding] of previousMap) {
    if (!currentMap.has(key)) {
      resolvedFindings.push(finding);
    }
  }

  // Severity changes: present in both but severity changed
  const changedSeverity: ChangeReport["changedSeverity"] = [];
  for (const [key, currentFinding] of currentMap) {
    const previousFinding = previousMap.get(key);
    if (
      previousFinding &&
      previousFinding.vulnerability.severity !== currentFinding.vulnerability.severity
    ) {
      changedSeverity.push({
        findingId: currentFinding.vulnerability.id,
        title: currentFinding.vulnerability.title,
        oldSeverity: previousFinding.vulnerability.severity,
        newSeverity: currentFinding.vulnerability.severity,
      });
    }
  }

  return {
    newFindings,
    resolvedFindings,
    changedSeverity,
    totalCurrent: currentFindings.length,
    totalPrevious: previousFindings.length,
  };
}

// ---------------------------------------------------------------------------
// Notification System
// ---------------------------------------------------------------------------

/**
 * Sends alert notifications to configured channels.
 * In production, this makes HTTP POST requests to webhook URLs stored
 * in the VulnHunter config (alerts.slack_webhook, alerts.discord_webhook).
 */
async function sendNotification(
  channel: NotificationChannel,
  target: string,
  changes: ChangeReport,
): Promise<void> {
  const chalk = (await import("chalk")).default;

  // Build the notification message
  const lines: string[] = [
    `VulnHunter Monitor Alert: ${target}`,
    ``,
    `New findings: ${changes.newFindings.length}`,
    `Resolved findings: ${changes.resolvedFindings.length}`,
    `Severity changes: ${changes.changedSeverity.length}`,
    `Current total: ${changes.totalCurrent} (was ${changes.totalPrevious})`,
  ];

  if (changes.newFindings.length > 0) {
    lines.push("", "New findings:");
    for (const f of changes.newFindings.slice(0, 5)) {
      lines.push(
        `  [${f.vulnerability.severity.toUpperCase()}] ${f.vulnerability.title} at ${f.vulnerability.endpoint || f.vulnerability.target}`,
      );
    }
    if (changes.newFindings.length > 5) {
      lines.push(`  ... and ${changes.newFindings.length - 5} more`);
    }
  }

  const message = lines.join("\n");

  switch (channel) {
    case "slack": {
      const webhookUrl = getConfigValue<string>("alerts.slack_webhook");
      if (!webhookUrl) {
        console.log(
          chalk.yellow(
            `  [notify] Slack webhook not configured. Set with: vulnhunter config set alerts.slack_webhook <url>`,
          ),
        );
        return;
      }
      await fetch(webhookUrl, {
        method: "POST",
        body: JSON.stringify({ text: message }),
        headers: { "Content-Type": "application/json" },
      });
      console.log(chalk.blue(`  [notify] Slack notification sent to configured webhook`));
      break;
    }
    case "discord": {
      const webhookUrl = getConfigValue<string>("alerts.discord_webhook");
      if (!webhookUrl) {
        console.log(
          chalk.yellow(
            `  [notify] Discord webhook not configured. Set with: vulnhunter config set alerts.discord_webhook <url>`,
          ),
        );
        return;
      }
      await fetch(webhookUrl, {
        method: "POST",
        body: JSON.stringify({ content: message }),
        headers: { "Content-Type": "application/json" },
      });
      console.log(chalk.blue(`  [notify] Discord notification sent to configured webhook`));
      break;
    }
    case "email": {
      const webhookUrl = getConfigValue<string>("alerts.webhook_url");
      if (!webhookUrl) {
        console.log(
          chalk.yellow(
            `  [notify] Email webhook not configured. Set with: vulnhunter config set alerts.webhook_url <url>`,
          ),
        );
        return;
      }
      await fetch(webhookUrl, {
        method: "POST",
        body: JSON.stringify({ subject: `VulnHunter Alert: ${target}`, body: message }),
        headers: { "Content-Type": "application/json" },
      });
      console.log(chalk.blue(`  [notify] Email notification sent via configured webhook`));
      break;
    }
  }
}

// ---------------------------------------------------------------------------
// Real Scan Execution via @vulnhunter/scanner
// ---------------------------------------------------------------------------

/**
 * Executes a monitoring scan against the target using the real ScanEngine.
 * Consumes the AsyncGenerator from engine.executeScan() and emits progress
 * callbacks for the CLI UI.
 */
async function executeMonitorScan(
  target: string,
  _previousFindings: Finding[],
  onProgress: (progress: ScanProgress) => void,
): Promise<{ findings: Finding[]; scanId: string }> {
  const { createFullEngine } = await import("@vulnhunter/scanner");
  const engine = await createFullEngine();

  const config: ScanConfig = {
    target,
    scanType: "web" as ScanType,
    options: {
      maxDepth: 5,
      rateLimit: 10,
      requestTimeoutMs: 30_000,
      scanTimeoutMs: 120_000,
      maxConcurrency: 5,
      maxRedirects: 5,
      enableCookies: true,
      scopeRestrictions: [] as string[],
      enabledModules: [] as Array<{ name: string; enabled: boolean }>,
      aiPayloadGeneration: false,
      exploitChainDetection: false,
    },
  };

  const gen = engine.executeScan(config);
  let result: ScanResult | undefined;

  while (true) {
    const { value, done } = await gen.next();
    if (done) {
      result = value as ScanResult;
      break;
    }
    onProgress(value as ScanProgress);
  }

  if (!result) {
    throw new Error("Monitor scan completed without producing a result");
  }

  return {
    findings: result.findings ?? [],
    scanId: result.id ?? crypto.randomUUID(),
  };
}

// ---------------------------------------------------------------------------
// State Persistence
// ---------------------------------------------------------------------------

/**
 * Loads the persisted monitor state for a target.
 */
function loadMonitorState(target: string): MonitorState | null {
  const stateFile = path.join(
    MONITOR_STATE_DIR,
    `${target.replace(/[^a-zA-Z0-9.-]/g, "_")}.json`,
  );
  if (fs.existsSync(stateFile)) {
    try {
      return JSON.parse(fs.readFileSync(stateFile, "utf-8"));
    } catch {
      return null;
    }
  }
  return null;
}

/**
 * Persists the monitor state for a target.
 */
function saveMonitorState(state: MonitorState): void {
  if (!fs.existsSync(MONITOR_STATE_DIR)) {
    fs.mkdirSync(MONITOR_STATE_DIR, { recursive: true });
  }
  const stateFile = path.join(
    MONITOR_STATE_DIR,
    `${state.target.replace(/[^a-zA-Z0-9.-]/g, "_")}.json`,
  );
  fs.writeFileSync(stateFile, JSON.stringify(state, null, 2), "utf-8");
}

// ---------------------------------------------------------------------------
// Command Registration
// ---------------------------------------------------------------------------

/**
 * Registers the `monitor` command with Commander.
 */
export function registerMonitorCommand(program: Command): void {
  program
    .command("monitor <target>")
    .description("Continuously monitor a target for security changes")
    .option(
      "-i, --interval <interval>",
      "Scan interval: 30m, 1h, 12h, 24h, 7d (default: 24h)",
      "24h",
    )
    .option(
      "-n, --notify <channels>",
      `Notification channels (comma-separated): ${NOTIFICATION_CHANNELS.join(", ")}`,
    )
    .option("-t, --type <type>", "Scan type: full, web, recon, network", "web")
    .option("--once", "Run a single monitoring scan and exit", false)
    .option("--dashboard", "Show live dashboard during scans", false)
    .option(
      "--min-severity <severity>",
      "Minimum severity to trigger notifications: critical, high, medium, low, info",
      getConfigValue<string>("alerts.min_severity") || "medium",
    )
    .action(async (target: string, opts: Record<string, unknown>) => {
      const chalk = (await import("chalk")).default;

      // Parse interval
      let intervalMs: number;
      try {
        intervalMs = parseInterval(opts.interval as string);
      } catch (err: any) {
        console.error(chalk.red(`\n  Error: ${err.message}\n`));
        process.exit(1);
      }

      // Parse notification channels
      const notifyChannels: NotificationChannel[] = [];
      if (opts.notify) {
        const channels = (opts.notify as string).split(",").map((c) => c.trim().toLowerCase());
        for (const ch of channels) {
          if ((NOTIFICATION_CHANNELS as readonly string[]).includes(ch)) {
            notifyChannels.push(ch as NotificationChannel);
          } else {
            console.error(
              chalk.yellow(
                `\n  Warning: Unknown notification channel "${ch}". Supported: ${NOTIFICATION_CHANNELS.join(", ")}\n`,
              ),
            );
          }
        }
      }

      // Strip protocol from target for display
      const cleanTarget = target.replace(/^https?:\/\//, "").replace(/\/.*$/, "");

      console.log();
      console.log(chalk.cyan.bold("  VulnHunter AI - Continuous Monitor"));
      console.log(chalk.gray("  " + "\u2500".repeat(50)));
      console.log(chalk.white(`  Target:     ${chalk.cyan.bold(target)}`));
      console.log(chalk.white(`  Interval:   ${chalk.yellow(formatDuration(intervalMs))}`));
      console.log(chalk.white(`  Scan Type:  ${chalk.yellow(String(opts.type))}`));
      console.log(chalk.white(`  Min Sev:    ${chalk.yellow(String(opts.minSeverity))}`));
      if (notifyChannels.length > 0) {
        console.log(chalk.white(`  Notify:     ${chalk.yellow(notifyChannels.join(", "))}`));
      }
      if (opts.once) {
        console.log(chalk.white(`  Mode:       ${chalk.yellow("Single scan")}`));
      } else {
        console.log(chalk.white(`  Mode:       ${chalk.green("Continuous")}`));
      }
      console.log(chalk.gray("  " + "\u2500".repeat(50)));
      console.log();

      if (!opts.once) {
        console.log(
          chalk.gray("  Press Ctrl+C to stop monitoring.\n"),
        );
      }

      // Load previous state
      let monitorState = loadMonitorState(cleanTarget);
      let scanIteration = monitorState?.scanCount ?? 0;
      let isFirstScan = !monitorState;

      // Graceful shutdown handler
      let isRunning = true;
      const shutdown = () => {
        isRunning = false;
        console.log(
          chalk.yellow("\n\n  Monitor stopped. State saved.\n"),
        );
      };
      process.on("SIGINT", shutdown);
      process.on("SIGTERM", shutdown);

      // Main monitoring loop
      while (isRunning) {
        scanIteration++;

        const scanLabel = opts.once
          ? "Monitoring scan"
          : `Scan #${scanIteration}`;

        console.log(
          chalk.cyan.bold(
            `\n  ${scanLabel} - ${new Date().toISOString()}\n`,
          ),
        );

        const progress = new ScanProgressDisplay();
        await progress.start(`${scanLabel}: Scanning ${target}...`);

        const previousFindings = monitorState?.lastFindings ?? [];
        const severityCounts: Record<string, number> = {
          critical: 0, high: 0, medium: 0, low: 0, info: 0,
        };
        // Accumulator for in-progress findings used by the dashboard callback.
        // executeMonitorScan returns the final array, but the dashboard needs
        // access to intermediate results during the scan.
        const progressFindings: Finding[] = [];

        try {
          const { findings, scanId } = await executeMonitorScan(
            target,
            previousFindings,
            async (prog: ScanProgress) => {
              if (opts.dashboard) {
                // Use the full dashboard for real-time display
                const dashState: DashboardState = {
                  scanProgress: prog,
                  findings: progressFindings,
                  startTime: Date.now() - 5000,
                  severityCounts,
                };
                await refreshDashboard(dashState);
              } else {
                await progress.update(prog);
              }
            },
          );

          // Update severity counts
          for (const f of findings) {
            const sev = f.vulnerability.severity;
            severityCounts[sev] = (severityCounts[sev] || 0) + 1;
          }

          await progress.complete(
            `${scanLabel} completed: ${findings.length} findings`,
          );

          // Detect changes from previous scan
          const changes = detectChanges(previousFindings, findings);

          // Display change report
          console.log();
          console.log(chalk.cyan.bold("  Change Detection"));
          console.log(chalk.gray("  " + "\u2500".repeat(50)));
          console.log(
            chalk.white(`  Current Findings:  ${chalk.yellow.bold(String(changes.totalCurrent))}`),
          );
          console.log(
            chalk.white(`  Previous Findings: ${chalk.gray(String(changes.totalPrevious))}`),
          );

          if (isFirstScan) {
            console.log(
              chalk.gray("  (First scan - no baseline for comparison)"),
            );
          } else {
            // New findings
            if (changes.newFindings.length > 0) {
              console.log(
                chalk.red.bold(
                  `\n  + ${changes.newFindings.length} NEW finding(s):`,
                ),
              );
              for (const f of changes.newFindings) {
                const sevColor =
                  f.vulnerability.severity === "critical"
                    ? chalk.bgRed.white.bold
                    : f.vulnerability.severity === "high"
                      ? chalk.red.bold
                      : f.vulnerability.severity === "medium"
                        ? chalk.yellow.bold
                        : chalk.gray;
                console.log(
                  `    ${sevColor(`[${f.vulnerability.severity.toUpperCase()}]`)} ${f.vulnerability.title}`,
                );
              }
            } else {
              console.log(chalk.green("  + No new findings"));
            }

            // Resolved findings
            if (changes.resolvedFindings.length > 0) {
              console.log(
                chalk.green.bold(
                  `\n  - ${changes.resolvedFindings.length} RESOLVED finding(s):`,
                ),
              );
              for (const f of changes.resolvedFindings) {
                console.log(
                  `    ${chalk.green("\u2713")} ${chalk.strikethrough(f.vulnerability.title)}`,
                );
              }
            } else if (!isFirstScan) {
              console.log(chalk.gray("  - No resolved findings"));
            }

            // Severity changes
            if (changes.changedSeverity.length > 0) {
              console.log(
                chalk.yellow.bold(
                  `\n  ~ ${changes.changedSeverity.length} severity change(s):`,
                ),
              );
              for (const ch of changes.changedSeverity) {
                console.log(
                  `    ${ch.title}: ${ch.oldSeverity.toUpperCase()} -> ${ch.newSeverity.toUpperCase()}`,
                );
              }
            }
          }

          console.log();

          // Show severity summary
          if (findings.length > 0) {
            await renderSeveritySummary(findings);
          }

          // Send notifications if there are changes
          const severityOrder: Record<string, number> = {
            critical: 0, high: 1, medium: 2, low: 3, info: 4,
          };
          const minSevOrder = severityOrder[opts.minSeverity as string] ?? 2;

          const notifiableNewFindings = changes.newFindings.filter(
            (f) => (severityOrder[f.vulnerability.severity] ?? 4) <= minSevOrder,
          );

          if (
            notifyChannels.length > 0 &&
            !isFirstScan &&
            (notifiableNewFindings.length > 0 || changes.changedSeverity.length > 0)
          ) {
            console.log(chalk.cyan.bold("  Sending Notifications"));
            for (const channel of notifyChannels) {
              await sendNotification(channel, target, {
                ...changes,
                newFindings: notifiableNewFindings,
              });
            }
            console.log();
          }

          // Update monitor state
          monitorState = {
            target: cleanTarget,
            lastScanId: scanId,
            lastScanTime: new Date().toISOString(),
            lastFindings: findings,
            scanCount: scanIteration,
            totalNewFindings: (monitorState?.totalNewFindings ?? 0) + changes.newFindings.length,
            totalResolvedFindings:
              (monitorState?.totalResolvedFindings ?? 0) + changes.resolvedFindings.length,
          };

          saveMonitorState(monitorState);
          isFirstScan = false;

          // If --once flag, exit after a single scan
          if (opts.once) {
            console.log(
              chalk.gray(
                `\n  Use 'vulnhunter monitor ${target}' without --once for continuous monitoring.\n`,
              ),
            );
            break;
          }

          // Wait for the next interval
          if (isRunning) {
            const nextScan = new Date(Date.now() + intervalMs);
            console.log(
              chalk.gray(
                `  Next scan at: ${nextScan.toISOString()} (in ${formatDuration(intervalMs)})\n`,
              ),
            );
            console.log(chalk.gray("  " + "\u2500".repeat(50)));

            // Wait in small increments so we can respond to SIGINT
            const checkIntervalMs = 5_000;
            let waited = 0;
            while (waited < intervalMs && isRunning) {
              const remaining = Math.min(checkIntervalMs, intervalMs - waited);
              await new Promise((r) => setTimeout(r, remaining));
              waited += remaining;
            }
          }
        } catch (err: any) {
          await progress.error(err.message || "Monitoring scan failed");

          // On error, don't exit -- wait for the next interval
          if (opts.once) {
            process.exit(1);
          }

          console.log(
            chalk.yellow(
              `\n  Scan failed. Retrying in ${formatDuration(intervalMs)}...\n`,
            ),
          );

          const checkIntervalMs = 5_000;
          let waited = 0;
          while (waited < intervalMs && isRunning) {
            const remaining = Math.min(checkIntervalMs, intervalMs - waited);
            await new Promise((r) => setTimeout(r, remaining));
            waited += remaining;
          }
        }
      }

      // Cleanup
      process.removeListener("SIGINT", shutdown);
      process.removeListener("SIGTERM", shutdown);

      // Final summary
      if (monitorState && scanIteration > 1) {
        console.log(chalk.cyan.bold("  Monitoring Session Summary"));
        console.log(chalk.gray("  " + "\u2500".repeat(50)));
        console.log(chalk.white(`  Target:              ${chalk.cyan(target)}`));
        console.log(chalk.white(`  Total Scans:         ${chalk.yellow(String(monitorState.scanCount))}`));
        console.log(chalk.white(`  Total New Findings:  ${chalk.red(String(monitorState.totalNewFindings))}`));
        console.log(
          chalk.white(
            `  Total Resolved:      ${chalk.green(String(monitorState.totalResolvedFindings))}`,
          ),
        );
        console.log(chalk.white(`  Current Findings:    ${chalk.yellow(String(monitorState.lastFindings.length))}`));
        console.log(chalk.white(`  State File:          ${chalk.gray(MONITOR_STATE_DIR)}`));
        console.log();
      }
    });
}
