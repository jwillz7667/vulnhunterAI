// =============================================================================
// @vulnhunter/cli - Terminal Dashboard
// =============================================================================
// Renders a rich terminal dashboard showing real-time scan progress,
// severity counts, active module status, and recent findings.
// Designed for full-screen terminal use during long-running scans.
// =============================================================================

import Table from "cli-table3";
import type { ScanProgress, Finding, Severity } from "@vulnhunter/core";

async function loadChalk() {
  return (await import("chalk")).default;
}

/**
 * Formats milliseconds into human-readable elapsed time.
 */
function formatElapsed(ms: number): string {
  const totalSeconds = Math.floor(ms / 1000);
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;

  if (hours > 0) return `${hours}h ${minutes}m ${seconds}s`;
  if (minutes > 0) return `${minutes}m ${seconds}s`;
  return `${seconds}s`;
}

/**
 * Renders a visual progress bar.
 */
function progressBar(percent: number, width = 30): string {
  const filled = Math.round((percent / 100) * width);
  const empty = width - filled;
  return "\u2588".repeat(filled) + "\u2591".repeat(empty);
}

export interface DashboardState {
  scanProgress: ScanProgress;
  findings: Finding[];
  startTime: number;
  severityCounts: Record<string, number>;
}

/**
 * Renders a comprehensive terminal dashboard showing scan status.
 *
 * Layout:
 *   +----------------------------+
 *   | SCAN PROGRESS              |
 *   | Phase: active_scan         |
 *   | Module: xss:reflected      |
 *   | [########............] 40% |
 *   +----------------------------+
 *   | SEVERITY COUNTS            |
 *   | CRITICAL: 2  HIGH: 5      |
 *   | MEDIUM: 8    LOW: 3       |
 *   +----------------------------+
 *   | RECENT FINDINGS (last 5)   |
 *   | ...                        |
 *   +----------------------------+
 *
 * @param state - Current dashboard state including progress and findings
 */
export async function renderDashboard(state: DashboardState): Promise<string> {
  const chalk = await loadChalk();
  const { scanProgress, findings, startTime, severityCounts } = state;
  const elapsed = formatElapsed(Date.now() - startTime);

  const lines: string[] = [];

  // ── Header ──
  lines.push("");
  lines.push(
    chalk.cyan.bold(
      "  \u250C" +
        "\u2500".repeat(70) +
        "\u2510",
    ),
  );
  lines.push(
    chalk.cyan.bold("  \u2502") +
      chalk.white.bold("  VULNHUNTER AI - SCAN DASHBOARD") +
      " ".repeat(38) +
      chalk.cyan.bold("\u2502"),
  );
  lines.push(
    chalk.cyan.bold(
      "  \u251C" +
        "\u2500".repeat(70) +
        "\u2524",
    ),
  );

  // ── Progress Section ──
  const bar = progressBar(scanProgress.progressPercent);
  const pctStr = `${scanProgress.progressPercent.toFixed(0)}%`.padStart(4);

  lines.push(
    chalk.cyan.bold("  \u2502") +
      chalk.yellow.bold("  Phase:   ") +
      chalk.white(scanProgress.phase.padEnd(20)) +
      chalk.yellow.bold("Module: ") +
      chalk.white(scanProgress.module.padEnd(22)) +
      chalk.cyan.bold("\u2502"),
  );

  lines.push(
    chalk.cyan.bold("  \u2502") +
      "  " +
      chalk.cyan(bar) +
      " " +
      chalk.white.bold(pctStr) +
      " ".repeat(70 - bar.length - pctStr.length - 3) +
      chalk.cyan.bold("\u2502"),
  );

  lines.push(
    chalk.cyan.bold("  \u2502") +
      chalk.gray(`  Requests: ${scanProgress.requestsSent}`.padEnd(25)) +
      chalk.gray(`Endpoints: ${scanProgress.endpointsTested}`.padEnd(25)) +
      chalk.gray(`Elapsed: ${elapsed}`.padEnd(20)) +
      chalk.cyan.bold("\u2502"),
  );

  lines.push(
    chalk.cyan.bold("  \u2502") +
      chalk.gray(`  ${scanProgress.message}`.padEnd(70)) +
      chalk.cyan.bold("\u2502"),
  );

  // ── Severity Counts ──
  lines.push(
    chalk.cyan.bold(
      "  \u251C" +
        "\u2500".repeat(70) +
        "\u2524",
    ),
  );

  const crit = severityCounts["critical"] || 0;
  const high = severityCounts["high"] || 0;
  const med = severityCounts["medium"] || 0;
  const low = severityCounts["low"] || 0;
  const info = severityCounts["info"] || 0;
  const total = findings.length;

  const severityLine = [
    chalk.bgRed.white.bold(` CRIT: ${crit} `),
    chalk.red.bold(` HIGH: ${high} `),
    chalk.yellow.bold(` MED: ${med} `),
    chalk.blue(` LOW: ${low} `),
    chalk.gray(` INFO: ${info} `),
    chalk.white.bold(` TOTAL: ${total} `),
  ].join(chalk.gray(" | "));

  lines.push(
    chalk.cyan.bold("  \u2502") +
      "  " +
      severityLine +
      " ".repeat(Math.max(0, 68 - stripAnsi(severityLine).length)) +
      chalk.cyan.bold("\u2502"),
  );

  // ── Recent Findings (last 5) ──
  lines.push(
    chalk.cyan.bold(
      "  \u251C" +
        "\u2500".repeat(70) +
        "\u2524",
    ),
  );

  lines.push(
    chalk.cyan.bold("  \u2502") +
      chalk.white.bold("  RECENT FINDINGS") +
      " ".repeat(53) +
      chalk.cyan.bold("\u2502"),
  );

  const recentFindings = findings.slice(-5).reverse();

  if (recentFindings.length === 0) {
    lines.push(
      chalk.cyan.bold("  \u2502") +
        chalk.gray("  No findings yet...".padEnd(70)) +
        chalk.cyan.bold("\u2502"),
    );
  } else {
    for (const f of recentFindings) {
      const v = f.vulnerability;
      const sevLabel = formatSeverityLabel(chalk, v.severity);
      const title = v.title.length > 40 ? v.title.slice(0, 37) + "..." : v.title;
      const endpoint = (v.endpoint || v.target).slice(0, 18);

      const row = `  ${sevLabel} ${chalk.white(title.padEnd(42))} ${chalk.gray(endpoint)}`;
      const rawLen = stripAnsi(row).length;
      const padding = Math.max(0, 70 - rawLen);

      lines.push(
        chalk.cyan.bold("  \u2502") +
          row +
          " ".repeat(padding) +
          chalk.cyan.bold("\u2502"),
      );
    }
  }

  // ── Footer ──
  lines.push(
    chalk.cyan.bold(
      "  \u2514" +
        "\u2500".repeat(70) +
        "\u2518",
    ),
  );
  lines.push("");

  const output = lines.join("\n");
  return output;
}

/**
 * Formats a severity label with color.
 */
function formatSeverityLabel(chalk: any, severity: string): string {
  switch (severity) {
    case "critical":
      return chalk.bgRed.white.bold(" CRIT ");
    case "high":
      return chalk.red.bold(" HIGH ");
    case "medium":
      return chalk.yellow.bold(" MED  ");
    case "low":
      return chalk.blue(" LOW  ");
    case "info":
      return chalk.gray(" INFO ");
    default:
      return chalk.gray(` ${severity.toUpperCase().padEnd(5)}`);
  }
}

/**
 * Simple ANSI escape code stripper for calculating visible string length.
 */
function stripAnsi(str: string): string {
  // eslint-disable-next-line no-control-regex
  return str.replace(/\x1B\[\d+(?:;\d+)*m/g, "");
}

/**
 * Clears the terminal and re-renders the dashboard.
 * Useful for continuous monitoring mode.
 */
export async function refreshDashboard(state: DashboardState): Promise<void> {
  const output = await renderDashboard(state);
  // Move cursor to top-left and clear screen
  process.stdout.write("\x1B[2J\x1B[0;0H");
  process.stdout.write(output);
}
