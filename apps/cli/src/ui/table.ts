// =============================================================================
// @vulnhunter/cli - Result Tables
// =============================================================================
// Renders vulnerability findings in color-coded cli-table3 tables.
// Severity levels are mapped to chalk colors for instant visual triage.
// =============================================================================

import Table from "cli-table3";
import type { Finding, Severity, BountyProgram, Vulnerability } from "@vulnhunter/core";

/**
 * Dynamically imports chalk (ESM-only in v5+).
 */
async function loadChalk() {
  return (await import("chalk")).default;
}

/**
 * Maps severity to a chalk-colorized string.
 */
async function colorSeverity(severity: Severity): Promise<string> {
  const chalk = await loadChalk();
  const map: Record<string, (s: string) => string> = {
    critical: (s: string) => chalk.bgRed.white.bold(` ${s.toUpperCase()} `),
    high: (s: string) => chalk.red.bold(s.toUpperCase()),
    medium: (s: string) => chalk.yellow.bold(s.toUpperCase()),
    low: (s: string) => chalk.blue(s.toUpperCase()),
    info: (s: string) => chalk.gray(s.toUpperCase()),
  };
  const colorizer = map[severity] || map["info"]!;
  return colorizer(severity);
}

/**
 * Truncates a string to maxLen characters, appending "..." if truncated.
 */
function truncate(str: string, maxLen: number): string {
  if (str.length <= maxLen) return str;
  return str.slice(0, maxLen - 3) + "...";
}

/**
 * Renders a vulnerability findings table to the terminal.
 *
 * Columns:
 *   Severity | Title | Category | Endpoint | CVSS | Confidence | Confirmed
 *
 * @param findings - Array of Finding objects from the core types
 */
export async function renderVulnerabilityTable(findings: Finding[]): Promise<void> {
  const chalk = await loadChalk();

  if (findings.length === 0) {
    console.log(chalk.gray("\n  No findings to display.\n"));
    return;
  }

  const table = new Table({
    head: [
      chalk.white.bold("Severity"),
      chalk.white.bold("Title"),
      chalk.white.bold("Category"),
      chalk.white.bold("Endpoint"),
      chalk.white.bold("CVSS"),
      chalk.white.bold("Confidence"),
      chalk.white.bold("Confirmed"),
    ],
    colWidths: [12, 35, 18, 30, 7, 12, 11],
    wordWrap: true,
    style: {
      head: [],
      border: ["gray"],
    },
  });

  // Sort findings by severity weight (critical first)
  const severityOrder: Record<string, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4,
  };

  const sorted = [...findings].sort((a, b) => {
    const aWeight = severityOrder[a.vulnerability.severity] ?? 5;
    const bWeight = severityOrder[b.vulnerability.severity] ?? 5;
    return aWeight - bWeight;
  });

  for (const finding of sorted) {
    const v = finding.vulnerability;
    const sevColor = await colorSeverity(v.severity);

    const cvssColor =
      v.cvssScore >= 9.0
        ? chalk.bgRed.white.bold(` ${v.cvssScore.toFixed(1)} `)
        : v.cvssScore >= 7.0
          ? chalk.red.bold(v.cvssScore.toFixed(1))
          : v.cvssScore >= 4.0
            ? chalk.yellow(v.cvssScore.toFixed(1))
            : chalk.green(v.cvssScore.toFixed(1));

    const confColor =
      finding.confidence >= 80
        ? chalk.green.bold(`${finding.confidence}%`)
        : finding.confidence >= 50
          ? chalk.yellow(`${finding.confidence}%`)
          : chalk.red(`${finding.confidence}%`);

    const confirmedStr = v.confirmed
      ? chalk.green.bold("\u2713 Yes")
      : chalk.gray("\u2717 No");

    table.push([
      sevColor,
      truncate(v.title, 32),
      v.category.replace(/_/g, " "),
      truncate(v.endpoint || v.target, 27),
      cvssColor,
      confColor,
      confirmedStr,
    ]);
  }

  console.log();
  console.log(table.toString());
  console.log();
}

/**
 * Renders a compact summary table showing finding counts by severity.
 */
export async function renderSeveritySummary(
  findings: Finding[],
): Promise<void> {
  const chalk = await loadChalk();

  const counts: Record<string, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  for (const f of findings) {
    const sev = f.vulnerability.severity;
    counts[sev] = (counts[sev] || 0) + 1;
  }

  const table = new Table({
    head: [
      chalk.white.bold("Severity"),
      chalk.white.bold("Count"),
      chalk.white.bold("Bar"),
    ],
    colWidths: [12, 8, 42],
    style: {
      head: [],
      border: ["gray"],
    },
  });

  const maxCount = Math.max(...Object.values(counts), 1);
  const barWidth = 35;

  const severities: Array<{ key: string; color: (s: string) => string }> = [
    { key: "critical", color: (s) => chalk.bgRed.white.bold(s) },
    { key: "high", color: (s) => chalk.red.bold(s) },
    { key: "medium", color: (s) => chalk.yellow.bold(s) },
    { key: "low", color: (s) => chalk.blue(s) },
    { key: "info", color: (s) => chalk.gray(s) },
  ];

  for (const { key, color } of severities) {
    const count = counts[key] || 0;
    const filled = Math.round((count / maxCount) * barWidth);
    const bar = color("\u2588".repeat(filled)) + chalk.gray("\u2591".repeat(barWidth - filled));
    table.push([color(key.toUpperCase()), String(count), bar]);
  }

  console.log(table.toString());
}

/**
 * Renders a table of bounty programs.
 */
export async function renderBountyProgramsTable(
  programs: BountyProgram[],
): Promise<void> {
  const chalk = await loadChalk();

  if (programs.length === 0) {
    console.log(chalk.gray("\n  No programs found.\n"));
    return;
  }

  const table = new Table({
    head: [
      chalk.white.bold("Program"),
      chalk.white.bold("Platform"),
      chalk.white.bold("Active"),
      chalk.white.bold("Bounty Range (USD)"),
      chalk.white.bold("Avg Payout"),
      chalk.white.bold("Response Time"),
    ],
    colWidths: [25, 12, 8, 22, 12, 16],
    wordWrap: true,
    style: {
      head: [],
      border: ["gray"],
    },
  });

  for (const prog of programs) {
    const minBounty = Math.min(...prog.bountyRanges.map((r) => r.minUsd));
    const maxBounty = Math.max(...prog.bountyRanges.map((r) => r.maxUsd));
    const bountyRange = `$${minBounty.toLocaleString()} - $${maxBounty.toLocaleString()}`;
    const avgPayout = `$${prog.statistics.averagePayoutUsd.toLocaleString()}`;
    const responseTime = `${prog.statistics.averageResponseTimeHours.toFixed(0)}h`;

    table.push([
      chalk.cyan.bold(truncate(prog.name, 22)),
      prog.platform === "hackerone"
        ? chalk.magenta("HackerOne")
        : chalk.yellow("Bugcrowd"),
      prog.active ? chalk.green.bold("Yes") : chalk.red("No"),
      chalk.green(bountyRange),
      chalk.yellow(avgPayout),
      chalk.blue(responseTime),
    ]);
  }

  console.log();
  console.log(table.toString());
  console.log();
}

/**
 * Renders a table of code audit findings grouped by file.
 */
export async function renderAuditTable(
  findings: Finding[],
): Promise<void> {
  const chalk = await loadChalk();

  if (findings.length === 0) {
    console.log(chalk.gray("\n  No findings to display.\n"));
    return;
  }

  // Group findings by file (using endpoint as file path)
  const grouped = new Map<string, Finding[]>();
  for (const f of findings) {
    const file = f.vulnerability.endpoint || f.vulnerability.target;
    if (!grouped.has(file)) {
      grouped.set(file, []);
    }
    grouped.get(file)!.push(f);
  }

  for (const [file, fileFindings] of grouped) {
    console.log(chalk.cyan.bold(`\n  ${file}`));

    const table = new Table({
      head: [
        chalk.white.bold("Line"),
        chalk.white.bold("Severity"),
        chalk.white.bold("Title"),
        chalk.white.bold("Category"),
        chalk.white.bold("CWE"),
      ],
      colWidths: [8, 12, 40, 18, 12],
      wordWrap: true,
      style: {
        head: [],
        border: ["gray"],
      },
    });

    const sorted = [...fileFindings].sort((a, b) => {
      const aWeight = severityWeight(a.vulnerability.severity);
      const bWeight = severityWeight(b.vulnerability.severity);
      return aWeight - bWeight;
    });

    for (const f of sorted) {
      const v = f.vulnerability;
      const sevColor = await colorSeverity(v.severity);
      // Extract line number from evidence or rawData
      const line = (f.rawData?.lineNumber as number) || "-";

      table.push([
        chalk.yellow(String(line)),
        sevColor,
        truncate(v.title, 37),
        v.category.replace(/_/g, " "),
        v.cweId || chalk.gray("N/A"),
      ]);
    }

    console.log(table.toString());
  }

  console.log();
}

/**
 * Renders recon results: subdomains, open ports, technologies, crawled URLs.
 */
export async function renderReconTable(reconData: {
  subdomains?: string[];
  openPorts?: Array<{ host: string; port: number; service?: string }>;
  technologies?: string[];
  crawledUrls?: string[];
  dnsRecords?: Record<string, string[]>;
}): Promise<void> {
  const chalk = await loadChalk();

  // Subdomains
  if (reconData.subdomains && reconData.subdomains.length > 0) {
    console.log(chalk.cyan.bold("\n  Discovered Subdomains"));
    const subTable = new Table({
      head: [chalk.white.bold("#"), chalk.white.bold("Subdomain")],
      colWidths: [6, 60],
      style: { head: [], border: ["gray"] },
    });
    reconData.subdomains.forEach((sub, i) => {
      subTable.push([String(i + 1), chalk.green(sub)]);
    });
    console.log(subTable.toString());
  }

  // Open Ports
  if (reconData.openPorts && reconData.openPorts.length > 0) {
    console.log(chalk.cyan.bold("\n  Open Ports"));
    const portTable = new Table({
      head: [
        chalk.white.bold("Host"),
        chalk.white.bold("Port"),
        chalk.white.bold("Service"),
      ],
      colWidths: [30, 10, 26],
      style: { head: [], border: ["gray"] },
    });
    for (const p of reconData.openPorts) {
      portTable.push([p.host, String(p.port), p.service || chalk.gray("unknown")]);
    }
    console.log(portTable.toString());
  }

  // Technologies
  if (reconData.technologies && reconData.technologies.length > 0) {
    console.log(chalk.cyan.bold("\n  Detected Technologies"));
    const techTable = new Table({
      head: [chalk.white.bold("#"), chalk.white.bold("Technology")],
      colWidths: [6, 60],
      style: { head: [], border: ["gray"] },
    });
    reconData.technologies.forEach((tech, i) => {
      techTable.push([String(i + 1), chalk.yellow(tech)]);
    });
    console.log(techTable.toString());
  }

  // DNS Records
  if (reconData.dnsRecords && Object.keys(reconData.dnsRecords).length > 0) {
    console.log(chalk.cyan.bold("\n  DNS Records"));
    const dnsTable = new Table({
      head: [chalk.white.bold("Type"), chalk.white.bold("Records")],
      colWidths: [10, 56],
      wordWrap: true,
      style: { head: [], border: ["gray"] },
    });
    for (const [type, records] of Object.entries(reconData.dnsRecords)) {
      dnsTable.push([chalk.magenta(type), records.join(", ")]);
    }
    console.log(dnsTable.toString());
  }

  // Crawled URLs
  if (reconData.crawledUrls && reconData.crawledUrls.length > 0) {
    console.log(chalk.cyan.bold("\n  Crawled URLs"));
    const urlTable = new Table({
      head: [chalk.white.bold("#"), chalk.white.bold("URL")],
      colWidths: [6, 70],
      style: { head: [], border: ["gray"] },
    });
    reconData.crawledUrls.slice(0, 50).forEach((url, i) => {
      urlTable.push([String(i + 1), chalk.blue(truncate(url, 67))]);
    });
    if (reconData.crawledUrls.length > 50) {
      console.log(chalk.gray(`  ... and ${reconData.crawledUrls.length - 50} more URLs`));
    }
    console.log(urlTable.toString());
  }

  console.log();
}

/**
 * Helper to get numeric sort weight for severity.
 */
function severityWeight(severity: string): number {
  const weights: Record<string, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4,
  };
  return weights[severity] ?? 5;
}
