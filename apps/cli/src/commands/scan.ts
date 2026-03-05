// =============================================================================
// @vulnhunter/cli - Scan Command
// =============================================================================
// Primary command for running security scans. Supports multiple scan types
// (full, recon, web, code, network, cloud, smart_contract), configurable
// depth, rate limiting, authentication, and output options.
//
// Orchestrates the scanning pipeline: API call -> progress tracking ->
// findings display -> summary statistics.
// =============================================================================

import { Command } from "commander";
import fs from "node:fs";
import path from "node:path";
import type {
  ScanConfig,
  ScanOptions,
  ScanResult,
  ScanProgress,
  ScanType,
  Finding,
  Severity,
  ScanModuleConfig,
} from "@vulnhunter/core";
import {
  AuthenticationType,
  ScanStatus,
} from "@vulnhunter/core";
import { ScanProgressDisplay } from "../ui/progress.js";
import { renderVulnerabilityTable, renderSeveritySummary } from "../ui/table.js";
import { renderDashboard, type DashboardState } from "../ui/dashboard.js";
import { getConfigValue } from "./config.js";

/**
 * Builds a ScanConfig object from the CLI target and option flags.
 */
function buildScanConfig(
  target: string,
  opts: Record<string, unknown>,
): ScanConfig {
  // Parse enabled modules from comma-separated --modules flag
  const enabledModules: ScanModuleConfig[] = [];
  if (opts.modules) {
    const moduleNames = (opts.modules as string).split(",").map((m) => m.trim());
    for (const name of moduleNames) {
      enabledModules.push({ name, enabled: true });
    }
  }

  // Parse scope restrictions from file
  let scopeRestrictions: string[] = [];
  if (opts.scopeFile) {
    const scopePath = path.resolve(opts.scopeFile as string);
    if (fs.existsSync(scopePath)) {
      const content = fs.readFileSync(scopePath, "utf-8");
      scopeRestrictions = content
        .split("\n")
        .map((l) => l.trim())
        .filter((l) => l.length > 0 && !l.startsWith("#"));
    }
  }

  // Build authentication config
  let authentication: ScanOptions["authentication"] | undefined;
  if (opts.authType && opts.authType !== "none") {
    const authType = opts.authType as string;
    const creds = opts.authCreds as string | undefined;

    switch (authType) {
      case "basic": {
        const [username, password] = (creds || ":").split(":");
        authentication = {
          type: AuthenticationType.Basic,
          credentials: { username: username || "", password: password || "" },
        };
        break;
      }
      case "bearer": {
        authentication = {
          type: AuthenticationType.Bearer,
          credentials: { token: creds || "" },
        };
        break;
      }
      case "cookie": {
        authentication = {
          type: AuthenticationType.Cookie,
          credentials: { cookieString: creds || "" },
        };
        break;
      }
      case "api_key": {
        const [keyName, keyValue] = (creds || "=").split("=");
        authentication = {
          type: AuthenticationType.APIKey,
          credentials: {
            keyName: keyName || "X-API-Key",
            keyValue: keyValue || "",
            in: "header" as const,
          },
        };
        break;
      }
      default: {
        authentication = { type: AuthenticationType.None };
      }
    }
  }

  const scanType = (opts.type as ScanType) || "full";
  const maxDepth = opts.depth ? Number(opts.depth) : (getConfigValue<number>("scan.max_depth") ?? 10);
  const rateLimit = opts.rateLimit ? Number(opts.rateLimit) : (getConfigValue<number>("scan.rate_limit") ?? 10);
  const scanTimeoutMs = opts.timeout
    ? Number(opts.timeout) * 1000
    : (getConfigValue<number>("scan.timeout") ?? 300) * 1000;

  const options: ScanOptions = {
    maxDepth,
    rateLimit,
    requestTimeoutMs: 30_000,
    scanTimeoutMs,
    maxConcurrency: getConfigValue<number>("scan.concurrency") ?? 10,
    customHeaders: {},
    userAgent: getConfigValue<string>("scan.user_agent") || "VulnHunter-AI/1.0",
    proxy: getConfigValue<string>("scan.proxy"),
    maxRedirects: 5,
    enableCookies: true,
    scopeRestrictions,
    enabledModules,
    aiPayloadGeneration: true,
    exploitChainDetection: true,
    authentication,
  };

  return {
    target,
    scanType: scanType as ScanType,
    options,
  };
}

/**
 * Executes a real scan using the @vulnhunter/scanner engine.
 * Consumes the AsyncGenerator from ScanEngine.executeScan() and
 * emits progress/finding callbacks for the CLI UI.
 */
async function executeScan(
  config: ScanConfig,
  onProgress: (progress: ScanProgress) => void,
  onFinding: (finding: Finding) => void,
): Promise<ScanResult> {
  const { createFullEngine } = await import("@vulnhunter/scanner");

  const engine = await createFullEngine();
  const gen = engine.executeScan(config);
  let result: ScanResult | undefined;

  while (true) {
    const { value, done } = await gen.next();
    if (done) {
      result = value as ScanResult;
      break;
    }
    // value is ScanProgress
    const progress = value as ScanProgress;
    onProgress(progress);
  }

  if (!result) {
    throw new Error("Scan completed without producing a result");
  }

  // Emit findings
  for (const finding of result.findings) {
    onFinding(finding);
  }

  return result;
}

/**
 * Writes scan results to a file in the specified format.
 */
async function writeOutput(
  result: ScanResult,
  format: string,
  outputFile: string,
): Promise<void> {
  const chalk = (await import("chalk")).default;
  const resolvedPath = path.resolve(outputFile);

  let content: string;

  switch (format) {
    case "json":
      content = JSON.stringify(result, null, 2);
      break;
    case "markdown": {
      const lines: string[] = [
        `# VulnHunter AI - Scan Report`,
        ``,
        `**Target:** ${result.target}`,
        `**Scan Type:** ${result.scanType}`,
        `**Status:** ${result.status}`,
        `**Start Time:** ${result.startTime}`,
        `**End Time:** ${result.endTime || "N/A"}`,
        `**Duration:** ${(result.stats.durationMs / 1000).toFixed(1)}s`,
        ``,
        `## Summary`,
        ``,
        `| Metric | Value |`,
        `|--------|-------|`,
        `| Total Findings | ${result.findings.length} |`,
        `| Confirmed | ${result.stats.confirmedFindings} |`,
        `| Requests Sent | ${result.stats.totalRequests} |`,
        `| Endpoints Discovered | ${result.stats.endpointsDiscovered} |`,
        `| Exploit Chains | ${result.stats.exploitChainsFound} |`,
        ``,
        `### Findings by Severity`,
        ``,
        `| Severity | Count |`,
        `|----------|-------|`,
      ];

      for (const [sev, count] of Object.entries(result.stats.findingsBySeverity)) {
        lines.push(`| ${sev.toUpperCase()} | ${count} |`);
      }

      lines.push("", "## Findings", "");

      for (const f of result.findings) {
        const v = f.vulnerability;
        lines.push(`### ${v.severity.toUpperCase()}: ${v.title}`);
        lines.push("");
        lines.push(`- **Category:** ${v.category}`);
        lines.push(`- **CVSS:** ${v.cvssScore}`);
        lines.push(`- **CWE:** ${v.cweId || "N/A"}`);
        lines.push(`- **Endpoint:** ${v.endpoint || v.target}`);
        lines.push(`- **Confidence:** ${f.confidence}%`);
        lines.push(`- **Confirmed:** ${v.confirmed ? "Yes" : "No"}`);
        lines.push("");
        lines.push(`**Description:** ${v.description}`);
        if (v.remediation) {
          lines.push("", `**Remediation:** ${v.remediation}`);
        }
        lines.push("");
        lines.push("---");
        lines.push("");
      }

      content = lines.join("\n");
      break;
    }
    default:
      content = JSON.stringify(result, null, 2);
  }

  // Ensure output directory exists
  const dir = path.dirname(resolvedPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  fs.writeFileSync(resolvedPath, content, "utf-8");
  console.log(chalk.green(`\n  \u2713 Results saved to ${resolvedPath}\n`));
}

/**
 * Registers the `scan` command with Commander.
 */
export function registerScanCommand(program: Command): void {
  program
    .command("scan <target>")
    .description("Run a security scan against a target (URL, domain, IP, CIDR, or contract address)")
    .option("-t, --type <type>", "Scan type: full, recon, web, code, network, cloud, smart_contract", "full")
    .option("-d, --depth <depth>", "Maximum crawl/traversal depth", "10")
    .option("-r, --rate-limit <rps>", "Maximum requests per second", "10")
    .option("-f, --output-format <format>", "Output format: json, markdown", "json")
    .option("-o, --output-file <path>", "Save results to file")
    .option("--auth-type <type>", "Authentication type: none, basic, bearer, cookie, api_key", "none")
    .option("--auth-creds <creds>", "Authentication credentials (format depends on auth-type)")
    .option("--scope-file <path>", "Path to scope restriction file (one pattern per line)")
    .option("--modules <modules>", "Comma-separated list of specific modules to enable")
    .option("--timeout <seconds>", "Overall scan timeout in seconds", "300")
    .option("--provider <provider>", "AI provider: anthropic, openai, google, deepseek, ollama")
    .option("--model <model>", "AI model override (e.g., gpt-4o, gemini-2.0-flash)")
    .option("--no-ai", "Disable AI-powered payload generation")
    .option("--no-exploit-chains", "Disable exploit chain detection")
    .action(async (target: string, opts: Record<string, unknown>) => {
      const chalk = (await import("chalk")).default;

      console.log();
      console.log(chalk.cyan.bold("  VulnHunter AI - Security Scan"));
      console.log(chalk.gray("  " + "\u2500".repeat(50)));
      console.log(chalk.white(`  Target:     ${chalk.cyan.bold(target)}`));
      console.log(chalk.white(`  Scan Type:  ${chalk.yellow(String(opts.type))}`));
      console.log(chalk.white(`  Depth:      ${opts.depth}`));
      console.log(chalk.white(`  Rate Limit: ${opts.rateLimit} req/s`));
      console.log(chalk.white(`  Timeout:    ${opts.timeout}s`));

      if (opts.provider) {
        console.log(chalk.white(`  Provider:   ${chalk.yellow(String(opts.provider))}`));
      }
      if (opts.model) {
        console.log(chalk.white(`  Model:      ${chalk.yellow(String(opts.model))}`));
      }
      if (opts.authType && opts.authType !== "none") {
        console.log(chalk.white(`  Auth:       ${opts.authType}`));
      }
      if (opts.modules) {
        console.log(chalk.white(`  Modules:    ${opts.modules}`));
      }

      console.log(chalk.gray("  " + "\u2500".repeat(50)));
      console.log();

      // Build scan configuration
      const config = buildScanConfig(target, opts);

      // Initialize progress display
      const progress = new ScanProgressDisplay();
      await progress.start(`Initializing ${opts.type} scan against ${target}...`);

      const allFindings: Finding[] = [];
      const severityCounts: Record<string, number> = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
      };

      try {
        const result = await executeScan(
          config,
          // Progress callback
          async (prog: ScanProgress) => {
            await progress.update(prog);
          },
          // Finding callback
          (finding: Finding) => {
            allFindings.push(finding);
            const sev = finding.vulnerability.severity;
            severityCounts[sev] = (severityCounts[sev] || 0) + 1;
          },
        );

        await progress.complete();

        // Display results
        console.log(chalk.cyan.bold("\n  Scan Results"));
        console.log(chalk.gray("  " + "\u2500".repeat(50)));
        console.log(chalk.white(`  Scan ID:    ${chalk.cyan(result.id)}`));
        console.log(chalk.white(`  Status:     ${chalk.green.bold(result.status.toUpperCase())}`));
        console.log(chalk.white(`  Duration:   ${(result.stats.durationMs / 1000).toFixed(1)}s`));
        console.log(chalk.white(`  Requests:   ${result.stats.totalRequests}`));
        console.log(chalk.white(`  Endpoints:  ${result.stats.endpointsDiscovered}`));
        console.log();

        // Severity summary bar chart
        await renderSeveritySummary(result.findings);

        // Detailed findings table
        if (result.findings.length > 0) {
          console.log(chalk.cyan.bold("  Detailed Findings"));
          await renderVulnerabilityTable(result.findings);
        }

        // Exploit chains
        if (result.stats.exploitChainsFound > 0) {
          console.log(
            chalk.red.bold(`  \u26A0  ${result.stats.exploitChainsFound} exploit chain(s) detected!`),
          );
          console.log(
            chalk.yellow("  Run 'vulnhunter report " + result.id + "' for full chain analysis.\n"),
          );
        }

        // Save output if requested
        if (opts.outputFile) {
          await writeOutput(
            result,
            opts.outputFormat as string,
            opts.outputFile as string,
          );
        }

        // Final summary line
        const critCount = severityCounts["critical"] || 0;
        const highCount = severityCounts["high"] || 0;

        if (critCount > 0) {
          console.log(
            chalk.bgRed.white.bold(`  \u26A0  ${critCount} CRITICAL finding(s) require immediate attention!  `),
          );
        }
        if (highCount > 0) {
          console.log(
            chalk.red.bold(`  \u26A0  ${highCount} HIGH severity finding(s) detected.`),
          );
        }

        console.log(
          chalk.gray(`\n  Use 'vulnhunter report ${result.id}' to generate a detailed report.\n`),
        );
      } catch (err: any) {
        await progress.error(err.message || "Unknown error during scan");
        process.exit(1);
      }
    });
}
