#!/usr/bin/env node
// =============================================================================
// @vulnhunter/cli - Main Entry Point
// =============================================================================
// Sets up the Commander.js program with global options and registers all
// subcommands: scan, recon, audit, report, bounty, monitor, config.
//
// Global options (--verbose, --output, --format, --config) are available to
// every command and stored on program.opts() for downstream consumers.
// =============================================================================

import { Command } from "commander";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

// ---------------------------------------------------------------------------
// Package version resolution
// ---------------------------------------------------------------------------

/**
 * Resolves the package version by walking up from the compiled dist/ directory
 * to find the nearest package.json. Falls back to "0.0.0-dev" if resolution
 * fails (e.g. running via ts-node or tsx without a build step).
 */
function resolveVersion(): string {
  try {
    // When compiled, this file lives at apps/cli/dist/index.js
    // When running from source via tsx, it's apps/cli/src/index.ts
    const currentDir = typeof __dirname !== "undefined"
      ? __dirname
      : path.dirname(fileURLToPath(import.meta.url));

    // Walk up to find package.json (works from both dist/ and src/)
    let dir = currentDir;
    for (let i = 0; i < 5; i++) {
      const pkgPath = path.join(dir, "package.json");
      if (fs.existsSync(pkgPath)) {
        const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf-8"));
        return pkg.version ?? "0.0.0-dev";
      }
      dir = path.dirname(dir);
    }
  } catch {
    // Swallow errors during version resolution
  }
  return "0.0.0-dev";
}

// ---------------------------------------------------------------------------
// ASCII Art Banner
// ---------------------------------------------------------------------------

/**
 * Renders the VulnHunter AI ASCII banner with chalk colors.
 */
async function printBanner(): Promise<void> {
  const chalk = (await import("chalk")).default;
  const version = resolveVersion();

  const banner = `
${chalk.cyan.bold("  ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ ")}
${chalk.cyan.bold("  ██║   ██║██║   ██║██║     ████╗  ██║██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗")}
${chalk.cyan.bold("  ██║   ██║██║   ██║██║     ██╔██╗ ██║███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝")}
${chalk.cyan("  ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗")}
${chalk.cyan("   ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║")}
${chalk.gray("    ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝")}
${chalk.yellow.bold("                              ▄▄▄  ▄▄▄▄▄")}
${chalk.yellow.bold("                             ▐█▀█▌  █  █▌")}
${chalk.yellow.bold("                             ▐█▀█▌  █  █▌")}
${chalk.yellow.bold("                             ▐█ █▌ ▄█▄ █▌")}
${chalk.gray("  " + "\u2500".repeat(89))}
${chalk.white("                      Autonomous Security Research Platform")}
${chalk.gray(`                                    v${version}`)}
${chalk.gray("  " + "\u2500".repeat(89))}
`;

  console.log(banner);
}

// ---------------------------------------------------------------------------
// Global Error Handlers
// ---------------------------------------------------------------------------

/**
 * Installs process-level error handlers for unhandled rejections and
 * uncaught exceptions. Ensures the CLI exits cleanly with a meaningful
 * error message instead of a raw stack trace.
 */
function installErrorHandlers(): void {
  process.on("unhandledRejection", async (reason: unknown) => {
    try {
      const chalk = (await import("chalk")).default;
      const message = reason instanceof Error ? reason.message : String(reason);
      console.error(chalk.red(`\n  Unhandled error: ${message}`));

      if (process.env.VULNHUNTER_VERBOSE === "1" || process.env.DEBUG) {
        if (reason instanceof Error && reason.stack) {
          console.error(chalk.gray(`\n  ${reason.stack}\n`));
        }
      } else {
        console.error(chalk.gray("  Set --verbose for stack trace.\n"));
      }
    } catch {
      console.error(`\n  Unhandled error: ${reason}\n`);
    }

    process.exit(1);
  });

  process.on("uncaughtException", async (error: Error) => {
    try {
      const chalk = (await import("chalk")).default;
      console.error(chalk.red(`\n  Fatal error: ${error.message}`));

      if (process.env.VULNHUNTER_VERBOSE === "1" || process.env.DEBUG) {
        console.error(chalk.gray(`\n  ${error.stack}\n`));
      } else {
        console.error(chalk.gray("  Set --verbose for stack trace.\n"));
      }
    } catch {
      console.error(`\n  Fatal error: ${error.message}\n`);
    }

    process.exit(1);
  });
}

// ---------------------------------------------------------------------------
// Program Setup
// ---------------------------------------------------------------------------

const program = new Command();

program
  .name("vulnhunter")
  .description(
    "VulnHunter AI - Autonomous Security Research Platform\n\n" +
    "An AI-powered vulnerability scanner and security assessment tool.\n" +
    "Combines automated reconnaissance, SAST, DAST, and exploit chain\n" +
    "detection with Claude AI for intelligent security research.",
  )
  .version(resolveVersion(), "-v, --version", "Display the current version")
  .option("--verbose", "Enable verbose/debug output", false)
  .option("--no-color", "Disable colored output")
  .option("-c, --config <path>", "Path to custom config file")
  .hook("preAction", async (thisCommand) => {
    const opts = thisCommand.opts();

    // If verbose is enabled, set a global flag for child commands
    if (opts.verbose) {
      process.env.VULNHUNTER_VERBOSE = "1";
    }

    // If colored output is disabled, set NO_COLOR
    if (opts.color === false) {
      process.env.NO_COLOR = "1";
    }

    // If a custom config path is specified, set it as an environment variable
    // so that the config module can pick it up
    if (opts.config) {
      const configPath = path.resolve(opts.config as string);
      if (!fs.existsSync(configPath)) {
        const chalk = (await import("chalk")).default;
        console.error(
          chalk.red(`\n  Error: Config file not found: ${configPath}\n`),
        );
        process.exit(1);
      }
      process.env.VULNHUNTER_CONFIG = configPath;
    }
  });

// Add help examples at the bottom of help text
program.addHelpText(
  "after",
  `
Examples:
  $ vulnhunter scan https://example.com --type full
  $ vulnhunter scan https://example.com --type web --depth 5 --rate-limit 20
  $ vulnhunter recon example.com --subdomain --ports --tech-detect
  $ vulnhunter audit ./my-project --language typescript --include-secrets
  $ vulnhunter report <scan-id> --format html --compliance owasp,pci-dss
  $ vulnhunter bounty list --platform hackerone
  $ vulnhunter bounty fetch github
  $ vulnhunter bounty submit <scan-id> --program github
  $ vulnhunter monitor https://example.com --interval 3600 --alert-severity high
  $ vulnhunter config set api.anthropic_key sk-ant-...
  $ vulnhunter config list --all

Documentation: https://github.com/vulnhunter/vulnhunter-ai
`,
);

// ---------------------------------------------------------------------------
// Register Commands
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  installErrorHandlers();

  // Dynamic imports to keep startup fast and avoid top-level await issues
  // with ESM-only dependencies (chalk v5+, ora v8+)
  const [
    { registerScanCommand },
    { registerReconCommand },
    { registerAuditCommand },
    { registerReportCommand },
    { registerBountyCommand },
    { registerMonitorCommand },
    { registerConfigCommand },
  ] = await Promise.all([
    import("./commands/scan.js"),
    import("./commands/recon.js"),
    import("./commands/audit.js"),
    import("./commands/report.js"),
    import("./commands/bounty.js"),
    import("./commands/monitor.js"),
    import("./commands/config.js"),
  ]);

  registerScanCommand(program);
  registerReconCommand(program);
  registerAuditCommand(program);
  registerReportCommand(program);
  registerBountyCommand(program);
  registerMonitorCommand(program);
  registerConfigCommand(program);

  // Print banner when no arguments or help is requested
  const args = process.argv.slice(2);
  const isHelpOrEmpty =
    args.length === 0 ||
    args.includes("--help") ||
    args.includes("-h");

  if (isHelpOrEmpty) {
    await printBanner();
  }

  await program.parseAsync(process.argv);
}

// ---------------------------------------------------------------------------
// Entrypoint
// ---------------------------------------------------------------------------

main().catch(async (err: unknown) => {
  try {
    const chalk = (await import("chalk")).default;
    const message = err instanceof Error ? err.message : String(err);
    console.error(chalk.red(`\n  Fatal error: ${message}\n`));

    if (process.env.VULNHUNTER_VERBOSE === "1" && err instanceof Error) {
      console.error(chalk.gray(err.stack ?? ""));
    }
  } catch {
    console.error("Fatal error:", err);
  }
  process.exit(1);
});
