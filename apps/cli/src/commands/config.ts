// =============================================================================
// @vulnhunter/cli - Config Command
// =============================================================================
// Manages persistent user configuration stored in ~/.vulnhunter/config.json.
// Supports set, get, list, and reset subcommands for managing API keys,
// default scan options, and integration settings.
// =============================================================================

import { Command } from "commander";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

const CONFIG_DIR = path.join(os.homedir(), ".vulnhunter");
const CONFIG_FILE = path.join(CONFIG_DIR, "config.json");

/**
 * Known configuration keys with descriptions and validation info.
 * This map drives the help text and basic type validation for config values.
 */
const KNOWN_KEYS: Record<string, { description: string; type: "string" | "number" | "boolean"; sensitive?: boolean }> = {
  "api.provider": { description: "AI provider (anthropic, openai, google, deepseek, ollama)", type: "string" },
  "api.anthropic_key": { description: "Anthropic API key for AI engine", type: "string", sensitive: true },
  "api.openai_key": { description: "OpenAI API key", type: "string", sensitive: true },
  "api.google_ai_key": { description: "Google AI API key", type: "string", sensitive: true },
  "api.deepseek_key": { description: "DeepSeek API key", type: "string", sensitive: true },
  "api.ollama_url": { description: "Ollama server URL (default: http://localhost:11434/v1)", type: "string" },
  "ai.model": { description: "AI model override (e.g., gpt-4o, gemini-2.0-flash)", type: "string" },
  "ai.max_tokens": { description: "Max output tokens for AI responses", type: "number" },
  "api.hackerone_token": { description: "HackerOne API token", type: "string", sensitive: true },
  "api.hackerone_username": { description: "HackerOne username", type: "string" },
  "api.bugcrowd_token": { description: "Bugcrowd API token", type: "string", sensitive: true },
  "api.bugcrowd_email": { description: "Bugcrowd email address", type: "string" },
  "api.github_token": { description: "GitHub personal access token", type: "string", sensitive: true },
  "api.gitlab_token": { description: "GitLab personal access token", type: "string", sensitive: true },
  "scan.default_type": { description: "Default scan type (full|recon|web|code|network|cloud|smart_contract)", type: "string" },
  "scan.max_depth": { description: "Default maximum crawl depth", type: "number" },
  "scan.rate_limit": { description: "Default requests per second", type: "number" },
  "scan.timeout": { description: "Default scan timeout in seconds", type: "number" },
  "scan.concurrency": { description: "Default max concurrent requests", type: "number" },
  "scan.user_agent": { description: "Custom User-Agent header", type: "string" },
  "scan.proxy": { description: "Default proxy URL (HTTP/HTTPS/SOCKS5)", type: "string" },
  "output.format": { description: "Default output format (json|markdown|html|pdf)", type: "string" },
  "output.directory": { description: "Default output directory for reports", type: "string" },
  "output.color": { description: "Enable colored output (true|false)", type: "boolean" },
  "alerts.webhook_url": { description: "Default webhook URL for alerts", type: "string" },
  "alerts.slack_webhook": { description: "Slack webhook URL for notifications", type: "string" },
  "alerts.discord_webhook": { description: "Discord webhook URL for notifications", type: "string" },
  "alerts.min_severity": { description: "Minimum severity for alerts (critical|high|medium|low|info)", type: "string" },
};

/**
 * Ensures the config directory and file exist.
 */
function ensureConfigDir(): void {
  if (!fs.existsSync(CONFIG_DIR)) {
    fs.mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
  }
  if (!fs.existsSync(CONFIG_FILE)) {
    fs.writeFileSync(CONFIG_FILE, JSON.stringify({}, null, 2), { mode: 0o600 });
  }
}

/**
 * Reads the config file and returns the parsed JSON object.
 */
function readConfig(): Record<string, unknown> {
  ensureConfigDir();
  try {
    const raw = fs.readFileSync(CONFIG_FILE, "utf-8");
    return JSON.parse(raw);
  } catch {
    return {};
  }
}

/**
 * Writes the config object back to disk.
 */
function writeConfig(config: Record<string, unknown>): void {
  ensureConfigDir();
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2), { mode: 0o600 });
}

/**
 * Gets a nested value from an object using a dot-separated key path.
 * Example: getNestedValue({ api: { key: "abc" } }, "api.key") => "abc"
 */
function getNestedValue(obj: Record<string, unknown>, keyPath: string): unknown {
  const parts = keyPath.split(".");
  let current: unknown = obj;

  for (const part of parts) {
    if (current === null || current === undefined || typeof current !== "object") {
      return undefined;
    }
    current = (current as Record<string, unknown>)[part];
  }

  return current;
}

/**
 * Sets a nested value in an object using a dot-separated key path.
 * Creates intermediate objects as needed.
 */
function setNestedValue(obj: Record<string, unknown>, keyPath: string, value: unknown): void {
  const parts = keyPath.split(".");
  let current: Record<string, unknown> = obj;

  for (let i = 0; i < parts.length - 1; i++) {
    const part = parts[i]!;
    if (typeof current[part] !== "object" || current[part] === null) {
      current[part] = {};
    }
    current = current[part] as Record<string, unknown>;
  }

  const lastPart = parts[parts.length - 1]!;
  current[lastPart] = value;
}

/**
 * Deletes a nested value from an object using a dot-separated key path.
 */
function deleteNestedValue(obj: Record<string, unknown>, keyPath: string): boolean {
  const parts = keyPath.split(".");
  let current: Record<string, unknown> = obj;

  for (let i = 0; i < parts.length - 1; i++) {
    const part = parts[i]!;
    if (typeof current[part] !== "object" || current[part] === null) {
      return false;
    }
    current = current[part] as Record<string, unknown>;
  }

  const lastPart = parts[parts.length - 1]!;
  if (lastPart in current) {
    delete current[lastPart];
    return true;
  }
  return false;
}

/**
 * Masks a sensitive value for display, showing only the last 4 characters.
 */
function maskSensitive(value: string): string {
  if (value.length <= 4) return "****";
  return "*".repeat(value.length - 4) + value.slice(-4);
}

/**
 * Coerces a string value to the appropriate type based on the key definition.
 */
function coerceValue(key: string, value: string): string | number | boolean {
  const keyDef = KNOWN_KEYS[key];
  if (!keyDef) return value;

  switch (keyDef.type) {
    case "number": {
      const num = Number(value);
      if (isNaN(num)) {
        throw new Error(`Value for "${key}" must be a number, got "${value}"`);
      }
      return num;
    }
    case "boolean": {
      const lower = value.toLowerCase();
      if (lower === "true" || lower === "1" || lower === "yes") return true;
      if (lower === "false" || lower === "0" || lower === "no") return false;
      throw new Error(`Value for "${key}" must be a boolean (true/false), got "${value}"`);
    }
    default:
      return value;
  }
}

/**
 * Registers the `config` command group with Commander.
 */
export function registerConfigCommand(program: Command): void {
  const configCmd = program
    .command("config")
    .description("Manage VulnHunter configuration (~/.vulnhunter/config.json)");

  // ── config set <key> <value> ──
  configCmd
    .command("set <key> <value>")
    .description("Set a configuration value")
    .action(async (key: string, value: string) => {
      const chalk = (await import("chalk")).default;

      try {
        const coerced = coerceValue(key, value);
        const config = readConfig();
        setNestedValue(config, key, coerced);
        writeConfig(config);

        const displayValue = KNOWN_KEYS[key]?.sensitive
          ? maskSensitive(String(coerced))
          : String(coerced);

        console.log(chalk.green(`\n  \u2713 Set ${chalk.bold(key)} = ${displayValue}\n`));
      } catch (err: any) {
        console.error(chalk.red(`\n  \u2717 Error: ${err.message}\n`));
        process.exit(1);
      }
    });

  // ── config get <key> ──
  configCmd
    .command("get <key>")
    .description("Get a configuration value")
    .action(async (key: string) => {
      const chalk = (await import("chalk")).default;

      const config = readConfig();
      const value = getNestedValue(config, key);

      if (value === undefined) {
        console.log(chalk.yellow(`\n  Key "${key}" is not set.\n`));

        // Show hint if it's a known key
        if (KNOWN_KEYS[key]) {
          console.log(chalk.gray(`  Description: ${KNOWN_KEYS[key]!.description}`));
          console.log(chalk.gray(`  Set it with: vulnhunter config set ${key} <value>\n`));
        }
        return;
      }

      const displayValue = KNOWN_KEYS[key]?.sensitive
        ? maskSensitive(String(value))
        : String(value);

      console.log(chalk.cyan(`\n  ${chalk.bold(key)} = ${displayValue}\n`));
    });

  // ── config list ──
  configCmd
    .command("list")
    .description("List all configuration values")
    .option("--all", "Show all known keys including unset ones")
    .action(async (options: { all?: boolean }) => {
      const chalk = (await import("chalk")).default;
      const Table = (await import("cli-table3")).default;

      const config = readConfig();

      const table = new Table({
        head: [
          chalk.white.bold("Key"),
          chalk.white.bold("Value"),
          chalk.white.bold("Description"),
        ],
        colWidths: [28, 30, 35],
        wordWrap: true,
        style: { head: [], border: ["gray"] },
      });

      if (options.all) {
        // Show all known keys
        for (const [key, def] of Object.entries(KNOWN_KEYS)) {
          const value = getNestedValue(config, key);
          let displayValue: string;

          if (value === undefined) {
            displayValue = chalk.gray("(not set)");
          } else if (def.sensitive) {
            displayValue = chalk.yellow(maskSensitive(String(value)));
          } else {
            displayValue = chalk.green(String(value));
          }

          table.push([chalk.cyan(key), displayValue, chalk.gray(def.description)]);
        }
      } else {
        // Show only set keys
        const flatKeys = flattenObject(config);

        if (Object.keys(flatKeys).length === 0) {
          console.log(chalk.gray("\n  No configuration values set."));
          console.log(chalk.gray("  Run 'vulnhunter config set <key> <value>' to configure.\n"));
          console.log(chalk.gray("  Available keys:"));
          for (const [key, def] of Object.entries(KNOWN_KEYS)) {
            console.log(chalk.gray(`    ${chalk.cyan(key)} - ${def.description}`));
          }
          console.log();
          return;
        }

        for (const [key, value] of Object.entries(flatKeys)) {
          const def = KNOWN_KEYS[key];
          let displayValue: string;

          if (def?.sensitive) {
            displayValue = chalk.yellow(maskSensitive(String(value)));
          } else {
            displayValue = chalk.green(String(value));
          }

          const description = def?.description || chalk.gray("(custom key)");
          table.push([chalk.cyan(key), displayValue, chalk.gray(String(description))]);
        }
      }

      console.log();
      console.log(table.toString());
      console.log(chalk.gray(`\n  Config file: ${CONFIG_FILE}\n`));
    });

  // ── config reset ──
  configCmd
    .command("reset")
    .description("Reset configuration to defaults (deletes config file)")
    .option("-k, --key <key>", "Reset a specific key instead of the entire config")
    .action(async (options: { key?: string }) => {
      const chalk = (await import("chalk")).default;

      if (options.key) {
        const config = readConfig();
        const deleted = deleteNestedValue(config, options.key);

        if (deleted) {
          writeConfig(config);
          console.log(chalk.green(`\n  \u2713 Removed key "${options.key}"\n`));
        } else {
          console.log(chalk.yellow(`\n  Key "${options.key}" was not set.\n`));
        }
      } else {
        writeConfig({});
        console.log(chalk.green("\n  \u2713 Configuration has been reset to defaults.\n"));
      }
    });

  // ── config path ──
  configCmd
    .command("path")
    .description("Show the configuration file path")
    .action(async () => {
      const chalk = (await import("chalk")).default;
      ensureConfigDir();
      console.log(chalk.cyan(`\n  ${CONFIG_FILE}\n`));
    });
}

/**
 * Flattens a nested object into dot-separated key-value pairs.
 * Example: { api: { key: "abc" } } => { "api.key": "abc" }
 */
function flattenObject(
  obj: Record<string, unknown>,
  prefix = "",
): Record<string, unknown> {
  const result: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(obj)) {
    const fullKey = prefix ? `${prefix}.${key}` : key;

    if (value !== null && typeof value === "object" && !Array.isArray(value)) {
      Object.assign(result, flattenObject(value as Record<string, unknown>, fullKey));
    } else {
      result[fullKey] = value;
    }
  }

  return result;
}

/**
 * Utility function for other commands to read config values programmatically.
 */
export function getConfigValue<T = unknown>(key: string): T | undefined {
  const config = readConfig();
  return getNestedValue(config, key) as T | undefined;
}

/**
 * Utility function for other commands to set config values programmatically.
 */
export function setConfigValue(key: string, value: unknown): void {
  const config = readConfig();
  setNestedValue(config, key, value);
  writeConfig(config);
}
