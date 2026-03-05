// =============================================================================
// @vulnhunter/cli - Audit Command
// =============================================================================
// Runs static application security testing (SAST) on a local codebase.
// Analyzes source files for common vulnerability patterns, dependency
// issues, and hardcoded secrets. Displays findings grouped by file
// with line numbers for direct developer action.
// =============================================================================

import { Command } from "commander";
import fs from "node:fs";
import path from "node:path";
import type { Finding, Severity } from "@vulnhunter/core";
import { ScanProgressDisplay } from "../ui/progress.js";
import { renderAuditTable, renderSeveritySummary } from "../ui/table.js";

/**
 * Supported language identifiers for code audit targeting.
 */
const SUPPORTED_LANGUAGES = [
  "javascript", "typescript", "python", "java", "go", "rust",
  "ruby", "php", "csharp", "solidity", "auto",
] as const;

/**
 * File extension to language mapping for auto-detection.
 */
const EXT_TO_LANGUAGE: Record<string, string> = {
  ".js": "javascript",
  ".jsx": "javascript",
  ".mjs": "javascript",
  ".cjs": "javascript",
  ".ts": "typescript",
  ".tsx": "typescript",
  ".mts": "typescript",
  ".py": "python",
  ".java": "java",
  ".go": "go",
  ".rs": "rust",
  ".rb": "ruby",
  ".php": "php",
  ".cs": "csharp",
  ".sol": "solidity",
};

/**
 * Code audit vulnerability patterns organized by category.
 * Each pattern defines what to look for and how to classify findings.
 */
interface AuditPattern {
  id: string;
  title: string;
  category: string;
  severity: Severity;
  cvss: number;
  cwe: string;
  pattern: RegExp;
  languages: string[];
  description: string;
  remediation: string;
}

const AUDIT_PATTERNS: AuditPattern[] = [
  {
    id: "sqli-string-concat",
    title: "Potential SQL Injection via string concatenation",
    category: "sqli",
    severity: "critical" as Severity,
    cvss: 9.8,
    cwe: "CWE-89",
    pattern: /(?:query|execute|exec)\s*\(\s*[`'"]\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP).*\$\{|(?:\+\s*(?:req\.|params\.|body\.|query\.))/i,
    languages: ["javascript", "typescript", "python", "java", "php", "ruby"],
    description: "SQL query constructed using string concatenation or template literals with user input, which can lead to SQL injection attacks.",
    remediation: "Use parameterized queries or prepared statements instead of string concatenation.",
  },
  {
    id: "xss-innerhtml",
    title: "Potential XSS via innerHTML/dangerouslySetInnerHTML",
    category: "xss",
    severity: "high" as Severity,
    cvss: 7.5,
    cwe: "CWE-79",
    pattern: /(?:innerHTML|outerHTML|dangerouslySetInnerHTML|document\.write)\s*[=({]/,
    languages: ["javascript", "typescript"],
    description: "Direct DOM manipulation using innerHTML or dangerouslySetInnerHTML with potentially unsanitized input.",
    remediation: "Use textContent instead of innerHTML, or properly sanitize input with a library like DOMPurify.",
  },
  {
    id: "command-injection",
    title: "Potential Command Injection via exec/spawn",
    category: "rce",
    severity: "critical" as Severity,
    cvss: 9.8,
    cwe: "CWE-78",
    pattern: /(?:child_process|exec|execSync|spawn|spawnSync|system|popen|subprocess\.call|os\.system)\s*\(/,
    languages: ["javascript", "typescript", "python", "ruby", "php"],
    description: "Use of process execution functions that may accept user-controlled input, enabling command injection.",
    remediation: "Avoid exec/system calls with user input. Use allowlists and parameterized execution instead.",
  },
  {
    id: "hardcoded-secret",
    title: "Hardcoded secret or API key detected",
    category: "information_disclosure",
    severity: "critical" as Severity,
    cvss: 9.0,
    cwe: "CWE-798",
    pattern: /(?:(?:api[_-]?key|secret[_-]?key|password|token|auth[_-]?token|private[_-]?key|access[_-]?key)\s*[:=]\s*['"][A-Za-z0-9+/=_\-]{16,}['"])/i,
    languages: ["javascript", "typescript", "python", "java", "go", "rust", "ruby", "php", "csharp", "solidity"],
    description: "Hardcoded credential or API key found in source code. This exposes sensitive authentication material.",
    remediation: "Move secrets to environment variables or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault).",
  },
  {
    id: "ssrf-user-url",
    title: "Potential SSRF via user-controlled URL",
    category: "ssrf",
    severity: "high" as Severity,
    cvss: 8.6,
    cwe: "CWE-918",
    pattern: /(?:fetch|axios|request|http\.get|urllib|requests\.get)\s*\(\s*(?:req\.|params\.|body\.|query\.|user)/i,
    languages: ["javascript", "typescript", "python", "java", "go"],
    description: "HTTP request made using a URL derived from user input without validation, potentially allowing SSRF attacks.",
    remediation: "Validate and sanitize URLs before making requests. Use allowlists for permitted domains.",
  },
  {
    id: "path-traversal",
    title: "Potential Path Traversal vulnerability",
    category: "lfi",
    severity: "high" as Severity,
    cvss: 7.5,
    cwe: "CWE-22",
    pattern: /(?:readFile|readFileSync|createReadStream|open)\s*\(\s*(?:req\.|params\.|body\.|query\.|path\.join\(.*req)/i,
    languages: ["javascript", "typescript", "python", "java", "go", "php"],
    description: "File system access using user-controlled path input without proper sanitization.",
    remediation: "Validate and canonicalize file paths. Use path.resolve() and verify the resolved path is within the expected directory.",
  },
  {
    id: "weak-crypto",
    title: "Use of weak cryptographic algorithm",
    category: "cryptographic",
    severity: "medium" as Severity,
    cvss: 5.9,
    cwe: "CWE-327",
    pattern: /(?:createHash|hashlib|MessageDigest\.getInstance)\s*\(\s*['"](?:md5|sha1|md4|rc4)['"]/i,
    languages: ["javascript", "typescript", "python", "java"],
    description: "Use of cryptographically weak hash algorithm (MD5, SHA-1) that is vulnerable to collision attacks.",
    remediation: "Use SHA-256 or SHA-3 for hashing. Use bcrypt, scrypt, or argon2 for password hashing.",
  },
  {
    id: "eval-usage",
    title: "Use of eval() with dynamic content",
    category: "rce",
    severity: "critical" as Severity,
    cvss: 9.8,
    cwe: "CWE-95",
    pattern: /\beval\s*\(\s*(?!['"])/,
    languages: ["javascript", "typescript", "python", "ruby", "php"],
    description: "Use of eval() to execute dynamically constructed code, which can lead to arbitrary code execution.",
    remediation: "Avoid eval() entirely. Use safer alternatives like JSON.parse() for data parsing.",
  },
  {
    id: "insecure-deserialization",
    title: "Potential insecure deserialization",
    category: "deserialization",
    severity: "high" as Severity,
    cvss: 8.1,
    cwe: "CWE-502",
    pattern: /(?:pickle\.loads|yaml\.load\((?!.*Loader)|unserialize|ObjectInputStream|Marshal\.load|JSON\.parse\(.*req\.body)/i,
    languages: ["python", "java", "php", "ruby", "javascript", "typescript"],
    description: "Deserialization of untrusted data that could lead to remote code execution or other attacks.",
    remediation: "Use safe deserialization methods (yaml.safe_load, json.loads). Validate and sanitize input before deserialization.",
  },
  {
    id: "open-redirect",
    title: "Potential Open Redirect vulnerability",
    category: "open_redirect",
    severity: "medium" as Severity,
    cvss: 6.1,
    cwe: "CWE-601",
    pattern: /(?:redirect|location\.href|window\.location|res\.redirect)\s*(?:\(|=)\s*(?:req\.|params\.|query\.|body\.)/i,
    languages: ["javascript", "typescript", "python", "java", "php", "ruby"],
    description: "Redirect URL derived from user input without validation, enabling phishing attacks via open redirect.",
    remediation: "Validate redirect URLs against an allowlist of permitted domains. Use relative paths when possible.",
  },
  {
    id: "cors-wildcard",
    title: "Overly permissive CORS configuration",
    category: "cors",
    severity: "medium" as Severity,
    cvss: 5.3,
    cwe: "CWE-942",
    pattern: /(?:Access-Control-Allow-Origin|allowedOrigins?|cors\()\s*(?:[:=]\s*['"]?\*['"]?|\(\s*\*\s*\))/i,
    languages: ["javascript", "typescript", "python", "java", "go", "php"],
    description: "CORS policy configured with wildcard origin (*), allowing any website to make cross-origin requests.",
    remediation: "Restrict CORS to specific trusted origins. Never use wildcard with credentials.",
  },
  {
    id: "jwt-none-alg",
    title: "JWT algorithm not enforced",
    category: "auth_bypass",
    severity: "critical" as Severity,
    cvss: 9.1,
    cwe: "CWE-347",
    pattern: /(?:jwt\.(?:verify|decode)|jsonwebtoken).*(?:algorithms\s*:\s*\[|algorithm\s*[:=])/i,
    languages: ["javascript", "typescript", "python", "java", "go"],
    description: "JWT verification without proper algorithm enforcement, potentially allowing 'none' algorithm bypass.",
    remediation: "Always specify allowed algorithms explicitly in JWT verification. Never accept the 'none' algorithm.",
  },
  {
    id: "reentrancy",
    title: "Potential reentrancy vulnerability in smart contract",
    category: "smart_contract",
    severity: "critical" as Severity,
    cvss: 9.8,
    cwe: "CWE-841",
    pattern: /\.call\{value:|\.send\(|\.transfer\(/,
    languages: ["solidity"],
    description: "External call made before state update, potentially enabling reentrancy attacks on smart contracts.",
    remediation: "Follow the checks-effects-interactions pattern. Use ReentrancyGuard from OpenZeppelin.",
  },
  {
    id: "deprecated-dependency",
    title: "Known vulnerable dependency pattern",
    category: "information_disclosure",
    severity: "medium" as Severity,
    cvss: 5.3,
    cwe: "CWE-1395",
    pattern: /(?:"lodash":\s*"[<^~]?[0-3]\.|"express":\s*"[<^~]?[0-3]\.|"axios":\s*"[<^~]?0\.[0-1])/,
    languages: ["javascript", "typescript"],
    description: "Package.json contains dependencies with known vulnerabilities based on version patterns.",
    remediation: "Update vulnerable dependencies to their latest patched versions. Run 'npm audit' for detailed analysis.",
  },
];

/**
 * Recursively discovers source files in a directory.
 */
function discoverFiles(
  dirPath: string,
  language: string,
  includePatterns: string[] = [],
): string[] {
  const files: string[] = [];

  // Directories to skip
  const skipDirs = new Set([
    "node_modules", ".git", ".svn", "dist", "build", "out",
    ".next", ".nuxt", "__pycache__", ".tox", "venv", "env",
    "vendor", "target", ".cargo", "coverage", ".nyc_output",
  ]);

  function walk(dir: string): void {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);

      if (entry.isDirectory()) {
        if (!skipDirs.has(entry.name) && !entry.name.startsWith(".")) {
          walk(fullPath);
        }
        continue;
      }

      if (!entry.isFile()) continue;

      const ext = path.extname(entry.name);
      const fileLang = EXT_TO_LANGUAGE[ext];

      // If auto-detect, include all known extensions
      // If specific language, only include matching files
      if (language === "auto") {
        if (fileLang || entry.name === "package.json" || entry.name === "requirements.txt") {
          files.push(fullPath);
        }
      } else if (fileLang === language) {
        files.push(fullPath);
      }

      // Always include dependency manifest files
      if (
        includePatterns.length > 0 ||
        ["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
         "requirements.txt", "Pipfile.lock", "Gemfile.lock", "go.sum",
         "Cargo.lock", "composer.lock"].includes(entry.name)
      ) {
        if (!files.includes(fullPath) && ["package.json", "requirements.txt"].includes(entry.name)) {
          files.push(fullPath);
        }
      }
    }
  }

  walk(dirPath);
  return files;
}

/**
 * Analyzes a single file for vulnerability patterns.
 */
function analyzeFile(
  filePath: string,
  patterns: AuditPattern[],
  language: string,
): Finding[] {
  const findings: Finding[] = [];

  let content: string;
  try {
    content = fs.readFileSync(filePath, "utf-8");
  } catch {
    return [];
  }

  const lines = content.split("\n");

  for (const pattern of patterns) {
    // Skip patterns not applicable to this language
    if (language !== "auto" && !pattern.languages.includes(language)) {
      continue;
    }

    for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
      const line = lines[lineIdx]!;

      // Skip comments (basic heuristic)
      const trimmed = line.trim();
      if (
        trimmed.startsWith("//") ||
        trimmed.startsWith("#") ||
        trimmed.startsWith("*") ||
        trimmed.startsWith("/*")
      ) {
        continue;
      }

      if (pattern.pattern.test(line)) {
        const id = crypto.randomUUID();
        findings.push({
          vulnerability: {
            id,
            title: pattern.title,
            description: pattern.description,
            severity: pattern.severity,
            category: pattern.category as any,
            cvssScore: pattern.cvss,
            cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            cweId: pattern.cwe,
            target: filePath,
            endpoint: `${filePath}:${lineIdx + 1}`,
            evidence: {
              description: `Pattern match on line ${lineIdx + 1}: ${trimmed.slice(0, 100)}`,
              matchedPattern: trimmed.slice(0, 200),
            },
            remediation: pattern.remediation,
            references: [
              `https://cwe.mitre.org/data/definitions/${pattern.cwe.replace("CWE-", "")}.html`,
            ],
            confirmed: false,
            falsePositive: false,
            discoveredAt: new Date().toISOString(),
          },
          module: `sast:${pattern.id}`,
          confidence: 65 + Math.floor(Math.random() * 25),
          timestamp: new Date().toISOString(),
          rawData: {
            lineNumber: lineIdx + 1,
            lineContent: trimmed.slice(0, 200),
            filePath,
            patternId: pattern.id,
          },
        });
      }
    }
  }

  return findings;
}

/**
 * Registers the `audit` command with Commander.
 */
export function registerAuditCommand(program: Command): void {
  program
    .command("audit <path>")
    .description("Run static analysis (SAST) on a local codebase")
    .option("-l, --language <lang>", `Language: ${SUPPORTED_LANGUAGES.join(", ")}`, "auto")
    .option("--include-deps", "Include dependency vulnerability scanning", true)
    .option("--include-secrets", "Include secret/credential scanning", true)
    .option("-o, --output <path>", "Save results to file (JSON)")
    .option(
      "-s, --severity-threshold <severity>",
      "Minimum severity to report: critical, high, medium, low, info",
      "info",
    )
    .action(async (targetPath: string, opts: Record<string, unknown>) => {
      const chalk = (await import("chalk")).default;

      const resolvedPath = path.resolve(targetPath);

      // Validate path exists
      if (!fs.existsSync(resolvedPath)) {
        console.error(chalk.red(`\n  \u2717 Error: Path does not exist: ${resolvedPath}\n`));
        process.exit(1);
      }

      const isDir = fs.statSync(resolvedPath).isDirectory();
      const language = opts.language as string;

      console.log();
      console.log(chalk.cyan.bold("  VulnHunter AI - Code Audit (SAST)"));
      console.log(chalk.gray("  " + "\u2500".repeat(50)));
      console.log(chalk.white(`  Target:    ${chalk.cyan.bold(resolvedPath)}`));
      console.log(chalk.white(`  Language:  ${chalk.yellow(language)}`));
      console.log(chalk.white(`  Threshold: ${chalk.yellow(String(opts.severityThreshold))}`));
      console.log(chalk.white(`  Secrets:   ${opts.includeSecrets !== false ? chalk.green("enabled") : chalk.red("disabled")}`));
      console.log(chalk.white(`  Deps:      ${opts.includeDeps !== false ? chalk.green("enabled") : chalk.red("disabled")}`));
      console.log(chalk.gray("  " + "\u2500".repeat(50)));
      console.log();

      const progress = new ScanProgressDisplay();
      await progress.start("Discovering source files...");

      try {
        // Discover files
        const files = isDir
          ? discoverFiles(resolvedPath, language)
          : [resolvedPath];

        await progress.update({
          phase: "discovery",
          module: "file_discovery",
          progressPercent: 10,
          message: `Found ${files.length} source files to analyze`,
          findingsCount: 0,
          endpointsTested: 0,
          requestsSent: 0,
        });

        if (files.length === 0) {
          await progress.complete("No source files found to analyze.");
          console.log(
            chalk.yellow("\n  No source files found matching the specified language.\n"),
          );
          return;
        }

        // Filter patterns based on options
        let patterns = [...AUDIT_PATTERNS];
        if (opts.includeSecrets === false) {
          patterns = patterns.filter((p) => p.id !== "hardcoded-secret");
        }
        if (opts.includeDeps === false) {
          patterns = patterns.filter((p) => p.id !== "deprecated-dependency");
        }

        // Analyze files
        const allFindings: Finding[] = [];
        const severityOrder: Record<string, number> = {
          critical: 0,
          high: 1,
          medium: 2,
          low: 3,
          info: 4,
        };
        const threshold = severityOrder[opts.severityThreshold as string] ?? 4;

        for (let i = 0; i < files.length; i++) {
          const file = files[i]!;
          const relativePath = path.relative(resolvedPath, file);
          const ext = path.extname(file);
          const fileLang = language === "auto" ? (EXT_TO_LANGUAGE[ext] || "auto") : language;

          await progress.update({
            phase: "analysis",
            module: `sast:${fileLang}`,
            progressPercent: 10 + Math.round((i / files.length) * 80),
            message: `Analyzing ${relativePath || path.basename(file)}`,
            findingsCount: allFindings.length,
            endpointsTested: i + 1,
            requestsSent: 0,
          });

          const fileFindings = analyzeFile(file, patterns, fileLang);

          // Filter by severity threshold
          for (const f of fileFindings) {
            const sev = severityOrder[f.vulnerability.severity] ?? 4;
            if (sev <= threshold) {
              allFindings.push(f);
            }
          }

          // Small delay to make progress visible
          if (i % 10 === 0) {
            await new Promise((resolve) => setTimeout(resolve, 50));
          }
        }

        await progress.complete(
          `Analysis complete: ${files.length} files scanned, ${allFindings.length} findings`,
        );

        // Display results
        console.log();
        console.log(chalk.cyan.bold("  Audit Results"));
        console.log(chalk.gray("  " + "\u2500".repeat(50)));
        console.log(chalk.white(`  Files Scanned: ${chalk.green(String(files.length))}`));
        console.log(chalk.white(`  Total Findings: ${chalk.yellow(String(allFindings.length))}`));
        console.log();

        if (allFindings.length > 0) {
          // Severity summary
          await renderSeveritySummary(allFindings);

          // Detailed findings grouped by file
          console.log(chalk.cyan.bold("\n  Findings by File"));
          await renderAuditTable(allFindings);
        } else {
          console.log(chalk.green.bold("  \u2713 No vulnerabilities found above the severity threshold.\n"));
        }

        // Save output if requested
        if (opts.output) {
          const outputPath = path.resolve(opts.output as string);
          const dir = path.dirname(outputPath);
          if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
          }

          const report = {
            target: resolvedPath,
            language,
            filesScanned: files.length,
            totalFindings: allFindings.length,
            severityThreshold: opts.severityThreshold,
            findings: allFindings,
            scannedAt: new Date().toISOString(),
          };

          fs.writeFileSync(outputPath, JSON.stringify(report, null, 2), "utf-8");
          console.log(chalk.green(`  \u2713 Results saved to ${outputPath}\n`));
        }

        // Summary with exit code hint
        const critCount = allFindings.filter((f) => f.vulnerability.severity === "critical").length;
        const highCount = allFindings.filter((f) => f.vulnerability.severity === "high").length;

        if (critCount > 0) {
          console.log(
            chalk.bgRed.white.bold(`  \u26A0  ${critCount} CRITICAL finding(s) require immediate attention!  `),
          );
        }
        if (highCount > 0) {
          console.log(chalk.red.bold(`  \u26A0  ${highCount} HIGH severity finding(s) detected.`));
        }
        console.log();
      } catch (err: any) {
        await progress.error(err.message || "Audit failed");
        process.exit(1);
      }
    });
}
