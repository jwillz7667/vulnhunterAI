// =============================================================================
// @vulnhunter/scanner - SAST (Static Application Security Testing) Engine
// =============================================================================
// Performs file-by-file static analysis on source code directories using
// regex-based vulnerability pattern matching. Supports JavaScript/TypeScript,
// Python, Go, Java, and PHP. Reports findings with exact file paths, line
// numbers, and CWE mappings.
// =============================================================================

import { readdir, readFile, stat } from "node:fs/promises";
import { join, extname, relative } from "node:path";
import type { Finding, Vulnerability } from "@vulnhunter/core";
import {
  Severity,
  VulnerabilityCategory,
} from "@vulnhunter/core";
import { generateUUID, createLogger } from "@vulnhunter/core";
import type { ScanModule } from "../engine.js";
import {
  type VulnerabilityPattern,
  patternsByLanguage,
  extensionToLanguage,
} from "./patterns/index.js";

const log = createLogger("sast-engine");

// ---------------------------------------------------------------------------
// Category Mapping
// ---------------------------------------------------------------------------

/**
 * Maps pattern category strings to the VulnerabilityCategory enum.
 * Patterns use short category names; the Finding type needs the enum value.
 */
const CATEGORY_MAP: Record<string, VulnerabilityCategory> = {
  rce: VulnerabilityCategory.RCE,
  xss: VulnerabilityCategory.XSS,
  sqli: VulnerabilityCategory.SQLi,
  ssrf: VulnerabilityCategory.SSRF,
  lfi: VulnerabilityCategory.LFI,
  xxe: VulnerabilityCategory.XXE,
  deserialization: VulnerabilityCategory.Deserialization,
  cryptographic: VulnerabilityCategory.Cryptographic,
  information_disclosure: VulnerabilityCategory.InformationDisclosure,
  cors: VulnerabilityCategory.CORS,
  header_misconfig: VulnerabilityCategory.HeaderMisconfig,
  auth_bypass: VulnerabilityCategory.AuthBypass,
  open_redirect: VulnerabilityCategory.OpenRedirect,
  api_vuln: VulnerabilityCategory.APIVuln,
  business_logic: VulnerabilityCategory.BusinessLogic,
};

/**
 * Maps severity strings from patterns to the Severity enum.
 */
const SEVERITY_MAP: Record<string, Severity> = {
  critical: Severity.Critical,
  high: Severity.High,
  medium: Severity.Medium,
  low: Severity.Low,
  info: Severity.Info,
};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/** Maximum file size in bytes to analyze (skip huge files to avoid OOM) */
const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5 MB

/** Directories to always skip during recursive traversal */
const SKIP_DIRS = new Set([
  "node_modules",
  ".git",
  ".svn",
  ".hg",
  "dist",
  "build",
  "out",
  ".next",
  "__pycache__",
  ".venv",
  "venv",
  "vendor",
  "target",
  ".idea",
  ".vscode",
  "coverage",
  ".nyc_output",
  ".pytest_cache",
  ".tox",
  ".eggs",
]);

/** Binary / non-text extensions to skip */
const SKIP_EXTENSIONS = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
  ".woff", ".woff2", ".ttf", ".eot", ".otf",
  ".mp3", ".mp4", ".avi", ".mov", ".mkv", ".webm",
  ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
  ".exe", ".dll", ".so", ".dylib", ".bin",
  ".pdf", ".doc", ".docx", ".xls", ".xlsx",
  ".wasm", ".map", ".lock",
]);

// ---------------------------------------------------------------------------
// SASTEngine
// ---------------------------------------------------------------------------

export class SASTEngine implements ScanModule {
  readonly name = "code:sast";

  /**
   * Execute SAST analysis on the given directory.
   *
   * @param target - Absolute path to the source code directory to scan
   * @param options - Scanner options (maxDepth, specific languages, etc.)
   * @yields Finding objects as vulnerabilities are discovered
   */
  async *execute(
    target: string,
    options: Record<string, unknown>,
  ): AsyncGenerator<Finding> {
    log.info({ target }, "Starting SAST analysis");

    const maxDepth = (options.maxDepth as number) ?? 20;
    const languages = options.languages as string[] | undefined;

    let filesScanned = 0;
    let findingsCount = 0;

    for await (const filePath of this.walkDirectory(target, maxDepth, 0)) {
      const ext = extname(filePath).toLowerCase();

      // Skip binary and non-text files
      if (SKIP_EXTENSIONS.has(ext)) continue;

      // Determine language from extension
      const language = extensionToLanguage[ext];
      if (!language) continue;

      // If user specified languages to scan, filter accordingly
      if (languages && languages.length > 0) {
        if (!languages.includes(language)) continue;
      }

      // Get patterns for this language
      const patterns = patternsByLanguage[language];
      if (!patterns || patterns.length === 0) continue;

      // Read file content
      let content: string;
      try {
        const fileStat = await stat(filePath);
        if (fileStat.size > MAX_FILE_SIZE) {
          log.debug({ filePath, size: fileStat.size }, "Skipping large file");
          continue;
        }
        content = await readFile(filePath, "utf-8");
      } catch (err) {
        log.warn(
          { filePath, error: err instanceof Error ? err.message : String(err) },
          "Failed to read file, skipping",
        );
        continue;
      }

      filesScanned++;

      // Split content into lines for line-number reporting
      const lines = content.split("\n");

      // Run each pattern against the file
      for (const pattern of patterns) {
        const matches = this.findPatternMatches(content, lines, pattern);

        for (const match of matches) {
          findingsCount++;

          const vulnerability: Vulnerability = {
            id: generateUUID(),
            title: `${pattern.name} in ${relative(target, filePath)}`,
            description: pattern.description,
            severity: SEVERITY_MAP[pattern.severity] ?? Severity.Medium,
            category: CATEGORY_MAP[pattern.category] ?? VulnerabilityCategory.RCE,
            cvssScore: pattern.cvssScore,
            cweId: pattern.cweId,
            target,
            endpoint: filePath,
            evidence: {
              description: `Pattern "${pattern.name}" matched at line ${match.line}`,
              matchedPattern: match.matchedText,
              extra: {
                filePath,
                lineNumber: match.line,
                column: match.column,
                lineContent: match.lineContent.trim(),
                patternId: pattern.id,
                language,
              },
            },
            remediation: pattern.remediation,
            references: [
              `https://cwe.mitre.org/data/definitions/${pattern.cweId.replace("CWE-", "")}.html`,
            ],
            confirmed: false,
            falsePositive: false,
            discoveredAt: new Date().toISOString(),
          };

          const finding: Finding = {
            vulnerability,
            module: this.name,
            confidence: this.calculateConfidence(pattern, match),
            timestamp: new Date().toISOString(),
            rawData: {
              patternId: pattern.id,
              filePath,
              lineNumber: match.line,
              column: match.column,
              matchedText: match.matchedText,
              language,
            },
          };

          yield finding;
        }
      }
    }

    log.info(
      { target, filesScanned, findingsCount },
      "SAST analysis complete",
    );
  }

  // -------------------------------------------------------------------------
  // Private: Directory Walker
  // -------------------------------------------------------------------------

  /**
   * Recursively walks a directory tree, yielding file paths.
   * Respects SKIP_DIRS and maxDepth limits.
   */
  private async *walkDirectory(
    dir: string,
    maxDepth: number,
    currentDepth: number,
  ): AsyncGenerator<string> {
    if (currentDepth > maxDepth) return;

    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch (err) {
      log.warn(
        { dir, error: err instanceof Error ? err.message : String(err) },
        "Cannot read directory, skipping",
      );
      return;
    }

    for (const entry of entries) {
      const fullPath = join(dir, entry.name);

      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        if (entry.name.startsWith(".")) continue;
        yield* this.walkDirectory(fullPath, maxDepth, currentDepth + 1);
      } else if (entry.isFile()) {
        yield fullPath;
      }
    }
  }

  // -------------------------------------------------------------------------
  // Private: Pattern Matching
  // -------------------------------------------------------------------------

  /**
   * Represents a single match of a vulnerability pattern in source code.
   */
  private findPatternMatches(
    content: string,
    lines: string[],
    pattern: VulnerabilityPattern,
  ): PatternMatch[] {
    const matches: PatternMatch[] = [];
    // Clone the regex to reset lastIndex for global patterns
    const regex = new RegExp(pattern.pattern.source, pattern.pattern.flags);

    let match: RegExpExecArray | null;
    while ((match = regex.exec(content)) !== null) {
      // Calculate line number from character offset
      const offset = match.index;
      const lineNumber = this.offsetToLine(content, offset);
      const lineContent = lines[lineNumber - 1] ?? "";
      const lineStart = content.lastIndexOf("\n", offset) + 1;
      const column = offset - lineStart + 1;

      matches.push({
        line: lineNumber,
        column,
        matchedText: match[0],
        lineContent,
      });

      // Safety valve: prevent infinite loops on zero-length matches
      if (match[0].length === 0) {
        regex.lastIndex++;
      }
    }

    return matches;
  }

  /**
   * Convert a character offset in a string to a 1-based line number.
   */
  private offsetToLine(content: string, offset: number): number {
    let line = 1;
    for (let i = 0; i < offset && i < content.length; i++) {
      if (content[i] === "\n") line++;
    }
    return line;
  }

  // -------------------------------------------------------------------------
  // Private: Confidence Scoring
  // -------------------------------------------------------------------------

  /**
   * Calculate a confidence score for a pattern match.
   * Higher severity patterns get a base confidence boost. Matches in
   * comments or strings get penalized.
   */
  private calculateConfidence(
    pattern: VulnerabilityPattern,
    match: PatternMatch,
  ): number {
    let confidence = 60; // Base confidence for regex pattern matching

    // Severity-based adjustment
    switch (pattern.severity) {
      case "critical":
        confidence += 15;
        break;
      case "high":
        confidence += 10;
        break;
      case "medium":
        confidence += 5;
        break;
    }

    // Penalize if the match appears to be inside a comment
    const trimmedLine = match.lineContent.trim();
    if (
      trimmedLine.startsWith("//") ||
      trimmedLine.startsWith("#") ||
      trimmedLine.startsWith("*") ||
      trimmedLine.startsWith("/*")
    ) {
      confidence -= 30;
    }

    // Penalize if the match appears to be in a string (test/example context)
    if (
      match.lineContent.includes("test") ||
      match.lineContent.includes("spec") ||
      match.lineContent.includes("mock") ||
      match.lineContent.includes("example")
    ) {
      confidence -= 15;
    }

    // Clamp to [5, 95] range (never fully 0 or 100 for regex-based detection)
    return Math.max(5, Math.min(95, confidence));
  }
}

// ---------------------------------------------------------------------------
// Internal Types
// ---------------------------------------------------------------------------

interface PatternMatch {
  /** 1-based line number */
  line: number;
  /** 1-based column number */
  column: number;
  /** The exact text that matched the regex */
  matchedText: string;
  /** Full content of the line where the match was found */
  lineContent: string;
}
