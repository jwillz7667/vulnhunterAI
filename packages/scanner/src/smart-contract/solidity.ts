// =============================================================================
// @vulnhunter/scanner - Solidity Smart Contract Analyzer
// =============================================================================
// Static analysis scanner for Solidity smart contracts. Detects common
// vulnerability patterns including reentrancy, integer overflow/underflow,
// access control issues, unchecked external calls, tx.origin usage,
// delegatecall risks, weak randomness, and more.
//
// Operates via pattern matching against the source code, with optional
// validation callbacks for reducing false positives.
// =============================================================================

import type { Finding, Vulnerability } from "@vulnhunter/core";
import { Severity, VulnerabilityCategory } from "@vulnhunter/core";
import { generateUUID, createLogger } from "@vulnhunter/core";
import type { ScanModule } from "../engine.js";
import {
  PATTERN_DATABASE,
  type SolidityVulnerabilityPattern,
} from "./patterns.js";

const log = createLogger("solidity-analyzer");

// ---------------------------------------------------------------------------
// Source Fetching Timeout
// ---------------------------------------------------------------------------

const REQUEST_TIMEOUT_MS = 15_000;

// ---------------------------------------------------------------------------
// Contract Metadata Extracted from Source
// ---------------------------------------------------------------------------

interface ContractMeta {
  /** Solidity compiler version pragma. */
  compilerVersion: string | null;
  /** Contract names declared in the source. */
  contractNames: string[];
  /** Import paths found in the source. */
  imports: string[];
  /** Number of lines of code (excluding blank lines and comments). */
  locCount: number;
  /** Whether the contract appears to be upgradeable (proxy pattern). */
  isUpgradeable: boolean;
  /** Whether the contract uses OpenZeppelin libraries. */
  usesOpenZeppelin: boolean;
}

// ---------------------------------------------------------------------------
// SolidityAnalyzer
// ---------------------------------------------------------------------------

export class SolidityAnalyzer implements ScanModule {
  readonly name = "smart-contract:solidity";

  async *execute(
    target: string,
    options: Record<string, unknown>,
  ): AsyncGenerator<Finding> {
    log.info({ target }, "Starting Solidity smart contract analysis");

    // Determine how to obtain the source code
    const source = await this.obtainSource(target, options);

    if (!source || source.trim().length === 0) {
      log.warn({ target }, "No Solidity source code to analyze");
      return;
    }

    log.info(
      { target, sourceLength: source.length },
      "Source code obtained, beginning analysis",
    );

    // Extract metadata for context-aware analysis
    const meta = this.extractMetadata(source);
    log.info(
      {
        compilerVersion: meta.compilerVersion,
        contracts: meta.contractNames,
        loc: meta.locCount,
        isUpgradeable: meta.isUpgradeable,
      },
      "Contract metadata extracted",
    );

    // 1. Pattern-Based Vulnerability Detection
    yield* this.runPatternAnalysis(target, source, meta, options);

    // 2. Structural Analysis (deeper checks beyond regex)
    yield* this.runStructuralAnalysis(target, source, meta);

    // 3. Compiler Version Analysis
    yield* this.checkCompilerVersion(target, meta);

    // 4. License and Pragma Checks
    yield* this.checkPragmaIssues(target, source, meta);

    log.info({ target }, "Solidity analysis complete");
  }

  // -------------------------------------------------------------------------
  // Source Code Acquisition
  // -------------------------------------------------------------------------

  /**
   * Obtains Solidity source code from various inputs:
   * - If `options.source` is provided, use it directly
   * - If `options.filePath` is provided, read from disk (via fs)
   * - If `target` is an HTTP URL, fetch the source
   * - If `target` is an Ethereum address, attempt to fetch verified source
   *   from Etherscan (if `options.etherscanApiKey` is provided)
   */
  private async obtainSource(
    target: string,
    options: Record<string, unknown>,
  ): Promise<string | null> {
    // Option 1: Source provided directly
    if (typeof options.source === "string" && options.source.length > 0) {
      return options.source;
    }

    // Option 2: File path provided
    if (typeof options.filePath === "string") {
      try {
        const { readFile } = await import("node:fs/promises");
        return await readFile(options.filePath, "utf-8");
      } catch (err) {
        log.error({ filePath: options.filePath, error: String(err) }, "Failed to read source file");
        return null;
      }
    }

    // Option 3: Target is an HTTP(S) URL pointing to a .sol file
    if (target.startsWith("http://") || target.startsWith("https://")) {
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

        const response = await fetch(target, {
          signal: controller.signal,
          redirect: "follow",
        });

        clearTimeout(timeout);

        if (response.ok) {
          const text = await response.text();
          // Verify it looks like Solidity
          if (text.includes("pragma solidity") || text.includes("contract ") || text.includes("interface ")) {
            return text;
          }
        }
      } catch {
        log.warn({ target }, "Failed to fetch source from URL");
      }
    }

    // Option 4: Target is an Ethereum address -- fetch from Etherscan
    if (/^0x[0-9a-fA-F]{40}$/.test(target) && typeof options.etherscanApiKey === "string") {
      return this.fetchFromEtherscan(target, options.etherscanApiKey, options);
    }

    return null;
  }

  /**
   * Fetches verified source code from Etherscan-like block explorers.
   */
  private async fetchFromEtherscan(
    address: string,
    apiKey: string,
    options: Record<string, unknown>,
  ): Promise<string | null> {
    const baseUrl = (options.etherscanBaseUrl as string) ?? "https://api.etherscan.io/api";

    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

      const url = `${baseUrl}?module=contract&action=getsourcecode&address=${address}&apikey=${apiKey}`;
      const response = await fetch(url, {
        signal: controller.signal,
      });

      clearTimeout(timeout);

      if (!response.ok) return null;

      const data = (await response.json()) as {
        status: string;
        result: Array<{ SourceCode: string; ContractName: string }>;
      };

      if (data.status === "1" && data.result?.[0]?.SourceCode) {
        let sourceCode = data.result[0].SourceCode;

        // Handle multi-file source (wrapped in {{ }})
        if (sourceCode.startsWith("{{")) {
          try {
            const parsed = JSON.parse(sourceCode.slice(1, -1)) as {
              sources: Record<string, { content: string }>;
            };
            sourceCode = Object.values(parsed.sources)
              .map((s) => s.content)
              .join("\n\n");
          } catch {
            // If parsing fails, use as-is
          }
        }

        return sourceCode;
      }
    } catch (err) {
      log.error({ address, error: String(err) }, "Failed to fetch from Etherscan");
    }

    return null;
  }

  // -------------------------------------------------------------------------
  // Metadata Extraction
  // -------------------------------------------------------------------------

  private extractMetadata(source: string): ContractMeta {
    // Compiler version
    const versionMatch = source.match(/pragma\s+solidity\s+([^;]+)/);
    const compilerVersion = versionMatch ? versionMatch[1].trim() : null;

    // Contract names
    const contractRegex = /(?:contract|library|interface)\s+(\w+)/g;
    const contractNames: string[] = [];
    let contractMatch: RegExpExecArray | null;
    while ((contractMatch = contractRegex.exec(source)) !== null) {
      contractNames.push(contractMatch[1]);
    }

    // Imports
    const importRegex = /import\s+(?:{[^}]+}\s+from\s+)?["']([^"']+)["']/g;
    const imports: string[] = [];
    let importMatch: RegExpExecArray | null;
    while ((importMatch = importRegex.exec(source)) !== null) {
      imports.push(importMatch[1]);
    }

    // Lines of code (non-blank, non-comment)
    const lines = source.split("\n");
    let locCount = 0;
    let inBlockComment = false;
    for (const line of lines) {
      const trimmed = line.trim();
      if (inBlockComment) {
        if (trimmed.includes("*/")) inBlockComment = false;
        continue;
      }
      if (trimmed.startsWith("/*")) {
        inBlockComment = !trimmed.includes("*/");
        continue;
      }
      if (trimmed.startsWith("//") || trimmed.length === 0) continue;
      locCount++;
    }

    // Upgradeable detection
    const isUpgradeable =
      imports.some((i) => i.includes("upgradeable") || i.includes("proxy") || i.includes("UUPSUpgradeable")) ||
      source.includes("delegatecall") ||
      source.includes("initializer") ||
      source.includes("Initializable");

    // OpenZeppelin usage
    const usesOpenZeppelin = imports.some((i) => i.includes("@openzeppelin"));

    return {
      compilerVersion,
      contractNames,
      imports,
      locCount,
      isUpgradeable,
      usesOpenZeppelin,
    };
  }

  // -------------------------------------------------------------------------
  // Pattern-Based Analysis
  // -------------------------------------------------------------------------

  private async *runPatternAnalysis(
    target: string,
    source: string,
    meta: ContractMeta,
    options: Record<string, unknown>,
  ): AsyncGenerator<Finding> {
    const minSeverity = (options.minSeverity as Severity) ?? Severity.Info;
    const severityWeight: Record<Severity, number> = {
      [Severity.Critical]: 5,
      [Severity.High]: 4,
      [Severity.Medium]: 3,
      [Severity.Low]: 2,
      [Severity.Info]: 1,
    };
    const minWeight = severityWeight[minSeverity];

    let matchCount = 0;

    for (const pattern of PATTERN_DATABASE) {
      // Skip patterns below minimum severity
      if (severityWeight[pattern.severity] < minWeight) continue;

      // Execute the regex
      const match = source.match(pattern.pattern);
      if (!match) continue;

      // Run optional validator to reduce false positives
      if (pattern.validate && !pattern.validate(source, match)) {
        log.debug(
          { patternId: pattern.id },
          "Pattern matched but failed validation, skipping",
        );
        continue;
      }

      matchCount++;

      // Find line number of the match
      const matchIndex = match.index ?? 0;
      const lineNumber = source.slice(0, matchIndex).split("\n").length;

      // Extract a code snippet around the match
      const lines = source.split("\n");
      const startLine = Math.max(0, lineNumber - 3);
      const endLine = Math.min(lines.length, lineNumber + 4);
      const codeSnippet = lines.slice(startLine, endLine).join("\n");

      yield this.createFinding(
        pattern.name,
        `${pattern.description}\n\nFound at line ${lineNumber} in ${meta.contractNames.join(", ") || "contract"}.`,
        pattern.severity,
        target,
        `${target}:L${lineNumber}`,
        pattern.cweId,
        pattern.cvssScore,
        pattern.confidence,
        {
          patternId: pattern.id,
          category: pattern.category,
          lineNumber,
          matchedCode: match[0].slice(0, 200),
          codeSnippet: codeSnippet.slice(0, 500),
          contractNames: meta.contractNames,
          compilerVersion: meta.compilerVersion,
        },
        pattern.remediation,
        pattern.references,
      );
    }

    log.info({ matchCount }, "Pattern analysis complete");
  }

  // -------------------------------------------------------------------------
  // Structural Analysis
  // -------------------------------------------------------------------------

  private async *runStructuralAnalysis(
    target: string,
    source: string,
    meta: ContractMeta,
  ): AsyncGenerator<Finding> {
    // Check for missing events on state changes
    yield* this.checkMissingEvents(target, source, meta);

    // Check for floating pragma
    yield* this.checkFloatingPragma(target, source, meta);

    // Check for multiple contracts in one file
    if (meta.contractNames.length > 3) {
      yield this.createFinding(
        "Multiple Contracts in Single Source File",
        `The source file contains ${meta.contractNames.length} contract/library/interface declarations: ${meta.contractNames.join(", ")}. While not a direct vulnerability, this increases complexity and the risk of storage collisions in upgradeable patterns.`,
        Severity.Info,
        target,
        target,
        "CWE-710",
        0.0,
        40,
        { contractCount: meta.contractNames.length, contractNames: meta.contractNames },
        "Split contracts into separate files, one contract per file. Use imports to reference dependencies.",
        [],
      );
    }

    // Check for unsafe ERC20 interactions
    yield* this.checkUnsafeErc20(target, source, meta);
  }

  /**
   * Detects state-changing functions that don't emit events.
   */
  private async *checkMissingEvents(
    target: string,
    source: string,
    meta: ContractMeta,
  ): AsyncGenerator<Finding> {
    // Find public/external state-changing functions
    const funcRegex = /function\s+(\w+)\s*\([^)]*\)\s*(?:public|external)(?!\s+view)(?!\s+pure)[^{]*\{/gm;
    let funcMatch: RegExpExecArray | null;
    const functionsWithoutEvents: string[] = [];

    while ((funcMatch = funcRegex.exec(source)) !== null) {
      const funcName = funcMatch[1];
      const funcStart = funcMatch.index;

      // Find the function body (rough approximation -- count braces)
      let braceCount = 1;
      let pos = funcStart + funcMatch[0].length;
      while (pos < source.length && braceCount > 0) {
        if (source[pos] === "{") braceCount++;
        if (source[pos] === "}") braceCount--;
        pos++;
      }

      const funcBody = source.slice(funcStart, pos);

      // Check if the function body emits an event
      if (!funcBody.includes("emit ") && funcBody.includes("=") && funcName !== "constructor") {
        functionsWithoutEvents.push(funcName);
      }
    }

    if (functionsWithoutEvents.length > 0) {
      yield this.createFinding(
        "State-Changing Functions Without Events",
        `${functionsWithoutEvents.length} public/external state-changing function(s) do not emit events: ${functionsWithoutEvents.slice(0, 10).join(", ")}. Events are essential for off-chain monitoring, indexing, and audit trails.`,
        Severity.Low,
        target,
        target,
        "CWE-778",
        3.7,
        55,
        { functionsWithoutEvents },
        "Add events for all state-changing operations. Emit events with indexed parameters for key values. This enables off-chain monitoring and incident response.",
        [],
      );
    }
  }

  /**
   * Detects floating (non-locked) pragma.
   */
  private async *checkFloatingPragma(
    target: string,
    source: string,
    _meta: ContractMeta,
  ): AsyncGenerator<Finding> {
    const pragmaMatch = source.match(/pragma\s+solidity\s+(\^|>=?\s*)\d+\.\d+\.\d+/);
    if (pragmaMatch && (pragmaMatch[1] === "^" || pragmaMatch[1].startsWith(">="))) {
      yield this.createFinding(
        "Floating Compiler Pragma",
        `The contract uses a floating pragma (${pragmaMatch[0]}). This means different developers or deployment environments may compile with different Solidity versions, potentially introducing compiler-specific bugs or behavior differences.`,
        Severity.Low,
        target,
        target,
        "CWE-710",
        3.7,
        80,
        { pragma: pragmaMatch[0] },
        "Lock the pragma to a specific compiler version, e.g., 'pragma solidity 0.8.20;'. Use the latest stable compiler version for new contracts.",
        ["https://swcregistry.io/docs/SWC-103"],
      );
    }
  }

  /**
   * Checks for unsafe ERC20 interactions (approve frontrunning, missing return check).
   */
  private async *checkUnsafeErc20(
    target: string,
    source: string,
    _meta: ContractMeta,
  ): AsyncGenerator<Finding> {
    // Check for approve() without setting to 0 first
    if (source.includes(".approve(") && !source.includes("safeApprove") && !source.includes("forceApprove")) {
      const approveMatch = source.match(/\.approve\s*\([^,]+,\s*[^)]+\)/);
      if (approveMatch) {
        yield this.createFinding(
          "ERC20 Approve Race Condition",
          "The contract calls .approve() directly without first setting the allowance to 0. This is vulnerable to the ERC20 approve frontrunning attack where a spender can spend both the old and new allowance.",
          Severity.Medium,
          target,
          target,
          "CWE-362",
          5.3,
          65,
          { matchedCode: approveMatch[0].slice(0, 200) },
          "Use OpenZeppelin's SafeERC20.forceApprove() or first set allowance to 0 then to the new value. Better yet, use increaseAllowance/decreaseAllowance if the token supports them.",
          ["https://swcregistry.io/docs/SWC-114"],
        );
      }
    }

    // Check for unchecked ERC20 transfer return values
    const unsafeTransferPattern = /IERC20\([^)]*\)\.transfer\s*\([^)]*\)\s*;|\.transfer\s*\([^)]*\)\s*;/m;
    if (unsafeTransferPattern.test(source) && !source.includes("safeTransfer")) {
      yield this.createFinding(
        "Unchecked ERC20 Transfer Return Value",
        "The contract calls .transfer() or .transferFrom() on an ERC20 token without checking the return value. Some tokens (e.g., USDT) do not revert on failure but return false. Unchecked transfers can silently fail, leading to accounting discrepancies.",
        Severity.High,
        target,
        target,
        "CWE-252",
        7.5,
        60,
        {},
        "Use OpenZeppelin's SafeERC20 library (safeTransfer, safeTransferFrom) which handles both reverting and non-reverting tokens.",
        ["https://github.com/d-xo/weird-erc20"],
      );
    }
  }

  // -------------------------------------------------------------------------
  // Compiler Version Analysis
  // -------------------------------------------------------------------------

  private async *checkCompilerVersion(
    target: string,
    meta: ContractMeta,
  ): AsyncGenerator<Finding> {
    if (!meta.compilerVersion) return;

    // Extract the primary version number
    const versionMatch = meta.compilerVersion.match(/(\d+)\.(\d+)\.(\d+)/);
    if (!versionMatch) return;

    const major = parseInt(versionMatch[1], 10);
    const minor = parseInt(versionMatch[2], 10);
    const patch = parseInt(versionMatch[3], 10);

    // Very old versions (< 0.5.0)
    if (major === 0 && minor < 5) {
      yield this.createFinding(
        "Severely Outdated Solidity Compiler",
        `The contract targets Solidity ${meta.compilerVersion}, which is severely outdated. Versions before 0.5.0 lack many safety features: no explicit visibility requirements, no strict calldata encoding, and support for deprecated constructs (var, throw, years).`,
        Severity.High,
        target,
        target,
        "CWE-1104",
        7.5,
        90,
        { compilerVersion: meta.compilerVersion, major, minor, patch },
        "Upgrade to Solidity >=0.8.0 for built-in overflow/underflow protection. If maintaining legacy code, migrate incrementally through 0.5.0, 0.6.0, 0.7.0 breaking changes.",
        ["https://docs.soliditylang.org/en/latest/080-breaking-changes.html"],
      );
    }
    // Old versions (0.5.x - 0.7.x)
    else if (major === 0 && minor < 8) {
      yield this.createFinding(
        "Outdated Solidity Compiler (Pre-0.8.0)",
        `The contract targets Solidity ${meta.compilerVersion}. Versions before 0.8.0 do not have built-in integer overflow/underflow protection, requiring manual use of SafeMath.`,
        Severity.Medium,
        target,
        target,
        "CWE-1104",
        5.3,
        85,
        { compilerVersion: meta.compilerVersion, major, minor, patch },
        "Upgrade to Solidity >=0.8.0. If upgrading is not possible, ensure SafeMath is used for all arithmetic operations.",
        ["https://docs.soliditylang.org/en/latest/080-breaking-changes.html"],
      );
    }
    // 0.8.x but old patch with known bugs
    else if (major === 0 && minor === 8 && patch < 13) {
      yield this.createFinding(
        "Solidity Compiler With Known Bugs",
        `The contract targets Solidity ${meta.compilerVersion}. Versions 0.8.0 to 0.8.12 have known compiler bugs including ABI encoding issues, optimizer bugs, and storage layout issues.`,
        Severity.Low,
        target,
        target,
        "CWE-1104",
        3.7,
        70,
        { compilerVersion: meta.compilerVersion, major, minor, patch },
        "Upgrade to Solidity >=0.8.20 for the latest bug fixes and features. Check the Solidity changelog for specific bugs affecting your version.",
        ["https://docs.soliditylang.org/en/latest/bugs.html"],
      );
    }
  }

  // -------------------------------------------------------------------------
  // Pragma Issues
  // -------------------------------------------------------------------------

  private async *checkPragmaIssues(
    target: string,
    source: string,
    _meta: ContractMeta,
  ): AsyncGenerator<Finding> {
    // Check for missing SPDX license identifier
    if (!source.includes("SPDX-License-Identifier")) {
      yield this.createFinding(
        "Missing SPDX License Identifier",
        "The source file does not include an SPDX license identifier comment (// SPDX-License-Identifier: MIT). While not a security issue, this is required by Solidity >=0.6.8 and its absence generates a compiler warning.",
        Severity.Info,
        target,
        target,
        "CWE-710",
        0.0,
        90,
        {},
        "Add an SPDX license identifier as the first line: // SPDX-License-Identifier: MIT (or your chosen license).",
        [],
      );
    }

    // Check for ABIEncoderV2 pragma (no longer needed in >=0.8.0)
    if (source.includes("pragma experimental ABIEncoderV2") || source.includes("pragma abicoder v2")) {
      yield this.createFinding(
        "Unnecessary ABIEncoderV2 Pragma",
        "The contract uses 'pragma experimental ABIEncoderV2' or 'pragma abicoder v2'. In Solidity >=0.8.0, ABIEncoderV2 is enabled by default. The experimental pragma is unnecessary and can be removed.",
        Severity.Info,
        target,
        target,
        "CWE-710",
        0.0,
        85,
        {},
        "Remove the ABIEncoderV2 pragma if targeting Solidity >=0.8.0.",
        [],
      );
    }
  }

  // -------------------------------------------------------------------------
  // Utility
  // -------------------------------------------------------------------------

  private createFinding(
    title: string,
    description: string,
    severity: Severity,
    target: string,
    endpoint: string,
    cweId: string,
    cvssScore: number,
    confidence: number,
    extra: Record<string, unknown>,
    remediation: string,
    references: string[] = [],
  ): Finding {
    const vulnerability: Vulnerability = {
      id: generateUUID(),
      title,
      description,
      severity,
      category: VulnerabilityCategory.SmartContract,
      cvssScore,
      cweId,
      target,
      endpoint,
      evidence: { description: title, extra },
      remediation,
      references: [
        `https://cwe.mitre.org/data/definitions/${cweId.replace("CWE-", "")}.html`,
        ...references,
      ],
      confirmed: false,
      falsePositive: false,
      discoveredAt: new Date().toISOString(),
    };

    return {
      vulnerability,
      module: this.name,
      confidence: Math.max(5, Math.min(95, confidence)),
      timestamp: new Date().toISOString(),
      rawData: extra,
    };
  }
}
