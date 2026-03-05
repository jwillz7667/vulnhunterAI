// =============================================================================
// @vulnhunter/scanner - Dependency Vulnerability Scanner
// =============================================================================
// Parses dependency manifests (package.json, requirements.txt, go.mod, Gemfile)
// and queries vulnerability databases (OSV.dev) for known CVEs. Provides
// severity mapping and upgrade recommendations.
// =============================================================================

import { readFile, access } from "node:fs/promises";
import { join, relative } from "node:path";
import type { Finding, Vulnerability } from "@vulnhunter/core";
import { Severity, VulnerabilityCategory } from "@vulnhunter/core";
import { generateUUID, createLogger } from "@vulnhunter/core";
import type { ScanModule } from "../engine.js";

const log = createLogger("dependency-scanner");

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface ParsedDependency {
  name: string;
  version: string;
  ecosystem: string;
  devOnly: boolean;
  manifestPath: string;
}

interface OsvVulnerability {
  id: string;
  summary: string;
  details: string;
  aliases: string[];
  severity: Array<{
    type: string;
    score: string;
  }>;
  affected: Array<{
    package: {
      name: string;
      ecosystem: string;
    };
    ranges: Array<{
      type: string;
      events: Array<{
        introduced?: string;
        fixed?: string;
        last_affected?: string;
      }>;
    }>;
  }>;
  references: Array<{
    type: string;
    url: string;
  }>;
}

interface OsvQueryResponse {
  vulns?: OsvVulnerability[];
}

// ---------------------------------------------------------------------------
// OSV.dev API Constants
// ---------------------------------------------------------------------------

const OSV_API_BASE = "https://api.osv.dev/v1";
const OSV_QUERY_ENDPOINT = `${OSV_API_BASE}/query`;
const REQUEST_TIMEOUT_MS = 15_000;

// Ecosystem identifiers used by OSV.dev
const ECOSYSTEM_NPM = "npm";
const ECOSYSTEM_PYPI = "PyPI";
const ECOSYSTEM_GO = "Go";
const ECOSYSTEM_RUBYGEMS = "RubyGems";

// ---------------------------------------------------------------------------
// DependencyScanner
// ---------------------------------------------------------------------------

export class DependencyScanner implements ScanModule {
  readonly name = "code:deps";

  async *execute(
    target: string,
    options: Record<string, unknown>,
  ): AsyncGenerator<Finding> {
    log.info({ target }, "Starting dependency vulnerability scan");

    const dependencies: ParsedDependency[] = [];
    const skipDev = (options.skipDevDependencies as boolean) ?? false;

    // Parse all supported manifest files
    const parsers: Array<{ file: string; parser: (content: string, path: string) => ParsedDependency[] }> = [
      { file: "package.json", parser: this.parsePackageJson.bind(this) },
      { file: "requirements.txt", parser: this.parseRequirementsTxt.bind(this) },
      { file: "go.mod", parser: this.parseGoMod.bind(this) },
      { file: "Gemfile", parser: this.parseGemfile.bind(this) },
      { file: "Gemfile.lock", parser: this.parseGemfileLock.bind(this) },
    ];

    for (const { file, parser } of parsers) {
      const manifestPath = join(target, file);
      try {
        await access(manifestPath);
        const content = await readFile(manifestPath, "utf-8");
        const parsed = parser(content, manifestPath);
        dependencies.push(...parsed);
        log.info({ file, count: parsed.length }, "Parsed dependencies from manifest");
      } catch {
        // Manifest not found, skip
      }
    }

    // Also look for nested package.json files in common locations
    const subDirs = ["frontend", "client", "server", "api", "backend", "web", "app", "packages"];
    for (const subDir of subDirs) {
      const nestedManifest = join(target, subDir, "package.json");
      try {
        await access(nestedManifest);
        const content = await readFile(nestedManifest, "utf-8");
        const parsed = this.parsePackageJson(content, nestedManifest);
        dependencies.push(...parsed);
        log.info({ file: `${subDir}/package.json`, count: parsed.length }, "Parsed nested dependencies");
      } catch {
        // Not found, skip
      }
    }

    if (dependencies.length === 0) {
      log.info({ target }, "No dependency manifests found");
      return;
    }

    log.info({ totalDependencies: dependencies.length }, "Total dependencies parsed, querying for vulnerabilities");

    // Filter out dev-only dependencies if requested
    const depsToCheck = skipDev
      ? dependencies.filter((d) => !d.devOnly)
      : dependencies;

    // Query OSV.dev for each dependency
    let vulnCount = 0;

    for (const dep of depsToCheck) {
      try {
        const vulns = await this.queryOsv(dep);

        for (const vuln of vulns) {
          vulnCount++;

          const severity = this.mapOsvSeverity(vuln);
          const cveId = vuln.aliases.find((a) => a.startsWith("CVE-")) ?? vuln.id;
          const cvssScore = this.extractCvssScore(vuln);
          const fixedVersion = this.extractFixedVersion(vuln, dep.name);

          const vulnerability: Vulnerability = {
            id: generateUUID(),
            title: `${cveId}: ${vuln.summary || "Known vulnerability"} in ${dep.name}@${dep.version}`,
            description: vuln.details || vuln.summary || `A known vulnerability (${vuln.id}) affects ${dep.name} version ${dep.version}.`,
            severity,
            category: VulnerabilityCategory.APIVuln,
            cvssScore,
            cweId: undefined,
            target,
            endpoint: dep.manifestPath,
            evidence: {
              description: `Vulnerable dependency ${dep.name}@${dep.version} found in ${relative(target, dep.manifestPath)}`,
              extra: {
                packageName: dep.name,
                installedVersion: dep.version,
                ecosystem: dep.ecosystem,
                vulnerabilityId: vuln.id,
                aliases: vuln.aliases,
                fixedVersion,
                devOnly: dep.devOnly,
              },
            },
            remediation: fixedVersion
              ? `Upgrade ${dep.name} to version ${fixedVersion} or later to fix this vulnerability.${this.getUpgradeCommand(dep, fixedVersion)}`
              : `Review the vulnerability advisory for ${dep.name} and consider alternative packages or applying patches.`,
            references: vuln.references.map((r) => r.url).filter((url) => {
              try {
                new URL(url);
                return true;
              } catch {
                return false;
              }
            }),
            confirmed: true,
            falsePositive: false,
            discoveredAt: new Date().toISOString(),
          };

          const finding: Finding = {
            vulnerability,
            module: this.name,
            confidence: 90,
            timestamp: new Date().toISOString(),
            rawData: {
              osvId: vuln.id,
              packageName: dep.name,
              installedVersion: dep.version,
              ecosystem: dep.ecosystem,
              fixedVersion,
              aliases: vuln.aliases,
            },
          };

          yield finding;
        }
      } catch (err) {
        log.warn(
          {
            package: dep.name,
            version: dep.version,
            error: err instanceof Error ? err.message : String(err),
          },
          "Failed to query vulnerability database for dependency",
        );
      }
    }

    log.info(
      { target, dependenciesChecked: depsToCheck.length, vulnerabilitiesFound: vulnCount },
      "Dependency vulnerability scan complete",
    );
  }

  // -------------------------------------------------------------------------
  // Manifest Parsers
  // -------------------------------------------------------------------------

  /**
   * Parse npm package.json for dependencies and devDependencies.
   */
  private parsePackageJson(content: string, manifestPath: string): ParsedDependency[] {
    const deps: ParsedDependency[] = [];

    try {
      const pkg = JSON.parse(content) as {
        dependencies?: Record<string, string>;
        devDependencies?: Record<string, string>;
      };

      if (pkg.dependencies) {
        for (const [name, versionSpec] of Object.entries(pkg.dependencies)) {
          const version = this.cleanNpmVersion(versionSpec);
          if (version) {
            deps.push({
              name,
              version,
              ecosystem: ECOSYSTEM_NPM,
              devOnly: false,
              manifestPath,
            });
          }
        }
      }

      if (pkg.devDependencies) {
        for (const [name, versionSpec] of Object.entries(pkg.devDependencies)) {
          const version = this.cleanNpmVersion(versionSpec);
          if (version) {
            deps.push({
              name,
              version,
              ecosystem: ECOSYSTEM_NPM,
              devOnly: true,
              manifestPath,
            });
          }
        }
      }
    } catch (err) {
      log.warn({ manifestPath, error: err instanceof Error ? err.message : String(err) }, "Failed to parse package.json");
    }

    return deps;
  }

  /**
   * Parse Python requirements.txt.
   * Supports formats: pkg==1.0.0, pkg>=1.0.0, pkg~=1.0.0, pkg[extra]==1.0.0
   */
  private parseRequirementsTxt(content: string, manifestPath: string): ParsedDependency[] {
    const deps: ParsedDependency[] = [];

    for (const rawLine of content.split("\n")) {
      const line = rawLine.trim();

      // Skip comments, empty lines, and flags
      if (!line || line.startsWith("#") || line.startsWith("-")) continue;

      // Parse package name and version
      // Formats: pkg==1.0.0, pkg>=1.0.0, pkg~=1.0.0, pkg[extra]==1.0.0
      const match = line.match(
        /^([a-zA-Z0-9_-]+(?:\[[a-zA-Z0-9_,-]+\])?)(?:\s*[=~<>!]+\s*([0-9][0-9a-zA-Z.*-]*))?/,
      );

      if (match) {
        const name = match[1].replace(/\[.*\]/, ""); // Strip extras
        const version = match[2] ?? "latest";

        deps.push({
          name,
          version,
          ecosystem: ECOSYSTEM_PYPI,
          devOnly: false,
          manifestPath,
        });
      }
    }

    return deps;
  }

  /**
   * Parse Go go.mod for require directives.
   */
  private parseGoMod(content: string, manifestPath: string): ParsedDependency[] {
    const deps: ParsedDependency[] = [];

    // Match single-line requires: require github.com/pkg v1.0.0
    const singleLineRegex = /require\s+([\w./\-@]+)\s+(v[0-9][0-9a-zA-Z.\-+]*)/g;
    let match: RegExpExecArray | null;

    while ((match = singleLineRegex.exec(content)) !== null) {
      deps.push({
        name: match[1],
        version: match[2],
        ecosystem: ECOSYSTEM_GO,
        devOnly: false,
        manifestPath,
      });
    }

    // Match block requires:
    // require (
    //   github.com/pkg v1.0.0
    //   github.com/pkg2 v2.0.0
    // )
    const blockRegex = /require\s*\(([\s\S]*?)\)/g;
    while ((match = blockRegex.exec(content)) !== null) {
      const block = match[1];
      const lineRegex = /([\w./\-@]+)\s+(v[0-9][0-9a-zA-Z.\-+]*)/g;
      let lineMatch: RegExpExecArray | null;

      while ((lineMatch = lineRegex.exec(block)) !== null) {
        // Avoid duplicates from the single-line parse
        if (!deps.some((d) => d.name === lineMatch![1] && d.version === lineMatch![2])) {
          deps.push({
            name: lineMatch[1],
            version: lineMatch[2],
            ecosystem: ECOSYSTEM_GO,
            devOnly: false,
            manifestPath,
          });
        }
      }
    }

    return deps;
  }

  /**
   * Parse Ruby Gemfile for gem declarations.
   */
  private parseGemfile(content: string, manifestPath: string): ParsedDependency[] {
    const deps: ParsedDependency[] = [];

    const gemRegex = /gem\s+['"]([^'"]+)['"]\s*(?:,\s*['"]([^'"]*)['"]\s*)?/g;
    let match: RegExpExecArray | null;

    while ((match = gemRegex.exec(content)) !== null) {
      const name = match[1];
      const versionConstraint = match[2] ?? "latest";
      const version = versionConstraint.replace(/[~>=<\s]/g, "");

      deps.push({
        name,
        version: version || "latest",
        ecosystem: ECOSYSTEM_RUBYGEMS,
        devOnly: false,
        manifestPath,
      });
    }

    return deps;
  }

  /**
   * Parse Gemfile.lock for exact resolved versions.
   */
  private parseGemfileLock(content: string, manifestPath: string): ParsedDependency[] {
    const deps: ParsedDependency[] = [];
    let inGemSection = false;

    for (const rawLine of content.split("\n")) {
      const line = rawLine.trimEnd();

      if (line === "  specs:") {
        inGemSection = true;
        continue;
      }

      if (inGemSection) {
        // Indented gem entries: "    gem_name (version)"
        const match = line.match(/^\s{4}(\S+)\s+\(([^)]+)\)/);
        if (match) {
          deps.push({
            name: match[1],
            version: match[2],
            ecosystem: ECOSYSTEM_RUBYGEMS,
            devOnly: false,
            manifestPath,
          });
        } else if (!line.startsWith("    ") && line.trim() !== "") {
          inGemSection = false;
        }
      }
    }

    return deps;
  }

  // -------------------------------------------------------------------------
  // OSV.dev API
  // -------------------------------------------------------------------------

  /**
   * Query OSV.dev for known vulnerabilities affecting a specific package version.
   */
  private async queryOsv(dep: ParsedDependency): Promise<OsvVulnerability[]> {
    if (dep.version === "latest" || dep.version === "*") {
      return [];
    }

    const body = JSON.stringify({
      version: dep.version,
      package: {
        name: dep.name,
        ecosystem: dep.ecosystem,
      },
    });

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

    try {
      const response = await fetch(OSV_QUERY_ENDPOINT, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body,
        signal: controller.signal,
      });

      if (!response.ok) {
        log.debug(
          { package: dep.name, status: response.status },
          "OSV API returned non-OK status",
        );
        return [];
      }

      const data = (await response.json()) as OsvQueryResponse;
      return data.vulns ?? [];
    } catch (err) {
      if (err instanceof Error && err.name === "AbortError") {
        log.debug({ package: dep.name }, "OSV API request timed out");
      }
      return [];
    } finally {
      clearTimeout(timeout);
    }
  }

  // -------------------------------------------------------------------------
  // Severity / Score Helpers
  // -------------------------------------------------------------------------

  /**
   * Map an OSV vulnerability to a Severity enum value.
   */
  private mapOsvSeverity(vuln: OsvVulnerability): Severity {
    const cvssScore = this.extractCvssScore(vuln);

    if (cvssScore >= 9.0) return Severity.Critical;
    if (cvssScore >= 7.0) return Severity.High;
    if (cvssScore >= 4.0) return Severity.Medium;
    if (cvssScore > 0) return Severity.Low;

    // Fallback: derive from summary text
    const text = (vuln.summary + " " + vuln.details).toLowerCase();
    if (text.includes("critical") || text.includes("remote code execution")) return Severity.Critical;
    if (text.includes("high") || text.includes("arbitrary code")) return Severity.High;
    if (text.includes("moderate") || text.includes("medium")) return Severity.Medium;
    if (text.includes("low") || text.includes("informational")) return Severity.Low;

    return Severity.Medium; // Default when no severity info is available
  }

  /**
   * Extract a CVSS numeric score from OSV severity data.
   */
  private extractCvssScore(vuln: OsvVulnerability): number {
    if (!vuln.severity || vuln.severity.length === 0) return 5.0;

    for (const sev of vuln.severity) {
      if (sev.type === "CVSS_V3") {
        // Parse CVSS vector to extract base score
        const scoreMatch = sev.score.match(/CVSS:3\.[01]\/.*?/);
        if (scoreMatch) {
          // The score field in OSV is typically the vector string, not the numeric score
          // Try to extract from the end if it's a numeric value
          const numericMatch = sev.score.match(/(\d+\.?\d*)/);
          if (numericMatch) {
            const parsed = parseFloat(numericMatch[1]);
            if (parsed >= 0 && parsed <= 10) return parsed;
          }
        }
        // Try parsing as a direct numeric score
        const directScore = parseFloat(sev.score);
        if (!isNaN(directScore) && directScore >= 0 && directScore <= 10) {
          return directScore;
        }
      }
    }

    return 5.0; // Default mid-range score
  }

  /**
   * Extract the fixed version from OSV affected data.
   */
  private extractFixedVersion(vuln: OsvVulnerability, packageName: string): string | undefined {
    for (const affected of vuln.affected) {
      if (affected.package.name !== packageName) continue;

      for (const range of affected.ranges) {
        for (const event of range.events) {
          if (event.fixed) return event.fixed;
        }
      }
    }

    return undefined;
  }

  // -------------------------------------------------------------------------
  // Utility
  // -------------------------------------------------------------------------

  /**
   * Clean an npm version spec to get a usable version string.
   * Strips range operators (^, ~, >=, etc.) and picks the base version.
   */
  private cleanNpmVersion(spec: string): string | undefined {
    if (!spec) return undefined;

    // Skip workspace references, URLs, and file paths
    if (spec.startsWith("workspace:") || spec.startsWith("file:") ||
        spec.startsWith("http") || spec.startsWith("git")) {
      return undefined;
    }

    // Strip range operators
    const cleaned = spec.replace(/^[\^~>=<|]+/, "").trim();

    // Extract version part (ignore || ranges, take first)
    const parts = cleaned.split("||");
    const first = parts[0].trim().replace(/^[\^~>=<]+/, "").trim();

    // Validate it looks like a semver
    if (/^\d+/.test(first)) {
      return first;
    }

    return spec.replace(/^[\^~]/, ""); // Best effort
  }

  /**
   * Generate an upgrade command for the given ecosystem.
   */
  private getUpgradeCommand(dep: ParsedDependency, fixedVersion: string): string {
    switch (dep.ecosystem) {
      case ECOSYSTEM_NPM:
        return `\n\nRun: npm install ${dep.name}@${fixedVersion}`;
      case ECOSYSTEM_PYPI:
        return `\n\nRun: pip install ${dep.name}>=${fixedVersion}`;
      case ECOSYSTEM_GO:
        return `\n\nRun: go get ${dep.name}@${fixedVersion}`;
      case ECOSYSTEM_RUBYGEMS:
        return `\n\nUpdate Gemfile to: gem '${dep.name}', '~> ${fixedVersion}' then run bundle update ${dep.name}`;
      default:
        return "";
    }
  }
}
