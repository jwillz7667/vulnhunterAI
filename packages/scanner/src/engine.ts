// =============================================================================
// @vulnhunter/scanner - Core Scan Engine Orchestrator
// =============================================================================
// Manages the lifecycle of scan modules, orchestrates execution based on scan
// type, emits progress events, respects rate limiting and scope constraints,
// and provides per-module error recovery so a single module failure never kills
// the entire scan.
// =============================================================================

import { randomBytes } from "crypto";
import type {
  ScanConfig,
  ScanResult,
  ScanProgress,
  ScanStatistics,
  Finding,
  Vulnerability,
  ScanModuleConfig,
} from "@vulnhunter/core";
import {
  ScanType,
  ScanStatus,
  Severity,
  VulnerabilityCategory,
  SEVERITY_WEIGHT,
} from "@vulnhunter/core";
import { RateLimiter, createLogger } from "@vulnhunter/core";

// ---------------------------------------------------------------------------
// UUID helper (avoids importing crypto.generateUUID which may not exist)
// ---------------------------------------------------------------------------
function uuid(): string {
  const bytes = randomBytes(16);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20, 32),
  ].join("-");
}

const log = createLogger("scan-engine");

// ---------------------------------------------------------------------------
// ScanModule interface
// ---------------------------------------------------------------------------

/**
 * Every scanner module (recon, web, network, code, etc.) must implement this
 * interface. The engine discovers modules via a registry and calls their
 * lifecycle methods in order: init -> execute -> cleanup.
 */
export interface ScanModule {
  /** Human-readable module name, e.g. "recon:subdomain" */
  readonly name: string;

  /**
   * Optional one-time initialization (open sockets, warm caches, etc.).
   * Called before `execute`. If it throws the module is skipped.
   */
  init?(target: string, options: Record<string, unknown>): Promise<void>;

  /**
   * Core execution method. Yields `Finding` objects as they are discovered.
   * The engine consumes these asynchronously and can abort the generator via
   * `.return()` when the scan is cancelled or the global timeout fires.
   */
  execute(
    target: string,
    options: Record<string, unknown>,
  ): AsyncGenerator<Finding>;

  /**
   * Optional cleanup (close sockets, flush buffers, etc.).
   * Called after `execute` finishes (whether normally or via abort).
   */
  cleanup?(): Promise<void>;
}

// ---------------------------------------------------------------------------
// Module Registry
// ---------------------------------------------------------------------------

/**
 * Maps scan types to ordered lists of module names that should execute.
 * Module names reference entries in `ScanEngine.modules`.
 */
const DEFAULT_PHASE_MAP: Record<ScanType, string[]> = {
  [ScanType.Full]: [
    "recon:subdomain",
    "recon:dns",
    "recon:port-scan",
    "recon:tech-detect",
    "recon:crawler",
    // web, network, code, cloud, and smart-contract modules go here
    // once they are implemented
  ],
  [ScanType.Recon]: [
    "recon:subdomain",
    "recon:dns",
    "recon:port-scan",
    "recon:tech-detect",
    "recon:crawler",
  ],
  [ScanType.Web]: [
    "recon:tech-detect",
    "recon:crawler",
  ],
  [ScanType.Network]: [
    "recon:dns",
    "recon:port-scan",
  ],
  [ScanType.Code]: [],
  [ScanType.Cloud]: [],
  [ScanType.SmartContract]: [],
};

// ---------------------------------------------------------------------------
// Scope Guard
// ---------------------------------------------------------------------------

/**
 * Returns true if the given URL or hostname falls within the declared scope
 * restrictions. An empty restrictions list means "everything is in scope."
 */
function isInScope(url: string, restrictions: string[]): boolean {
  if (restrictions.length === 0) return true;
  const lower = url.toLowerCase();
  return restrictions.some((r) => lower.includes(r.toLowerCase()));
}

// ---------------------------------------------------------------------------
// ScanEngine
// ---------------------------------------------------------------------------

export class ScanEngine {
  /** Registered modules keyed by their `name` property. */
  private readonly modules = new Map<string, ScanModule>();

  /** Global rate limiter shared across modules. */
  private rateLimiter!: RateLimiter;

  /** Custom phase map (can be overridden at construction). */
  private phaseMap: Record<string, string[]>;

  constructor(phaseMap?: Record<string, string[]>) {
    this.phaseMap = phaseMap ?? DEFAULT_PHASE_MAP;
  }

  // -------------------------------------------------------------------------
  // Module Registration
  // -------------------------------------------------------------------------

  /**
   * Register a scan module. If a module with the same name already exists it
   * is silently overwritten (useful for testing / plugin overrides).
   */
  registerModule(mod: ScanModule): void {
    this.modules.set(mod.name, mod);
    log.info({ module: mod.name }, "Module registered");
  }

  /**
   * Bulk-register an array of modules.
   */
  registerModules(mods: ScanModule[]): void {
    for (const mod of mods) {
      this.registerModule(mod);
    }
  }

  /**
   * Retrieve a registered module by name (or undefined).
   */
  getModule(name: string): ScanModule | undefined {
    return this.modules.get(name);
  }

  // -------------------------------------------------------------------------
  // Scan Execution
  // -------------------------------------------------------------------------

  /**
   * Primary entry point. Returns an `AsyncGenerator` that yields
   * `ScanProgress` events during the scan and returns the final `ScanResult`
   * when the generator is exhausted.
   *
   * Usage:
   * ```ts
   * const engine = new ScanEngine();
   * engine.registerModules([...]);
   * const gen = engine.executeScan(config);
   * for await (const progress of gen) {
   *   console.log(progress.message);
   * }
   * // gen.return value holds the ScanResult (access via iterator protocol)
   * ```
   */
  async *executeScan(
    config: ScanConfig,
  ): AsyncGenerator<ScanProgress, ScanResult> {
    const scanId = uuid();
    const startTime = new Date().toISOString();

    log.info(
      { scanId, target: config.target, type: config.scanType },
      "Scan started",
    );

    // Initialize the rate limiter from config
    this.rateLimiter = new RateLimiter(config.options.rateLimit);

    // Collect all findings across modules
    const findings: Finding[] = [];
    const modulesCompleted: string[] = [];
    const modulesFailed: string[] = [];
    let totalRequests = 0;
    let endpointsDiscovered = 0;

    // Determine which modules to run based on scan type
    const moduleNames = this.resolveModules(config);
    const totalModules = moduleNames.length;

    if (totalModules === 0) {
      log.warn({ scanId }, "No modules to execute for this scan type");
    }

    // Set up scan timeout
    const scanTimeoutMs = config.options.scanTimeoutMs;
    let timedOut = false;
    let timeoutHandle: ReturnType<typeof setTimeout> | undefined;
    if (scanTimeoutMs > 0) {
      timeoutHandle = setTimeout(() => {
        timedOut = true;
        log.warn({ scanId, scanTimeoutMs }, "Scan timeout reached");
      }, scanTimeoutMs);
    }

    // Execute modules sequentially (respecting dependency ordering)
    for (let i = 0; i < moduleNames.length; i++) {
      if (timedOut) {
        log.warn(
          { scanId, skippedModules: moduleNames.slice(i) },
          "Skipping remaining modules due to timeout",
        );
        break;
      }

      const moduleName = moduleNames[i];
      const mod = this.modules.get(moduleName);

      if (!mod) {
        log.warn({ scanId, module: moduleName }, "Module not registered, skipping");
        modulesFailed.push(moduleName);
        continue;
      }

      // Build module-level options by merging global scan options with
      // per-module overrides from enabledModules
      const moduleOptions = this.buildModuleOptions(config, moduleName);

      // Emit progress: module starting
      yield this.createProgress(scanId, {
        phase: this.getPhase(moduleName),
        module: moduleName,
        progressPercent: Math.round((i / totalModules) * 100),
        message: `Starting module: ${moduleName}`,
        findingsCount: findings.length,
        endpointsTested: endpointsDiscovered,
        requestsSent: totalRequests,
      });

      try {
        // --- INIT ---
        if (mod.init) {
          await mod.init(config.target, moduleOptions);
        }

        // --- EXECUTE ---
        const gen = mod.execute(config.target, moduleOptions);
        let moduleFindings = 0;

        try {
          for await (const finding of gen) {
            if (timedOut) {
              // Abort the module generator gracefully
              await gen.return(undefined as never);
              break;
            }

            // Rate-limit between findings (proxy for request pacing)
            await this.rateLimiter.acquire();

            // Apply minimum severity filter
            if (
              config.options.minimumSeverity &&
              SEVERITY_WEIGHT[finding.vulnerability.severity] <
                SEVERITY_WEIGHT[config.options.minimumSeverity]
            ) {
              continue;
            }

            // Scope check
            if (
              finding.vulnerability.endpoint &&
              !isInScope(
                finding.vulnerability.endpoint,
                config.options.scopeRestrictions,
              )
            ) {
              continue;
            }

            findings.push(finding);
            moduleFindings++;
            totalRequests++;

            // Periodic progress updates (every 5 findings)
            if (moduleFindings % 5 === 0) {
              yield this.createProgress(scanId, {
                phase: this.getPhase(moduleName),
                module: moduleName,
                progressPercent: Math.round(
                  ((i + 0.5) / totalModules) * 100,
                ),
                message: `${moduleName}: ${moduleFindings} findings so far`,
                findingsCount: findings.length,
                endpointsTested: endpointsDiscovered,
                requestsSent: totalRequests,
              });
            }
          }
        } catch (execError) {
          // Error during iteration -- module failure, not scan failure
          const errMsg =
            execError instanceof Error ? execError.message : String(execError);
          log.error(
            { scanId, module: moduleName, error: errMsg },
            "Module execution error",
          );
          modulesFailed.push(moduleName);

          // Emit progress with error
          yield this.createProgress(scanId, {
            phase: this.getPhase(moduleName),
            module: moduleName,
            progressPercent: Math.round(((i + 1) / totalModules) * 100),
            message: `Module ${moduleName} failed: ${errMsg}`,
            findingsCount: findings.length,
            endpointsTested: endpointsDiscovered,
            requestsSent: totalRequests,
          });
          continue; // Move to the next module
        }

        // --- CLEANUP ---
        if (mod.cleanup) {
          try {
            await mod.cleanup();
          } catch (cleanupErr) {
            log.warn(
              {
                scanId,
                module: moduleName,
                error:
                  cleanupErr instanceof Error
                    ? cleanupErr.message
                    : String(cleanupErr),
              },
              "Module cleanup error (non-fatal)",
            );
          }
        }

        modulesCompleted.push(moduleName);
        endpointsDiscovered += moduleFindings;

        log.info(
          { scanId, module: moduleName, findings: moduleFindings },
          "Module completed",
        );
      } catch (moduleError) {
        // Catch-all for init failures or unexpected errors
        const errMsg =
          moduleError instanceof Error
            ? moduleError.message
            : String(moduleError);
        log.error(
          { scanId, module: moduleName, error: errMsg },
          "Module lifecycle error",
        );
        modulesFailed.push(moduleName);

        // Attempt cleanup even on init failure
        if (mod.cleanup) {
          try {
            await mod.cleanup();
          } catch {
            // Swallow cleanup errors during error recovery
          }
        }

        yield this.createProgress(scanId, {
          phase: this.getPhase(moduleName),
          module: moduleName,
          progressPercent: Math.round(((i + 1) / totalModules) * 100),
          message: `Module ${moduleName} failed: ${errMsg}`,
          findingsCount: findings.length,
          endpointsTested: endpointsDiscovered,
          requestsSent: totalRequests,
        });
      }
    }

    // Clear timeout
    if (timeoutHandle) {
      clearTimeout(timeoutHandle);
    }

    const endTime = new Date().toISOString();
    const durationMs = Date.now() - new Date(startTime).getTime();

    // Build statistics
    const stats = this.buildStatistics(
      findings,
      modulesCompleted,
      modulesFailed,
      totalRequests,
      endpointsDiscovered,
      durationMs,
    );

    // Determine final status
    const status = timedOut
      ? ScanStatus.Failed
      : modulesFailed.length === totalModules && totalModules > 0
        ? ScanStatus.Failed
        : ScanStatus.Completed;

    // Final progress event
    yield this.createProgress(scanId, {
      phase: "complete",
      module: "engine",
      progressPercent: 100,
      message: `Scan ${status}: ${findings.length} findings from ${modulesCompleted.length}/${totalModules} modules`,
      findingsCount: findings.length,
      endpointsTested: endpointsDiscovered,
      requestsSent: totalRequests,
    });

    const result: ScanResult = {
      id: scanId,
      target: config.target,
      status,
      scanType: config.scanType,
      config,
      startTime,
      endTime,
      findings,
      stats,
      error: timedOut
        ? "Scan timed out"
        : status === ScanStatus.Failed
          ? `All ${totalModules} modules failed`
          : undefined,
    };

    log.info(
      {
        scanId,
        status,
        findings: findings.length,
        durationMs,
        modulesCompleted: modulesCompleted.length,
        modulesFailed: modulesFailed.length,
      },
      "Scan finished",
    );

    return result;
  }

  // -------------------------------------------------------------------------
  // Private Helpers
  // -------------------------------------------------------------------------

  /**
   * Resolve which modules to run, respecting the enabledModules config.
   * If enabledModules is non-empty, only those modules (that are also in the
   * phase map for this scan type) are included. Disabled modules are excluded.
   */
  private resolveModules(config: ScanConfig): string[] {
    const phaseModules =
      this.phaseMap[config.scanType] ?? [];

    const enabledModulesConfig = config.options.enabledModules;

    // If no per-module config is specified, run all modules in the phase map
    if (!enabledModulesConfig || enabledModulesConfig.length === 0) {
      return phaseModules;
    }

    // Build a lookup of module configs
    const configLookup = new Map<string, ScanModuleConfig>();
    for (const mc of enabledModulesConfig) {
      configLookup.set(mc.name, mc);
    }

    // Filter phase modules: include only those that are either not in the
    // config (default enabled) or explicitly enabled
    return phaseModules.filter((name) => {
      const mc = configLookup.get(name);
      // If no config entry exists for this module, it runs by default
      if (!mc) return true;
      return mc.enabled;
    });
  }

  /**
   * Build the options object for a specific module by merging the global scan
   * options with any module-specific overrides.
   */
  private buildModuleOptions(
    config: ScanConfig,
    moduleName: string,
  ): Record<string, unknown> {
    // Start with a subset of global options relevant to modules
    const base: Record<string, unknown> = {
      maxDepth: config.options.maxDepth,
      rateLimit: config.options.rateLimit,
      requestTimeoutMs: config.options.requestTimeoutMs,
      maxConcurrency: config.options.maxConcurrency,
      customHeaders: config.options.customHeaders ?? {},
      userAgent:
        config.options.userAgent ??
        "VulnHunter/1.0 (Security Scanner; +https://vulnhunter.ai)",
      proxy: config.options.proxy,
      maxRedirects: config.options.maxRedirects,
      enableCookies: config.options.enableCookies,
      scopeRestrictions: config.options.scopeRestrictions,
      authentication: config.options.authentication,
      wordlists: config.options.wordlists,
    };

    // Merge module-specific overrides
    const moduleConfig = config.options.enabledModules?.find(
      (mc) => mc.name === moduleName,
    );
    if (moduleConfig?.options) {
      Object.assign(base, moduleConfig.options);
    }

    return base;
  }

  /**
   * Derive the high-level phase name from a module name.
   * e.g. "recon:subdomain" -> "recon", "web:xss:reflected" -> "web"
   */
  private getPhase(moduleName: string): string {
    const colonIndex = moduleName.indexOf(":");
    return colonIndex > 0 ? moduleName.slice(0, colonIndex) : moduleName;
  }

  /**
   * Create a ScanProgress event with consistent shape.
   */
  private createProgress(
    scanId: string,
    overrides: Omit<ScanProgress, "scanId" | "timestamp">,
  ): ScanProgress {
    return {
      scanId,
      timestamp: new Date().toISOString(),
      ...overrides,
    };
  }

  /**
   * Build aggregate statistics from the collected findings.
   */
  private buildStatistics(
    findings: Finding[],
    modulesCompleted: string[],
    modulesFailed: string[],
    totalRequests: number,
    endpointsDiscovered: number,
    durationMs: number,
  ): ScanStatistics {
    const findingsBySeverity: Record<Severity, number> = {
      [Severity.Critical]: 0,
      [Severity.High]: 0,
      [Severity.Medium]: 0,
      [Severity.Low]: 0,
      [Severity.Info]: 0,
    };

    const findingsByCategory: Record<string, number> = {};

    let confirmedFindings = 0;
    let falsePositives = 0;

    for (const f of findings) {
      const sev = f.vulnerability.severity;
      findingsBySeverity[sev] = (findingsBySeverity[sev] ?? 0) + 1;

      const cat = f.vulnerability.category;
      findingsByCategory[cat] = (findingsByCategory[cat] ?? 0) + 1;

      if (f.vulnerability.confirmed) confirmedFindings++;
      if (f.vulnerability.falsePositive) falsePositives++;
    }

    return {
      totalRequests,
      endpointsDiscovered,
      findingsBySeverity,
      findingsByCategory,
      confirmedFindings,
      falsePositives,
      exploitChainsFound: 0,
      durationMs,
      modulesCompleted,
      modulesFailed,
    };
  }
}

// ---------------------------------------------------------------------------
// Convenience factory: creates a ScanEngine pre-loaded with all built-in
// recon modules. Import and call this if you want the batteries-included
// experience.
// ---------------------------------------------------------------------------
export async function createDefaultEngine(): Promise<ScanEngine> {
  const engine = new ScanEngine();

  // Lazy-load recon modules to avoid circular deps and keep tree-shakeable
  const { SubdomainEnumerator } = await import("./recon/subdomain.js");
  const { DnsEnumerator } = await import("./recon/dns.js");
  const { PortScanner } = await import("./recon/port-scan.js");
  const { TechDetector } = await import("./recon/tech-detect.js");
  const { WebCrawler } = await import("./recon/crawler.js");

  engine.registerModules([
    new SubdomainEnumerator(),
    new DnsEnumerator(),
    new PortScanner(),
    new TechDetector(),
    new WebCrawler(),
  ]);

  return engine;
}
