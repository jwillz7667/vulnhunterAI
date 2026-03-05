// =============================================================================
// @vulnhunter/scanner - Nuclei-Compatible YAML Template Loader & Executor
// =============================================================================
// Parses Nuclei-style YAML security templates, executes HTTP-based templates
// against targets, matches response patterns (status codes, body, headers,
// regex), supports variables and extractors, and yields Finding objects.
//
// Nuclei template specification reference:
// https://docs.projectdiscovery.io/templates/introduction
// =============================================================================

import type { Finding, Vulnerability } from "@vulnhunter/core";
import { Severity, VulnerabilityCategory } from "@vulnhunter/core";
import { generateUUID, createLogger } from "@vulnhunter/core";
import type { ScanModule } from "../engine.js";

const log = createLogger("template-loader");

const REQUEST_TIMEOUT_MS = 15_000;

// ---------------------------------------------------------------------------
// Template Type Definitions
// ---------------------------------------------------------------------------

/** Severity mapping from Nuclei template format to VulnHunter Severity. */
const SEVERITY_MAP: Record<string, Severity> = {
  critical: Severity.Critical,
  high: Severity.High,
  medium: Severity.Medium,
  low: Severity.Low,
  info: Severity.Info,
};

/** Supported matcher types in Nuclei templates. */
type MatcherType = "status" | "word" | "regex" | "binary" | "size" | "dsl";

/** Condition for combining multiple matchers. */
type MatcherCondition = "and" | "or";

/** Supported extractor types. */
type ExtractorType = "regex" | "kval" | "json" | "xpath";

/**
 * A single matcher definition from the template.
 */
interface TemplateMatcher {
  type: MatcherType;
  /** For word matchers: list of words to search in the response. */
  words?: string[];
  /** For regex matchers: list of regex patterns. */
  regex?: string[];
  /** For status matchers: list of expected HTTP status codes. */
  status?: number[];
  /** For size matchers: expected response body size. */
  size?: number[];
  /** Part of the response to match against (body, header, all). */
  part?: "body" | "header" | "all" | "status_code";
  /** Whether all items must match (AND) or any item (OR). Default: OR. */
  condition?: MatcherCondition;
  /** If true, this matcher must NOT match (negative/inverse). */
  negative?: boolean;
  /** Whether this is an internal matcher (not used for final match). */
  internal?: boolean;
  /** DSL expressions for complex matching. */
  dsl?: string[];
}

/**
 * An extractor definition that pulls data from the response.
 */
interface TemplateExtractor {
  type: ExtractorType;
  name?: string;
  /** For regex extractors: regex patterns with capture groups. */
  regex?: string[];
  /** For kval extractors: header names to extract. */
  kval?: string[];
  /** For json extractors: JSONPath expressions. */
  json?: string[];
  /** Group index for regex capture groups. */
  group?: number;
  /** Part of the response to extract from. */
  part?: "body" | "header" | "all";
  /** Whether this extractor is internal (used in variables only). */
  internal?: boolean;
}

/**
 * A single HTTP request definition in a template.
 */
interface TemplateHttpRequest {
  method: string;
  path: string[];
  headers?: Record<string, string>;
  body?: string;
  /** Follow redirects. Default: true. */
  redirects?: boolean;
  /** Max redirects to follow. Default: 10. */
  maxRedirects?: number;
  /** Matchers to apply to the response. */
  matchers?: TemplateMatcher[];
  /** How to combine matchers: "and" (all must match) or "or" (any). Default: or. */
  matchersCondition?: MatcherCondition;
  /** Extractors to pull data from the response. */
  extractors?: TemplateExtractor[];
  /** Raw request (if provided, overrides method/path/headers/body). */
  raw?: string[];
  /** Cookie reuse from previous requests. */
  cookieReuse?: boolean;
}

/**
 * The parsed representation of a Nuclei YAML template.
 */
export interface NucleiTemplate {
  /** Template unique identifier. */
  id: string;
  /** Template metadata. */
  info: {
    name: string;
    author: string;
    severity: string;
    description?: string;
    reference?: string[];
    tags?: string;
    classification?: {
      cveId?: string;
      cweId?: string;
      cvssMetrics?: string;
      cvssScore?: number;
    };
    remediation?: string;
  };
  /** HTTP request definitions. */
  http?: TemplateHttpRequest[];
  /** Legacy 'requests' field (alias for http). */
  requests?: TemplateHttpRequest[];
  /** Template-level variables. */
  variables?: Record<string, string>;
}

// ---------------------------------------------------------------------------
// Template Loader & Executor
// ---------------------------------------------------------------------------

export class TemplateLoader implements ScanModule {
  readonly name = "templates:nuclei";

  /** Loaded templates ready for execution. */
  private templates: NucleiTemplate[] = [];

  /** Extracted variables from previous requests (for chaining). */
  private extractedVars: Map<string, string> = new Map();

  /**
   * Initialize: parse and load all templates from the provided paths.
   */
  async init(
    _target: string,
    options: Record<string, unknown>,
  ): Promise<void> {
    this.templates = [];
    this.extractedVars.clear();

    const templatePaths = (options.templatePaths as string[]) ?? [];
    const templateStrings = (options.templates as string[]) ?? [];
    const templateObjects = (options.templateObjects as NucleiTemplate[]) ?? [];

    // Load from file paths
    for (const templatePath of templatePaths) {
      try {
        const template = await this.loadTemplateFromFile(templatePath);
        if (template) {
          this.templates.push(template);
        }
      } catch (err) {
        log.warn({ path: templatePath, error: String(err) }, "Failed to load template file");
      }
    }

    // Parse from raw YAML strings
    for (const yamlStr of templateStrings) {
      try {
        const template = this.parseTemplate(yamlStr);
        if (template) {
          this.templates.push(template);
        }
      } catch (err) {
        log.warn({ error: String(err) }, "Failed to parse template string");
      }
    }

    // Add pre-parsed template objects
    for (const tmpl of templateObjects) {
      if (tmpl.id && tmpl.info) {
        this.templates.push(tmpl);
      }
    }

    log.info(
      { templateCount: this.templates.length },
      "Templates loaded and ready for execution",
    );
  }

  /**
   * Execute all loaded templates against the target.
   */
  async *execute(
    target: string,
    options: Record<string, unknown>,
  ): AsyncGenerator<Finding> {
    if (this.templates.length === 0) {
      log.warn("No templates loaded, skipping template execution");
      return;
    }

    const baseUrl = target.replace(/\/$/, "");

    for (const template of this.templates) {
      log.info(
        { templateId: template.id, templateName: template.info.name },
        "Executing template",
      );

      try {
        yield* this.executeTemplate(template, baseUrl, options);
      } catch (err) {
        log.error(
          { templateId: template.id, error: String(err) },
          "Template execution failed",
        );
      }
    }
  }

  /**
   * Cleanup: clear loaded templates and extracted variables.
   */
  async cleanup(): Promise<void> {
    this.templates = [];
    this.extractedVars.clear();
  }

  // -------------------------------------------------------------------------
  // Template File Loading
  // -------------------------------------------------------------------------

  private async loadTemplateFromFile(filePath: string): Promise<NucleiTemplate | null> {
    try {
      const { readFile } = await import("node:fs/promises");
      const content = await readFile(filePath, "utf-8");
      return this.parseTemplate(content);
    } catch (err) {
      log.error({ filePath, error: String(err) }, "Failed to read template file");
      return null;
    }
  }

  // -------------------------------------------------------------------------
  // Template Parsing
  // -------------------------------------------------------------------------

  /**
   * Parse a YAML string into a NucleiTemplate.
   * Uses the `yaml` package for YAML parsing.
   */
  private parseTemplate(yamlContent: string): NucleiTemplate | null {
    try {
      // Dynamically import yaml to avoid issues if not installed
      // The yaml package is listed as a dependency in package.json
      const yaml = this.parseYamlSync(yamlContent);

      if (!yaml || typeof yaml !== "object") {
        log.warn("Template YAML parsed to non-object value");
        return null;
      }

      const template = yaml as NucleiTemplate;

      // Validate required fields
      if (!template.id || !template.info?.name || !template.info?.severity) {
        log.warn(
          { id: template.id },
          "Template missing required fields (id, info.name, info.severity)",
        );
        return null;
      }

      // Normalize: 'requests' is a legacy alias for 'http'
      if (template.requests && !template.http) {
        template.http = template.requests;
      }

      return template;
    } catch (err) {
      log.error({ error: String(err) }, "YAML parsing failed");
      return null;
    }
  }

  /**
   * Synchronous YAML parsing using a simple parser.
   * Falls back to a basic line-based parser if the yaml package is not available.
   */
  private parseYamlSync(content: string): unknown {
    try {
      // Try to use the yaml package (synchronous API)
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const yamlModule = require("yaml") as { parse: (s: string) => unknown };
      return yamlModule.parse(content);
    } catch {
      // Fallback: attempt to use js-yaml
      try {
        // eslint-disable-next-line @typescript-eslint/no-require-imports
        const jsYaml = require("js-yaml") as { load: (s: string) => unknown };
        return jsYaml.load(content);
      } catch {
        // Last resort: try JSON parse in case it's a JSON template
        try {
          return JSON.parse(content);
        } catch {
          log.error("No YAML parser available and content is not JSON");
          return null;
        }
      }
    }
  }

  // -------------------------------------------------------------------------
  // Template Execution
  // -------------------------------------------------------------------------

  private async *executeTemplate(
    template: NucleiTemplate,
    baseUrl: string,
    _options: Record<string, unknown>,
  ): AsyncGenerator<Finding> {
    const httpRequests = template.http ?? [];

    if (httpRequests.length === 0) {
      log.debug({ templateId: template.id }, "Template has no HTTP requests, skipping");
      return;
    }

    // Initialize template-level variables
    if (template.variables) {
      for (const [key, value] of Object.entries(template.variables)) {
        this.extractedVars.set(key, value);
      }
    }

    for (const httpReq of httpRequests) {
      const paths = httpReq.path ?? [""];

      for (const path of paths) {
        const fullUrl = this.interpolateVariables(
          path.startsWith("http") ? path : `${baseUrl}${path}`,
          baseUrl,
        );

        try {
          const result = await this.sendTemplateRequest(httpReq, fullUrl);

          if (!result) continue;

          // Run extractors first (may populate variables for matchers)
          this.runExtractors(httpReq.extractors ?? [], result);

          // Run matchers
          const matched = this.runMatchers(
            httpReq.matchers ?? [],
            httpReq.matchersCondition ?? "or",
            result,
          );

          if (matched) {
            yield this.templateToFinding(template, baseUrl, fullUrl, result);
          }
        } catch (err) {
          log.debug(
            { templateId: template.id, url: fullUrl, error: String(err) },
            "Request failed during template execution",
          );
        }
      }
    }
  }

  // -------------------------------------------------------------------------
  // HTTP Request Execution
  // -------------------------------------------------------------------------

  private async sendTemplateRequest(
    httpReq: TemplateHttpRequest,
    url: string,
  ): Promise<TemplateResponse | null> {
    const method = (httpReq.method ?? "GET").toUpperCase();
    const headers: Record<string, string> = { ...httpReq.headers };
    const body = httpReq.body ? this.interpolateVariables(httpReq.body, url) : undefined;

    // Interpolate header values
    for (const [key, value] of Object.entries(headers)) {
      headers[key] = this.interpolateVariables(value, url);
    }

    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

      const response = await fetch(url, {
        method,
        headers,
        body: method !== "GET" && method !== "HEAD" ? body : undefined,
        signal: controller.signal,
        redirect: httpReq.redirects === false ? "manual" : "follow",
      });

      clearTimeout(timeout);

      const responseBody = await response.text();
      const responseHeaders: Record<string, string> = {};
      response.headers.forEach((value, key) => {
        responseHeaders[key.toLowerCase()] = value;
      });

      return {
        statusCode: response.status,
        headers: responseHeaders,
        body: responseBody,
        bodySize: responseBody.length,
      };
    } catch (err) {
      log.debug({ url, error: String(err) }, "Template request failed");
      return null;
    }
  }

  // -------------------------------------------------------------------------
  // Matcher Engine
  // -------------------------------------------------------------------------

  private runMatchers(
    matchers: TemplateMatcher[],
    condition: MatcherCondition,
    response: TemplateResponse,
  ): boolean {
    if (matchers.length === 0) return false;

    // Filter out internal matchers
    const externalMatchers = matchers.filter((m) => !m.internal);
    if (externalMatchers.length === 0) return false;

    const results = externalMatchers.map((matcher) => {
      const result = this.evaluateMatcher(matcher, response);
      return matcher.negative ? !result : result;
    });

    if (condition === "and") {
      return results.every(Boolean);
    }
    return results.some(Boolean);
  }

  private evaluateMatcher(
    matcher: TemplateMatcher,
    response: TemplateResponse,
  ): boolean {
    const content = this.getMatcherContent(matcher.part ?? "body", response);

    switch (matcher.type) {
      case "status":
        return (matcher.status ?? []).includes(response.statusCode);

      case "word":
        return this.matchWords(matcher.words ?? [], content, matcher.condition ?? "or");

      case "regex":
        return this.matchRegex(matcher.regex ?? [], content, matcher.condition ?? "or");

      case "size":
        return (matcher.size ?? []).includes(response.bodySize);

      case "binary":
        // Binary matching not implemented for HTTP text responses
        return false;

      case "dsl":
        return this.matchDsl(matcher.dsl ?? [], response);

      default:
        return false;
    }
  }

  private getMatcherContent(
    part: string,
    response: TemplateResponse,
  ): string {
    switch (part) {
      case "body":
        return response.body;
      case "header":
        return Object.entries(response.headers)
          .map(([k, v]) => `${k}: ${v}`)
          .join("\n");
      case "status_code":
        return String(response.statusCode);
      case "all":
      default:
        return (
          Object.entries(response.headers)
            .map(([k, v]) => `${k}: ${v}`)
            .join("\n") +
          "\n\n" +
          response.body
        );
    }
  }

  private matchWords(
    words: string[],
    content: string,
    condition: MatcherCondition,
  ): boolean {
    const interpolatedWords = words.map((w) => this.interpolateVariables(w, ""));
    if (condition === "and") {
      return interpolatedWords.every((word) => content.includes(word));
    }
    return interpolatedWords.some((word) => content.includes(word));
  }

  private matchRegex(
    patterns: string[],
    content: string,
    condition: MatcherCondition,
  ): boolean {
    try {
      if (condition === "and") {
        return patterns.every((p) => new RegExp(p, "gmi").test(content));
      }
      return patterns.some((p) => new RegExp(p, "gmi").test(content));
    } catch {
      log.warn("Invalid regex pattern in template matcher");
      return false;
    }
  }

  private matchDsl(
    expressions: string[],
    response: TemplateResponse,
  ): boolean {
    // Simplified DSL evaluation for common expressions
    for (const expr of expressions) {
      try {
        const evaluated = this.evaluateSimpleDsl(expr, response);
        if (evaluated) return true;
      } catch {
        // DSL evaluation failed
      }
    }
    return false;
  }

  /**
   * Evaluates simple DSL expressions commonly found in Nuclei templates.
   * Supports basic comparisons and helper functions.
   */
  private evaluateSimpleDsl(
    expr: string,
    response: TemplateResponse,
  ): boolean {
    // Handle contains() function
    const containsMatch = expr.match(/contains\((\w+),\s*"([^"]*)"\)/);
    if (containsMatch) {
      const part = containsMatch[1];
      const needle = containsMatch[2];
      const haystack = this.getMatcherContent(part, response);
      return haystack.includes(needle);
    }

    // Handle status_code comparisons
    const statusMatch = expr.match(/status_code\s*==\s*(\d+)/);
    if (statusMatch) {
      return response.statusCode === parseInt(statusMatch[1], 10);
    }

    // Handle content_length comparisons
    const lengthMatch = expr.match(/content_length\s*([<>=!]+)\s*(\d+)/);
    if (lengthMatch) {
      const op = lengthMatch[1];
      const value = parseInt(lengthMatch[2], 10);
      switch (op) {
        case ">": return response.bodySize > value;
        case "<": return response.bodySize < value;
        case ">=": return response.bodySize >= value;
        case "<=": return response.bodySize <= value;
        case "==": return response.bodySize === value;
        case "!=": return response.bodySize !== value;
        default: return false;
      }
    }

    return false;
  }

  // -------------------------------------------------------------------------
  // Extractor Engine
  // -------------------------------------------------------------------------

  private runExtractors(
    extractors: TemplateExtractor[],
    response: TemplateResponse,
  ): void {
    for (const extractor of extractors) {
      const content = this.getMatcherContent(extractor.part ?? "body", response);
      const name = extractor.name ?? `extractor_${extractors.indexOf(extractor)}`;

      switch (extractor.type) {
        case "regex":
          this.extractRegex(extractor, content, name);
          break;
        case "kval":
          this.extractKval(extractor, response.headers, name);
          break;
        case "json":
          this.extractJson(extractor, content, name);
          break;
        default:
          break;
      }
    }
  }

  private extractRegex(
    extractor: TemplateExtractor,
    content: string,
    name: string,
  ): void {
    const group = extractor.group ?? 0;

    for (const pattern of extractor.regex ?? []) {
      try {
        const match = new RegExp(pattern, "gmi").exec(content);
        if (match && match[group] !== undefined) {
          this.extractedVars.set(name, match[group]);
        }
      } catch {
        // Invalid regex
      }
    }
  }

  private extractKval(
    extractor: TemplateExtractor,
    headers: Record<string, string>,
    name: string,
  ): void {
    for (const key of extractor.kval ?? []) {
      const value = headers[key.toLowerCase()];
      if (value) {
        this.extractedVars.set(name || key, value);
      }
    }
  }

  private extractJson(
    extractor: TemplateExtractor,
    content: string,
    name: string,
  ): void {
    try {
      const parsed = JSON.parse(content);

      for (const jsonPath of extractor.json ?? []) {
        // Simple JSONPath evaluation (supports dot notation only)
        const parts = jsonPath.replace(/^\$\.?/, "").split(".");
        let current: unknown = parsed;

        for (const part of parts) {
          if (current == null || typeof current !== "object") {
            current = undefined;
            break;
          }
          current = (current as Record<string, unknown>)[part];
        }

        if (current !== undefined) {
          this.extractedVars.set(name, String(current));
        }
      }
    } catch {
      // Not valid JSON
    }
  }

  // -------------------------------------------------------------------------
  // Variable Interpolation
  // -------------------------------------------------------------------------

  private interpolateVariables(input: string, baseUrl: string): string {
    let result = input;

    // Replace {{BaseURL}} and {{RootURL}}
    result = result.replace(/\{\{BaseURL\}\}/gi, baseUrl);
    result = result.replace(/\{\{RootURL\}\}/gi, baseUrl);

    // Replace {{Hostname}}
    try {
      const hostname = new URL(baseUrl).hostname;
      result = result.replace(/\{\{Hostname\}\}/gi, hostname);
      result = result.replace(/\{\{Host\}\}/gi, hostname);
    } catch {
      // Invalid URL, skip hostname interpolation
    }

    // Replace {{Port}}
    try {
      const port = new URL(baseUrl).port || (baseUrl.startsWith("https") ? "443" : "80");
      result = result.replace(/\{\{Port\}\}/gi, port);
    } catch {
      // Skip
    }

    // Replace {{Scheme}}
    try {
      const scheme = new URL(baseUrl).protocol.replace(":", "");
      result = result.replace(/\{\{Scheme\}\}/gi, scheme);
    } catch {
      // Skip
    }

    // Replace extracted variables
    for (const [key, value] of this.extractedVars) {
      const varPattern = new RegExp(`\\{\\{${key}\\}\\}`, "gi");
      result = result.replace(varPattern, value);
    }

    // Replace random placeholders
    result = result.replace(/\{\{randstr\}\}/gi, this.randomString(8));
    result = result.replace(/\{\{rand_int\(\s*(\d+)\s*,\s*(\d+)\s*\)\}\}/gi, (_m, min, max) => {
      return String(Math.floor(Math.random() * (parseInt(max) - parseInt(min) + 1)) + parseInt(min));
    });

    return result;
  }

  private randomString(length: number): string {
    const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
    let result = "";
    for (let i = 0; i < length; i++) {
      result += chars[Math.floor(Math.random() * chars.length)];
    }
    return result;
  }

  // -------------------------------------------------------------------------
  // Finding Generation
  // -------------------------------------------------------------------------

  private templateToFinding(
    template: NucleiTemplate,
    baseUrl: string,
    matchedUrl: string,
    response: TemplateResponse,
  ): Finding {
    const severity = SEVERITY_MAP[template.info.severity.toLowerCase()] ?? Severity.Info;
    const classification = template.info.classification ?? {};

    const vulnerability: Vulnerability = {
      id: generateUUID(),
      title: template.info.name,
      description:
        template.info.description ??
        `Vulnerability detected by Nuclei template "${template.id}": ${template.info.name}`,
      severity,
      category: this.inferCategory(template),
      cvssScore: classification.cvssScore ?? this.severityToCvss(severity),
      cvssVector: classification.cvssMetrics,
      cweId: classification.cweId,
      target: baseUrl,
      endpoint: matchedUrl,
      evidence: {
        description: `Matched by template: ${template.id}`,
        extra: {
          templateId: template.id,
          statusCode: response.statusCode,
          responseSize: response.bodySize,
          extractedVars: Object.fromEntries(this.extractedVars),
        },
      },
      remediation: template.info.remediation ?? undefined,
      references: [
        ...(template.info.reference ?? []),
        ...(classification.cveId
          ? [`https://nvd.nist.gov/vuln/detail/${classification.cveId}`]
          : []),
      ],
      confirmed: severity === Severity.Critical || severity === Severity.High,
      falsePositive: false,
      discoveredAt: new Date().toISOString(),
    };

    return {
      vulnerability,
      module: this.name,
      confidence: severity === Severity.Critical ? 85 : severity === Severity.High ? 75 : 60,
      timestamp: new Date().toISOString(),
      rawData: {
        templateId: template.id,
        matchedUrl,
        statusCode: response.statusCode,
        responseHeaders: response.headers,
        responseBodySnippet: response.body.slice(0, 500),
      },
    };
  }

  /**
   * Infer a VulnerabilityCategory from template tags and metadata.
   */
  private inferCategory(template: NucleiTemplate): VulnerabilityCategory {
    const tags = (template.info.tags ?? "").toLowerCase();
    const name = template.info.name.toLowerCase();
    const id = template.id.toLowerCase();

    const all = `${tags} ${name} ${id}`;

    if (all.includes("xss")) return VulnerabilityCategory.XSS;
    if (all.includes("sqli") || all.includes("sql-injection")) return VulnerabilityCategory.SQLi;
    if (all.includes("ssrf")) return VulnerabilityCategory.SSRF;
    if (all.includes("rce") || all.includes("command-injection")) return VulnerabilityCategory.RCE;
    if (all.includes("lfi") || all.includes("path-traversal")) return VulnerabilityCategory.LFI;
    if (all.includes("open-redirect") || all.includes("redirect")) return VulnerabilityCategory.OpenRedirect;
    if (all.includes("xxe")) return VulnerabilityCategory.XXE;
    if (all.includes("deserialization")) return VulnerabilityCategory.Deserialization;
    if (all.includes("cors")) return VulnerabilityCategory.CORS;
    if (all.includes("auth") || all.includes("bypass")) return VulnerabilityCategory.AuthBypass;
    if (all.includes("idor")) return VulnerabilityCategory.IDOR;
    if (all.includes("header") || all.includes("misconfig")) return VulnerabilityCategory.HeaderMisconfig;
    if (all.includes("api")) return VulnerabilityCategory.APIVuln;
    if (all.includes("graphql")) return VulnerabilityCategory.GraphQL;
    if (all.includes("crypto") || all.includes("tls") || all.includes("ssl")) return VulnerabilityCategory.Cryptographic;

    return VulnerabilityCategory.InformationDisclosure;
  }

  /**
   * Default CVSS score based on severity when the template does not specify one.
   */
  private severityToCvss(severity: Severity): number {
    switch (severity) {
      case Severity.Critical: return 9.8;
      case Severity.High: return 7.5;
      case Severity.Medium: return 5.3;
      case Severity.Low: return 3.7;
      case Severity.Info: return 0.0;
    }
  }
}

// ---------------------------------------------------------------------------
// Internal Response Type
// ---------------------------------------------------------------------------

interface TemplateResponse {
  statusCode: number;
  headers: Record<string, string>;
  body: string;
  bodySize: number;
}

// ---------------------------------------------------------------------------
// Static Helpers for External Use
// ---------------------------------------------------------------------------

/**
 * Load templates from a directory of YAML files.
 * Returns an array of parsed NucleiTemplate objects.
 */
export async function loadTemplatesFromDirectory(
  dirPath: string,
): Promise<NucleiTemplate[]> {
  const templates: NucleiTemplate[] = [];

  try {
    const { readdir, readFile } = await import("node:fs/promises");
    const { join } = await import("node:path");

    const entries = await readdir(dirPath, { withFileTypes: true, recursive: true });

    for (const entry of entries) {
      if (!entry.isFile()) continue;
      if (!entry.name.endsWith(".yaml") && !entry.name.endsWith(".yml")) continue;

      try {
        const filePath = join(dirPath, entry.name);
        const content = await readFile(filePath, "utf-8");

        const loader = new TemplateLoader();
        // Access the private parseTemplate via a small trick
        const parsed = (loader as unknown as { parseTemplate: (s: string) => NucleiTemplate | null }).parseTemplate(content);

        if (parsed) {
          templates.push(parsed);
        }
      } catch {
        // Skip unparseable files
      }
    }
  } catch (err) {
    log.error({ dirPath, error: String(err) }, "Failed to read template directory");
  }

  return templates;
}
