// =============================================================================
// @vulnhunter/scanner - Web Crawler Module
// =============================================================================
// Breadth-first web crawler that discovers:
//   - Links (anchors, redirects) from HTML pages
//   - Forms and their parameters
//   - API endpoints
//   - sitemap.xml entries
//   - robots.txt directives
// Respects scope restrictions and deduplicates URLs.
// =============================================================================

import { randomBytes } from "crypto";
import type { ScanModule } from "../engine.js";
import type { Finding, Vulnerability } from "@vulnhunter/core";
import { Severity, VulnerabilityCategory } from "@vulnhunter/core";
import { createLogger } from "@vulnhunter/core";

const log = createLogger("recon:crawler");

// ---------------------------------------------------------------------------
// UUID helper
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

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface CrawlPage {
  url: string;
  depth: number;
}

interface DiscoveredForm {
  action: string;
  method: string;
  inputs: Array<{
    name: string;
    type: string;
    value?: string;
  }>;
  pageUrl: string;
}

interface DiscoveredEndpoint {
  url: string;
  method: string;
  type: "page" | "form" | "api" | "sitemap" | "robots" | "resource";
  parameters: string[];
  depth: number;
}

// ---------------------------------------------------------------------------
// WebCrawler
// ---------------------------------------------------------------------------

export class WebCrawler implements ScanModule {
  readonly name = "recon:crawler";

  private maxDepth = 5;
  private maxPages = 500;
  private timeoutMs = 15000;
  private maxConcurrency = 5;
  private userAgent = "VulnHunter/1.0 (Security Scanner)";
  private customHeaders: Record<string, string> = {};
  private scopeRestrictions: string[] = [];

  /** Set of visited normalized URLs (for deduplication). */
  private visited = new Set<string>();
  /** All discovered endpoints. */
  private endpoints: DiscoveredEndpoint[] = [];
  /** All discovered forms. */
  private forms: DiscoveredForm[] = [];
  /** The allowed origin (protocol + host) for scope enforcement. */
  private allowedOrigin = "";

  async init(
    target: string,
    options: Record<string, unknown>,
  ): Promise<void> {
    if (typeof options.maxDepth === "number") {
      this.maxDepth = Math.min(options.maxDepth, 20);
    }
    if (typeof options.maxConcurrency === "number") {
      this.maxConcurrency = options.maxConcurrency;
    }
    if (typeof options.requestTimeoutMs === "number") {
      this.timeoutMs = options.requestTimeoutMs;
    }
    if (typeof options.userAgent === "string") {
      this.userAgent = options.userAgent;
    }
    if (
      options.customHeaders &&
      typeof options.customHeaders === "object"
    ) {
      this.customHeaders = options.customHeaders as Record<string, string>;
    }
    if (Array.isArray(options.scopeRestrictions)) {
      this.scopeRestrictions = options.scopeRestrictions as string[];
    }
    if (typeof options.maxPages === "number") {
      this.maxPages = options.maxPages;
    }

    // Derive the allowed origin from the target
    const baseUrl = this.normalizeUrl(target);
    try {
      const parsed = new URL(baseUrl);
      this.allowedOrigin = parsed.origin;
    } catch {
      this.allowedOrigin = baseUrl;
    }

    // Reset state
    this.visited.clear();
    this.endpoints = [];
    this.forms = [];

    log.info(
      { maxDepth: this.maxDepth, maxPages: this.maxPages },
      "WebCrawler initialized",
    );
  }

  async *execute(
    target: string,
    _options: Record<string, unknown>,
  ): AsyncGenerator<Finding> {
    const baseUrl = this.normalizeUrl(target);
    log.info({ baseUrl }, "Starting web crawl");

    // --- Phase 1: Parse robots.txt ---
    const robotsEntries = await this.parseRobotsTxt(baseUrl);
    for (const entry of robotsEntries) {
      this.addEndpoint(entry);
    }

    // --- Phase 2: Parse sitemap.xml ---
    const sitemapEntries = await this.parseSitemapXml(baseUrl);
    for (const entry of sitemapEntries) {
      this.addEndpoint(entry);
    }

    // --- Phase 3: BFS Crawl ---
    const queue: CrawlPage[] = [{ url: baseUrl, depth: 0 }];
    // Also seed queue from sitemap URLs
    for (const entry of sitemapEntries) {
      if (!this.visited.has(this.normalizeForDedup(entry.url))) {
        queue.push({ url: entry.url, depth: 1 });
      }
    }

    while (queue.length > 0 && this.visited.size < this.maxPages) {
      // Process in batches for concurrency
      const batchSize = Math.min(
        this.maxConcurrency,
        queue.length,
        this.maxPages - this.visited.size,
      );
      const batch = queue.splice(0, batchSize);

      const results = await Promise.allSettled(
        batch.map((page) => this.crawlPage(page)),
      );

      for (const result of results) {
        if (result.status === "fulfilled" && result.value) {
          const { discoveredUrls, discoveredForms, discoveredApis, depth } =
            result.value;

          // Enqueue new URLs
          if (depth < this.maxDepth) {
            for (const url of discoveredUrls) {
              const normalized = this.normalizeForDedup(url);
              if (
                !this.visited.has(normalized) &&
                this.isInScope(url)
              ) {
                queue.push({ url, depth: depth + 1 });
              }
            }
          }

          // Record forms
          for (const form of discoveredForms) {
            this.forms.push(form);
          }

          // Record API endpoints
          for (const api of discoveredApis) {
            this.addEndpoint(api);
          }
        }
      }
    }

    log.info(
      {
        baseUrl,
        pagesVisited: this.visited.size,
        endpointsFound: this.endpoints.length,
        formsFound: this.forms.length,
      },
      "Web crawl complete",
    );

    // --- Yield findings ---

    // Yield all discovered endpoints as a single aggregate finding
    if (this.endpoints.length > 0) {
      yield this.createEndpointsFinding(baseUrl);
    }

    // Yield each discovered form individually
    for (const form of this.forms) {
      yield this.createFormFinding(baseUrl, form);
    }

    // Yield API endpoint findings
    const apiEndpoints = this.endpoints.filter((e) => e.type === "api");
    if (apiEndpoints.length > 0) {
      yield this.createApiEndpointsFinding(baseUrl, apiEndpoints);
    }
  }

  async cleanup(): Promise<void> {
    this.visited.clear();
    this.endpoints = [];
    this.forms = [];
    log.info("WebCrawler cleanup complete");
  }

  // -------------------------------------------------------------------------
  // Page Crawling
  // -------------------------------------------------------------------------

  private async crawlPage(page: CrawlPage): Promise<{
    discoveredUrls: string[];
    discoveredForms: DiscoveredForm[];
    discoveredApis: DiscoveredEndpoint[];
    depth: number;
  } | null> {
    const normalized = this.normalizeForDedup(page.url);
    if (this.visited.has(normalized)) return null;
    this.visited.add(normalized);

    try {
      const controller = new AbortController();
      const timeout = setTimeout(
        () => controller.abort(),
        this.timeoutMs,
      );

      const response = await fetch(page.url, {
        method: "GET",
        headers: {
          "User-Agent": this.userAgent,
          Accept:
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
          "Accept-Language": "en-US,en;q=0.5",
          ...this.customHeaders,
        },
        signal: controller.signal,
        redirect: "follow",
      });

      clearTimeout(timeout);

      const contentType = response.headers.get("content-type") ?? "";
      if (
        !contentType.includes("text/html") &&
        !contentType.includes("application/xhtml")
      ) {
        // Not an HTML page -- record it but don't parse
        this.addEndpoint({
          url: page.url,
          method: "GET",
          type: "resource",
          parameters: [],
          depth: page.depth,
        });
        return {
          discoveredUrls: [],
          discoveredForms: [],
          discoveredApis: [],
          depth: page.depth,
        };
      }

      const body = await response.text();

      // Record this page
      this.addEndpoint({
        url: page.url,
        method: "GET",
        type: "page",
        parameters: this.extractQueryParams(page.url),
        depth: page.depth,
      });

      // Extract links
      const discoveredUrls = this.extractLinks(body, page.url);

      // Extract forms
      const discoveredForms = this.extractForms(body, page.url);

      // Detect API endpoints from the HTML
      const discoveredApis = this.detectApiEndpoints(body, page.url, page.depth);

      return {
        discoveredUrls,
        discoveredForms,
        discoveredApis,
        depth: page.depth,
      };
    } catch (error) {
      log.debug(
        {
          url: page.url,
          error:
            error instanceof Error ? error.message : String(error),
        },
        "Failed to crawl page",
      );
      return null;
    }
  }

  // -------------------------------------------------------------------------
  // Link Extraction
  // -------------------------------------------------------------------------

  private extractLinks(html: string, pageUrl: string): string[] {
    const links: string[] = [];
    const seen = new Set<string>();

    // Match <a href="...">, <link href="...">, <area href="...">
    const hrefPattern = /<(?:a|link|area)\s[^>]*href=["']([^"'#]+)/gi;
    let match: RegExpExecArray | null;

    while ((match = hrefPattern.exec(html)) !== null) {
      const href = match[1].trim();
      const resolved = this.resolveUrl(href, pageUrl);
      if (resolved && !seen.has(resolved) && this.isInScope(resolved)) {
        seen.add(resolved);
        links.push(resolved);
      }
    }

    // Match <frame src="...">, <iframe src="...">
    const srcPattern = /<(?:frame|iframe)\s[^>]*src=["']([^"'#]+)/gi;
    while ((match = srcPattern.exec(html)) !== null) {
      const src = match[1].trim();
      const resolved = this.resolveUrl(src, pageUrl);
      if (resolved && !seen.has(resolved) && this.isInScope(resolved)) {
        seen.add(resolved);
        links.push(resolved);
      }
    }

    // Match window.location, document.location, location.href assignments
    const jsRedirectPattern =
      /(?:window\.location|document\.location|location\.href)\s*=\s*["']([^"']+)["']/gi;
    while ((match = jsRedirectPattern.exec(html)) !== null) {
      const href = match[1].trim();
      const resolved = this.resolveUrl(href, pageUrl);
      if (resolved && !seen.has(resolved) && this.isInScope(resolved)) {
        seen.add(resolved);
        links.push(resolved);
      }
    }

    return links;
  }

  // -------------------------------------------------------------------------
  // Form Extraction
  // -------------------------------------------------------------------------

  private extractForms(html: string, pageUrl: string): DiscoveredForm[] {
    const forms: DiscoveredForm[] = [];

    // Use a regex-based approach for form extraction (no external parser dependency)
    const formPattern = /<form\s[^>]*>([\s\S]*?)<\/form>/gi;
    let formMatch: RegExpExecArray | null;

    while ((formMatch = formPattern.exec(html)) !== null) {
      const formTag = formMatch[0];
      const formBody = formMatch[1];

      // Extract action
      const actionMatch = formTag.match(/action=["']([^"']*?)["']/i);
      const rawAction = actionMatch ? actionMatch[1] : "";
      const action = this.resolveUrl(rawAction || pageUrl, pageUrl) ?? pageUrl;

      // Extract method
      const methodMatch = formTag.match(/method=["']([^"']*?)["']/i);
      const method = (methodMatch ? methodMatch[1] : "GET").toUpperCase();

      // Extract inputs
      const inputs: Array<{ name: string; type: string; value?: string }> = [];
      const inputPattern =
        /<(?:input|textarea|select)\s[^>]*?(?:name=["']([^"']*?)["'])?[^>]*?(?:type=["']([^"']*?)["'])?[^>]*?(?:value=["']([^"']*?)["'])?[^>]*/gi;
      let inputMatch: RegExpExecArray | null;

      while ((inputMatch = inputPattern.exec(formBody)) !== null) {
        // Also try reverse attribute order
        const fullTag = inputMatch[0];

        const nameMatch2 = fullTag.match(/name=["']([^"']*?)["']/i);
        const typeMatch2 = fullTag.match(/type=["']([^"']*?)["']/i);
        const valueMatch2 = fullTag.match(/value=["']([^"']*?)["']/i);

        const name = nameMatch2 ? nameMatch2[1] : "";
        const type = typeMatch2 ? typeMatch2[1] : "text";
        const value = valueMatch2 ? valueMatch2[1] : undefined;

        if (name) {
          inputs.push({ name, type, value });
        }
      }

      forms.push({ action, method, inputs, pageUrl });
    }

    return forms;
  }

  // -------------------------------------------------------------------------
  // API Endpoint Detection
  // -------------------------------------------------------------------------

  private detectApiEndpoints(
    html: string,
    pageUrl: string,
    depth: number,
  ): DiscoveredEndpoint[] {
    const endpoints: DiscoveredEndpoint[] = [];
    const seen = new Set<string>();

    // Pattern: fetch(), axios, XMLHttpRequest URLs
    const fetchPattern =
      /(?:fetch|axios\.(?:get|post|put|patch|delete)|\.open)\s*\(\s*["'`]([^"'`]+)["'`]/gi;
    let match: RegExpExecArray | null;

    while ((match = fetchPattern.exec(html)) !== null) {
      const url = match[1].trim();
      if (this.looksLikeApiUrl(url)) {
        const resolved = this.resolveUrl(url, pageUrl);
        if (resolved && !seen.has(resolved)) {
          seen.add(resolved);

          // Try to determine the HTTP method
          const contextStart = Math.max(0, match.index - 20);
          const context = html.slice(contextStart, match.index + match[0].length);
          let method = "GET";
          if (/\.post\b/i.test(context)) method = "POST";
          if (/\.put\b/i.test(context)) method = "PUT";
          if (/\.patch\b/i.test(context)) method = "PATCH";
          if (/\.delete\b/i.test(context)) method = "DELETE";

          endpoints.push({
            url: resolved,
            method,
            type: "api",
            parameters: this.extractQueryParams(resolved),
            depth,
          });
        }
      }
    }

    // Pattern: "/api/..." string literals in JavaScript
    const apiStringPattern = /["'`](\/api\/[^"'`\s]+)["'`]/gi;
    while ((match = apiStringPattern.exec(html)) !== null) {
      const url = match[1].trim();
      const resolved = this.resolveUrl(url, pageUrl);
      if (resolved && !seen.has(resolved)) {
        seen.add(resolved);
        endpoints.push({
          url: resolved,
          method: "GET",
          type: "api",
          parameters: this.extractQueryParams(resolved),
          depth,
        });
      }
    }

    // Pattern: "/graphql" references
    const graphqlPattern = /["'`](\/graphql\b[^"'`]*)["'`]/gi;
    while ((match = graphqlPattern.exec(html)) !== null) {
      const url = match[1].trim();
      const resolved = this.resolveUrl(url, pageUrl);
      if (resolved && !seen.has(resolved)) {
        seen.add(resolved);
        endpoints.push({
          url: resolved,
          method: "POST",
          type: "api",
          parameters: ["query"],
          depth,
        });
      }
    }

    return endpoints;
  }

  // -------------------------------------------------------------------------
  // robots.txt
  // -------------------------------------------------------------------------

  private async parseRobotsTxt(
    baseUrl: string,
  ): Promise<DiscoveredEndpoint[]> {
    const endpoints: DiscoveredEndpoint[] = [];

    try {
      const robotsUrl = new URL("/robots.txt", baseUrl).toString();
      const controller = new AbortController();
      const timeout = setTimeout(
        () => controller.abort(),
        this.timeoutMs,
      );

      const response = await fetch(robotsUrl, {
        headers: {
          "User-Agent": this.userAgent,
          ...this.customHeaders,
        },
        signal: controller.signal,
      });

      clearTimeout(timeout);

      if (!response.ok) return endpoints;

      const body = await response.text();
      const lines = body.split("\n");

      for (const line of lines) {
        const trimmed = line.trim();

        // Extract Disallow and Allow paths
        const directiveMatch = trimmed.match(
          /^(?:Dis)?allow:\s*(.+)/i,
        );
        if (directiveMatch) {
          const path = directiveMatch[1].trim();
          if (path && path !== "/") {
            const resolved = this.resolveUrl(path, baseUrl);
            if (resolved) {
              endpoints.push({
                url: resolved,
                method: "GET",
                type: "robots",
                parameters: [],
                depth: 0,
              });
            }
          }
        }

        // Extract Sitemap directives
        const sitemapMatch = trimmed.match(/^Sitemap:\s*(.+)/i);
        if (sitemapMatch) {
          const sitemapUrl = sitemapMatch[1].trim();
          // We'll handle sitemaps separately but record the URL
          endpoints.push({
            url: sitemapUrl,
            method: "GET",
            type: "sitemap",
            parameters: [],
            depth: 0,
          });
        }
      }

      log.info(
        { entries: endpoints.length },
        "robots.txt parsed",
      );
    } catch (error) {
      log.debug(
        {
          error:
            error instanceof Error ? error.message : String(error),
        },
        "Failed to parse robots.txt (non-fatal)",
      );
    }

    return endpoints;
  }

  // -------------------------------------------------------------------------
  // sitemap.xml
  // -------------------------------------------------------------------------

  private async parseSitemapXml(
    baseUrl: string,
  ): Promise<DiscoveredEndpoint[]> {
    const endpoints: DiscoveredEndpoint[] = [];

    try {
      const sitemapUrl = new URL("/sitemap.xml", baseUrl).toString();
      const controller = new AbortController();
      const timeout = setTimeout(
        () => controller.abort(),
        this.timeoutMs,
      );

      const response = await fetch(sitemapUrl, {
        headers: {
          "User-Agent": this.userAgent,
          Accept: "application/xml,text/xml,*/*",
          ...this.customHeaders,
        },
        signal: controller.signal,
      });

      clearTimeout(timeout);

      if (!response.ok) return endpoints;

      const body = await response.text();

      // Extract <loc> elements
      const locPattern = /<loc>\s*([^<]+)\s*<\/loc>/gi;
      let match: RegExpExecArray | null;
      const seen = new Set<string>();

      while ((match = locPattern.exec(body)) !== null) {
        const url = match[1].trim();
        if (!seen.has(url) && this.isInScope(url)) {
          seen.add(url);
          endpoints.push({
            url,
            method: "GET",
            type: "sitemap",
            parameters: this.extractQueryParams(url),
            depth: 0,
          });
        }
      }

      // Check for sitemap index (references to other sitemaps)
      const sitemapLocPattern =
        /<sitemap>\s*<loc>\s*([^<]+)\s*<\/loc>/gi;
      const childSitemaps: string[] = [];
      while ((match = sitemapLocPattern.exec(body)) !== null) {
        childSitemaps.push(match[1].trim());
      }

      // Fetch child sitemaps (limit to first 5 to avoid explosion)
      for (const childUrl of childSitemaps.slice(0, 5)) {
        try {
          const childController = new AbortController();
          const childTimeout = setTimeout(
            () => childController.abort(),
            this.timeoutMs,
          );

          const childResponse = await fetch(childUrl, {
            headers: {
              "User-Agent": this.userAgent,
              Accept: "application/xml,text/xml,*/*",
              ...this.customHeaders,
            },
            signal: childController.signal,
          });

          clearTimeout(childTimeout);

          if (childResponse.ok) {
            const childBody = await childResponse.text();
            while ((match = locPattern.exec(childBody)) !== null) {
              const url = match[1].trim();
              if (!seen.has(url) && this.isInScope(url)) {
                seen.add(url);
                endpoints.push({
                  url,
                  method: "GET",
                  type: "sitemap",
                  parameters: this.extractQueryParams(url),
                  depth: 0,
                });
              }
            }
          }
        } catch {
          // Skip failed child sitemaps
        }
      }

      log.info(
        { entries: endpoints.length },
        "sitemap.xml parsed",
      );
    } catch (error) {
      log.debug(
        {
          error:
            error instanceof Error ? error.message : String(error),
        },
        "Failed to parse sitemap.xml (non-fatal)",
      );
    }

    return endpoints;
  }

  // -------------------------------------------------------------------------
  // Scope & URL Helpers
  // -------------------------------------------------------------------------

  private isInScope(url: string): boolean {
    try {
      const parsed = new URL(url);

      // Must be same origin (or match scope restrictions)
      if (parsed.origin !== this.allowedOrigin) {
        return false;
      }

      // Check explicit scope restrictions
      if (this.scopeRestrictions.length > 0) {
        return this.scopeRestrictions.some((r) =>
          parsed.pathname.startsWith(r),
        );
      }

      return true;
    } catch {
      return false;
    }
  }

  private resolveUrl(
    href: string,
    pageUrl: string,
  ): string | null {
    if (!href) return null;

    // Skip non-HTTP schemes
    if (/^(?:javascript|mailto|tel|data|blob):/i.test(href)) {
      return null;
    }

    try {
      const resolved = new URL(href, pageUrl);
      // Strip fragment
      resolved.hash = "";
      return resolved.toString();
    } catch {
      return null;
    }
  }

  private normalizeForDedup(url: string): string {
    try {
      const parsed = new URL(url);
      // Normalize by removing fragment and sorting query params
      parsed.hash = "";
      parsed.searchParams.sort();
      return parsed.toString().toLowerCase();
    } catch {
      return url.toLowerCase();
    }
  }

  private normalizeUrl(target: string): string {
    if (!target.includes("://")) {
      return `https://${target}`;
    }
    return target;
  }

  private extractQueryParams(url: string): string[] {
    try {
      const parsed = new URL(url);
      return Array.from(parsed.searchParams.keys());
    } catch {
      return [];
    }
  }

  private looksLikeApiUrl(url: string): boolean {
    const apiIndicators = [
      "/api/",
      "/api?",
      "/v1/",
      "/v2/",
      "/v3/",
      "/graphql",
      "/rest/",
      "/ws/",
      ".json",
      ".xml",
      "/webhook",
    ];
    const lower = url.toLowerCase();
    return apiIndicators.some((indicator) => lower.includes(indicator));
  }

  private addEndpoint(endpoint: DiscoveredEndpoint): void {
    const key = `${endpoint.method}:${this.normalizeForDedup(endpoint.url)}`;
    if (
      !this.endpoints.some(
        (e) =>
          `${e.method}:${this.normalizeForDedup(e.url)}` === key,
      )
    ) {
      this.endpoints.push(endpoint);
    }
  }

  // -------------------------------------------------------------------------
  // Finding Factories
  // -------------------------------------------------------------------------

  private createEndpointsFinding(baseUrl: string): Finding {
    const now = new Date().toISOString();
    const pageEndpoints = this.endpoints.filter(
      (e) => e.type === "page" || e.type === "resource",
    );

    const vulnerability: Vulnerability = {
      id: uuid(),
      title: `Web crawl discovered ${this.endpoints.length} endpoints on ${baseUrl}`,
      description:
        `A breadth-first crawl of ${baseUrl} discovered ${this.endpoints.length} total endpoints: ` +
        `${pageEndpoints.length} pages/resources, ` +
        `${this.endpoints.filter((e) => e.type === "sitemap").length} sitemap entries, ` +
        `${this.endpoints.filter((e) => e.type === "robots").length} robots.txt paths, ` +
        `${this.endpoints.filter((e) => e.type === "api").length} API endpoints, ` +
        `${this.forms.length} forms. ` +
        `Pages visited: ${this.visited.size}. Max depth reached: ${Math.max(0, ...this.endpoints.map((e) => e.depth))}.`,
      severity: Severity.Info,
      category: VulnerabilityCategory.InformationDisclosure,
      cvssScore: 0.0,
      target: baseUrl,
      endpoint: baseUrl,
      evidence: {
        description: `Crawl discovered ${this.endpoints.length} endpoints`,
        extra: {
          totalEndpoints: this.endpoints.length,
          pagesVisited: this.visited.size,
          formsFound: this.forms.length,
          endpointsByType: {
            page: this.endpoints.filter((e) => e.type === "page").length,
            resource: this.endpoints.filter((e) => e.type === "resource").length,
            sitemap: this.endpoints.filter((e) => e.type === "sitemap").length,
            robots: this.endpoints.filter((e) => e.type === "robots").length,
            api: this.endpoints.filter((e) => e.type === "api").length,
          },
          endpoints: this.endpoints.slice(0, 200).map((e) => ({
            url: e.url,
            method: e.method,
            type: e.type,
            parameters: e.parameters,
          })),
        },
      },
      remediation:
        "Review all discovered endpoints to ensure they are intentionally public. " +
        "Remove or restrict access to any endpoints that should not be publicly accessible.",
      references: [
        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage",
      ],
      confirmed: true,
      falsePositive: false,
      discoveredAt: now,
    };

    return {
      vulnerability,
      module: this.name,
      confidence: 90,
      timestamp: now,
      rawData: {
        totalEndpoints: this.endpoints.length,
        pagesVisited: this.visited.size,
      },
    };
  }

  private createFormFinding(
    baseUrl: string,
    form: DiscoveredForm,
  ): Finding {
    const now = new Date().toISOString();
    const paramNames = form.inputs.map((i) => i.name).join(", ");

    const vulnerability: Vulnerability = {
      id: uuid(),
      title: `Form discovered: ${form.method} ${form.action}`,
      description:
        `A form was discovered at ${form.pageUrl} with action="${form.action}" ` +
        `and method="${form.method}". Input fields: ${paramNames || "none"}. ` +
        `Forms are potential targets for injection attacks (XSS, SQLi, CSRF).`,
      severity: Severity.Info,
      category: VulnerabilityCategory.InformationDisclosure,
      cvssScore: 0.0,
      target: baseUrl,
      endpoint: form.action,
      evidence: {
        description: `Form with ${form.inputs.length} input(s) found on ${form.pageUrl}`,
        extra: {
          action: form.action,
          method: form.method,
          inputs: form.inputs,
          pageUrl: form.pageUrl,
        },
      },
      remediation:
        "Ensure all form inputs are properly validated and sanitized server-side. " +
        "Implement CSRF tokens for state-changing forms.",
      references: [
        "https://owasp.org/www-community/attacks/csrf",
        "https://owasp.org/www-community/attacks/xss/",
      ],
      confirmed: true,
      falsePositive: false,
      discoveredAt: now,
    };

    return {
      vulnerability,
      module: this.name,
      confidence: 95,
      timestamp: now,
      rawData: {
        form: {
          action: form.action,
          method: form.method,
          inputs: form.inputs,
          pageUrl: form.pageUrl,
        },
      },
    };
  }

  private createApiEndpointsFinding(
    baseUrl: string,
    apiEndpoints: DiscoveredEndpoint[],
  ): Finding {
    const now = new Date().toISOString();

    const vulnerability: Vulnerability = {
      id: uuid(),
      title: `${apiEndpoints.length} API endpoint(s) discovered on ${baseUrl}`,
      description:
        `The crawler detected ${apiEndpoints.length} API endpoint(s) referenced in the application's client-side code. ` +
        `These endpoints represent the application's API surface and are potential targets for ` +
        `authentication bypass, IDOR, injection, and other API-specific vulnerabilities.`,
      severity: Severity.Info,
      category: VulnerabilityCategory.InformationDisclosure,
      cvssScore: 0.0,
      target: baseUrl,
      endpoint: baseUrl,
      evidence: {
        description: `${apiEndpoints.length} API endpoints detected`,
        extra: {
          apiEndpoints: apiEndpoints.map((e) => ({
            url: e.url,
            method: e.method,
            parameters: e.parameters,
          })),
        },
      },
      remediation:
        "Review all API endpoints for proper authentication, authorization, " +
        "input validation, and rate limiting. Ensure sensitive APIs are not " +
        "unnecessarily exposed to the client.",
      references: [
        "https://owasp.org/API-Security/editions/2023/en/0x11-t10/",
      ],
      confirmed: true,
      falsePositive: false,
      discoveredAt: now,
    };

    return {
      vulnerability,
      module: this.name,
      confidence: 80,
      timestamp: now,
      rawData: {
        apiEndpoints: apiEndpoints.map((e) => ({
          url: e.url,
          method: e.method,
          parameters: e.parameters,
        })),
      },
    };
  }
}
