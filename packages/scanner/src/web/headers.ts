// =============================================================================
// VulnHunter AI - Security Headers Scanner Module
// =============================================================================
// Checks for missing or misconfigured security headers: CSP, HSTS,
// X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy,
// cookie security flags, and information leakage headers.
// =============================================================================

import {
  type Finding,
  type Vulnerability,
  Severity,
  VulnerabilityCategory,
} from "@vulnhunter/core";
import { generateUUID } from "@vulnhunter/core";
import { sendRequest, type HttpResponse } from "@vulnhunter/core";
import { createLogger } from "@vulnhunter/core";
import { RateLimiter } from "@vulnhunter/core";

import type { ScanModule } from "./xss.js";

const log = createLogger("scanner:headers");

// ---------------------------------------------------------------------------
// Security Header Definitions
// ---------------------------------------------------------------------------

interface HeaderCheck {
  header: string;
  description: string;
  missingDescription: string;
  missingSeverity: Severity;
  cweId?: string;
  references: string[];
  validate: (value: string) => HeaderValidationResult;
}

interface HeaderValidationResult {
  isSecure: boolean;
  issues: string[];
  severity: Severity;
}

// ---------------------------------------------------------------------------
// CSP Analysis
// ---------------------------------------------------------------------------

function analyzeCSP(value: string): HeaderValidationResult {
  const issues: string[] = [];
  const directives = new Map<string, string[]>();

  value.split(";").forEach((part) => {
    const trimmed = part.trim();
    if (!trimmed) return;
    const tokens = trimmed.split(/\s+/);
    const directiveName = tokens[0].toLowerCase();
    directives.set(directiveName, tokens.slice(1));
  });

  // Check for unsafe-inline
  for (const [directive, sources] of directives) {
    if (
      sources.includes("'unsafe-inline'") &&
      (directive === "script-src" || directive === "default-src")
    ) {
      issues.push(
        `'unsafe-inline' in ${directive} allows inline script execution, negating XSS protection.`,
      );
    }
    if (
      sources.includes("'unsafe-eval'") &&
      (directive === "script-src" || directive === "default-src")
    ) {
      issues.push(
        `'unsafe-eval' in ${directive} allows eval() and similar, enabling code injection.`,
      );
    }
    if (sources.includes("*")) {
      issues.push(
        `Wildcard (*) in ${directive} allows loading resources from any domain.`,
      );
    }
    if (sources.includes("data:") && (directive === "script-src" || directive === "default-src")) {
      issues.push(
        `data: URI in ${directive} can be abused for script injection.`,
      );
    }
    if (sources.some((s) => s === "http:" || s === "https:")) {
      issues.push(
        `Overly broad scheme source (http: or https:) in ${directive} allows any host.`,
      );
    }
  }

  // Missing critical directives
  if (!directives.has("default-src") && !directives.has("script-src")) {
    issues.push("Missing both default-src and script-src directives.");
  }
  if (!directives.has("object-src") && !directives.get("default-src")?.includes("'none'")) {
    issues.push(
      "Missing object-src directive. Consider adding object-src 'none' to prevent plugin-based attacks.",
    );
  }
  if (!directives.has("base-uri")) {
    issues.push(
      "Missing base-uri directive. Consider adding base-uri 'self' to prevent base tag hijacking.",
    );
  }
  if (!directives.has("form-action")) {
    issues.push(
      "Missing form-action directive. Forms can submit data to any origin.",
    );
  }
  if (!directives.has("frame-ancestors")) {
    issues.push(
      "Missing frame-ancestors directive. Page can be framed by any origin (clickjacking risk).",
    );
  }

  const severity =
    issues.some(
      (i) =>
        i.includes("unsafe-inline") ||
        i.includes("unsafe-eval") ||
        i.includes("Wildcard"),
    )
      ? Severity.Medium
      : issues.length > 0
        ? Severity.Low
        : Severity.Info;

  return { isSecure: issues.length === 0, issues, severity };
}

// ---------------------------------------------------------------------------
// HSTS Analysis
// ---------------------------------------------------------------------------

function analyzeHSTS(value: string): HeaderValidationResult {
  const issues: string[] = [];
  const lowerValue = value.toLowerCase();

  const maxAgeMatch = /max-age=(\d+)/i.exec(value);
  if (!maxAgeMatch) {
    issues.push("Missing max-age directive in HSTS header.");
  } else {
    const maxAge = parseInt(maxAgeMatch[1], 10);
    if (maxAge < 31536000) {
      issues.push(
        `HSTS max-age is ${maxAge} seconds (${(maxAge / 86400).toFixed(0)} days). ` +
          `Recommended minimum is 31536000 (1 year).`,
      );
    }
    if (maxAge === 0) {
      issues.push("HSTS max-age is 0, effectively disabling HSTS.");
    }
  }

  if (!lowerValue.includes("includesubdomains")) {
    issues.push(
      "Missing includeSubDomains directive. Subdomains are not protected by HSTS.",
    );
  }

  if (!lowerValue.includes("preload")) {
    issues.push(
      "Missing preload directive. The domain is not eligible for HSTS preloading in browsers.",
    );
  }

  const severity = issues.some(
    (i) => i.includes("max-age is 0") || i.includes("Missing max-age"),
  )
    ? Severity.Medium
    : issues.length > 0
      ? Severity.Low
      : Severity.Info;

  return { isSecure: issues.length === 0, issues, severity };
}

// ---------------------------------------------------------------------------
// Header Check Definitions
// ---------------------------------------------------------------------------

const SECURITY_HEADERS: HeaderCheck[] = [
  {
    header: "content-security-policy",
    description: "Content Security Policy",
    missingDescription:
      "No Content-Security-Policy header found. The application is vulnerable to " +
      "cross-site scripting (XSS) attacks as the browser has no instruction to restrict " +
      "resource loading.",
    missingSeverity: Severity.Medium,
    cweId: "CWE-693",
    references: [
      "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
      "https://csp-evaluator.withgoogle.com/",
    ],
    validate: analyzeCSP,
  },
  {
    header: "strict-transport-security",
    description: "HTTP Strict Transport Security",
    missingDescription:
      "No Strict-Transport-Security header found. The application does not enforce " +
      "HTTPS connections, making it vulnerable to downgrade attacks and cookie hijacking.",
    missingSeverity: Severity.Medium,
    cweId: "CWE-319",
    references: [
      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
      "https://hstspreload.org/",
    ],
    validate: analyzeHSTS,
  },
  {
    header: "x-frame-options",
    description: "X-Frame-Options",
    missingDescription:
      "No X-Frame-Options header found. The page can be embedded in iframes on " +
      "any origin, making it vulnerable to clickjacking attacks.",
    missingSeverity: Severity.Medium,
    cweId: "CWE-1021",
    references: [
      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
    ],
    validate: (value: string): HeaderValidationResult => {
      const issues: string[] = [];
      const upper = value.toUpperCase().trim();
      if (upper !== "DENY" && upper !== "SAMEORIGIN" && !upper.startsWith("ALLOW-FROM")) {
        issues.push(`Invalid X-Frame-Options value: "${value}". Expected DENY or SAMEORIGIN.`);
      }
      if (upper.startsWith("ALLOW-FROM")) {
        issues.push(
          "ALLOW-FROM is deprecated and not supported by modern browsers. Use CSP frame-ancestors instead.",
        );
      }
      return {
        isSecure: issues.length === 0,
        issues,
        severity: issues.length > 0 ? Severity.Low : Severity.Info,
      };
    },
  },
  {
    header: "x-content-type-options",
    description: "X-Content-Type-Options",
    missingDescription:
      "No X-Content-Type-Options header found. The browser may MIME-sniff responses, " +
      "potentially interpreting non-script content as JavaScript.",
    missingSeverity: Severity.Low,
    cweId: "CWE-693",
    references: [
      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
    ],
    validate: (value: string): HeaderValidationResult => {
      const issues: string[] = [];
      if (value.trim().toLowerCase() !== "nosniff") {
        issues.push(
          `Expected "nosniff" but got "${value}". MIME-sniffing protection is not active.`,
        );
      }
      return {
        isSecure: issues.length === 0,
        issues,
        severity: issues.length > 0 ? Severity.Low : Severity.Info,
      };
    },
  },
  {
    header: "referrer-policy",
    description: "Referrer-Policy",
    missingDescription:
      "No Referrer-Policy header found. The browser may send the full URL (including " +
      "query parameters with sensitive data) in the Referer header to third parties.",
    missingSeverity: Severity.Low,
    references: [
      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
    ],
    validate: (value: string): HeaderValidationResult => {
      const issues: string[] = [];
      const insecureValues = ["unsafe-url", "no-referrer-when-downgrade"];
      const tokens = value.split(",").map((v) => v.trim().toLowerCase());
      for (const token of tokens) {
        if (insecureValues.includes(token)) {
          issues.push(
            `"${token}" leaks the full URL to all destinations. Use "strict-origin-when-cross-origin" or "no-referrer".`,
          );
        }
      }
      return {
        isSecure: issues.length === 0,
        issues,
        severity: issues.length > 0 ? Severity.Low : Severity.Info,
      };
    },
  },
  {
    header: "permissions-policy",
    description: "Permissions-Policy",
    missingDescription:
      "No Permissions-Policy header found. The browser may allow access to sensitive " +
      "APIs (camera, microphone, geolocation) from embedded third-party content.",
    missingSeverity: Severity.Low,
    references: [
      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
      "https://www.permissionspolicy.com/",
    ],
    validate: (value: string): HeaderValidationResult => {
      const issues: string[] = [];
      const sensitiveFeaturesDefault = [
        "camera",
        "microphone",
        "geolocation",
        "payment",
        "usb",
        "bluetooth",
        "midi",
      ];
      const lowerValue = value.toLowerCase();
      for (const feature of sensitiveFeaturesDefault) {
        if (lowerValue.includes(`${feature}=*`) || lowerValue.includes(`${feature}=("*")`)) {
          issues.push(
            `Feature "${feature}" is allowed for all origins. Consider restricting to self or specific origins.`,
          );
        }
      }
      return {
        isSecure: issues.length === 0,
        issues,
        severity: issues.length > 0 ? Severity.Low : Severity.Info,
      };
    },
  },
  {
    header: "x-xss-protection",
    description: "X-XSS-Protection",
    missingDescription:
      "No X-XSS-Protection header found. While this header is deprecated in modern browsers, " +
      "legacy browsers may lack built-in XSS filtering.",
    missingSeverity: Severity.Info,
    references: [
      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection",
    ],
    validate: (value: string): HeaderValidationResult => {
      const issues: string[] = [];
      if (value.trim() === "0") {
        issues.push(
          "X-XSS-Protection is explicitly disabled (value: 0). While this header is deprecated, " +
            "disabling it removes a defense-in-depth layer for legacy browsers.",
        );
      }
      if (value.includes("mode=block")) {
        // This is actually the recommended value for legacy support
      }
      return {
        isSecure: issues.length === 0,
        issues,
        severity: issues.length > 0 ? Severity.Info : Severity.Info,
      };
    },
  },
];

// ---------------------------------------------------------------------------
// Information Leakage Headers
// ---------------------------------------------------------------------------

const INFO_LEAK_HEADERS: Array<{
  header: string;
  description: string;
  severity: Severity;
}> = [
  { header: "server", description: "Server technology and version", severity: Severity.Info },
  { header: "x-powered-by", description: "Server-side framework/runtime", severity: Severity.Low },
  { header: "x-aspnet-version", description: "ASP.NET version", severity: Severity.Low },
  { header: "x-aspnetmvc-version", description: "ASP.NET MVC version", severity: Severity.Low },
  { header: "x-generator", description: "CMS or site generator", severity: Severity.Info },
  { header: "x-drupal-cache", description: "Drupal CMS", severity: Severity.Info },
  { header: "x-varnish", description: "Varnish cache server", severity: Severity.Info },
  { header: "x-request-id", description: "Internal request ID", severity: Severity.Info },
  { header: "x-runtime", description: "Server-side processing time", severity: Severity.Info },
  { header: "x-debug-token", description: "Debug token (Symfony)", severity: Severity.Medium },
  { header: "x-debug-token-link", description: "Debug profiler link", severity: Severity.Medium },
];

// ---------------------------------------------------------------------------
// Cookie Security Analysis
// ---------------------------------------------------------------------------

interface CookieIssue {
  cookieName: string;
  issues: string[];
  severity: Severity;
}

function analyzeCookies(setCookieHeaders: string[]): CookieIssue[] {
  const results: CookieIssue[] = [];

  for (const setCookie of setCookieHeaders) {
    const issues: string[] = [];
    const parts = setCookie.split(";").map((p) => p.trim());
    const nameValue = parts[0];
    const cookieName = nameValue.split("=")[0].trim();
    const lowerCookie = setCookie.toLowerCase();

    // Session-like cookie names
    const isSessionCookie =
      /^(session|sid|sess|ssid|phpsessid|jsessionid|asp\.net_sessionid|connect\.sid|token|jwt|auth|csrf|xsrf)/i.test(
        cookieName,
      );

    if (!lowerCookie.includes("httponly") && isSessionCookie) {
      issues.push(
        "Missing HttpOnly flag. Session cookie is accessible via JavaScript (document.cookie), " +
          "enabling theft via XSS attacks.",
      );
    }

    if (!lowerCookie.includes("secure") && isSessionCookie) {
      issues.push(
        "Missing Secure flag. Session cookie can be transmitted over unencrypted HTTP connections.",
      );
    }

    if (!lowerCookie.includes("samesite")) {
      issues.push(
        "Missing SameSite attribute. Cookie may be sent with cross-site requests, " +
          "potentially enabling CSRF attacks.",
      );
    } else if (lowerCookie.includes("samesite=none")) {
      if (!lowerCookie.includes("secure")) {
        issues.push(
          "SameSite=None requires the Secure flag. Without it, the cookie will be rejected by modern browsers.",
        );
      } else {
        issues.push(
          "SameSite=None allows the cookie to be sent with all cross-site requests. " +
            "Ensure this is intentional and the application has CSRF protection.",
        );
      }
    }

    // Check for __Secure- and __Host- prefixes
    if (
      cookieName.startsWith("__Secure-") &&
      !lowerCookie.includes("secure")
    ) {
      issues.push(
        `Cookie "${cookieName}" uses __Secure- prefix but lacks the Secure flag.`,
      );
    }
    if (cookieName.startsWith("__Host-")) {
      if (!lowerCookie.includes("secure")) {
        issues.push(
          `Cookie "${cookieName}" uses __Host- prefix but lacks the Secure flag.`,
        );
      }
      if (!lowerCookie.includes("path=/")) {
        issues.push(
          `Cookie "${cookieName}" uses __Host- prefix but Path is not set to "/".`,
        );
      }
    }

    if (issues.length > 0) {
      const hasCriticalIssue = issues.some(
        (i) => i.includes("HttpOnly") || (i.includes("Secure") && isSessionCookie),
      );
      results.push({
        cookieName,
        issues,
        severity: hasCriticalIssue ? Severity.Medium : Severity.Low,
      });
    }
  }

  return results;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function stealthDelay(baseMs: number): Promise<void> {
  const jitter = Math.floor(Math.random() * baseMs * 0.5);
  return new Promise((resolve) => setTimeout(resolve, baseMs + jitter));
}

// ---------------------------------------------------------------------------
// HeadersScanner Class
// ---------------------------------------------------------------------------

export class HeadersScanner implements ScanModule {
  public readonly name = "headers";

  private rateLimiter: RateLimiter;
  private userAgent: string;

  constructor() {
    this.rateLimiter = new RateLimiter(10);
    this.userAgent =
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36";
  }

  async *execute(
    target: string,
    options: Record<string, unknown>,
  ): AsyncGenerator<Finding> {
    log.info({ target }, "Starting security headers scan");

    const rateLimit = typeof options.rateLimit === "number" ? options.rateLimit : 10;
    this.rateLimiter = new RateLimiter(rateLimit);
    if (typeof options.userAgent === "string") {
      this.userAgent = options.userAgent;
    }

    // Fetch the target page
    await this.rateLimiter.acquire();
    let resp: HttpResponse;
    try {
      resp = await sendRequest({
        method: "GET",
        url: target,
        headers: {
          "User-Agent": this.userAgent,
          Accept: "text/html,application/xhtml+xml",
        },
      });
    } catch (err) {
      log.error({ error: err }, "Failed to fetch target");
      return;
    }

    // Phase 1: Check security headers
    yield* this.checkSecurityHeaders(target, resp);

    // Phase 2: Check for information leakage headers
    yield* this.checkInfoLeakHeaders(target, resp);

    // Phase 3: Cookie security analysis
    yield* this.checkCookieSecurity(target, resp);

    // Phase 4: Additional header-based checks on HTTPS
    yield* this.checkHttpsHeaders(target, resp);

    log.info({ target }, "Security headers scan complete");
  }

  // -------------------------------------------------------------------------
  // Phase 1: Security headers check
  // -------------------------------------------------------------------------

  private async *checkSecurityHeaders(
    target: string,
    resp: HttpResponse,
  ): AsyncGenerator<Finding> {
    for (const check of SECURITY_HEADERS) {
      const headerValue = resp.headers[check.header];

      if (!headerValue) {
        // Header is missing
        const vulnId = generateUUID();
        const vulnerability: Vulnerability = {
          id: vulnId,
          title: `Missing Security Header: ${check.description}`,
          description: check.missingDescription,
          severity: check.missingSeverity,
          category: VulnerabilityCategory.HeaderMisconfig,
          cvssScore:
            check.missingSeverity === Severity.Medium
              ? 5.3
              : check.missingSeverity === Severity.Low
                ? 3.7
                : 0.0,
          cvssVector:
            check.missingSeverity === Severity.Medium
              ? "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"
              : undefined,
          cweId: check.cweId,
          target,
          endpoint: target,
          evidence: {
            description: `The ${check.header} response header is not set.`,
            extra: { missingHeader: check.header },
          },
          remediation: `Add the ${check.description} header to all HTTP responses. See references for recommended values.`,
          references: check.references,
          confirmed: true,
          falsePositive: false,
          discoveredAt: new Date().toISOString(),
        };

        yield {
          vulnerability,
          module: `scanner:headers:missing_${check.header.replace(/-/g, "_")}`,
          confidence: 100,
          timestamp: new Date().toISOString(),
        };
      } else {
        // Header exists, validate its value
        const result = check.validate(headerValue);
        if (!result.isSecure) {
          const vulnId = generateUUID();
          const vulnerability: Vulnerability = {
            id: vulnId,
            title: `Weak ${check.description} Configuration`,
            description:
              `The ${check.description} header is present but has configuration issues:\n` +
              result.issues.map((i) => `- ${i}`).join("\n"),
            severity: result.severity,
            category: VulnerabilityCategory.HeaderMisconfig,
            cvssScore:
              result.severity === Severity.Medium
                ? 5.3
                : result.severity === Severity.Low
                  ? 3.7
                  : 0.0,
            cweId: check.cweId,
            target,
            endpoint: target,
            evidence: {
              description: `${check.header}: ${headerValue}`,
              matchedPattern: headerValue,
              extra: { headerValue, issues: result.issues },
            },
            remediation:
              result.issues.map((i, idx) => `${idx + 1}. Fix: ${i}`).join("\n") +
              "\nSee references for recommended configuration.",
            references: check.references,
            confirmed: true,
            falsePositive: false,
            discoveredAt: new Date().toISOString(),
          };

          yield {
            vulnerability,
            module: `scanner:headers:weak_${check.header.replace(/-/g, "_")}`,
            confidence: 95,
            timestamp: new Date().toISOString(),
          };
        }
      }
    }
  }

  // -------------------------------------------------------------------------
  // Phase 2: Information leakage headers
  // -------------------------------------------------------------------------

  private async *checkInfoLeakHeaders(
    target: string,
    resp: HttpResponse,
  ): AsyncGenerator<Finding> {
    const leakedHeaders: Array<{
      header: string;
      value: string;
      description: string;
      severity: Severity;
    }> = [];

    for (const check of INFO_LEAK_HEADERS) {
      const value = resp.headers[check.header];
      if (value) {
        leakedHeaders.push({
          header: check.header,
          value,
          description: check.description,
          severity: check.severity,
        });
      }
    }

    if (leakedHeaders.length === 0) return;

    // Group low/info severity headers into one finding
    const infoHeaders = leakedHeaders.filter(
      (h) => h.severity === Severity.Info || h.severity === Severity.Low,
    );
    const criticalHeaders = leakedHeaders.filter(
      (h) => h.severity === Severity.Medium || h.severity === Severity.High,
    );

    if (infoHeaders.length > 0) {
      const vulnId = generateUUID();
      const vulnerability: Vulnerability = {
        id: vulnId,
        title: "Information Leakage via HTTP Response Headers",
        description:
          `The server exposes technology details through HTTP response headers. ` +
          `This information assists attackers in fingerprinting the technology stack ` +
          `and identifying known vulnerabilities for the specific versions in use.\n\n` +
          `Leaked headers:\n` +
          infoHeaders.map((h) => `- ${h.header}: ${h.value} (${h.description})`).join("\n"),
        severity: Severity.Low,
        category: VulnerabilityCategory.InformationDisclosure,
        cvssScore: 3.7,
        cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        cweId: "CWE-200",
        target,
        endpoint: target,
        evidence: {
          description: infoHeaders
            .map((h) => `${h.header}: ${h.value}`)
            .join("; "),
          extra: Object.fromEntries(infoHeaders.map((h) => [h.header, h.value])),
        },
        remediation:
          "1. Remove or suppress the Server header or set it to a generic value.\n" +
          "2. Remove X-Powered-By, X-AspNet-Version, and similar headers.\n" +
          "3. Configure your web server/framework to not expose version information.\n" +
          "4. In Express.js, use helmet() middleware or app.disable('x-powered-by').\n" +
          "5. In Apache, use ServerTokens Prod and ServerSignature Off.\n" +
          "6. In Nginx, use server_tokens off.",
        references: [
          "https://owasp.org/www-project-secure-headers/",
          "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
        ],
        confirmed: true,
        falsePositive: false,
        discoveredAt: new Date().toISOString(),
      };

      yield {
        vulnerability,
        module: "scanner:headers:info_leak",
        confidence: 100,
        timestamp: new Date().toISOString(),
        rawData: Object.fromEntries(infoHeaders.map((h) => [h.header, h.value])),
      };
    }

    // Individual findings for medium/high severity info leak headers
    for (const header of criticalHeaders) {
      const vulnId = generateUUID();
      const vulnerability: Vulnerability = {
        id: vulnId,
        title: `Sensitive Information in ${header.header} Header`,
        description:
          `The server exposes "${header.header}: ${header.value}" which reveals ${header.description}. ` +
          `This may expose debug/profiler endpoints or internal system details.`,
        severity: header.severity,
        category: VulnerabilityCategory.InformationDisclosure,
        cvssScore: header.severity === Severity.Medium ? 5.3 : 3.7,
        cweId: "CWE-200",
        target,
        endpoint: target,
        evidence: {
          description: `${header.header}: ${header.value}`,
          matchedPattern: header.value,
        },
        remediation: `Remove the "${header.header}" header from production responses. This likely indicates a debug mode is enabled.`,
        references: [
          "https://owasp.org/www-project-secure-headers/",
        ],
        confirmed: true,
        falsePositive: false,
        discoveredAt: new Date().toISOString(),
      };

      yield {
        vulnerability,
        module: `scanner:headers:info_leak_${header.header.replace(/-/g, "_")}`,
        confidence: 100,
        timestamp: new Date().toISOString(),
      };
    }
  }

  // -------------------------------------------------------------------------
  // Phase 3: Cookie security
  // -------------------------------------------------------------------------

  private async *checkCookieSecurity(
    target: string,
    resp: HttpResponse,
  ): AsyncGenerator<Finding> {
    // Collect all Set-Cookie headers
    // Note: the HTTP utility normalizes headers to lowercase single values
    // In real world, there can be multiple Set-Cookie headers
    const setCookieRaw = resp.headers["set-cookie"] || "";
    if (!setCookieRaw) return;

    // Split on comma that is followed by a cookie name pattern
    // (handles multiple cookies in one header value)
    const cookies = setCookieRaw.split(/,(?=\s*[a-zA-Z_][a-zA-Z0-9_.-]*=)/);
    if (cookies.length === 0) return;

    const issues = analyzeCookies(cookies);
    if (issues.length === 0) return;

    for (const cookieIssue of issues) {
      const vulnId = generateUUID();
      const vulnerability: Vulnerability = {
        id: vulnId,
        title: `Insecure Cookie: ${cookieIssue.cookieName}`,
        description:
          `The cookie "${cookieIssue.cookieName}" has security configuration issues:\n` +
          cookieIssue.issues.map((i) => `- ${i}`).join("\n"),
        severity: cookieIssue.severity,
        category: VulnerabilityCategory.HeaderMisconfig,
        cvssScore:
          cookieIssue.severity === Severity.Medium
            ? 5.3
            : cookieIssue.severity === Severity.Low
              ? 3.7
              : 0.0,
        cvssVector:
          cookieIssue.severity === Severity.Medium
            ? "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
            : undefined,
        cweId: "CWE-614",
        target,
        endpoint: target,
        evidence: {
          description: cookieIssue.issues.join("; "),
          extra: {
            cookieName: cookieIssue.cookieName,
            issues: cookieIssue.issues,
          },
        },
        remediation:
          `1. Set the HttpOnly flag on session cookies: Set-Cookie: ${cookieIssue.cookieName}=value; HttpOnly\n` +
          `2. Set the Secure flag on all cookies: Set-Cookie: ${cookieIssue.cookieName}=value; Secure\n` +
          `3. Set SameSite=Lax or SameSite=Strict: Set-Cookie: ${cookieIssue.cookieName}=value; SameSite=Lax\n` +
          `4. Consider using __Host- or __Secure- cookie prefixes.`,
        references: [
          "https://owasp.org/www-community/controls/SecureCookieAttribute",
          "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies",
        ],
        confirmed: true,
        falsePositive: false,
        discoveredAt: new Date().toISOString(),
      };

      yield {
        vulnerability,
        module: "scanner:headers:cookie_security",
        confidence: 100,
        timestamp: new Date().toISOString(),
        rawData: { cookieName: cookieIssue.cookieName, issues: cookieIssue.issues },
      };
    }
  }

  // -------------------------------------------------------------------------
  // Phase 4: HTTPS-specific checks
  // -------------------------------------------------------------------------

  private async *checkHttpsHeaders(
    target: string,
    _resp: HttpResponse,
  ): AsyncGenerator<Finding> {
    // Check if HTTP version redirects to HTTPS
    const url = new URL(target);
    if (url.protocol === "https:") {
      const httpUrl = target.replace("https://", "http://");

      await this.rateLimiter.acquire();
      await stealthDelay(100);

      try {
        // Fetch without following redirects to check redirect behavior
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 10000);

        try {
          const httpResp = await fetch(httpUrl, {
            method: "GET",
            redirect: "manual",
            signal: controller.signal,
            headers: { "User-Agent": this.userAgent },
          });

          if (
            httpResp.status !== 301 &&
            httpResp.status !== 302 &&
            httpResp.status !== 307 &&
            httpResp.status !== 308
          ) {
            const vulnId = generateUUID();
            const vulnerability: Vulnerability = {
              id: vulnId,
              title: "HTTP to HTTPS Redirect Not Enforced",
              description:
                `The HTTP version of the site (${httpUrl}) does not redirect to HTTPS. ` +
                `Users accessing the site over HTTP will have their traffic transmitted ` +
                `in cleartext, vulnerable to interception and modification.`,
              severity: Severity.Medium,
              category: VulnerabilityCategory.HeaderMisconfig,
              cvssScore: 5.3,
              cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
              cweId: "CWE-319",
              target,
              endpoint: httpUrl,
              evidence: {
                description: `HTTP request returned status ${httpResp.status} instead of a redirect to HTTPS.`,
                extra: { httpStatus: httpResp.status },
              },
              remediation:
                "1. Configure a permanent redirect (301) from HTTP to HTTPS for all paths.\n" +
                "2. Enable HSTS with a long max-age to prevent future HTTP requests.\n" +
                "3. Submit the domain to the HSTS preload list.",
              references: [
                "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
              ],
              confirmed: true,
              falsePositive: false,
              discoveredAt: new Date().toISOString(),
            };

            yield {
              vulnerability,
              module: "scanner:headers:http_redirect",
              confidence: 100,
              timestamp: new Date().toISOString(),
            };
          }
        } finally {
          clearTimeout(timeout);
        }
      } catch {
        // HTTP port may not be accessible, which is fine
      }
    }
  }
}
