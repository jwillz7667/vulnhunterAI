// =============================================================================
// VulnHunter AI - API Fuzzer Scanner Module
// =============================================================================
// Discovers and fuzzes REST API endpoints, tests HTTP methods, discovers
// parameters, manipulates content types, detects rate limits, and tests for
// mass assignment vulnerabilities.
// CWE-20 | CVSS varies by finding type
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

const log = createLogger("scanner:api-fuzzer");

// ---------------------------------------------------------------------------
// Common API Endpoint Patterns
// ---------------------------------------------------------------------------

const API_PREFIXES: string[] = [
  "/api",
  "/api/v1",
  "/api/v2",
  "/api/v3",
  "/v1",
  "/v2",
  "/v3",
  "/rest",
  "/rest/v1",
  "/graphql",
];

const API_RESOURCES: string[] = [
  "users",
  "user",
  "accounts",
  "account",
  "profiles",
  "profile",
  "me",
  "admin",
  "config",
  "configuration",
  "settings",
  "preferences",
  "organizations",
  "orgs",
  "teams",
  "groups",
  "roles",
  "permissions",
  "auth",
  "login",
  "logout",
  "register",
  "signup",
  "password",
  "reset",
  "token",
  "tokens",
  "session",
  "sessions",
  "orders",
  "order",
  "products",
  "product",
  "items",
  "item",
  "invoices",
  "payments",
  "subscriptions",
  "plans",
  "files",
  "uploads",
  "documents",
  "images",
  "media",
  "comments",
  "posts",
  "articles",
  "messages",
  "notifications",
  "events",
  "logs",
  "audit",
  "health",
  "status",
  "info",
  "version",
  "docs",
  "swagger",
  "openapi",
  "schema",
  "debug",
  "test",
  "internal",
  "private",
  "search",
  "export",
  "import",
  "backup",
  "webhooks",
  "callbacks",
  "cron",
  "jobs",
  "queue",
  "workers",
  "metrics",
  "analytics",
  "reports",
  "dashboard",
  "admin/users",
  "admin/settings",
  "admin/config",
];

const HTTP_METHODS: string[] = [
  "GET",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "OPTIONS",
  "HEAD",
];

// Common API parameter names for discovery
const COMMON_PARAMS: string[] = [
  "id",
  "user_id",
  "email",
  "username",
  "name",
  "password",
  "role",
  "admin",
  "is_admin",
  "status",
  "type",
  "category",
  "page",
  "limit",
  "offset",
  "sort",
  "order",
  "filter",
  "q",
  "query",
  "search",
  "fields",
  "include",
  "expand",
  "embed",
  "format",
  "callback",
  "token",
  "api_key",
  "key",
  "secret",
  "debug",
  "verbose",
  "pretty",
  "raw",
];

// Mass assignment sensitive fields
const MASS_ASSIGNMENT_FIELDS: Array<{ field: string; value: unknown; description: string }> = [
  { field: "role", value: "admin", description: "Role escalation to admin" },
  { field: "is_admin", value: true, description: "Admin flag escalation" },
  { field: "isAdmin", value: true, description: "Admin flag escalation (camelCase)" },
  { field: "admin", value: true, description: "Admin flag escalation" },
  { field: "is_superuser", value: true, description: "Superuser escalation" },
  { field: "permissions", value: ["*"], description: "Wildcard permissions" },
  { field: "verified", value: true, description: "Account verification bypass" },
  { field: "email_verified", value: true, description: "Email verification bypass" },
  { field: "active", value: true, description: "Account activation bypass" },
  { field: "banned", value: false, description: "Ban removal" },
  { field: "balance", value: 999999, description: "Balance manipulation" },
  { field: "credits", value: 999999, description: "Credits manipulation" },
  { field: "discount", value: 100, description: "Discount manipulation" },
  { field: "price", value: 0, description: "Price manipulation" },
  { field: "plan", value: "enterprise", description: "Plan escalation" },
  { field: "tier", value: "premium", description: "Tier escalation" },
  { field: "created_by", value: "admin", description: "Creator manipulation" },
  { field: "org_id", value: "1", description: "Organization manipulation" },
  { field: "tenant_id", value: "1", description: "Tenant manipulation" },
];

// Fuzz values for parameter type testing
const FUZZ_VALUES: Array<{ value: string; type: string }> = [
  { value: "", type: "empty" },
  { value: "null", type: "null_string" },
  { value: "undefined", type: "undefined_string" },
  { value: "true", type: "boolean" },
  { value: "false", type: "boolean" },
  { value: "0", type: "zero" },
  { value: "-1", type: "negative" },
  { value: "99999999999", type: "large_number" },
  { value: "1.1", type: "float" },
  { value: "NaN", type: "nan" },
  { value: "Infinity", type: "infinity" },
  { value: "../../../etc/passwd", type: "path_traversal" },
  { value: "${7*7}", type: "template_injection" },
  { value: "{{7*7}}", type: "ssti" },
  { value: "<script>alert(1)</script>", type: "xss" },
  { value: "' OR '1'='1", type: "sqli" },
  { value: "a".repeat(10000), type: "overflow" },
  { value: "%00", type: "null_byte" },
  { value: "\r\n\r\n", type: "crlf" },
  { value: "[]", type: "empty_array" },
  { value: "{}", type: "empty_object" },
  { value: "SELECT * FROM users", type: "sql" },
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function stealthDelay(baseMs: number): Promise<void> {
  const jitter = Math.floor(Math.random() * baseMs * 0.5);
  return new Promise((resolve) => setTimeout(resolve, baseMs + jitter));
}

function buildApiFinding(params: {
  target: string;
  endpoint: string;
  method: string;
  findingType: string;
  confidence: number;
  evidence: string;
  responseBody: string;
  responseStatus: number;
  severity: Severity;
  cweId: string;
  cvssScore: number;
  remediation: string;
}): Finding {
  const vulnId = generateUUID();

  const vulnerability: Vulnerability = {
    id: vulnId,
    title: `API ${params.findingType} at ${params.endpoint}`,
    description:
      `An API vulnerability (${params.findingType}) was detected at ${params.endpoint} ` +
      `using the ${params.method} method. ${params.evidence}`,
    severity: params.severity,
    category: VulnerabilityCategory.APIVuln,
    cvssScore: params.cvssScore,
    cvssVector:
      params.severity === Severity.High
        ? "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"
        : params.severity === Severity.Medium
          ? "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"
          : "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    cweId: params.cweId,
    target: params.target,
    endpoint: params.endpoint,
    evidence: {
      description: params.evidence,
      extra: { findingType: params.findingType, method: params.method },
    },
    request: {
      method: params.method,
      url: params.endpoint,
      headers: {},
    },
    response: {
      statusCode: params.responseStatus,
      headers: {},
      body: params.responseBody.slice(0, 2000),
      responseTimeMs: 0,
    },
    remediation: params.remediation,
    references: [
      "https://owasp.org/API-Security/",
      "https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html",
    ],
    confirmed: params.confidence >= 80,
    falsePositive: false,
    discoveredAt: new Date().toISOString(),
  };

  return {
    vulnerability,
    module: `scanner:api_fuzzer:${params.findingType.toLowerCase().replace(/[- /]/g, "_")}`,
    confidence: params.confidence,
    timestamp: new Date().toISOString(),
    rawData: { endpoint: params.endpoint, method: params.method, findingType: params.findingType },
  };
}

// ---------------------------------------------------------------------------
// ApiFuzzer Class
// ---------------------------------------------------------------------------

export class ApiFuzzer implements ScanModule {
  public readonly name = "api-fuzzer";

  private rateLimiter: RateLimiter;
  private userAgent: string;
  private discoveredEndpoints: Map<string, Set<string>>; // endpoint -> allowed methods

  constructor() {
    this.rateLimiter = new RateLimiter(8);
    this.userAgent =
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36";
    this.discoveredEndpoints = new Map();
  }

  async *execute(
    target: string,
    options: Record<string, unknown>,
  ): AsyncGenerator<Finding> {
    log.info({ target }, "Starting API fuzzer scan");

    const rateLimit = typeof options.rateLimit === "number" ? options.rateLimit : 8;
    this.rateLimiter = new RateLimiter(rateLimit);
    if (typeof options.userAgent === "string") {
      this.userAgent = options.userAgent;
    }

    const authHeaders: Record<string, string> = {};
    if (options.authToken && typeof options.authToken === "string") {
      authHeaders["Authorization"] = `Bearer ${options.authToken}`;
    }
    if (options.cookie && typeof options.cookie === "string") {
      authHeaders["Cookie"] = options.cookie;
    }

    // Phase 1: API endpoint discovery
    yield* this.discoverEndpoints(target, authHeaders);

    // Phase 2: HTTP method fuzzing
    yield* this.fuzzMethods(target, authHeaders);

    // Phase 3: Content-Type manipulation
    yield* this.fuzzContentType(target, authHeaders);

    // Phase 4: Parameter discovery and type fuzzing
    yield* this.fuzzParameters(target, authHeaders);

    // Phase 5: Rate limit detection
    yield* this.detectRateLimits(target, authHeaders);

    // Phase 6: Mass assignment testing
    yield* this.testMassAssignment(target, authHeaders);

    // Phase 7: API documentation exposure
    yield* this.checkApiDocs(target);

    log.info({ target }, "API fuzzer scan complete");
  }

  // -------------------------------------------------------------------------
  // Phase 1: API endpoint discovery
  // -------------------------------------------------------------------------

  private async *discoverEndpoints(
    target: string,
    authHeaders: Record<string, string>,
  ): AsyncGenerator<Finding> {
    const baseUrl = new URL(target).origin;
    let discoveredCount = 0;

    for (const prefix of API_PREFIXES) {
      for (const resource of API_RESOURCES) {
        const endpointUrl = `${baseUrl}${prefix}/${resource}`;

        await this.rateLimiter.acquire();
        await stealthDelay(50);

        try {
          const resp = await sendRequest({
            method: "GET",
            url: endpointUrl,
            headers: {
              "User-Agent": this.userAgent,
              Accept: "application/json,text/html,*/*",
              ...authHeaders,
            },
          });

          // Consider it discovered if it returns something other than 404
          if (resp.status !== 404 && resp.status < 500) {
            this.discoveredEndpoints.set(
              endpointUrl,
              new Set(["GET"]),
            );
            discoveredCount++;

            // Check for unauthenticated access to sensitive endpoints
            const sensitiveResources = [
              "admin",
              "config",
              "internal",
              "debug",
              "settings",
              "users",
              "logs",
              "audit",
              "backup",
              "export",
            ];
            const isSensitive = sensitiveResources.some((s) =>
              resource.toLowerCase().includes(s),
            );

            if (
              isSensitive &&
              resp.status === 200 &&
              Object.keys(authHeaders).length === 0
            ) {
              yield buildApiFinding({
                target,
                endpoint: endpointUrl,
                method: "GET",
                findingType: "Unauthenticated Sensitive Endpoint",
                confidence: 75,
                evidence:
                  `Sensitive API endpoint "${prefix}/${resource}" is accessible without authentication. ` +
                  `Response: HTTP ${resp.status}, ${resp.body.length} bytes.`,
                responseBody: resp.body,
                responseStatus: resp.status,
                severity: Severity.High,
                cweId: "CWE-306",
                cvssScore: 7.5,
                remediation:
                  "1. Implement authentication on all sensitive API endpoints.\n" +
                  "2. Use middleware to enforce auth checks before route handlers.\n" +
                  "3. Return 401/403 for unauthenticated requests to protected resources.",
              });
            }
          }
        } catch {
          continue;
        }
      }
    }

    log.info({ discoveredCount }, "API endpoint discovery complete");
  }

  // -------------------------------------------------------------------------
  // Phase 2: HTTP method fuzzing
  // -------------------------------------------------------------------------

  private async *fuzzMethods(
    target: string,
    authHeaders: Record<string, string>,
  ): AsyncGenerator<Finding> {
    // Test methods on discovered endpoints
    const endpoints = Array.from(this.discoveredEndpoints.keys()).slice(0, 20);

    for (const endpoint of endpoints) {
      for (const method of HTTP_METHODS) {
        if (method === "GET") continue; // Already tested during discovery

        await this.rateLimiter.acquire();
        await stealthDelay(50);

        try {
          const resp = await sendRequest({
            method,
            url: endpoint,
            headers: {
              "User-Agent": this.userAgent,
              Accept: "application/json,*/*",
              "Content-Type": "application/json",
              ...authHeaders,
            },
            body:
              method !== "HEAD" && method !== "OPTIONS"
                ? JSON.stringify({ test: "vulnhunter" })
                : undefined,
          });

          if (resp.status !== 404 && resp.status !== 405 && resp.status < 500) {
            const methods = this.discoveredEndpoints.get(endpoint) || new Set();
            methods.add(method);
            this.discoveredEndpoints.set(endpoint, methods);

            // Dangerous method without auth
            if (
              (method === "DELETE" || method === "PUT" || method === "PATCH") &&
              (resp.status === 200 || resp.status === 204) &&
              Object.keys(authHeaders).length === 0
            ) {
              yield buildApiFinding({
                target,
                endpoint,
                method,
                findingType: "Unprotected Destructive Method",
                confidence: 70,
                evidence:
                  `${method} method on ${endpoint} returned HTTP ${resp.status} without authentication. ` +
                  `This could allow unauthenticated data modification or deletion.`,
                responseBody: resp.body,
                responseStatus: resp.status,
                severity: Severity.High,
                cweId: "CWE-306",
                cvssScore: 8.1,
                remediation:
                  "1. Require authentication for all write operations (POST, PUT, PATCH, DELETE).\n" +
                  "2. Implement proper authorization checks.\n" +
                  "3. Use the OPTIONS method to declare allowed methods.",
              });
            }
          }

          // TRACE method (XST attack)
          if (method === "OPTIONS" && resp.status === 200) {
            const allow = resp.headers["allow"] || "";
            if (allow.toUpperCase().includes("TRACE")) {
              yield buildApiFinding({
                target,
                endpoint,
                method: "TRACE",
                findingType: "TRACE Method Enabled",
                confidence: 90,
                evidence:
                  `TRACE method is allowed on ${endpoint} (Allow: ${allow}). ` +
                  `TRACE can be used for Cross-Site Tracing (XST) attacks to steal credentials.`,
                responseBody: resp.body,
                responseStatus: resp.status,
                severity: Severity.Low,
                cweId: "CWE-693",
                cvssScore: 3.7,
                remediation: "Disable the TRACE HTTP method on the server.",
              });
            }
          }
        } catch {
          continue;
        }
      }
    }
  }

  // -------------------------------------------------------------------------
  // Phase 3: Content-Type manipulation
  // -------------------------------------------------------------------------

  private async *fuzzContentType(
    target: string,
    authHeaders: Record<string, string>,
  ): AsyncGenerator<Finding> {
    const endpoints = Array.from(this.discoveredEndpoints.entries())
      .filter(([_, methods]) => methods.has("POST") || methods.has("PUT"))
      .map(([ep]) => ep)
      .slice(0, 10);

    const contentTypes = [
      { type: "application/json", body: '{"test":"vulnhunter"}' },
      { type: "application/xml", body: '<?xml version="1.0"?><test>vulnhunter</test>' },
      {
        type: "application/xml",
        body: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>',
      },
      { type: "application/x-www-form-urlencoded", body: "test=vulnhunter" },
      { type: "text/plain", body: "test=vulnhunter" },
      { type: "multipart/form-data; boundary=----VulnHunter", body: "------VulnHunter\r\nContent-Disposition: form-data; name=\"test\"\r\n\r\nvulnhunter\r\n------VulnHunter--" },
    ];

    for (const endpoint of endpoints) {
      let baselineResp: HttpResponse | null = null;
      try {
        await this.rateLimiter.acquire();
        baselineResp = await sendRequest({
          method: "POST",
          url: endpoint,
          headers: {
            "User-Agent": this.userAgent,
            "Content-Type": "application/json",
            Accept: "*/*",
            ...authHeaders,
          },
          body: '{"test":"vulnhunter"}',
        });
      } catch {
        continue;
      }

      for (const ct of contentTypes) {
        await this.rateLimiter.acquire();
        await stealthDelay(100);

        try {
          const resp = await sendRequest({
            method: "POST",
            url: endpoint,
            headers: {
              "User-Agent": this.userAgent,
              "Content-Type": ct.type,
              Accept: "*/*",
              ...authHeaders,
            },
            body: ct.body,
          });

          // XXE detection via XML content type
          if (
            ct.type === "application/xml" &&
            ct.body.includes("xxe") &&
            (resp.body.includes("root:") ||
              resp.body.includes("/bin/") ||
              resp.body.includes("passwd"))
          ) {
            yield buildApiFinding({
              target,
              endpoint,
              method: "POST",
              findingType: "XXE via Content-Type Manipulation",
              confidence: 95,
              evidence:
                `Endpoint accepts XML content type and processes external entities. ` +
                `File content from /etc/passwd was returned in response.`,
              responseBody: resp.body,
              responseStatus: resp.status,
              severity: Severity.Critical,
              cweId: "CWE-611",
              cvssScore: 9.1,
              remediation:
                "1. Disable external entity processing in XML parsers.\n" +
                "2. Validate and restrict accepted Content-Type headers.\n" +
                "3. Use JSON instead of XML where possible.",
            });
          }

          // Content-type confusion (accepts unexpected types)
          if (
            ct.type !== "application/json" &&
            ct.type !== "application/x-www-form-urlencoded" &&
            resp.status >= 200 &&
            resp.status < 300 &&
            baselineResp &&
            resp.status === baselineResp.status
          ) {
            // Just note it, not necessarily a vulnerability
            log.debug(
              { endpoint, contentType: ct.type },
              "Endpoint accepts alternative content type",
            );
          }
        } catch {
          continue;
        }
      }
    }
  }

  // -------------------------------------------------------------------------
  // Phase 4: Parameter discovery and type fuzzing
  // -------------------------------------------------------------------------

  private async *fuzzParameters(
    target: string,
    authHeaders: Record<string, string>,
  ): AsyncGenerator<Finding> {
    const endpoints = Array.from(this.discoveredEndpoints.keys()).slice(0, 10);

    for (const endpoint of endpoints) {
      // Probe for accepted parameters
      for (const fuzz of FUZZ_VALUES.slice(0, 10)) {
        const paramUrl = new URL(endpoint);
        paramUrl.searchParams.set("_test_param", fuzz.value);

        await this.rateLimiter.acquire();
        await stealthDelay(50);

        try {
          const resp = await sendRequest({
            method: "GET",
            url: paramUrl.toString(),
            headers: {
              "User-Agent": this.userAgent,
              Accept: "application/json,*/*",
              ...authHeaders,
            },
          });

          // Check for error messages that reveal internal details
          const errorPatterns = [
            { pattern: /stack\s*trace/i, type: "Stack Trace Exposure" },
            { pattern: /traceback|File ".*\.py"/i, type: "Python Traceback" },
            { pattern: /at\s+\S+\.java:\d+/i, type: "Java Stack Trace" },
            { pattern: /at\s+\S+\s+\(\S+\.js:\d+:\d+\)/i, type: "Node.js Stack Trace" },
            { pattern: /TypeError|ReferenceError|SyntaxError/i, type: "JavaScript Error" },
            { pattern: /Fatal error|Parse error|Warning:/i, type: "PHP Error" },
            { pattern: /ActiveRecord::RecordNotFound/i, type: "Rails Error" },
            { pattern: /SQLSTATE\[/i, type: "Database Error" },
            { pattern: /Microsoft\.AspNetCore|System\.Exception/i, type: ".NET Error" },
          ];

          for (const ep of errorPatterns) {
            if (ep.pattern.test(resp.body)) {
              yield buildApiFinding({
                target,
                endpoint: paramUrl.toString(),
                method: "GET",
                findingType: `Verbose Error (${ep.type})`,
                confidence: 85,
                evidence:
                  `Input value "${fuzz.value}" (type: ${fuzz.type}) triggered a verbose error response. ` +
                  `Error type: ${ep.type}. This leaks internal implementation details.`,
                responseBody: resp.body,
                responseStatus: resp.status,
                severity: Severity.Medium,
                cweId: "CWE-209",
                cvssScore: 5.3,
                remediation:
                  "1. Implement proper error handling that returns generic error messages.\n" +
                  "2. Log detailed errors server-side, never expose to clients.\n" +
                  "3. Use structured error responses with error codes, not stack traces.",
              });
              break;
            }
          }
        } catch {
          continue;
        }
      }
    }
  }

  // -------------------------------------------------------------------------
  // Phase 5: Rate limit detection
  // -------------------------------------------------------------------------

  private async *detectRateLimits(
    target: string,
    authHeaders: Record<string, string>,
  ): AsyncGenerator<Finding> {
    // Pick sensitive endpoints to test for rate limiting
    const sensitiveEndpoints: string[] = [];
    for (const [endpoint] of this.discoveredEndpoints) {
      const lower = endpoint.toLowerCase();
      if (
        lower.includes("login") ||
        lower.includes("auth") ||
        lower.includes("register") ||
        lower.includes("password") ||
        lower.includes("reset") ||
        lower.includes("token")
      ) {
        sensitiveEndpoints.push(endpoint);
      }
    }

    // Also check the target directly if it looks auth-related
    const targetLower = target.toLowerCase();
    if (
      targetLower.includes("login") ||
      targetLower.includes("auth") ||
      targetLower.includes("register")
    ) {
      sensitiveEndpoints.push(target);
    }

    for (const endpoint of sensitiveEndpoints.slice(0, 5)) {
      let rateLimited = false;
      const requestCount = 20;

      for (let i = 0; i < requestCount; i++) {
        try {
          const resp = await sendRequest({
            method: "POST",
            url: endpoint,
            headers: {
              "User-Agent": this.userAgent,
              "Content-Type": "application/json",
              Accept: "application/json",
              ...authHeaders,
            },
            body: JSON.stringify({
              username: `test_user_${i}`,
              password: `test_pass_${i}`,
            }),
          });

          if (resp.status === 429 || resp.headers["retry-after"]) {
            rateLimited = true;
            break;
          }
        } catch {
          break;
        }
      }

      if (!rateLimited) {
        yield buildApiFinding({
          target,
          endpoint,
          method: "POST",
          findingType: "Missing Rate Limiting",
          confidence: 70,
          evidence:
            `${requestCount} rapid requests to ${endpoint} were all accepted without rate limiting. ` +
            `This endpoint handles authentication and should have rate limiting to prevent brute-force attacks.`,
          responseBody: "",
          responseStatus: 200,
          severity: Severity.Medium,
          cweId: "CWE-307",
          cvssScore: 5.3,
          remediation:
            "1. Implement rate limiting on authentication endpoints (e.g., 5 attempts per minute).\n" +
            "2. Use exponential backoff or account lockout after failed attempts.\n" +
            "3. Add CAPTCHA after multiple failed login attempts.\n" +
            "4. Return 429 Too Many Requests with Retry-After header.",
        });
      }
    }
  }

  // -------------------------------------------------------------------------
  // Phase 6: Mass assignment testing
  // -------------------------------------------------------------------------

  private async *testMassAssignment(
    target: string,
    authHeaders: Record<string, string>,
  ): AsyncGenerator<Finding> {
    // Find endpoints that accept POST/PUT/PATCH with JSON
    const writeEndpoints = Array.from(this.discoveredEndpoints.entries())
      .filter(
        ([_, methods]) =>
          methods.has("POST") || methods.has("PUT") || methods.has("PATCH"),
      )
      .map(([ep]) => ep)
      .slice(0, 10);

    for (const endpoint of writeEndpoints) {
      // First, try a normal request to establish baseline
      await this.rateLimiter.acquire();

      let baselineResp: HttpResponse;
      try {
        baselineResp = await sendRequest({
          method: "POST",
          url: endpoint,
          headers: {
            "User-Agent": this.userAgent,
            "Content-Type": "application/json",
            Accept: "application/json",
            ...authHeaders,
          },
          body: JSON.stringify({ name: "vulnhunter_test" }),
        });
      } catch {
        continue;
      }

      // Skip if endpoint returned error
      if (baselineResp.status >= 400) continue;

      // Try mass assignment with sensitive fields
      const massAssignPayload: Record<string, unknown> = {
        name: "vulnhunter_test",
      };
      for (const field of MASS_ASSIGNMENT_FIELDS) {
        massAssignPayload[field.field] = field.value;
      }

      await this.rateLimiter.acquire();
      await stealthDelay(200);

      try {
        const resp = await sendRequest({
          method: "POST",
          url: endpoint,
          headers: {
            "User-Agent": this.userAgent,
            "Content-Type": "application/json",
            Accept: "application/json",
            ...authHeaders,
          },
          body: JSON.stringify(massAssignPayload),
        });

        if (resp.status >= 200 && resp.status < 300) {
          // Check if any sensitive fields appear in the response
          const acceptedFields: string[] = [];
          try {
            const responseData = JSON.parse(resp.body);
            const responseStr = JSON.stringify(responseData);
            for (const field of MASS_ASSIGNMENT_FIELDS) {
              if (responseStr.includes(`"${field.field}"`) && responseStr.includes(String(field.value))) {
                acceptedFields.push(`${field.field}=${JSON.stringify(field.value)}`);
              }
            }
          } catch {
            // Response not JSON, can't verify
          }

          if (acceptedFields.length > 0) {
            yield buildApiFinding({
              target,
              endpoint,
              method: "POST",
              findingType: "Mass Assignment",
              confidence: 80,
              evidence:
                `Endpoint accepted and returned sensitive fields in the response: ` +
                `${acceptedFields.join(", ")}. ` +
                `An attacker can manipulate these fields to escalate privileges.`,
              responseBody: resp.body,
              responseStatus: resp.status,
              severity: Severity.High,
              cweId: "CWE-915",
              cvssScore: 8.1,
              remediation:
                "1. Use DTOs/allowlists to explicitly define which fields can be set by users.\n" +
                "2. Never bind raw request data directly to database models.\n" +
                "3. Separate admin-only fields from user-writable fields.\n" +
                "4. Use framework-specific mass assignment protection (e.g., guard/fillable in Laravel).",
            });
          }
        }
      } catch {
        continue;
      }
    }
  }

  // -------------------------------------------------------------------------
  // Phase 7: API documentation exposure
  // -------------------------------------------------------------------------

  private async *checkApiDocs(target: string): AsyncGenerator<Finding> {
    const baseUrl = new URL(target).origin;
    const docPaths = [
      "/swagger",
      "/swagger/",
      "/swagger-ui",
      "/swagger-ui/",
      "/swagger-ui.html",
      "/swagger.json",
      "/swagger/v1/swagger.json",
      "/api-docs",
      "/api-docs/",
      "/api/docs",
      "/docs",
      "/docs/",
      "/openapi",
      "/openapi.json",
      "/openapi.yaml",
      "/v1/openapi.json",
      "/v2/api-docs",
      "/v3/api-docs",
      "/redoc",
      "/graphiql",
      "/graphql/playground",
      "/playground",
      "/.well-known/openapi.json",
    ];

    for (const docPath of docPaths) {
      const docUrl = `${baseUrl}${docPath}`;

      await this.rateLimiter.acquire();
      await stealthDelay(50);

      try {
        const resp = await sendRequest({
          method: "GET",
          url: docUrl,
          headers: {
            "User-Agent": this.userAgent,
            Accept: "text/html,application/json,*/*",
          },
        });

        if (resp.status === 200 && resp.body.length > 200) {
          // Check for API doc indicators
          const isApiDoc =
            resp.body.includes("swagger") ||
            resp.body.includes("openapi") ||
            resp.body.includes("api-docs") ||
            resp.body.includes("GraphiQL") ||
            resp.body.includes("graphql-playground") ||
            resp.body.includes('"paths"') ||
            resp.body.includes('"info"') ||
            resp.body.includes("Swagger UI") ||
            resp.body.includes("redoc");

          if (isApiDoc) {
            yield buildApiFinding({
              target,
              endpoint: docUrl,
              method: "GET",
              findingType: "Exposed API Documentation",
              confidence: 90,
              evidence:
                `API documentation is publicly accessible at ${docUrl} without authentication. ` +
                `This reveals endpoint structure, parameter schemas, and authentication requirements.`,
              responseBody: resp.body,
              responseStatus: resp.status,
              severity: Severity.Low,
              cweId: "CWE-200",
              cvssScore: 3.7,
              remediation:
                "1. Restrict API documentation to authenticated/internal users only.\n" +
                "2. Remove or disable documentation endpoints in production.\n" +
                "3. If documentation must be public, ensure it does not reveal sensitive internal endpoints.",
            });
          }
        }
      } catch {
        continue;
      }
    }
  }
}
