// =============================================================================
// VulnHunter AI - IDOR / Broken Access Control Scanner Module
// =============================================================================
// Detects Insecure Direct Object Reference vulnerabilities by manipulating
// resource identifiers in URLs, parameters, and request bodies.
// CWE-639 | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N (6.5 base)
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

const log = createLogger("scanner:idor");

// ---------------------------------------------------------------------------
// Patterns that indicate numeric IDs in URLs
// ---------------------------------------------------------------------------

const ID_PATH_PATTERNS: RegExp[] = [
  /\/(\d+)(?:\/|$|\?)/,              // /123 or /123/ or /123?
  /\/users?\/(\d+)/i,                // /user/123 or /users/123
  /\/accounts?\/(\d+)/i,             // /account/123
  /\/profiles?\/(\d+)/i,             // /profile/123
  /\/orders?\/(\d+)/i,               // /order/123
  /\/invoices?\/(\d+)/i,             // /invoice/123
  /\/posts?\/(\d+)/i,                // /post/123
  /\/articles?\/(\d+)/i,             // /article/123
  /\/comments?\/(\d+)/i,             // /comment/123
  /\/messages?\/(\d+)/i,             // /message/123
  /\/files?\/(\d+)/i,                // /file/123
  /\/documents?\/(\d+)/i,            // /document/123
  /\/items?\/(\d+)/i,                // /item/123
  /\/products?\/(\d+)/i,             // /product/123
  /\/transactions?\/(\d+)/i,         // /transaction/123
  /\/reports?\/(\d+)/i,              // /report/123
  /\/tickets?\/(\d+)/i,              // /ticket/123
  /\/projects?\/(\d+)/i,             // /project/123
  /\/settings?\/(\d+)/i,             // /settings/123
  /\/api\/v\d+\/\w+\/(\d+)/i,        // /api/v1/resource/123
];

// Parameter names likely to contain object IDs
const ID_PARAM_NAMES: string[] = [
  "id",
  "user_id",
  "userId",
  "uid",
  "account_id",
  "accountId",
  "profile_id",
  "order_id",
  "orderId",
  "invoice_id",
  "post_id",
  "postId",
  "comment_id",
  "message_id",
  "file_id",
  "fileId",
  "doc_id",
  "document_id",
  "item_id",
  "itemId",
  "product_id",
  "productId",
  "project_id",
  "report_id",
  "ticket_id",
  "transaction_id",
  "pid",
  "cid",
  "oid",
  "rid",
  "tid",
  "fid",
  "did",
  "num",
  "number",
  "ref",
  "reference",
  "key",
  "token",
  "code",
  "slug",
];

// UUID pattern
const UUID_PATTERN =
  /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function stealthDelay(baseMs: number): Promise<void> {
  const jitter = Math.floor(Math.random() * baseMs * 0.5);
  return new Promise((resolve) => setTimeout(resolve, baseMs + jitter));
}

function extractParams(urlStr: string): Map<string, string> {
  const params = new Map<string, string>();
  try {
    const url = new URL(urlStr);
    url.searchParams.forEach((v, k) => params.set(k, v));
  } catch {
    // Skip
  }
  return params;
}

/** Check if a string looks like a numeric ID */
function isNumericId(value: string): boolean {
  return /^\d+$/.test(value) && parseInt(value, 10) > 0;
}

/** Check if a string looks like a UUID */
function isUuid(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(
    value,
  );
}

/** Generate incremented/decremented IDs for testing */
function generateIdVariants(originalId: string): string[] {
  const variants: string[] = [];
  if (isNumericId(originalId)) {
    const num = parseInt(originalId, 10);
    // Adjacent IDs
    if (num > 1) variants.push(String(num - 1));
    variants.push(String(num + 1));
    if (num > 10) variants.push(String(num - 10));
    variants.push(String(num + 10));
    // Boundary values
    variants.push("1");
    variants.push("0");
    variants.push("-1");
    if (num > 100) variants.push(String(num - 100));
    variants.push(String(num + 100));
  } else if (isUuid(originalId)) {
    // Modify last characters of UUID to test adjacent objects
    const base = originalId.slice(0, -4);
    const lastFour = parseInt(originalId.slice(-4), 16);
    if (lastFour > 0) {
      variants.push(base + (lastFour - 1).toString(16).padStart(4, "0"));
    }
    variants.push(base + (lastFour + 1).toString(16).padStart(4, "0"));
    // Zero UUID
    variants.push("00000000-0000-0000-0000-000000000000");
    // All 1s UUID
    variants.push("11111111-1111-1111-1111-111111111111");
  }
  return variants;
}

/** Measure how similar two response bodies are (for detecting different objects) */
function responseSimilarity(a: string, b: string): number {
  if (a === b) return 1.0;
  if (a.length === 0 || b.length === 0) return 0;
  const maxLen = Math.max(a.length, b.length);
  const lenDiff = Math.abs(a.length - b.length) / maxLen;
  if (lenDiff > 0.5) return 0.5 - lenDiff;
  // Sample comparison
  const sampleLen = Math.min(a.length, b.length, 3000);
  let matches = 0;
  for (let i = 0; i < sampleLen; i++) {
    if (a[i] === b[i]) matches++;
  }
  return matches / sampleLen;
}

/** Check if response indicates an unauthorized access */
function isAccessDenied(resp: HttpResponse): boolean {
  return (
    resp.status === 401 ||
    resp.status === 403 ||
    resp.body.toLowerCase().includes("unauthorized") ||
    resp.body.toLowerCase().includes("forbidden") ||
    resp.body.toLowerCase().includes("access denied") ||
    resp.body.toLowerCase().includes("not permitted") ||
    resp.body.toLowerCase().includes("permission denied")
  );
}

/** Check if response indicates a different object was returned (not 404/error) */
function isValidResourceResponse(resp: HttpResponse): boolean {
  return (
    resp.status >= 200 &&
    resp.status < 300 &&
    resp.body.length > 50 &&
    !resp.body.toLowerCase().includes("not found") &&
    !resp.body.toLowerCase().includes("does not exist")
  );
}

function buildIdorFinding(params: {
  target: string;
  endpoint: string;
  method: string;
  parameter: string;
  originalId: string;
  manipulatedId: string;
  idorType: string;
  confidence: number;
  evidence: string;
  responseBody: string;
  responseStatus: number;
}): Finding {
  const vulnId = generateUUID();
  const severity =
    params.confidence >= 80 ? Severity.High : Severity.Medium;
  const cvssScore = severity === Severity.High ? 7.5 : 6.5;

  const vulnerability: Vulnerability = {
    id: vulnId,
    title: `${params.idorType} IDOR in "${params.parameter}" (${params.originalId} -> ${params.manipulatedId})`,
    description:
      `An Insecure Direct Object Reference (IDOR) vulnerability was detected. ` +
      `The "${params.parameter}" parameter at ${params.endpoint} can be manipulated ` +
      `to access resources belonging to other users or outside the current user's ` +
      `authorization scope. The original ID "${params.originalId}" was changed to ` +
      `"${params.manipulatedId}" and the server returned a valid response, suggesting ` +
      `insufficient authorization checks.`,
    severity,
    category: VulnerabilityCategory.IDOR,
    cvssScore,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    cweId: "CWE-639",
    target: params.target,
    endpoint: params.endpoint,
    evidence: {
      description: params.evidence,
      payload: params.manipulatedId,
      matchedPattern: params.manipulatedId,
      extra: {
        idorType: params.idorType,
        originalId: params.originalId,
        manipulatedId: params.manipulatedId,
      },
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
    remediation:
      "1. Implement proper authorization checks on every object access.\n" +
      "2. Use indirect reference maps (mapping user-visible IDs to internal IDs) per session.\n" +
      "3. Replace sequential numeric IDs with UUIDs to reduce guessability.\n" +
      "4. Verify that the authenticated user owns or has permission to access the requested resource.\n" +
      "5. Log and alert on suspicious access patterns (e.g., rapid enumeration).\n" +
      "6. Implement rate limiting on resource access endpoints.",
    references: [
      "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
      "https://portswigger.net/web-security/access-control/idor",
      "https://cwe.mitre.org/data/definitions/639.html",
      "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html",
    ],
    confirmed: params.confidence >= 80,
    falsePositive: false,
    discoveredAt: new Date().toISOString(),
  };

  return {
    vulnerability,
    module: `scanner:idor:${params.idorType.toLowerCase().replace(/[- ]/g, "_")}`,
    confidence: params.confidence,
    timestamp: new Date().toISOString(),
    rawData: {
      originalId: params.originalId,
      manipulatedId: params.manipulatedId,
      idorType: params.idorType,
      parameter: params.parameter,
    },
  };
}

// ---------------------------------------------------------------------------
// IdorScanner Class
// ---------------------------------------------------------------------------

export class IdorScanner implements ScanModule {
  public readonly name = "idor";

  private rateLimiter: RateLimiter;
  private userAgent: string;

  constructor() {
    this.rateLimiter = new RateLimiter(5);
    this.userAgent =
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36";
  }

  async *execute(
    target: string,
    options: Record<string, unknown>,
  ): AsyncGenerator<Finding> {
    log.info({ target }, "Starting IDOR scan");

    const rateLimit = typeof options.rateLimit === "number" ? options.rateLimit : 5;
    this.rateLimiter = new RateLimiter(rateLimit);
    if (typeof options.userAgent === "string") {
      this.userAgent = options.userAgent;
    }

    // Extract authentication headers if provided
    const authHeaders: Record<string, string> = {};
    if (options.authToken && typeof options.authToken === "string") {
      authHeaders["Authorization"] = `Bearer ${options.authToken}`;
    }
    if (options.cookie && typeof options.cookie === "string") {
      authHeaders["Cookie"] = options.cookie;
    }

    // Phase 1: Path-based numeric ID manipulation
    yield* this.scanPathIds(target, authHeaders);

    // Phase 2: Query parameter ID manipulation
    yield* this.scanParamIds(target, authHeaders);

    // Phase 3: UUID guessability testing
    yield* this.scanUuids(target, authHeaders);

    // Phase 4: Horizontal privilege escalation via common API patterns
    yield* this.scanApiPatterns(target, authHeaders);

    // Phase 5: HTTP method manipulation on ID endpoints
    yield* this.scanMethodManipulation(target, authHeaders);

    log.info({ target }, "IDOR scan complete");
  }

  // -------------------------------------------------------------------------
  // Phase 1: Path-based numeric ID manipulation
  // -------------------------------------------------------------------------

  private async *scanPathIds(
    target: string,
    authHeaders: Record<string, string>,
  ): AsyncGenerator<Finding> {
    const url = new URL(target);
    const path = url.pathname;

    for (const pattern of ID_PATH_PATTERNS) {
      const match = pattern.exec(path);
      if (!match) continue;

      const originalId = match[1];
      const variants = generateIdVariants(originalId);

      // Get the original response for comparison
      await this.rateLimiter.acquire();
      let originalResp: HttpResponse;
      try {
        originalResp = await sendRequest({
          method: "GET",
          url: target,
          headers: {
            "User-Agent": this.userAgent,
            Accept: "text/html,application/json",
            ...authHeaders,
          },
        });
      } catch {
        continue;
      }

      if (!isValidResourceResponse(originalResp)) continue;

      for (const variant of variants) {
        const manipulatedPath = path.replace(originalId, variant);
        const manipulatedUrl = new URL(target);
        manipulatedUrl.pathname = manipulatedPath;

        await this.rateLimiter.acquire();
        await stealthDelay(200);

        try {
          const resp = await sendRequest({
            method: "GET",
            url: manipulatedUrl.toString(),
            headers: {
              "User-Agent": this.userAgent,
              Accept: "text/html,application/json",
              ...authHeaders,
            },
          });

          if (isValidResourceResponse(resp)) {
            const sim = responseSimilarity(originalResp.body, resp.body);

            // If the response is valid but different content (different object)
            if (sim < 0.95 && sim > 0.2) {
              let confidence = 65;

              // Higher confidence if the response structure is similar (same template) but data differs
              if (sim > 0.5 && sim < 0.9) {
                confidence = 80;
              }

              // If we're accessing without auth and still getting data
              if (Object.keys(authHeaders).length === 0) {
                confidence += 10;
              }

              confidence = Math.min(confidence, 95);

              yield buildIdorFinding({
                target,
                endpoint: manipulatedUrl.toString(),
                method: "GET",
                parameter: `path:${pattern.source}`,
                originalId,
                manipulatedId: variant,
                idorType: "Horizontal Privilege Escalation",
                confidence,
                evidence:
                  `Changed path ID from "${originalId}" to "${variant}". ` +
                  `Both returned HTTP 200 with valid content. ` +
                  `Response similarity: ${(sim * 100).toFixed(1)}% ` +
                  `(original: ${originalResp.body.length}B, manipulated: ${resp.body.length}B)`,
                responseBody: resp.body,
                responseStatus: resp.status,
              });
              break; // One finding per pattern
            }
          }
        } catch {
          continue;
        }
      }
    }
  }

  // -------------------------------------------------------------------------
  // Phase 2: Query parameter ID manipulation
  // -------------------------------------------------------------------------

  private async *scanParamIds(
    target: string,
    authHeaders: Record<string, string>,
  ): AsyncGenerator<Finding> {
    const params = extractParams(target);

    // Also check for known ID param names in the URL
    for (const [paramName, paramValue] of params) {
      const isIdParam =
        ID_PARAM_NAMES.includes(paramName.toLowerCase()) ||
        isNumericId(paramValue) ||
        isUuid(paramValue);

      if (!isIdParam) continue;

      // Get original response
      await this.rateLimiter.acquire();
      let originalResp: HttpResponse;
      try {
        originalResp = await sendRequest({
          method: "GET",
          url: target,
          headers: {
            "User-Agent": this.userAgent,
            Accept: "text/html,application/json",
            ...authHeaders,
          },
        });
      } catch {
        continue;
      }

      if (!isValidResourceResponse(originalResp)) continue;

      const variants = generateIdVariants(paramValue);

      for (const variant of variants) {
        const manipulatedUrl = new URL(target);
        manipulatedUrl.searchParams.set(paramName, variant);

        await this.rateLimiter.acquire();
        await stealthDelay(200);

        try {
          const resp = await sendRequest({
            method: "GET",
            url: manipulatedUrl.toString(),
            headers: {
              "User-Agent": this.userAgent,
              Accept: "text/html,application/json",
              ...authHeaders,
            },
          });

          if (isValidResourceResponse(resp)) {
            const sim = responseSimilarity(originalResp.body, resp.body);

            if (sim < 0.95 && sim > 0.2) {
              let confidence = 65;
              if (sim > 0.5 && sim < 0.9) confidence = 80;
              if (Object.keys(authHeaders).length === 0) confidence += 10;
              confidence = Math.min(confidence, 95);

              yield buildIdorFinding({
                target,
                endpoint: manipulatedUrl.toString(),
                method: "GET",
                parameter: paramName,
                originalId: paramValue,
                manipulatedId: variant,
                idorType: "Horizontal Privilege Escalation",
                confidence,
                evidence:
                  `Changed parameter "${paramName}" from "${paramValue}" to "${variant}". ` +
                  `Both returned valid responses with different content. ` +
                  `Similarity: ${(sim * 100).toFixed(1)}%`,
                responseBody: resp.body,
                responseStatus: resp.status,
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
  // Phase 3: UUID guessability testing
  // -------------------------------------------------------------------------

  private async *scanUuids(
    target: string,
    authHeaders: Record<string, string>,
  ): AsyncGenerator<Finding> {
    // Fetch the page and look for UUIDs
    await this.rateLimiter.acquire();
    let pageResp: HttpResponse;
    try {
      pageResp = await sendRequest({
        method: "GET",
        url: target,
        headers: {
          "User-Agent": this.userAgent,
          Accept: "text/html,application/json",
          ...authHeaders,
        },
      });
    } catch {
      return;
    }

    const uuids = pageResp.body.match(UUID_PATTERN);
    if (!uuids || uuids.length === 0) return;

    // Deduplicate
    const uniqueUuids = [...new Set(uuids)];

    // Check if UUIDs are sequential (UUID v1 time-based)
    const uuidV1Pattern = /^[0-9a-f]{8}-[0-9a-f]{4}-1[0-9a-f]{3}-/i;
    const v1Uuids = uniqueUuids.filter((u) => uuidV1Pattern.test(u));

    if (v1Uuids.length > 0) {
      const vulnId = generateUUID();
      const vulnerability: Vulnerability = {
        id: vulnId,
        title: "UUID v1 (Time-based) Identifiers Detected",
        description:
          `The application uses UUID v1 identifiers which are based on timestamps and MAC ` +
          `addresses, making them predictable. An attacker who obtains one UUID can compute ` +
          `adjacent UUIDs created around the same time, enabling enumeration of resources.`,
        severity: Severity.Low,
        category: VulnerabilityCategory.IDOR,
        cvssScore: 4.3,
        cvssVector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
        cweId: "CWE-639",
        target,
        endpoint: target,
        evidence: {
          description: `Found ${v1Uuids.length} UUID v1 identifiers: ${v1Uuids.slice(0, 3).join(", ")}`,
          payload: v1Uuids[0],
          extra: { uuidCount: v1Uuids.length, sampleUuids: v1Uuids.slice(0, 5) },
        },
        remediation:
          "1. Use UUID v4 (random) instead of UUID v1 (time-based) for resource identifiers.\n" +
          "2. Implement proper authorization checks regardless of ID format.\n" +
          "3. Consider using opaque tokens or signed references.",
        references: [
          "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
          "https://cwe.mitre.org/data/definitions/639.html",
        ],
        confirmed: true,
        falsePositive: false,
        discoveredAt: new Date().toISOString(),
      };

      yield {
        vulnerability,
        module: "scanner:idor:uuid_predictability",
        confidence: 70,
        timestamp: new Date().toISOString(),
        rawData: { v1Uuids: v1Uuids.slice(0, 10) },
      };
    }
  }

  // -------------------------------------------------------------------------
  // Phase 4: Common API patterns
  // -------------------------------------------------------------------------

  private async *scanApiPatterns(
    target: string,
    authHeaders: Record<string, string>,
  ): AsyncGenerator<Finding> {
    const baseUrl = new URL(target).origin;
    const apiPrefixes = ["/api", "/api/v1", "/api/v2", "/v1", "/v2"];
    const resources = [
      "users",
      "accounts",
      "profiles",
      "orders",
      "invoices",
      "documents",
      "files",
      "messages",
      "settings",
    ];
    const idValues = ["1", "2", "100", "admin"];

    for (const prefix of apiPrefixes) {
      for (const resource of resources) {
        for (const id of idValues) {
          const apiUrl = `${baseUrl}${prefix}/${resource}/${id}`;

          await this.rateLimiter.acquire();
          await stealthDelay(100);

          try {
            const resp = await sendRequest({
              method: "GET",
              url: apiUrl,
              headers: {
                "User-Agent": this.userAgent,
                Accept: "application/json,text/html",
                ...authHeaders,
              },
            });

            if (
              isValidResourceResponse(resp) &&
              !isAccessDenied(resp)
            ) {
              // Check if it looks like it returned actual data
              const looksLikeData =
                resp.body.includes('"id"') ||
                resp.body.includes('"email"') ||
                resp.body.includes('"name"') ||
                resp.body.includes('"username"');

              if (looksLikeData) {
                yield buildIdorFinding({
                  target,
                  endpoint: apiUrl,
                  method: "GET",
                  parameter: `path:/${resource}/:id`,
                  originalId: "N/A",
                  manipulatedId: id,
                  idorType: "API Enumeration",
                  confidence: 60,
                  evidence:
                    `API endpoint ${apiUrl} returned valid data for ID "${id}" ` +
                    `without proper authorization. Response contains data fields ` +
                    `(${resp.body.length} bytes).`,
                  responseBody: resp.body,
                  responseStatus: resp.status,
                });
              }
            }
          } catch {
            continue;
          }
        }
      }
    }
  }

  // -------------------------------------------------------------------------
  // Phase 5: HTTP method manipulation
  // -------------------------------------------------------------------------

  private async *scanMethodManipulation(
    target: string,
    authHeaders: Record<string, string>,
  ): AsyncGenerator<Finding> {
    const methods = ["PUT", "PATCH", "DELETE"];
    const url = new URL(target);
    const path = url.pathname;

    // Only test if the path contains an ID-like segment
    let hasId = false;
    for (const pattern of ID_PATH_PATTERNS) {
      if (pattern.test(path)) {
        hasId = true;
        break;
      }
    }
    if (!hasId) return;

    // Get baseline GET response
    await this.rateLimiter.acquire();
    let getResp: HttpResponse;
    try {
      getResp = await sendRequest({
        method: "GET",
        url: target,
        headers: {
          "User-Agent": this.userAgent,
          Accept: "application/json,text/html",
          ...authHeaders,
        },
      });
    } catch {
      return;
    }

    for (const method of methods) {
      await this.rateLimiter.acquire();
      await stealthDelay(200);

      try {
        const resp = await sendRequest({
          method,
          url: target,
          headers: {
            "User-Agent": this.userAgent,
            Accept: "application/json,text/html",
            "Content-Type": "application/json",
            ...authHeaders,
          },
          body: JSON.stringify({ test: "vulnhunter" }),
        });

        // If a destructive method returns 200/204 without auth
        if (
          (resp.status === 200 || resp.status === 204) &&
          !isAccessDenied(resp) &&
          Object.keys(authHeaders).length === 0
        ) {
          yield buildIdorFinding({
            target,
            endpoint: target,
            method,
            parameter: "HTTP Method",
            originalId: "GET",
            manipulatedId: method,
            idorType: "Missing Authorization on Write Method",
            confidence: 70,
            evidence:
              `${method} request to ${target} returned status ${resp.status} ` +
              `without authentication, indicating potential unauthorized modification/deletion capability.`,
            responseBody: resp.body,
            responseStatus: resp.status,
          });
        }
      } catch {
        continue;
      }
    }
  }
}
