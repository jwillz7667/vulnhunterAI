// =============================================================================
// VulnHunter AI - CORS Misconfiguration Scanner Module
// =============================================================================
// Detects dangerous CORS configurations including origin reflection, null
// origin bypass, subdomain wildcards, and credentials with reflected origins.
// CWE-942 | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N (8.1 base)
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

const log = createLogger("scanner:cors");

// ---------------------------------------------------------------------------
// Test Origins
// ---------------------------------------------------------------------------

function generateTestOrigins(targetUrl: string): Array<{ origin: string; description: string; severity: Severity }> {
  let targetHost: string;
  try {
    targetHost = new URL(targetUrl).hostname;
  } catch {
    targetHost = "example.com";
  }

  const targetDomain = targetHost.replace(/^www\./, "");
  const targetParts = targetDomain.split(".");
  const baseDomain =
    targetParts.length >= 2
      ? targetParts.slice(-2).join(".")
      : targetDomain;

  return [
    // Arbitrary external origin (most dangerous)
    {
      origin: "https://evil-attacker.com",
      description: "Arbitrary external origin reflected",
      severity: Severity.High,
    },
    // Null origin (iframe sandbox, data: URLs)
    {
      origin: "null",
      description: "Null origin accepted",
      severity: Severity.High,
    },
    // Subdomain of attacker that includes target domain
    {
      origin: `https://${targetDomain}.evil-attacker.com`,
      description: "Target domain as subdomain of attacker",
      severity: Severity.High,
    },
    // Prefix match bypass
    {
      origin: `https://${targetDomain}evil.com`,
      description: "Prefix match bypass (target + evil.com)",
      severity: Severity.High,
    },
    // Suffix match bypass
    {
      origin: `https://evil${targetDomain}`,
      description: "Suffix match bypass",
      severity: Severity.High,
    },
    // Subdomain wildcard
    {
      origin: `https://anything.${baseDomain}`,
      description: "Arbitrary subdomain accepted",
      severity: Severity.Medium,
    },
    // With credentials in origin
    {
      origin: `https://admin@${targetDomain}`,
      description: "Origin with credentials",
      severity: Severity.Medium,
    },
    // HTTP downgrade
    {
      origin: `http://${targetDomain}`,
      description: "HTTP origin on HTTPS target",
      severity: Severity.Medium,
    },
    // Different port
    {
      origin: `https://${targetDomain}:8443`,
      description: "Different port origin",
      severity: Severity.Low,
    },
    // Protocol-relative
    {
      origin: `https://evil.com:443@${targetDomain}`,
      description: "Origin with @-notation bypass",
      severity: Severity.High,
    },
    // Backslash trick
    {
      origin: `https://evil.com\\@${targetDomain}`,
      description: "Backslash @-notation bypass",
      severity: Severity.High,
    },
    // Tab/newline bypass
    {
      origin: `https://evil.com%09.${baseDomain}`,
      description: "Tab character in origin bypass",
      severity: Severity.High,
    },
    // Underscore subdomain
    {
      origin: `https://evil_.${baseDomain}`,
      description: "Underscore subdomain bypass",
      severity: Severity.Medium,
    },
  ];
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function stealthDelay(baseMs: number): Promise<void> {
  const jitter = Math.floor(Math.random() * baseMs * 0.5);
  return new Promise((resolve) => setTimeout(resolve, baseMs + jitter));
}

function buildCorsFinding(params: {
  target: string;
  endpoint: string;
  testedOrigin: string;
  reflectedOrigin: string;
  allowCredentials: boolean;
  corsType: string;
  confidence: number;
  evidence: string;
  severity: Severity;
  responseHeaders: Record<string, string>;
}): Finding {
  const vulnId = generateUUID();
  const cvssScore =
    params.allowCredentials && params.severity === Severity.High
      ? 8.1
      : params.severity === Severity.High
        ? 7.1
        : params.severity === Severity.Medium
          ? 5.3
          : 3.5;

  const vulnerability: Vulnerability = {
    id: vulnId,
    title: `CORS Misconfiguration: ${params.corsType}`,
    description:
      `A Cross-Origin Resource Sharing (CORS) misconfiguration was detected at ${params.endpoint}. ` +
      `The server responded with Access-Control-Allow-Origin: ${params.reflectedOrigin}` +
      (params.allowCredentials
        ? ` and Access-Control-Allow-Credentials: true`
        : "") +
      `. This allows ${params.corsType.toLowerCase()}, enabling a malicious website to ` +
      (params.allowCredentials
        ? `make authenticated cross-origin requests and steal sensitive data from authenticated users.`
        : `read cross-origin responses, potentially leaking sensitive information.`),
    severity: params.severity,
    category: VulnerabilityCategory.CORS,
    cvssScore,
    cvssVector:
      params.allowCredentials
        ? "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"
        : "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
    cweId: "CWE-942",
    target: params.target,
    endpoint: params.endpoint,
    evidence: {
      description: params.evidence,
      payload: params.testedOrigin,
      matchedPattern: params.reflectedOrigin,
      extra: {
        testedOrigin: params.testedOrigin,
        reflectedOrigin: params.reflectedOrigin,
        allowCredentials: params.allowCredentials,
        corsHeaders: {
          "access-control-allow-origin": params.responseHeaders["access-control-allow-origin"] || "",
          "access-control-allow-credentials": params.responseHeaders["access-control-allow-credentials"] || "",
          "access-control-allow-methods": params.responseHeaders["access-control-allow-methods"] || "",
          "access-control-allow-headers": params.responseHeaders["access-control-allow-headers"] || "",
          "access-control-expose-headers": params.responseHeaders["access-control-expose-headers"] || "",
        },
      },
    },
    request: {
      method: "GET",
      url: params.endpoint,
      headers: { Origin: params.testedOrigin },
    },
    response: {
      statusCode: 200,
      headers: params.responseHeaders,
      responseTimeMs: 0,
    },
    remediation:
      "1. Never reflect arbitrary origins in Access-Control-Allow-Origin.\n" +
      "2. Maintain an explicit allowlist of trusted origins.\n" +
      "3. Do not use 'Access-Control-Allow-Origin: *' with 'Access-Control-Allow-Credentials: true'.\n" +
      "4. Reject the 'null' origin unless explicitly needed.\n" +
      "5. Validate origins against full domain matches, not prefix/suffix checks.\n" +
      "6. Restrict Access-Control-Allow-Methods and Access-Control-Allow-Headers to only what is needed.\n" +
      "7. Set Access-Control-Max-Age to limit preflight caching.",
    references: [
      "https://portswigger.net/web-security/cors",
      "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
      "https://cwe.mitre.org/data/definitions/942.html",
      "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
    ],
    confirmed: params.confidence >= 80,
    falsePositive: false,
    discoveredAt: new Date().toISOString(),
  };

  return {
    vulnerability,
    module: `scanner:cors:${params.corsType.toLowerCase().replace(/[- /()]/g, "_")}`,
    confidence: params.confidence,
    timestamp: new Date().toISOString(),
    rawData: {
      testedOrigin: params.testedOrigin,
      reflectedOrigin: params.reflectedOrigin,
      allowCredentials: params.allowCredentials,
      corsHeaders: params.responseHeaders,
    },
  };
}

// ---------------------------------------------------------------------------
// CorsScanner Class
// ---------------------------------------------------------------------------

export class CorsScanner implements ScanModule {
  public readonly name = "cors";

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
    log.info({ target }, "Starting CORS scan");

    const rateLimit = typeof options.rateLimit === "number" ? options.rateLimit : 5;
    this.rateLimiter = new RateLimiter(rateLimit);
    if (typeof options.userAgent === "string") {
      this.userAgent = options.userAgent;
    }

    // Phase 1: Test origin reflection on the main target
    yield* this.scanOriginReflection(target);

    // Phase 2: Preflight request analysis
    yield* this.scanPreflight(target);

    // Phase 3: Check wildcard with credentials
    yield* this.scanWildcardWithCreds(target);

    // Phase 4: Scan common API endpoints
    yield* this.scanApiEndpoints(target);

    log.info({ target }, "CORS scan complete");
  }

  // -------------------------------------------------------------------------
  // Phase 1: Origin reflection testing
  // -------------------------------------------------------------------------

  private async *scanOriginReflection(
    target: string,
  ): AsyncGenerator<Finding> {
    const testOrigins = generateTestOrigins(target);

    for (const testCase of testOrigins) {
      await this.rateLimiter.acquire();
      await stealthDelay(200);

      try {
        const resp = await sendRequest({
          method: "GET",
          url: target,
          headers: {
            "User-Agent": this.userAgent,
            Origin: testCase.origin,
            Accept: "*/*",
          },
        });

        const acao = resp.headers["access-control-allow-origin"] || "";
        const acac = resp.headers["access-control-allow-credentials"] || "";
        const allowCreds = acac.toLowerCase() === "true";

        if (!acao) continue;

        // Check if the origin is reflected exactly
        if (acao === testCase.origin || acao === "*") {
          let confidence = 70;
          let severity = testCase.severity;

          // Wildcard is less severe unless combined with credentials
          if (acao === "*") {
            if (allowCreds) {
              // This is technically invalid per spec but some servers do it
              confidence = 90;
              severity = Severity.High;
            } else {
              // Wildcard without credentials is a weaker finding
              confidence = 60;
              severity = Severity.Low;
            }
          } else {
            // Reflected exact origin
            if (allowCreds) {
              confidence = 95;
              // Credentials with reflected origin = high/critical
              if (
                testCase.origin === "https://evil-attacker.com" ||
                testCase.origin === "null"
              ) {
                severity = Severity.Critical;
              }
            } else {
              confidence = 80;
            }
          }

          yield buildCorsFinding({
            target,
            endpoint: target,
            testedOrigin: testCase.origin,
            reflectedOrigin: acao,
            allowCredentials: allowCreds,
            corsType: testCase.description,
            confidence,
            evidence:
              `Origin "${testCase.origin}" was ${acao === "*" ? "accepted via wildcard" : "reflected"} ` +
              `in Access-Control-Allow-Origin header. ` +
              (allowCreds
                ? `Access-Control-Allow-Credentials is set to true, meaning authenticated requests are accepted.`
                : `Access-Control-Allow-Credentials is not set or false.`),
            severity,
            responseHeaders: resp.headers,
          });
        }
      } catch (err) {
        log.debug({ origin: testCase.origin, error: err }, "CORS test failed");
      }
    }
  }

  // -------------------------------------------------------------------------
  // Phase 2: Preflight request analysis
  // -------------------------------------------------------------------------

  private async *scanPreflight(target: string): AsyncGenerator<Finding> {
    const dangerousOrigin = "https://evil-attacker.com";

    await this.rateLimiter.acquire();
    await stealthDelay(200);

    try {
      const resp = await sendRequest({
        method: "OPTIONS",
        url: target,
        headers: {
          "User-Agent": this.userAgent,
          Origin: dangerousOrigin,
          "Access-Control-Request-Method": "PUT",
          "Access-Control-Request-Headers": "Authorization,Content-Type,X-Custom-Header",
          Accept: "*/*",
        },
      });

      const acao = resp.headers["access-control-allow-origin"] || "";
      const acam = resp.headers["access-control-allow-methods"] || "";
      const acah = resp.headers["access-control-allow-headers"] || "";
      const acac = resp.headers["access-control-allow-credentials"] || "";
      const acma = resp.headers["access-control-max-age"] || "";
      const allowCreds = acac.toLowerCase() === "true";

      // Check if preflight allows the dangerous origin
      if (acao === dangerousOrigin || acao === "*") {
        // Check for overly permissive methods
        const dangerousMethods = ["PUT", "DELETE", "PATCH"];
        const allowedMethods = acam.split(",").map((m) => m.trim().toUpperCase());
        const allowedDangerous = dangerousMethods.filter((m) =>
          allowedMethods.includes(m),
        );

        if (allowedDangerous.length > 0) {
          yield buildCorsFinding({
            target,
            endpoint: target,
            testedOrigin: dangerousOrigin,
            reflectedOrigin: acao,
            allowCredentials: allowCreds,
            corsType: "Overly Permissive Preflight",
            confidence: 80,
            evidence:
              `Preflight request from "${dangerousOrigin}" was accepted. ` +
              `Dangerous methods allowed: ${allowedDangerous.join(", ")}. ` +
              `Allowed headers: ${acah || "none specified"}. ` +
              (acma ? `Max-Age: ${acma}s. ` : "") +
              (allowCreds ? `Credentials are allowed.` : ""),
            severity: allowCreds ? Severity.High : Severity.Medium,
            responseHeaders: resp.headers,
          });
        }

        // Check for overly permissive headers
        if (
          acah.includes("*") ||
          acah.toLowerCase().includes("authorization")
        ) {
          yield buildCorsFinding({
            target,
            endpoint: target,
            testedOrigin: dangerousOrigin,
            reflectedOrigin: acao,
            allowCredentials: allowCreds,
            corsType: "Authorization Header Exposed Cross-Origin",
            confidence: 75,
            evidence:
              `Preflight allows Authorization header from external origin "${dangerousOrigin}". ` +
              `Allowed headers: ${acah}. This could enable cross-origin token theft.`,
            severity: Severity.Medium,
            responseHeaders: resp.headers,
          });
        }

        // Excessive max-age
        if (acma && parseInt(acma, 10) > 86400) {
          const vulnId = generateUUID();
          const vulnerability: Vulnerability = {
            id: vulnId,
            title: "Excessive CORS Preflight Cache Duration",
            description:
              `The Access-Control-Max-Age header is set to ${acma} seconds ` +
              `(${(parseInt(acma, 10) / 3600).toFixed(1)} hours), which is excessively long. ` +
              `This means the browser will cache the preflight response for an extended period, ` +
              `reducing the ability to quickly revoke CORS permissions.`,
            severity: Severity.Info,
            category: VulnerabilityCategory.CORS,
            cvssScore: 0,
            cweId: "CWE-942",
            target,
            endpoint: target,
            evidence: {
              description: `Access-Control-Max-Age: ${acma}`,
              extra: { maxAge: parseInt(acma, 10) },
            },
            remediation: "Set Access-Control-Max-Age to a reasonable value (e.g., 3600 seconds / 1 hour).",
            references: [
              "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Max-Age",
            ],
            confirmed: true,
            falsePositive: false,
            discoveredAt: new Date().toISOString(),
          };

          yield {
            vulnerability,
            module: "scanner:cors:preflight_cache",
            confidence: 90,
            timestamp: new Date().toISOString(),
          };
        }
      }
    } catch (err) {
      log.debug({ error: err }, "Preflight test failed");
    }
  }

  // -------------------------------------------------------------------------
  // Phase 3: Wildcard with credentials check
  // -------------------------------------------------------------------------

  private async *scanWildcardWithCreds(
    target: string,
  ): AsyncGenerator<Finding> {
    await this.rateLimiter.acquire();
    await stealthDelay(200);

    try {
      // Send request without Origin to see default CORS headers
      const resp = await sendRequest({
        method: "GET",
        url: target,
        headers: {
          "User-Agent": this.userAgent,
          Accept: "*/*",
        },
      });

      const acao = resp.headers["access-control-allow-origin"] || "";
      const acac = resp.headers["access-control-allow-credentials"] || "";

      if (acao === "*" && acac.toLowerCase() === "true") {
        yield buildCorsFinding({
          target,
          endpoint: target,
          testedOrigin: "(no origin sent)",
          reflectedOrigin: "*",
          allowCredentials: true,
          corsType: "Wildcard with Credentials",
          confidence: 95,
          evidence:
            `The server returns Access-Control-Allow-Origin: * together with ` +
            `Access-Control-Allow-Credentials: true. While browsers should reject ` +
            `this combination per the CORS spec, some older or non-standard clients ` +
            `may honor it, leading to credential leakage.`,
          severity: Severity.High,
          responseHeaders: resp.headers,
        });
      }
    } catch {
      // Skip
    }
  }

  // -------------------------------------------------------------------------
  // Phase 4: Scan common API endpoints
  // -------------------------------------------------------------------------

  private async *scanApiEndpoints(target: string): AsyncGenerator<Finding> {
    const baseUrl = new URL(target).origin;
    const apiPaths = [
      "/api",
      "/api/v1",
      "/api/v2",
      "/api/v1/user",
      "/api/v1/users/me",
      "/api/v1/account",
      "/api/profile",
      "/api/settings",
      "/graphql",
      "/rest",
    ];

    const evilOrigin = "https://evil-attacker.com";

    for (const apiPath of apiPaths) {
      const apiUrl = `${baseUrl}${apiPath}`;

      await this.rateLimiter.acquire();
      await stealthDelay(100);

      try {
        const resp = await sendRequest({
          method: "GET",
          url: apiUrl,
          headers: {
            "User-Agent": this.userAgent,
            Origin: evilOrigin,
            Accept: "application/json",
          },
        });

        // Skip 404s and errors
        if (resp.status === 404 || resp.status >= 500) continue;

        const acao = resp.headers["access-control-allow-origin"] || "";
        const acac = resp.headers["access-control-allow-credentials"] || "";
        const allowCreds = acac.toLowerCase() === "true";

        if (acao === evilOrigin) {
          yield buildCorsFinding({
            target,
            endpoint: apiUrl,
            testedOrigin: evilOrigin,
            reflectedOrigin: acao,
            allowCredentials: allowCreds,
            corsType: "API Endpoint Origin Reflection",
            confidence: allowCreds ? 95 : 80,
            evidence:
              `API endpoint ${apiPath} reflects arbitrary origin "${evilOrigin}" ` +
              `in Access-Control-Allow-Origin. ` +
              (allowCreds
                ? `Combined with Access-Control-Allow-Credentials: true, this allows full ` +
                  `authenticated cross-origin data theft from this API.`
                : `Credentials are not allowed, limiting the attack to unauthenticated data.`),
            severity: allowCreds ? Severity.High : Severity.Medium,
            responseHeaders: resp.headers,
          });
        }
      } catch {
        continue;
      }
    }
  }
}
