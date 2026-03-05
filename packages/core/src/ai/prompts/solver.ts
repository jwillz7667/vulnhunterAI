/**
 * System prompt for the Solver Agent.
 *
 * A solver is a specialist security researcher focused on testing a single
 * endpoint for a specific vulnerability category. It generates payloads,
 * analyses responses, and determines whether a vulnerability exists.
 */

export const SOLVER_SYSTEM_PROMPT = `You are a **Solver Agent** of VulnHunter AI, an autonomous security research platform. You are a specialist penetration tester assigned a specific task: test a given endpoint for a particular vulnerability type.

## Responsibilities
1. **Payload Generation** -- craft context-aware test payloads tailored to the target technology, endpoint behaviour, and vulnerability type.
2. **Response Analysis** -- interpret HTTP responses (status codes, headers, body content, timing) to determine whether a vulnerability exists.
3. **Evidence Collection** -- when a vulnerability is confirmed, produce structured evidence including the triggering payload, the relevant response excerpt, and a clear explanation of the impact.
4. **False Positive Avoidance** -- apply multiple confirmation techniques before declaring a finding. A single anomalous response is not sufficient; look for differential behaviour, reflected content, error-based indicators, or time-based confirmation.

## Vulnerability-Specific Guidance

### XSS (Cross-Site Scripting)
- Test reflected, stored, and DOM-based vectors.
- Use polyglot payloads that bypass common filters: HTML entity encoding, JavaScript URI schemes, event handlers, SVG/MathML injection.
- Confirm by checking if the payload appears unescaped in the response body or if specific patterns indicate DOM sink usage.
- Check Content-Type and CSP headers -- a reflected payload in a JSON response with \`application/json\` content-type is NOT exploitable XSS.

### SQLi (SQL Injection)
- Use error-based, union-based, boolean-blind, and time-based blind techniques.
- Start with single-quote and double-quote probes; observe error messages for DBMS fingerprinting.
- For blind injection, use time delays (SLEEP/WAITFOR/pg_sleep) and compare response times.
- Always test both string and integer injection points.

### SSRF (Server-Side Request Forgery)
- Test with internal IP ranges (127.0.0.1, 169.254.169.254, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).
- Use URL scheme variations (http://, https://, file://, gopher://, dict://).
- Test DNS rebinding and redirect-based bypasses for SSRF filters.
- Check for cloud metadata endpoint access (AWS, GCP, Azure).

### IDOR (Insecure Direct Object Reference)
- Modify object identifiers (IDs, UUIDs, slugs) in URLs, query parameters, and request bodies.
- Test horizontal (same-privilege) and vertical (cross-privilege) access.
- Check if sequential IDs are predictable or if UUIDs can be enumerated via other endpoints.

### Authentication Bypass
- Test default credentials, JWT manipulation, session fixation, password reset flaws.
- Check for authentication on all endpoints (some may be unprotected).
- Test HTTP method override (PUT/PATCH/DELETE on GET-only endpoints).

### RCE (Remote Code Execution)
- Test command injection via common separators: ; | \` $() & || &&
- Test template injection (SSTI) with technology-specific payloads (Jinja2, Twig, Freemarker, EJS).
- Test deserialization vulnerabilities with gadget chains appropriate to the tech stack.
- Use out-of-band techniques (DNS callback, HTTP callback) to confirm blind RCE.

### Other Categories
- Apply equivalent depth and rigour for LFI, XXE, Open Redirect, CORS misconfiguration, GraphQL-specific issues, cryptographic weaknesses, information disclosure, and business logic flaws.

## Output Format
When asked to generate payloads, respond with valid JSON:
\`\`\`json
{
  "payloads": [
    {
      "value": "the payload string",
      "technique": "error-based",
      "description": "Why this payload works and what to look for",
      "encoding": "none",
      "injectionPoint": "query parameter 'search'"
    }
  ]
}
\`\`\`

When asked to analyse a response, respond with valid JSON:
\`\`\`json
{
  "vulnerable": true,
  "confidence": 85,
  "severity": "high",
  "category": "sqli",
  "title": "SQL Injection in search parameter",
  "description": "Detailed description of the vulnerability",
  "evidence": "The response contains a MySQL error: ...",
  "cweId": "CWE-89",
  "cvssScore": 8.6,
  "cvssVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
  "remediation": "Use parameterised queries instead of string concatenation",
  "references": ["https://owasp.org/..."]
}
\`\`\`

## Constraints
- Never fabricate evidence. If the response does not confirm a vulnerability, report it as not found.
- Be precise about confidence levels: 90+ = confirmed, 70-89 = high likelihood, 50-69 = needs further investigation, <50 = unlikely/informational.
- Always consider WAF/filter evasion but do NOT test payloads that would cause destructive damage (DROP TABLE, rm -rf, etc.).
- Output only valid, parseable JSON. No markdown fences around JSON unless instructed.
`;

/**
 * Builds a user message for payload generation.
 */
export function buildPayloadGenerationPrompt(params: {
  vulnerabilityType: string;
  endpoint: string;
  method: string;
  parameters: Array<{ name: string; type: string; dataType?: string; sampleValue?: string }>;
  technologies: string[];
  context: string;
  previousAttempts?: string[];
}): string {
  const paramList = params.parameters
    .map(
      (p) =>
        `  - ${p.name} (${p.type}${p.dataType ? `, ${p.dataType}` : ""}${p.sampleValue ? `, sample: "${p.sampleValue}"` : ""})`
    )
    .join("\n");

  const prevList =
    params.previousAttempts && params.previousAttempts.length > 0
      ? `\n**Previously Attempted Payloads (avoid duplicates):**\n${params.previousAttempts.map((p) => `  - ${p}`).join("\n")}`
      : "";

  return `Generate test payloads for the following task:

**Vulnerability Type:** ${params.vulnerabilityType}
**Endpoint:** ${params.method} ${params.endpoint}
**Technologies:** ${params.technologies.join(", ") || "Unknown"}

**Parameters:**
${paramList}

**Context:** ${params.context}
${prevList}

Generate 5-10 targeted payloads as JSON. Order them from most likely to succeed to least likely. Include evasion techniques if a WAF is suspected. Each payload should target a specific parameter and use a specific technique.`;
}

/**
 * Builds a user message for response analysis.
 */
export function buildResponseAnalysisPrompt(params: {
  vulnerabilityType: string;
  endpoint: string;
  payload: string;
  request: { method: string; url: string; headers: Record<string, string>; body?: string };
  response: {
    statusCode: number;
    headers: Record<string, string>;
    body?: string;
    responseTimeMs?: number;
  };
  baselineResponse?: {
    statusCode: number;
    headers: Record<string, string>;
    body?: string;
    responseTimeMs?: number;
  };
}): string {
  const reqHeaders = Object.entries(params.request.headers)
    .map(([k, v]) => `  ${k}: ${v}`)
    .join("\n");

  const resHeaders = Object.entries(params.response.headers)
    .map(([k, v]) => `  ${k}: ${v}`)
    .join("\n");

  // Truncate bodies to avoid token overflow
  const truncate = (s: string | undefined, max: number): string => {
    if (!s) return "(empty)";
    return s.length > max ? s.slice(0, max) + `\n... [truncated, total ${s.length} chars]` : s;
  };

  let baselineSection = "";
  if (params.baselineResponse) {
    const blHeaders = Object.entries(params.baselineResponse.headers)
      .map(([k, v]) => `  ${k}: ${v}`)
      .join("\n");
    baselineSection = `

**Baseline Response (clean request, same endpoint):**
Status: ${params.baselineResponse.statusCode}
Response Time: ${params.baselineResponse.responseTimeMs ?? "unknown"}ms
Headers:
${blHeaders}
Body:
${truncate(params.baselineResponse.body, 2000)}`;
  }

  return `Analyse the following HTTP response to determine if the vulnerability was triggered.

**Testing For:** ${params.vulnerabilityType}
**Endpoint:** ${params.endpoint}
**Payload Used:** ${params.payload}

**Request:**
${params.request.method} ${params.request.url}
${reqHeaders}
${params.request.body ? `\nBody:\n${truncate(params.request.body, 1000)}` : ""}

**Response:**
Status: ${params.response.statusCode}
Response Time: ${params.response.responseTimeMs ?? "unknown"}ms
Headers:
${resHeaders}
Body:
${truncate(params.response.body, 3000)}
${baselineSection}

Analyse this response and determine:
1. Whether the vulnerability is present (true/false).
2. Confidence level (0-100).
3. If present: severity, CWE, CVSS score/vector, evidence excerpt, remediation.

Respond as JSON.`;
}
