/**
 * System prompt for the Reporter Agent.
 *
 * The reporter transforms raw vulnerability data into polished, human-readable
 * reports. It writes narratives, remediation guidance, executive summaries,
 * and platform-specific submissions for HackerOne / Bugcrowd.
 */

export const REPORTER_SYSTEM_PROMPT = `You are the **Reporter Agent** of VulnHunter AI, an autonomous security research platform. You are a senior security consultant who writes clear, compelling, and actionable vulnerability reports.

## Responsibilities
1. **Vulnerability Narratives** -- write detailed, human-readable descriptions of vulnerabilities that explain the issue, its impact, and how it was discovered. Write for a technical audience (developers and security engineers).
2. **Remediation Guidance** -- provide specific, actionable fix recommendations with code examples where possible. Reference the target's technology stack.
3. **Executive Summaries** -- write concise summaries for non-technical stakeholders (CISOs, CTOs, board members) that focus on business risk and recommended actions.
4. **Platform Formatting** -- format findings for bug bounty platforms (HackerOne, Bugcrowd) following their specific templates and best practices for maximum impact and bounty.

## Writing Guidelines
- **Be Specific** -- reference exact endpoints, parameters, payloads, and response excerpts. Never write vague descriptions.
- **Impact First** -- lead with the business impact, then explain the technical details.
- **Reproducible Steps** -- always include step-by-step reproduction instructions that a developer can follow.
- **Evidence-Based** -- reference the actual HTTP requests and responses that prove the vulnerability.
- **Actionable Remediation** -- provide code-level fixes, not just "sanitise input". Show the exact function, library, or configuration change.

## Executive Summary Guidelines
- Use plain language. Avoid jargon.
- Quantify risk: number of critical/high/medium/low findings.
- Highlight the most impactful finding and its potential business consequence.
- Provide 3-5 prioritised recommendations.
- Keep it under 500 words.

## Platform-Specific Formatting

### HackerOne Format
\`\`\`markdown
## Summary
[1-2 sentence summary of the vulnerability]

## Steps to Reproduce
1. [Step 1]
2. [Step 2]
3. [Step 3]

## Impact
[Description of the security impact]

## Supporting Material/References
- [Screenshot/PoC URL]
- [CWE reference]
- [OWASP reference]
\`\`\`

### Bugcrowd Format
\`\`\`markdown
**Title:** [Vulnerability Title]

**URL:** [Affected URL]

**Severity:** [P1/P2/P3/P4]

**Description:**
[Detailed description of the vulnerability]

**Steps to Reproduce:**
1. [Step 1]
2. [Step 2]

**Impact:**
[Business and technical impact]

**Remediation:**
[Recommended fix]
\`\`\`

## Severity-to-Bugcrowd Priority Mapping
- Critical -> P1
- High -> P2
- Medium -> P3
- Low -> P4
- Info -> P5

## Constraints
- Never exaggerate severity or impact. Be accurate and honest.
- Never include sensitive data (real credentials, PII) in reports -- redact them.
- Always provide remediation. A finding without a fix is incomplete.
- Output should be clean, well-formatted text (Markdown for narratives, JSON when requested).
`;

/**
 * Builds a user message for vulnerability narrative generation.
 */
export function buildNarrativePrompt(params: {
  title: string;
  severity: string;
  category: string;
  endpoint: string;
  description: string;
  payload?: string;
  evidence?: string;
  request?: { method: string; url: string; headers: Record<string, string>; body?: string };
  response?: { statusCode: number; headers: Record<string, string>; body?: string };
  technologies: string[];
  cweId?: string;
  cvssScore?: number;
  cvssVector?: string;
}): string {
  const requestSection = params.request
    ? `\n**HTTP Request:**
\`\`\`
${params.request.method} ${params.request.url}
${Object.entries(params.request.headers)
  .map(([k, v]) => `${k}: ${v}`)
  .join("\n")}
${params.request.body ? `\n${params.request.body}` : ""}
\`\`\``
    : "";

  const responseSection = params.response
    ? `\n**HTTP Response:**
\`\`\`
HTTP/1.1 ${params.response.statusCode}
${Object.entries(params.response.headers)
  .map(([k, v]) => `${k}: ${v}`)
  .join("\n")}

${params.response.body ? params.response.body.slice(0, 2000) : "(empty body)"}
\`\`\``
    : "";

  return `Write a detailed vulnerability narrative for the following finding:

**Title:** ${params.title}
**Severity:** ${params.severity}
**Category:** ${params.category}
**CWE:** ${params.cweId || "N/A"}
**CVSS:** ${params.cvssScore ?? "N/A"} ${params.cvssVector ? `(${params.cvssVector})` : ""}
**Endpoint:** ${params.endpoint}
**Technologies:** ${params.technologies.join(", ")}

**Raw Description:** ${params.description}
**Payload:** ${params.payload || "N/A"}
**Evidence:** ${params.evidence || "N/A"}
${requestSection}
${responseSection}

Write a comprehensive narrative that includes:
1. A clear explanation of the vulnerability and why it exists.
2. Step-by-step reproduction instructions.
3. The security impact (CIA triad analysis).
4. References to relevant standards (CWE, OWASP).

Output as plain Markdown text.`;
}

/**
 * Builds a user message for remediation suggestion.
 */
export function buildRemediationPrompt(params: {
  title: string;
  category: string;
  endpoint: string;
  description: string;
  technologies: string[];
  cweId?: string;
}): string {
  return `Provide specific, actionable remediation guidance for the following vulnerability:

**Title:** ${params.title}
**Category:** ${params.category}
**CWE:** ${params.cweId || "N/A"}
**Endpoint:** ${params.endpoint}
**Technologies:** ${params.technologies.join(", ")}
**Description:** ${params.description}

Provide:
1. **Immediate Fix** -- the specific code change or configuration update to fix this issue.
2. **Code Example** -- show before/after code using the target's technology stack.
3. **Defense in Depth** -- additional layers of protection (WAF rules, CSP headers, etc.).
4. **Testing** -- how to verify the fix is effective.
5. **Prevention** -- how to prevent similar issues in the future (linting rules, SAST integration, etc.).

Output as Markdown.`;
}

/**
 * Builds a user message for executive summary generation.
 */
export function buildExecutiveSummaryPrompt(params: {
  targetName: string;
  scanType: string;
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  exploitChainCount: number;
  topFindings: Array<{ title: string; severity: string; impact: string }>;
  scanDurationMinutes: number;
}): string {
  const topList = params.topFindings
    .map((f) => `  - [${f.severity.toUpperCase()}] ${f.title}: ${f.impact}`)
    .join("\n");

  return `Write an executive summary for a security assessment of **${params.targetName}**.

**Scan Type:** ${params.scanType}
**Duration:** ${params.scanDurationMinutes} minutes
**Total Findings:** ${params.totalFindings}
  - Critical: ${params.criticalCount}
  - High: ${params.highCount}
  - Medium: ${params.mediumCount}
  - Low: ${params.lowCount}
  - Informational: ${params.infoCount}
**Exploit Chains Detected:** ${params.exploitChainCount}

**Most Significant Findings:**
${topList}

Write an executive summary (under 500 words) for a non-technical audience (CISO, CTO, board). Include:
1. Overall risk posture (critical/high/moderate/low).
2. The most impactful findings and their business consequences.
3. 3-5 prioritised recommendations.
4. A brief note on what went well (if applicable).

Output as Markdown.`;
}

/**
 * Builds a user message for platform-specific formatting.
 */
export function buildPlatformFormatPrompt(params: {
  platform: "hackerone" | "bugcrowd" | "intigriti";
  title: string;
  severity: string;
  category: string;
  endpoint: string;
  description: string;
  payload?: string;
  evidence?: string;
  request?: { method: string; url: string; headers: Record<string, string>; body?: string };
  response?: { statusCode: number; headers: Record<string, string>; body?: string };
  cweId?: string;
  cvssScore?: number;
  remediation?: string;
}): string {
  return `Format the following vulnerability for submission to **${params.platform}**.

**Title:** ${params.title}
**Severity:** ${params.severity}
**Category:** ${params.category}
**CWE:** ${params.cweId || "N/A"}
**CVSS:** ${params.cvssScore ?? "N/A"}
**Endpoint:** ${params.endpoint}

**Description:** ${params.description}
**Payload:** ${params.payload || "N/A"}
**Evidence:** ${params.evidence || "N/A"}
**Remediation:** ${params.remediation || "N/A"}

${params.request ? `**Request:** ${params.request.method} ${params.request.url}` : ""}
${params.response ? `**Response Status:** ${params.response.statusCode}` : ""}

Format this using the ${params.platform} submission template. Maximise clarity, impact description, and reproducibility. For Bugcrowd, map severity to priority (Critical=P1, High=P2, Medium=P3, Low=P4).

Output as Markdown.`;
}
