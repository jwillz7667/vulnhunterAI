/**
 * System prompt for the Analyzer Agent.
 *
 * The analyzer is responsible for post-processing findings: correlating
 * vulnerabilities, detecting exploit chains, assessing real-world impact,
 * eliminating false positives, and correlating static + dynamic results.
 */

export const ANALYZER_SYSTEM_PROMPT = `You are the **Analyzer Agent** of VulnHunter AI, an autonomous security research platform. You are a senior security analyst who reviews raw findings from automated testing and performs deep analysis.

## Responsibilities
1. **Correlation** -- identify relationships between findings (same root cause, same component, same attack surface).
2. **Exploit Chain Detection** -- determine when multiple lower-severity vulnerabilities can be chained to achieve a higher-impact attack.
3. **Impact Assessment** -- evaluate the real-world business impact of each finding (data breach, account takeover, financial loss, reputational damage, compliance violation).
4. **False Positive Elimination** -- apply expert reasoning to filter out findings that are not actually exploitable, using response context, technology awareness, and security control analysis.
5. **SAST/DAST Correlation** -- when both static and dynamic findings are available, correlate code-level issues with runtime behaviour to increase or decrease confidence.

## Correlation Rules
- Two findings targeting the same parameter on the same endpoint with the same root cause should be merged into one, keeping the higher confidence and severity.
- Findings on different endpoints that share the same vulnerable code path (identified via SAST) are related.
- Findings that affect the same authentication/authorisation mechanism should be grouped.

## Exploit Chain Analysis
Think like an attacker constructing a kill chain:
1. **Initial Access** -- what is the entry point? (e.g., XSS, open redirect, information disclosure)
2. **Escalation** -- how can initial access be leveraged? (e.g., XSS -> session hijack, SSRF -> internal API access)
3. **Impact** -- what is the final impact? (e.g., account takeover, data exfiltration, RCE)

Score chains by:
- **Feasibility** (1-10): How practical is it to execute this chain in a real attack?
- **Impact** (1-10): What is the worst-case outcome?
- **Combined Score**: Feasibility x Impact, normalised to a CVSS-like 0-10 scale.

## False Positive Detection Rules
Mark a finding as a likely false positive if:
- The payload is reflected but within a properly escaped context (HTML-encoded in an HTML attribute, for example).
- The response Content-Type prevents execution (e.g., XSS payload in \`application/json\` response).
- A WAF or framework-level protection is confirmed to block the payload (but the scanner reported it based on partial reflection).
- The "error message" is a generic 500 error that does not leak database-specific information.
- Time-based findings have a timing differential < 2x the baseline variance.
- The same endpoint returns identical content regardless of the injected value (no differential behaviour).

## SAST/DAST Correlation Rules
- A SAST finding at a code location that is confirmed reachable via a DAST finding should have its confidence elevated to 90+.
- A SAST finding for which DAST testing showed no exploitability (the code path is protected by input validation or WAF) should have its confidence reduced to 30-50.
- A DAST finding with no corresponding SAST source should be flagged for manual review (could be a third-party dependency or runtime-only issue).

## Output Format

### Correlation Output
\`\`\`json
{
  "correlations": [
    {
      "findingIds": ["id1", "id2"],
      "relationship": "same_root_cause",
      "description": "Both findings stem from unsanitised user input in the search handler",
      "mergedSeverity": "high",
      "mergedConfidence": 92
    }
  ]
}
\`\`\`

### Exploit Chain Output
\`\`\`json
{
  "chains": [
    {
      "name": "XSS to Account Takeover",
      "steps": [
        {"order": 1, "vulnerabilityId": "...", "outcome": "Execute JavaScript in victim's browser"},
        {"order": 2, "vulnerabilityId": "...", "outcome": "Steal session cookie via missing HttpOnly flag"},
        {"order": 3, "vulnerabilityId": "...", "outcome": "Full account takeover via session hijacking"}
      ],
      "feasibility": 8,
      "impact": 9,
      "combinedScore": 9.2,
      "combinedSeverity": "critical",
      "narrative": "An attacker can chain the reflected XSS with the missing HttpOnly cookie flag..."
    }
  ]
}
\`\`\`

### False Positive Analysis Output
\`\`\`json
{
  "analysis": [
    {
      "findingId": "...",
      "isFalsePositive": true,
      "confidence": 90,
      "reason": "The XSS payload is reflected within a JSON response with Content-Type: application/json, which browsers will not render as HTML"
    }
  ]
}
\`\`\`

## Constraints
- Be conservative: it is better to keep a real finding than to dismiss it as a false positive. Only mark as false positive with >80% confidence.
- Always explain your reasoning. Security findings have legal and business implications.
- Output only valid, parseable JSON. No markdown fences around JSON unless instructed.
`;

/**
 * Builds a user message for finding correlation.
 */
export function buildCorrelationPrompt(
  findings: Array<{
    id: string;
    title: string;
    severity: string;
    category: string;
    endpoint: string;
    description: string;
    confidence: number;
    cweId?: string;
  }>
): string {
  const findingsList = findings
    .map(
      (f) =>
        `- **${f.id}**: ${f.title}
    Severity: ${f.severity} | Category: ${f.category} | CWE: ${f.cweId || "N/A"}
    Endpoint: ${f.endpoint} | Confidence: ${f.confidence}%
    Description: ${f.description}`
    )
    .join("\n\n");

  return `Analyse the following ${findings.length} findings and identify correlations between them.

${findingsList}

For each group of related findings, explain the relationship and suggest whether they should be merged or grouped. Output as JSON.`;
}

/**
 * Builds a user message for exploit chain detection.
 */
export function buildExploitChainPrompt(
  findings: Array<{
    id: string;
    title: string;
    severity: string;
    category: string;
    endpoint: string;
    description: string;
  }>
): string {
  const findingsList = findings
    .map(
      (f) =>
        `- **${f.id}** [${f.severity.toUpperCase()}]: ${f.title} (${f.category}) at ${f.endpoint}
    ${f.description}`
    )
    .join("\n\n");

  return `Given the following security findings, identify any exploit chains where multiple vulnerabilities can be combined to achieve a higher-impact attack.

${findingsList}

Think like an attacker. For each chain:
1. Define the step-by-step attack path.
2. Score feasibility (1-10) and impact (1-10).
3. Calculate a combined CVSS-like score.
4. Write a narrative explaining the full attack.

Output as JSON.`;
}

/**
 * Builds a user message for false positive analysis.
 */
export function buildFalsePositivePrompt(
  findings: Array<{
    id: string;
    title: string;
    category: string;
    endpoint: string;
    payload: string;
    responseContentType?: string;
    responseBody?: string;
    responseStatusCode?: number;
    confidence: number;
  }>
): string {
  const findingsList = findings
    .map(
      (f) =>
        `- **${f.id}**: ${f.title} (${f.category})
    Endpoint: ${f.endpoint}
    Payload: ${f.payload}
    Response Status: ${f.responseStatusCode ?? "unknown"}
    Content-Type: ${f.responseContentType ?? "unknown"}
    Response Body (excerpt): ${f.responseBody ? f.responseBody.slice(0, 500) : "(not available)"}
    Current Confidence: ${f.confidence}%`
    )
    .join("\n\n");

  return `Review the following ${findings.length} findings and determine which are likely false positives.

${findingsList}

For each finding, assess whether it is a true positive or false positive, with confidence and reasoning. Be conservative -- only mark as false positive if you are >80% confident. Output as JSON.`;
}

/**
 * Builds a user message for SAST/DAST correlation.
 */
export function buildSASTDASTCorrelationPrompt(params: {
  staticFindings: Array<{
    id: string;
    title: string;
    filePath: string;
    lineNumber: number;
    category: string;
    severity: string;
    codeSnippet: string;
  }>;
  dynamicFindings: Array<{
    id: string;
    title: string;
    endpoint: string;
    category: string;
    severity: string;
    confidence: number;
  }>;
}): string {
  const staticList = params.staticFindings
    .map(
      (f) =>
        `- **${f.id}** [SAST]: ${f.title} (${f.category}, ${f.severity})
    File: ${f.filePath}:${f.lineNumber}
    Code: \`${f.codeSnippet}\``
    )
    .join("\n\n");

  const dynamicList = params.dynamicFindings
    .map(
      (f) =>
        `- **${f.id}** [DAST]: ${f.title} (${f.category}, ${f.severity}, confidence: ${f.confidence}%)
    Endpoint: ${f.endpoint}`
    )
    .join("\n\n");

  return `Correlate the following static analysis (SAST) and dynamic analysis (DAST) findings.

**Static Findings (code-level):**
${staticList}

**Dynamic Findings (runtime):**
${dynamicList}

For each pair or group of correlated findings:
1. Explain how the code-level issue manifests at runtime (or doesn't).
2. Adjust confidence levels based on the correlation.
3. Identify DAST findings with no SAST counterpart (potential third-party or runtime-only issues).
4. Identify SAST findings that DAST could not confirm (potentially protected by input validation or WAF).

Output as JSON with correlations, adjusted confidences, and explanations.`;
}

/**
 * Builds a user message for impact assessment.
 */
export function buildImpactAssessmentPrompt(params: {
  title: string;
  severity: string;
  category: string;
  description: string;
  endpoint: string;
  technologies: string[];
  targetType: string;
  hasAuthentication: boolean;
}): string {
  return `Assess the real-world business impact of the following vulnerability:

**Title:** ${params.title}
**Severity:** ${params.severity}
**Category:** ${params.category}
**Endpoint:** ${params.endpoint}
**Target Type:** ${params.targetType}
**Technologies:** ${params.technologies.join(", ")}
**Authentication Required:** ${params.hasAuthentication ? "Yes" : "No"}

**Description:** ${params.description}

Evaluate impact across these dimensions:
1. **Confidentiality** -- can an attacker access sensitive data? What data?
2. **Integrity** -- can an attacker modify data or functionality?
3. **Availability** -- can an attacker disrupt the service?
4. **Business Impact** -- financial loss, reputational damage, regulatory consequences.
5. **Exploitability** -- how easy is it to exploit in practice?

Provide a CVSS 3.1 vector string and score. Output as JSON:
\`\`\`json
{
  "confidentiality": "high",
  "integrity": "low",
  "availability": "none",
  "businessImpact": "Description of business impact...",
  "exploitability": "Description of exploitability...",
  "adjustedSeverity": "critical",
  "cvssScore": 9.1,
  "cvssVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
  "narrative": "Full impact narrative..."
}
\`\`\``;
}
