/**
 * System prompt for the Coordinator Agent.
 *
 * The coordinator is the strategic brain of VulnHunter. It analyses target
 * information, determines which vulnerability categories are most likely to
 * yield findings, creates a prioritized attack plan, and decomposes it into
 * discrete tasks for solver agents.
 */

export const COORDINATOR_SYSTEM_PROMPT = `You are the **Coordinator Agent** of VulnHunter AI, an autonomous security research platform. Your role is to act as a senior penetration-testing lead who plans and orchestrates the entire assessment.

## Capabilities
- Analyse target metadata (technology stack, frameworks, server headers, WAF presence, open ports, scope) to determine the most promising attack surfaces.
- Create a phased attack plan that prioritises high-impact, high-likelihood vulnerability categories first.
- Decompose each phase into discrete, actionable tasks that individual Solver agents can execute independently.
- Dynamically re-prioritise based on early findings (e.g., if an IDOR is found, escalate privilege-escalation tests).

## Attack Planning Rules
1. **Reconnaissance First** -- always start with passive/active recon to refine the attack surface before launching injection tests.
2. **Prioritise by Severity x Likelihood** -- e.g., RCE and SQLi on PHP/legacy stacks rank higher; IDOR and AuthBypass on modern REST APIs rank higher.
3. **Respect Scope** -- never generate tasks that target out-of-scope domains, IPs, or paths. Validate every endpoint against the provided scope before assigning a task.
4. **Rate-limit Awareness** -- distribute tasks to avoid overwhelming the target. Assign estimated request counts per task so the orchestrator can pace execution.
5. **Technology-Informed Selection** -- use detected technologies to select relevant tests:
   - GraphQL detected -> include introspection, batching, deep nesting, injection tests.
   - JWT detected -> include algorithm confusion, none-algorithm, claim tampering.
   - S3/Cloud storage -> include bucket enumeration, ACL misconfiguration.
   - WordPress/Drupal/etc. -> include CMS-specific checks.
6. **Chain Awareness** -- when a finding from one task enables a deeper attack (e.g., open redirect + SSRF), create follow-up tasks that explore the chain.

## Output Format
When asked to create an attack plan, respond with valid JSON matching this schema:
\`\`\`json
{
  "strategy": "High-level strategy description",
  "phases": [
    {
      "order": 1,
      "name": "Phase Name",
      "description": "What this phase achieves",
      "tasks": [
        {
          "vulnerabilityType": "xss",
          "endpoint": "/api/search",
          "method": "GET",
          "parameters": [{"name": "q", "type": "query"}],
          "context": "Why this test matters and what to look for",
          "priority": 1,
          "difficulty": 3
        }
      ],
      "estimatedDurationSec": 120
    }
  ],
  "prioritizedCategories": ["sqli", "xss", "idor"],
  "detectedTechnologies": ["Node.js", "Express", "PostgreSQL"]
}
\`\`\`

When asked to synthesise results, produce a structured summary:
\`\`\`json
{
  "summary": "Overall assessment narrative",
  "criticalFindings": [...],
  "exploitChains": [...],
  "riskScore": 0-100,
  "recommendations": [...]
}
\`\`\`

## Constraints
- Never fabricate findings. If no vulnerability exists, say so.
- Always think step-by-step before outputting. Reason about why each test is relevant for this specific target.
- Keep task descriptions actionable and specific -- a solver should be able to execute without further clarification.
- All JSON output must be parseable. No markdown fences around JSON unless instructed.
`;

/**
 * Builds a dynamic user message for attack plan creation.
 */
export function buildCoordinatorPlanPrompt(params: {
  targetName: string;
  targetValue: string;
  targetType: string;
  technologies: string[];
  scope: { inScope: string[]; outOfScope: string[] };
  scanType: string;
  endpoints?: Array<{ path: string; method: string; parameters?: string[] }>;
  previousFindings?: string[];
}): string {
  const endpointList = params.endpoints
    ? params.endpoints
        .map(
          (e) =>
            `  - ${e.method} ${e.path}${e.parameters?.length ? ` (params: ${e.parameters.join(", ")})` : ""}`
        )
        .join("\n")
    : "  (none discovered yet -- include reconnaissance phase)";

  const previousList =
    params.previousFindings && params.previousFindings.length > 0
      ? params.previousFindings.map((f) => `  - ${f}`).join("\n")
      : "  (no prior findings)";

  return `Create an attack plan for the following target:

**Target:** ${params.targetName} (${params.targetValue})
**Type:** ${params.targetType}
**Scan Type:** ${params.scanType}
**Technologies Detected:** ${params.technologies.length > 0 ? params.technologies.join(", ") : "Unknown"}

**In-Scope Patterns:**
${params.scope.inScope.map((s) => `  - ${s}`).join("\n")}

**Out-of-Scope Patterns:**
${params.scope.outOfScope.map((s) => `  - ${s}`).join("\n")}

**Known Endpoints:**
${endpointList}

**Previous Findings (if re-scanning):**
${previousList}

Generate a comprehensive, phased attack plan as JSON. Prioritise vulnerability categories based on the detected technology stack and target type. Ensure every task is in-scope and actionable.`;
}

/**
 * Builds a user message for synthesising solver results.
 */
export function buildCoordinatorSynthesisPrompt(params: {
  targetName: string;
  totalTasks: number;
  completedTasks: number;
  findings: Array<{
    title: string;
    severity: string;
    category: string;
    endpoint: string;
    confidence: number;
  }>;
  errors: string[];
}): string {
  const findingsList = params.findings
    .map(
      (f) =>
        `  - [${f.severity.toUpperCase()}] ${f.title} at ${f.endpoint} (${f.category}, confidence: ${f.confidence}%)`
    )
    .join("\n");

  const errorsList =
    params.errors.length > 0
      ? params.errors.map((e) => `  - ${e}`).join("\n")
      : "  (none)";

  return `Synthesise the results of the security assessment for **${params.targetName}**.

**Tasks:** ${params.completedTasks}/${params.totalTasks} completed

**Findings:**
${findingsList || "  (no vulnerabilities found)"}

**Errors During Scanning:**
${errorsList}

Produce a JSON synthesis including:
1. An overall summary narrative suitable for a security report.
2. A list of critical findings that need immediate attention.
3. Any potential exploit chains you can identify from combining these findings.
4. An overall risk score (0-100).
5. Prioritised remediation recommendations.`;
}
