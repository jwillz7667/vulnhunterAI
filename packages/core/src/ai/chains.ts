import { randomUUID } from "node:crypto";
import type { ChatMessage, TokenUsage } from "./types.js";
import type { IAIClient } from "./interface.js";
import { createLogger } from "../utils/logger.js";

import type {
  Finding,
  Vulnerability,
  ExploitChain,
  ExploitStep,
  Severity,
} from "../types/vulnerability.js";
import {
  Severity as SeverityEnum,
  SEVERITY_WEIGHT,
} from "../types/vulnerability.js";

// ---------------------------------------------------------------------------
// Logger
// ---------------------------------------------------------------------------

const log = createLogger("ai:chains");

// ---------------------------------------------------------------------------
// Graph-based vulnerability relationship model
// ---------------------------------------------------------------------------

/**
 * Directed edge in the vulnerability relationship graph.
 * An edge from A to B means "exploiting A enables or enhances B".
 */
interface VulnEdge {
  from: string; // vulnerability ID
  to: string; // vulnerability ID
  relationship: string;
  weight: number; // 0-1, how strongly A enables B
}

/**
 * A node in the vulnerability graph, wrapping a Finding with
 * adjacency information.
 */
interface VulnNode {
  finding: Finding;
  outEdges: VulnEdge[];
  inEdges: VulnEdge[];
}

/**
 * A candidate chain path through the graph.
 */
interface CandidateChain {
  path: string[]; // vulnerability IDs in order
  totalWeight: number;
  maxSeverityWeight: number;
}

// ---------------------------------------------------------------------------
// LLM response shapes
// ---------------------------------------------------------------------------

interface LLMRelationshipResponse {
  relationships: Array<{
    from: string;
    to: string;
    relationship: string;
    enablement: string;
    weight: number;
  }>;
}

interface LLMChainEvaluationResponse {
  chains: Array<{
    vulnerabilityIds: string[];
    description: string;
    exploitPath: string;
    steps: Array<{
      vulnerabilityId: string;
      outcome: string;
      preconditions: string[];
    }>;
    feasibility: number;
    impact: number;
    combinedCvssScore: number;
    combinedSeverity: string;
  }>;
}

// ---------------------------------------------------------------------------
// System prompt for chain analysis
// ---------------------------------------------------------------------------

const CHAIN_ANALYSIS_SYSTEM_PROMPT = `You are an expert security researcher specialising in exploit chain analysis. Your task is to identify how multiple vulnerabilities in a target can be combined to achieve a higher-impact attack than any individual vulnerability alone.

## How Exploit Chains Work
1. **Initial Access** -- an entry point vulnerability (e.g., XSS, open redirect, information disclosure) gives the attacker a foothold.
2. **Escalation** -- the attacker leverages the foothold to exploit a second vulnerability (e.g., SSRF via CSRF, privilege escalation via IDOR).
3. **Impact** -- the combined chain achieves a critical outcome (e.g., RCE, full account takeover, data exfiltration).

## Common Chain Patterns
- XSS + Missing HttpOnly Cookie -> Session Hijacking -> Account Takeover
- Information Disclosure + IDOR -> Sensitive Data Access
- Open Redirect + SSRF -> Internal Network Access
- CORS Misconfiguration + XSS -> Cross-Origin Data Theft
- SQL Injection + LFI -> Remote Code Execution
- Authentication Bypass + IDOR -> Horizontal/Vertical Privilege Escalation
- XXE + SSRF -> Internal Service Exploitation

## Output Format
Respond with valid JSON only. No markdown fences.

## Constraints
- Only identify chains that are practically exploitable. Do not fabricate speculative chains.
- Score feasibility honestly: if the chain requires unlikely user interaction or very specific conditions, lower the score.
- The combined CVSS score should reflect the worst-case outcome of the full chain, not simply the sum.
`;

// ---------------------------------------------------------------------------
// ExploitChainEngine
// ---------------------------------------------------------------------------

export class ExploitChainEngine {
  private readonly client: IAIClient;
  private tokenUsage = { input: 0, output: 0 };

  constructor(params: { client: IAIClient }) {
    this.client = params.client;
    log.info("ExploitChainEngine initialised");
  }

  // -----------------------------------------------------------------------
  // analyze
  // -----------------------------------------------------------------------

  /**
   * Primary entry point. Takes all findings from a scan, builds a vulnerability
   * relationship graph using AI, identifies candidate chains, evaluates them,
   * and returns scored exploit chains.
   */
  async analyze(findings: Finding[]): Promise<ExploitChain[]> {
    if (findings.length < 2) {
      log.info("Fewer than 2 findings -- no chains possible");
      return [];
    }

    log.info(
      { findingCount: findings.length },
      "Starting exploit chain analysis"
    );

    // Step 1: Build the vulnerability relationship graph
    const graph = await this.buildRelationshipGraph(findings);

    // Step 2: Find candidate chains via graph traversal
    const candidates = this.findCandidateChains(graph);

    if (candidates.length === 0) {
      log.info("No candidate chains found");
      return [];
    }

    log.info(
      { candidateCount: candidates.length },
      "Candidate chains identified, evaluating"
    );

    // Step 3: Use AI to evaluate and score the candidates
    const chains = await this.evaluateChains(candidates, findings);

    // Step 4: Score and sort
    const scored = chains
      .map((chain) => this.scoreChain(chain))
      .sort(
        (a, b) =>
          (SEVERITY_WEIGHT[b.combinedSeverity] ?? 0) -
          (SEVERITY_WEIGHT[a.combinedSeverity] ?? 0)
      );

    log.info(
      { chainCount: scored.length },
      "Exploit chain analysis complete"
    );

    return scored;
  }

  // -----------------------------------------------------------------------
  // buildChain (public for direct use)
  // -----------------------------------------------------------------------

  /**
   * Constructs an ExploitChain from a given set of vulnerabilities.
   * Uses AI to determine the optimal ordering and describe the attack path.
   */
  async buildChain(vulns: Vulnerability[]): Promise<ExploitChain | null> {
    if (vulns.length < 2) return null;

    const dummyFindings: Finding[] = vulns.map((v) => ({
      vulnerability: v,
      module: "manual",
      confidence: 100,
      timestamp: new Date().toISOString(),
    }));

    const chains = await this.analyze(dummyFindings);
    return chains.length > 0 ? chains[0] : null;
  }

  // -----------------------------------------------------------------------
  // scoreChain (public for direct use)
  // -----------------------------------------------------------------------

  /**
   * Calculates/adjusts the combined severity and CVSS for an exploit chain
   * based on the individual steps, feasibility, and impact escalation.
   */
  scoreChain(chain: ExploitChain): ExploitChain {
    // If no combined score exists, compute one from step count and max severity
    if (chain.combinedCvssScore == null) {
      const stepCount = chain.vulnerabilities.length;
      // Base: the chain's combined severity weight
      const severityBase = SEVERITY_WEIGHT[chain.combinedSeverity] ?? 3;
      // Bonus for multi-step chains (more steps = harder but higher impact)
      const chainBonus = Math.min(2, (stepCount - 1) * 0.5);
      const computed = Math.min(10, severityBase * 2 + chainBonus);
      return { ...chain, combinedCvssScore: Math.round(computed * 10) / 10 };
    }
    return chain;
  }

  // -----------------------------------------------------------------------
  // Token usage
  // -----------------------------------------------------------------------

  getTokenUsage(): { input: number; output: number } {
    return { ...this.tokenUsage };
  }

  // -----------------------------------------------------------------------
  // Private: Graph construction
  // -----------------------------------------------------------------------

  /**
   * Uses AI to identify directed relationships between findings.
   * Returns a graph of VulnNodes with edges representing enablement.
   */
  private async buildRelationshipGraph(
    findings: Finding[]
  ): Promise<Map<string, VulnNode>> {
    const graph = new Map<string, VulnNode>();

    // Initialize nodes
    for (const finding of findings) {
      graph.set(finding.vulnerability.id, {
        finding,
        outEdges: [],
        inEdges: [],
      });
    }

    // Build summary for AI
    const summaryList = findings
      .map(
        (f) =>
          `- ${f.vulnerability.id}: ${f.vulnerability.title} [${f.vulnerability.severity}/${f.vulnerability.category}] at ${f.vulnerability.endpoint ?? f.vulnerability.target}`
      )
      .join("\n");

    const prompt = `Analyse the following vulnerabilities and identify directed relationships where exploiting one vulnerability enables or enhances exploitation of another.

**Vulnerabilities:**
${summaryList}

For each relationship, specify:
- "from": the enabling vulnerability ID
- "to": the vulnerability that becomes exploitable/more impactful
- "relationship": type of relationship (e.g., "enables", "escalates", "exposes_data_for", "bypasses_control_for")
- "enablement": how the first vulnerability enables the second
- "weight": 0.0-1.0 indicating how strongly the first enables the second

Respond as JSON:
{"relationships": [{"from": "...", "to": "...", "relationship": "...", "enablement": "...", "weight": 0.8}]}

Only include relationships that are practically exploitable. Do not fabricate speculative relationships.`;

    const messages: ChatMessage[] = [{ role: "user", content: prompt }];

    const response = await this.client.chat(
      messages,
      CHAIN_ANALYSIS_SYSTEM_PROMPT
    );
    this.accumulateTokens(response.usage);

    try {
      const parsed = this.parseJSON<LLMRelationshipResponse>(response.content);

      for (const rel of parsed.relationships) {
        const fromNode = graph.get(rel.from);
        const toNode = graph.get(rel.to);
        if (!fromNode || !toNode) continue;

        const edge: VulnEdge = {
          from: rel.from,
          to: rel.to,
          relationship: rel.relationship,
          weight: Math.min(1, Math.max(0, rel.weight)),
        };

        fromNode.outEdges.push(edge);
        toNode.inEdges.push(edge);
      }

      log.debug(
        {
          nodes: graph.size,
          edges: parsed.relationships.length,
        },
        "Vulnerability relationship graph built"
      );
    } catch (err) {
      log.error({ error: String(err) }, "Failed to build relationship graph");
    }

    return graph;
  }

  // -----------------------------------------------------------------------
  // Private: Graph traversal for candidate chains
  // -----------------------------------------------------------------------

  /**
   * Uses DFS to find all paths of length >= 2 through the vulnerability graph.
   * Pruned to avoid cycles and limited to a maximum depth of 6.
   */
  private findCandidateChains(graph: Map<string, VulnNode>): CandidateChain[] {
    const candidates: CandidateChain[] = [];
    const maxDepth = 6;
    const maxCandidates = 20;

    const dfs = (
      nodeId: string,
      path: string[],
      totalWeight: number,
      maxSeverityWeight: number,
      visited: Set<string>
    ): void => {
      if (candidates.length >= maxCandidates) return;

      const node = graph.get(nodeId);
      if (!node) return;

      const currentPath = [...path, nodeId];
      const currentVisited = new Set(visited);
      currentVisited.add(nodeId);

      const sevWeight =
        SEVERITY_WEIGHT[node.finding.vulnerability.severity as Severity] ?? 1;
      const currentMaxSev = Math.max(maxSeverityWeight, sevWeight);

      // If we have at least 2 nodes, this is a valid chain
      if (currentPath.length >= 2) {
        candidates.push({
          path: currentPath,
          totalWeight,
          maxSeverityWeight: currentMaxSev,
        });
      }

      // Continue DFS if under max depth
      if (currentPath.length < maxDepth) {
        for (const edge of node.outEdges) {
          if (!currentVisited.has(edge.to)) {
            dfs(
              edge.to,
              currentPath,
              totalWeight + edge.weight,
              currentMaxSev,
              currentVisited
            );
          }
        }
      }
    };

    // Start DFS from every node that has outgoing edges
    for (const [nodeId, node] of graph) {
      if (node.outEdges.length > 0) {
        dfs(nodeId, [], 0, 0, new Set());
      }
    }

    // Sort by total weight * max severity, take top candidates
    candidates.sort(
      (a, b) =>
        b.totalWeight * b.maxSeverityWeight - a.totalWeight * a.maxSeverityWeight
    );

    // Deduplicate chains that are subsets of longer chains
    const deduped = this.deduplicateChains(candidates);

    return deduped.slice(0, 10);
  }

  /**
   * Remove chains that are strict subsets of longer chains.
   */
  private deduplicateChains(chains: CandidateChain[]): CandidateChain[] {
    const result: CandidateChain[] = [];

    for (const chain of chains) {
      const pathStr = chain.path.join("->");

      // Check if this path is a strict subset of any chain already in results
      const isSubset = result.some((existing) => {
        const existingStr = existing.path.join("->");
        if (existingStr === pathStr) return true;

        // Check if chain.path is a subsequence of existing.path
        if (existing.path.length <= chain.path.length) return false;
        let idx = 0;
        for (const node of existing.path) {
          if (node === chain.path[idx]) idx++;
          if (idx === chain.path.length) return true;
        }
        return false;
      });

      if (!isSubset) {
        result.push(chain);
      }
    }

    return result;
  }

  // -----------------------------------------------------------------------
  // Private: Chain evaluation via AI
  // -----------------------------------------------------------------------

  /**
   * Uses AI to evaluate candidate chains: determine if they are practically
   * exploitable, describe the attack path, and score them.
   */
  private async evaluateChains(
    candidates: CandidateChain[],
    findings: Finding[]
  ): Promise<ExploitChain[]> {
    const findingMap = new Map(
      findings.map((f) => [f.vulnerability.id, f])
    );

    // Build chain descriptions for AI
    const chainDescriptions = candidates
      .map((chain, idx) => {
        const steps = chain.path.map((id, stepIdx) => {
          const finding = findingMap.get(id);
          if (!finding) return `  ${stepIdx + 1}. [UNKNOWN] ${id}`;
          return `  ${stepIdx + 1}. [${finding.vulnerability.severity.toUpperCase()}] ${finding.vulnerability.title} (${finding.vulnerability.category}) at ${finding.vulnerability.endpoint ?? finding.vulnerability.target}`;
        });
        return `Chain ${idx + 1}:\n${steps.join("\n")}`;
      })
      .join("\n\n");

    const prompt = `Evaluate the following candidate exploit chains. For each chain that is practically exploitable, provide:
1. A description of the full attack.
2. Step-by-step exploit path with preconditions for each step.
3. Feasibility score (1-10).
4. Impact score (1-10).
5. Combined CVSS score (0-10).
6. Combined severity (critical/high/medium/low).

Discard chains that are not practically exploitable.

**Candidate Chains:**
${chainDescriptions}

Respond as JSON:
{"chains": [{"vulnerabilityIds": [...], "description": "...", "exploitPath": "...", "steps": [{"vulnerabilityId": "...", "outcome": "...", "preconditions": ["..."]}], "feasibility": 8, "impact": 9, "combinedCvssScore": 9.1, "combinedSeverity": "critical"}]}`;

    const messages: ChatMessage[] = [{ role: "user", content: prompt }];

    const response = await this.client.chat(
      messages,
      CHAIN_ANALYSIS_SYSTEM_PROMPT
    );
    this.accumulateTokens(response.usage);

    try {
      const parsed = this.parseJSON<LLMChainEvaluationResponse>(response.content);

      return parsed.chains.map((chain) => ({
        id: randomUUID(),
        vulnerabilities: chain.steps.map((step, idx) => ({
          order: idx + 1,
          vulnerabilityId: step.vulnerabilityId,
          outcome: step.outcome,
          preconditions: step.preconditions,
        })),
        description: chain.description,
        combinedSeverity: this.resolveSeverity(chain.combinedSeverity),
        exploitPath: chain.exploitPath,
        combinedCvssScore: Math.min(10, Math.max(0, chain.combinedCvssScore)),
      }));
    } catch (err) {
      log.error({ error: String(err) }, "Failed to evaluate chains");
      return [];
    }
  }

  // -----------------------------------------------------------------------
  // Private helpers
  // -----------------------------------------------------------------------

  private resolveSeverity(raw: string): Severity {
    const normalised = raw.toLowerCase().trim();
    const map: Record<string, Severity> = {
      critical: SeverityEnum.Critical,
      high: SeverityEnum.High,
      medium: SeverityEnum.Medium,
      low: SeverityEnum.Low,
      info: SeverityEnum.Info,
      informational: SeverityEnum.Info,
    };
    return map[normalised] ?? SeverityEnum.High;
  }

  private accumulateTokens(usage: TokenUsage): void {
    this.tokenUsage.input += usage.inputTokens;
    this.tokenUsage.output += usage.outputTokens;
  }

  private parseJSON<T>(text: string): T {
    let cleaned = text.trim();

    const jsonFenceRegex = /```(?:json)?\s*\n?([\s\S]*?)\n?\s*```/;
    const fenceMatch = cleaned.match(jsonFenceRegex);
    if (fenceMatch) {
      cleaned = fenceMatch[1].trim();
    }

    const jsonStartObj = cleaned.indexOf("{");
    const jsonStartArr = cleaned.indexOf("[");
    let jsonStart = -1;
    if (jsonStartObj === -1) jsonStart = jsonStartArr;
    else if (jsonStartArr === -1) jsonStart = jsonStartObj;
    else jsonStart = Math.min(jsonStartObj, jsonStartArr);

    if (jsonStart > 0) {
      cleaned = cleaned.slice(jsonStart);
    }

    if (cleaned.length === 0 || (cleaned[0] !== "{" && cleaned[0] !== "[")) {
      throw new Error(`ExploitChainEngine: No JSON found in LLM response`);
    }

    const openChar = cleaned[0];
    const closeChar = openChar === "{" ? "}" : "]";
    let depth = 0;
    let jsonEnd = -1;
    let inString = false;
    let escape = false;

    for (let i = 0; i < cleaned.length; i++) {
      const ch = cleaned[i];
      if (escape) { escape = false; continue; }
      if (ch === "\\") { escape = true; continue; }
      if (ch === '"') { inString = !inString; continue; }
      if (inString) continue;
      if (ch === openChar) depth++;
      if (ch === closeChar) {
        depth--;
        if (depth === 0) { jsonEnd = i; break; }
      }
    }

    if (jsonEnd > 0) {
      cleaned = cleaned.slice(0, jsonEnd + 1);
    }

    try {
      return JSON.parse(cleaned) as T;
    } catch (err) {
      log.error({ text: text.slice(0, 500) }, "Failed to parse LLM JSON response");
      throw new Error(
        `ExploitChainEngine: Failed to parse LLM response. Excerpt: ${cleaned.slice(0, 200)}...`
      );
    }
  }
}
