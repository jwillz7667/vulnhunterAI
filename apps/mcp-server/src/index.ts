#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { scanTarget } from "./tools/scan.js";
import { getVulnerabilities } from "./tools/vulnerabilities.js";
import { generateReport } from "./tools/report.js";
import { reconDomain } from "./tools/recon.js";

const server = new Server(
  {
    name: "vulnhunter-mcp",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
      resources: {},
    },
  }
);

// List available tools
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "scan_target",
      description:
        "Run a comprehensive security scan against a target URL, domain, or IP address. Returns discovered vulnerabilities with severity ratings, CVSS scores, and remediation guidance.",
      inputSchema: {
        type: "object" as const,
        properties: {
          target: {
            type: "string",
            description: "The target URL, domain, or IP to scan",
          },
          scanType: {
            type: "string",
            enum: ["full", "recon", "web", "code", "network", "cloud"],
            description: "Type of scan to perform (default: full)",
          },
          maxDepth: {
            type: "number",
            description: "Maximum crawl depth (default: 3)",
          },
        },
        required: ["target"],
      },
    },
    {
      name: "get_vulnerabilities",
      description:
        "Retrieve vulnerabilities from a completed scan. Can filter by severity, category, and confirmation status.",
      inputSchema: {
        type: "object" as const,
        properties: {
          scanId: {
            type: "string",
            description: "The scan ID to retrieve vulnerabilities for",
          },
          severity: {
            type: "string",
            enum: ["critical", "high", "medium", "low", "info"],
            description: "Filter by severity level",
          },
          category: {
            type: "string",
            description: "Filter by vulnerability category (e.g., xss, sqli, ssrf)",
          },
          confirmedOnly: {
            type: "boolean",
            description: "Only return confirmed vulnerabilities",
          },
        },
        required: ["scanId"],
      },
    },
    {
      name: "generate_report",
      description:
        "Generate a security assessment report from scan results. Supports JSON, Markdown, and HTML formats with optional compliance mapping.",
      inputSchema: {
        type: "object" as const,
        properties: {
          scanId: {
            type: "string",
            description: "The scan ID to generate a report for",
          },
          format: {
            type: "string",
            enum: ["json", "markdown", "html"],
            description: "Report output format (default: markdown)",
          },
          complianceFrameworks: {
            type: "array",
            items: { type: "string" },
            description: "Compliance frameworks to include (owasp_top10, pci_dss, nist, soc2, iso27001)",
          },
        },
        required: ["scanId"],
      },
    },
    {
      name: "recon_domain",
      description:
        "Perform reconnaissance on a domain including subdomain enumeration, port scanning, technology detection, and DNS analysis.",
      inputSchema: {
        type: "object" as const,
        properties: {
          domain: {
            type: "string",
            description: "The domain to perform reconnaissance on",
          },
          modules: {
            type: "array",
            items: { type: "string" },
            description: "Specific recon modules to run (subdomain, ports, tech, dns, crawl)",
          },
        },
        required: ["domain"],
      },
    },
  ],
}));

// Handle tool calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case "scan_target":
        return await scanTarget(args as { target: string; scanType?: string; maxDepth?: number });
      case "get_vulnerabilities":
        return await getVulnerabilities(
          args as { scanId: string; severity?: string; category?: string; confirmedOnly?: boolean }
        );
      case "generate_report":
        return await generateReport(
          args as { scanId: string; format?: string; complianceFrameworks?: string[] }
        );
      case "recon_domain":
        return await reconDomain(args as { domain: string; modules?: string[] });
      default:
        return {
          content: [{ type: "text" as const, text: `Unknown tool: ${name}` }],
          isError: true,
        };
    }
  } catch (error) {
    return {
      content: [
        {
          type: "text" as const,
          text: `Error: ${error instanceof Error ? error.message : String(error)}`,
        },
      ],
      isError: true,
    };
  }
});

// List resources
server.setRequestHandler(ListResourcesRequestSchema, async () => ({
  resources: [
    {
      uri: "vulnhunter://scans",
      name: "Recent Scans",
      description: "List of recent security scans",
      mimeType: "application/json",
    },
    {
      uri: "vulnhunter://templates",
      name: "Scan Templates",
      description: "Available scan templates",
      mimeType: "application/json",
    },
  ],
}));

// Read resources (queries Prisma for real data)
server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
  const { uri } = request.params;
  const { prisma } = await import("@vulnhunter/core");

  switch (uri) {
    case "vulnhunter://scans": {
      const scans = await prisma.scan.findMany({
        include: { target: true },
        orderBy: { createdAt: "desc" },
        take: 20,
      });
      return {
        contents: [
          {
            uri,
            mimeType: "application/json",
            text: JSON.stringify({
              scans: scans.map((s) => ({
                id: s.id,
                target: s.target.value,
                type: s.type,
                status: s.status,
                findingsCount: s.findingsCount,
                startedAt: s.startedAt?.toISOString(),
                completedAt: s.completedAt?.toISOString(),
              })),
            }),
          },
        ],
      };
    }
    case "vulnhunter://templates": {
      const templates = await prisma.scanTemplate.findMany({ orderBy: { isDefault: "desc" } });
      return {
        contents: [
          {
            uri,
            mimeType: "application/json",
            text: JSON.stringify({
              templates: templates.map((t) => ({
                name: t.name,
                description: t.description,
                config: t.config,
                isDefault: t.isDefault,
              })),
            }),
          },
        ],
      };
    }
    default:
      throw new Error(`Unknown resource: ${uri}`);
  }
});

// Start server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((error) => {
  console.error("MCP Server error:", error);
  process.exit(1);
});
