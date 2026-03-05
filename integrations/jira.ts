import { createLogger } from "@vulnhunter/core";

const log = createLogger("integration:jira");

export interface JiraIssue {
  id: string;
  key: string;
  self: string;
  fields: {
    summary: string;
    description: string;
    status: { name: string };
    priority: { name: string };
    created: string;
    updated: string;
  };
}

function severityToJiraPriority(severity: string): string {
  switch (severity.toLowerCase()) {
    case "critical": return "Highest";
    case "high": return "High";
    case "medium": return "Medium";
    case "low": return "Low";
    default: return "Lowest";
  }
}

export class JiraClient {
  private host: string;
  private email: string;
  private apiToken: string;
  private projectKey: string;

  constructor(config?: {
    host?: string;
    email?: string;
    apiToken?: string;
    projectKey?: string;
  }) {
    this.host = config?.host || process.env.JIRA_HOST || "";
    this.email = config?.email || process.env.JIRA_EMAIL || "";
    this.apiToken = config?.apiToken || process.env.JIRA_API_TOKEN || "";
    this.projectKey = config?.projectKey || process.env.JIRA_PROJECT_KEY || "";
  }

  private get authHeader(): string {
    return "Basic " + Buffer.from(`${this.email}:${this.apiToken}`).toString("base64");
  }

  private async request<T>(path: string, options: RequestInit = {}): Promise<T> {
    const url = `${this.host}/rest/api/3${path}`;
    const response = await fetch(url, {
      ...options,
      headers: {
        Authorization: this.authHeader,
        "Content-Type": "application/json",
        Accept: "application/json",
        ...options.headers,
      },
    });

    if (!response.ok) {
      throw new Error(`Jira API error ${response.status}: ${await response.text()}`);
    }

    return response.json() as T;
  }

  async createSecurityIssue(vuln: {
    title: string;
    description: string;
    severity: string;
    category: string;
    endpoint?: string;
    cvssScore?: number;
    cweId?: string;
    remediation?: string;
    scanId: string;
  }): Promise<JiraIssue> {
    log.info({ title: vuln.title, severity: vuln.severity }, "Creating Jira issue");

    const description = {
      type: "doc",
      version: 1,
      content: [
        {
          type: "heading",
          attrs: { level: 2 },
          content: [{ type: "text", text: "Vulnerability Details" }],
        },
        {
          type: "table",
          content: [
            this.tableRow("Severity", vuln.severity.toUpperCase()),
            this.tableRow("Category", vuln.category),
            this.tableRow("CVSS Score", String(vuln.cvssScore ?? "N/A")),
            this.tableRow("CWE", vuln.cweId || "N/A"),
            this.tableRow("Endpoint", vuln.endpoint || "N/A"),
            this.tableRow("Scan ID", vuln.scanId),
          ],
        },
        {
          type: "heading",
          attrs: { level: 2 },
          content: [{ type: "text", text: "Description" }],
        },
        {
          type: "paragraph",
          content: [{ type: "text", text: vuln.description }],
        },
        ...(vuln.remediation
          ? [
              {
                type: "heading",
                attrs: { level: 2 },
                content: [{ type: "text", text: "Remediation" }],
              },
              {
                type: "paragraph",
                content: [{ type: "text", text: vuln.remediation }],
              },
            ]
          : []),
      ],
    };

    return this.request("/issue", {
      method: "POST",
      body: JSON.stringify({
        fields: {
          project: { key: this.projectKey },
          summary: `[VulnHunter] ${vuln.severity.toUpperCase()}: ${vuln.title}`,
          description,
          issuetype: { name: "Bug" },
          priority: { name: severityToJiraPriority(vuln.severity) },
          labels: ["security", "vulnhunter", vuln.category],
        },
      }),
    });
  }

  async getIssue(issueKey: string): Promise<JiraIssue> {
    return this.request(`/issue/${issueKey}`);
  }

  async searchIssues(jql: string): Promise<{ issues: JiraIssue[] }> {
    return this.request(`/search?jql=${encodeURIComponent(jql)}`);
  }

  async addComment(issueKey: string, comment: string): Promise<void> {
    await this.request(`/issue/${issueKey}/comment`, {
      method: "POST",
      body: JSON.stringify({
        body: {
          type: "doc",
          version: 1,
          content: [
            { type: "paragraph", content: [{ type: "text", text: comment }] },
          ],
        },
      }),
    });
  }

  private tableRow(label: string, value: string) {
    return {
      type: "tableRow",
      content: [
        {
          type: "tableCell",
          content: [
            { type: "paragraph", content: [{ type: "text", text: label, marks: [{ type: "strong" }] }] },
          ],
        },
        {
          type: "tableCell",
          content: [
            { type: "paragraph", content: [{ type: "text", text: value }] },
          ],
        },
      ],
    };
  }
}
