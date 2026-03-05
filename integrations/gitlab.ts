import { createLogger } from "@vulnhunter/core";

const log = createLogger("integration:gitlab");

export class GitLabClient {
  private token: string;
  private baseUrl: string;

  constructor(token?: string, baseUrl?: string) {
    this.token = token || process.env.GITLAB_TOKEN || "";
    this.baseUrl = baseUrl || "https://gitlab.com/api/v4";
  }

  private async request<T>(path: string, options: RequestInit = {}): Promise<T> {
    const response = await fetch(`${this.baseUrl}${path}`, {
      ...options,
      headers: {
        "PRIVATE-TOKEN": this.token,
        "Content-Type": "application/json",
        ...options.headers,
      },
    });

    if (!response.ok) {
      throw new Error(`GitLab API error ${response.status}: ${await response.text()}`);
    }

    return response.json() as T;
  }

  async getProjectVulnerabilities(
    projectId: string | number
  ): Promise<Array<{ id: number; title: string; severity: string; state: string }>> {
    log.info({ projectId }, "Fetching GitLab project vulnerabilities");
    return this.request(`/projects/${projectId}/vulnerabilities`);
  }

  async createVulnerabilityReport(
    projectId: string | number,
    report: {
      name: string;
      scanner: { id: string; name: string; version: string };
      vulnerabilities: Array<{
        category: string;
        name: string;
        message: string;
        severity: string;
        confidence: string;
        location: { file: string; start_line: number; end_line: number };
        identifiers: Array<{ type: string; name: string; value: string; url?: string }>;
      }>;
    }
  ): Promise<void> {
    log.info({ projectId, name: report.name }, "Creating GitLab SAST report");
    await this.request(`/projects/${projectId}/vulnerability_findings`, {
      method: "POST",
      body: JSON.stringify(report),
    });
  }

  async cloneProject(projectId: string | number, targetDir: string): Promise<void> {
    const project = await this.request<{ http_url_to_repo: string }>(
      `/projects/${projectId}`
    );
    const { execSync } = await import("child_process");
    const cloneUrl = project.http_url_to_repo.replace(
      "https://",
      `https://oauth2:${this.token}@`
    );
    execSync(`git clone --depth 1 ${cloneUrl} ${targetDir}`, {
      stdio: "pipe",
      timeout: 60000,
    });
  }
}
