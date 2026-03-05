import { createLogger } from "@vulnhunter/core";

const log = createLogger("integration:github");

const GITHUB_API_BASE = "https://api.github.com";

export interface GitHubAdvisory {
  ghsa_id: string;
  cve_id: string;
  summary: string;
  description: string;
  severity: string;
  published_at: string;
  updated_at: string;
  vulnerabilities: Array<{
    package: { ecosystem: string; name: string };
    vulnerable_version_range: string;
    first_patched_version: string;
  }>;
}

export class GitHubClient {
  private token: string;

  constructor(token?: string) {
    this.token = token || process.env.GITHUB_TOKEN || "";
  }

  private async request<T>(path: string, options: RequestInit = {}): Promise<T> {
    const url = path.startsWith("http") ? path : `${GITHUB_API_BASE}${path}`;
    const response = await fetch(url, {
      ...options,
      headers: {
        Authorization: this.token ? `Bearer ${this.token}` : "",
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        ...options.headers,
      },
    });

    if (!response.ok) {
      throw new Error(`GitHub API error ${response.status}: ${await response.text()}`);
    }

    return response.json() as T;
  }

  async searchAdvisories(
    ecosystem: string,
    packageName: string
  ): Promise<GitHubAdvisory[]> {
    log.info({ ecosystem, packageName }, "Searching GitHub security advisories");
    const query = encodeURIComponent(`${packageName} in:package ecosystem:${ecosystem}`);
    const data = await this.request<GitHubAdvisory[]>(
      `/advisories?type=reviewed&ecosystem=${ecosystem}&affects=${encodeURIComponent(packageName)}`
    );
    return data;
  }

  async getAdvisory(ghsaId: string): Promise<GitHubAdvisory> {
    return this.request(`/advisories/${ghsaId}`);
  }

  async cloneRepo(owner: string, repo: string, targetDir: string): Promise<void> {
    const { execSync } = await import("child_process");
    const cloneUrl = this.token
      ? `https://x-access-token:${this.token}@github.com/${owner}/${repo}.git`
      : `https://github.com/${owner}/${repo}.git`;

    log.info({ owner, repo, targetDir }, "Cloning repository");
    execSync(`git clone --depth 1 ${cloneUrl} ${targetDir}`, {
      stdio: "pipe",
      timeout: 60000,
    });
  }

  async createSecurityAdvisory(
    owner: string,
    repo: string,
    advisory: {
      summary: string;
      description: string;
      severity: "critical" | "high" | "medium" | "low";
      vulnerabilities: Array<{
        package: { ecosystem: string; name: string };
        vulnerable_version_range: string;
        patched_versions?: string;
      }>;
      cve_id?: string;
      cwe_ids?: string[];
    }
  ): Promise<{ ghsa_id: string }> {
    log.info({ owner, repo, summary: advisory.summary }, "Creating security advisory");
    return this.request(`/repos/${owner}/${repo}/security-advisories`, {
      method: "POST",
      body: JSON.stringify(advisory),
    });
  }

  async createIssueComment(
    owner: string,
    repo: string,
    issueNumber: number,
    body: string
  ): Promise<void> {
    await this.request(`/repos/${owner}/${repo}/issues/${issueNumber}/comments`, {
      method: "POST",
      body: JSON.stringify({ body }),
    });
  }

  async getRepoLanguages(owner: string, repo: string): Promise<Record<string, number>> {
    return this.request(`/repos/${owner}/${repo}/languages`);
  }
}
