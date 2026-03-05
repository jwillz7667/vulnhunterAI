import { createLogger } from "@vulnhunter/core";

const log = createLogger("integration:hackerone");

const HACKERONE_API_BASE = "https://api.hackerone.com/v1";

export interface H1Program {
  id: string;
  type: string;
  attributes: {
    handle: string;
    name: string;
    url: string;
    offers_bounties: boolean;
    state: string;
    submission_state: string;
    started_accepting_at: string;
    policy: string;
  };
}

export interface H1Report {
  id: string;
  type: string;
  attributes: {
    title: string;
    state: string;
    severity_rating: string;
    created_at: string;
    bounty_amount: string | null;
  };
}

export interface H1Scope {
  id: string;
  type: string;
  attributes: {
    asset_type: string;
    asset_identifier: string;
    eligible_for_bounty: boolean;
    eligible_for_submission: boolean;
    instruction: string;
  };
}

export class HackerOneClient {
  private username: string;
  private apiToken: string;

  constructor(username?: string, apiToken?: string) {
    this.username = username || process.env.HACKERONE_USERNAME || "";
    this.apiToken = apiToken || process.env.HACKERONE_API_TOKEN || "";

    if (!this.username || !this.apiToken) {
      log.warn("HackerOne credentials not configured");
    }
  }

  private get authHeader(): string {
    return "Basic " + Buffer.from(`${this.username}:${this.apiToken}`).toString("base64");
  }

  private async request<T>(path: string, options: RequestInit = {}): Promise<T> {
    const url = `${HACKERONE_API_BASE}${path}`;
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
      const body = await response.text();
      throw new Error(`HackerOne API error ${response.status}: ${body}`);
    }

    return response.json() as T;
  }

  async listPrograms(page = 1, pageSize = 25): Promise<{ data: H1Program[]; links: Record<string, string> }> {
    log.info({ page, pageSize }, "Listing HackerOne programs");
    return this.request(`/hackers/programs?page[number]=${page}&page[size]=${pageSize}`);
  }

  async getProgram(handle: string): Promise<{ data: H1Program }> {
    log.info({ handle }, "Fetching HackerOne program");
    return this.request(`/hackers/programs/${handle}`);
  }

  async getProgramScope(handle: string): Promise<{ data: H1Scope[] }> {
    log.info({ handle }, "Fetching program scope");
    return this.request(`/hackers/programs/${handle}/structured_scopes`);
  }

  async submitReport(
    programHandle: string,
    report: {
      title: string;
      vulnerabilityInformation: string;
      impact: string;
      severity: { rating: "none" | "low" | "medium" | "high" | "critical" };
      weakness_id?: string;
      structured_scope_id?: string;
    }
  ): Promise<{ data: H1Report }> {
    log.info({ program: programHandle, title: report.title }, "Submitting report to HackerOne");

    return this.request("/hackers/reports", {
      method: "POST",
      body: JSON.stringify({
        data: {
          type: "report",
          attributes: {
            team_handle: programHandle,
            title: report.title,
            vulnerability_information: report.vulnerabilityInformation,
            impact: report.impact,
            severity: report.severity,
            weakness_id: report.weakness_id,
            structured_scope_id: report.structured_scope_id,
          },
        },
      }),
    });
  }

  async getReport(reportId: string): Promise<{ data: H1Report }> {
    return this.request(`/hackers/reports/${reportId}`);
  }

  async listMyReports(
    page = 1,
    pageSize = 25,
    state?: string
  ): Promise<{ data: H1Report[] }> {
    let path = `/hackers/me/reports?page[number]=${page}&page[size]=${pageSize}`;
    if (state) path += `&filter[state][]=${state}`;
    return this.request(path);
  }

  async addComment(reportId: string, message: string): Promise<void> {
    await this.request(`/hackers/reports/${reportId}/activities`, {
      method: "POST",
      body: JSON.stringify({
        data: {
          type: "activity-comment",
          attributes: { message },
        },
      }),
    });
  }
}
