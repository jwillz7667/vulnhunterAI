import { createLogger } from "@vulnhunter/core";

const log = createLogger("integration:bugcrowd");

const BUGCROWD_API_BASE = "https://api.bugcrowd.com";

export interface BcProgram {
  id: string;
  type: string;
  attributes: {
    code: string;
    name: string;
    tagline: string;
    program_url: string;
    max_payout: number;
    min_payout: number;
    starts_at: string;
    ends_at: string | null;
    demo: boolean;
    organization: { name: string };
  };
}

export interface BcSubmission {
  id: string;
  type: string;
  attributes: {
    title: string;
    severity: number;
    state: string;
    caption: string;
    submitted_at: string;
    closed_at: string | null;
    bounty_amount: string | null;
  };
}

export interface BcTarget {
  id: string;
  type: string;
  attributes: {
    name: string;
    uri: string;
    category: string;
    tags: string[];
  };
}

export class BugcrowdClient {
  private apiToken: string;
  private email: string;

  constructor(apiToken?: string, email?: string) {
    this.apiToken = apiToken || process.env.BUGCROWD_API_TOKEN || "";
    this.email = email || process.env.BUGCROWD_EMAIL || "";

    if (!this.apiToken) {
      log.warn("Bugcrowd API token not configured");
    }
  }

  private async request<T>(path: string, options: RequestInit = {}): Promise<T> {
    const url = `${BUGCROWD_API_BASE}${path}`;
    const response = await fetch(url, {
      ...options,
      headers: {
        Authorization: `Token ${this.apiToken}`,
        "Content-Type": "application/vnd.bugcrowd+json",
        Accept: "application/vnd.bugcrowd+json",
        ...options.headers,
      },
    });

    if (!response.ok) {
      const body = await response.text();
      throw new Error(`Bugcrowd API error ${response.status}: ${body}`);
    }

    return response.json() as T;
  }

  async listPrograms(
    page = 1,
    pageSize = 25
  ): Promise<{ data: BcProgram[] }> {
    log.info({ page, pageSize }, "Listing Bugcrowd programs");
    return this.request(
      `/programs?page[offset]=${(page - 1) * pageSize}&page[limit]=${pageSize}`
    );
  }

  async getProgram(code: string): Promise<{ data: BcProgram }> {
    log.info({ code }, "Fetching Bugcrowd program");
    return this.request(`/programs/${code}`);
  }

  async getProgramTargets(programId: string): Promise<{ data: BcTarget[] }> {
    log.info({ programId }, "Fetching program targets");
    return this.request(`/programs/${programId}/targets`);
  }

  async submitReport(
    programId: string,
    report: {
      title: string;
      description: string;
      severity: 1 | 2 | 3 | 4 | 5;
      targetId?: string;
      extraInfo?: string;
    }
  ): Promise<{ data: BcSubmission }> {
    log.info({ programId, title: report.title }, "Submitting to Bugcrowd");

    return this.request(`/programs/${programId}/submissions`, {
      method: "POST",
      body: JSON.stringify({
        data: {
          type: "submission",
          attributes: {
            title: report.title,
            description_markdown: report.description,
            severity: report.severity,
            extra_info: report.extraInfo,
          },
          relationships: report.targetId
            ? {
                target: {
                  data: { type: "target", id: report.targetId },
                },
              }
            : undefined,
        },
      }),
    });
  }

  async getSubmission(submissionId: string): Promise<{ data: BcSubmission }> {
    return this.request(`/submissions/${submissionId}`);
  }

  async listMySubmissions(
    page = 1,
    pageSize = 25,
    state?: string
  ): Promise<{ data: BcSubmission[] }> {
    let path = `/submissions?page[offset]=${(page - 1) * pageSize}&page[limit]=${pageSize}`;
    if (state) path += `&filter[state]=${state}`;
    return this.request(path);
  }

  async addComment(submissionId: string, comment: string): Promise<void> {
    await this.request(`/submissions/${submissionId}/comments`, {
      method: "POST",
      body: JSON.stringify({
        data: {
          type: "comment",
          attributes: { body_markdown: comment },
        },
      }),
    });
  }
}
