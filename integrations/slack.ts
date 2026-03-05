import { createLogger } from "@vulnhunter/core";

const log = createLogger("integration:slack");

export interface SlackNotification {
  title: string;
  severity: string;
  category: string;
  endpoint?: string;
  cvssScore?: number;
  description: string;
  scanId: string;
}

function severityColor(severity: string): string {
  switch (severity.toLowerCase()) {
    case "critical": return "#dc2626";
    case "high": return "#ea580c";
    case "medium": return "#d97706";
    case "low": return "#2563eb";
    default: return "#6b7280";
  }
}

export class SlackClient {
  private webhookUrl: string;

  constructor(webhookUrl?: string) {
    this.webhookUrl = webhookUrl || process.env.SLACK_WEBHOOK_URL || "";
  }

  async sendVulnerabilityAlert(notification: SlackNotification): Promise<void> {
    if (!this.webhookUrl) {
      log.warn("Slack webhook URL not configured, skipping notification");
      return;
    }

    log.info(
      { title: notification.title, severity: notification.severity },
      "Sending Slack vulnerability alert"
    );

    const payload = {
      blocks: [
        {
          type: "header",
          text: {
            type: "plain_text",
            text: `VulnHunter: ${notification.severity.toUpperCase()} Vulnerability Found`,
          },
        },
        {
          type: "section",
          fields: [
            { type: "mrkdwn", text: `*Title:*\n${notification.title}` },
            { type: "mrkdwn", text: `*Severity:*\n${notification.severity.toUpperCase()}` },
            { type: "mrkdwn", text: `*Category:*\n${notification.category}` },
            { type: "mrkdwn", text: `*CVSS:*\n${notification.cvssScore ?? "N/A"}` },
          ],
        },
        {
          type: "section",
          text: {
            type: "mrkdwn",
            text: `*Description:*\n${notification.description.slice(0, 500)}`,
          },
        },
        {
          type: "context",
          elements: [
            {
              type: "mrkdwn",
              text: `Scan ID: ${notification.scanId}${notification.endpoint ? ` | Endpoint: ${notification.endpoint}` : ""}`,
            },
          ],
        },
      ],
      attachments: [
        {
          color: severityColor(notification.severity),
          text: "",
        },
      ],
    };

    const response = await fetch(this.webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      throw new Error(`Slack webhook error ${response.status}`);
    }
  }

  async sendScanComplete(scanId: string, stats: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    duration: string;
    target: string;
  }): Promise<void> {
    if (!this.webhookUrl) return;

    const payload = {
      blocks: [
        {
          type: "header",
          text: { type: "plain_text", text: "VulnHunter: Scan Complete" },
        },
        {
          type: "section",
          fields: [
            { type: "mrkdwn", text: `*Target:*\n${stats.target}` },
            { type: "mrkdwn", text: `*Duration:*\n${stats.duration}` },
            { type: "mrkdwn", text: `*Total Findings:*\n${stats.total}` },
            { type: "mrkdwn", text: `*Critical/High:*\n${stats.critical}/${stats.high}` },
          ],
        },
        {
          type: "context",
          elements: [
            { type: "mrkdwn", text: `Scan ID: ${scanId}` },
          ],
        },
      ],
    };

    await fetch(this.webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
  }
}
