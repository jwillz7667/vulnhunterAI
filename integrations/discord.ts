import { createLogger } from "@vulnhunter/core";

const log = createLogger("integration:discord");

function severityColor(severity: string): number {
  switch (severity.toLowerCase()) {
    case "critical": return 0xdc2626;
    case "high": return 0xea580c;
    case "medium": return 0xd97706;
    case "low": return 0x2563eb;
    default: return 0x6b7280;
  }
}

export class DiscordClient {
  private webhookUrl: string;

  constructor(webhookUrl?: string) {
    this.webhookUrl = webhookUrl || process.env.DISCORD_WEBHOOK_URL || "";
  }

  async sendVulnerabilityAlert(notification: {
    title: string;
    severity: string;
    category: string;
    endpoint?: string;
    cvssScore?: number;
    description: string;
    scanId: string;
  }): Promise<void> {
    if (!this.webhookUrl) {
      log.warn("Discord webhook URL not configured");
      return;
    }

    const payload = {
      embeds: [
        {
          title: `${notification.severity.toUpperCase()}: ${notification.title}`,
          description: notification.description.slice(0, 2000),
          color: severityColor(notification.severity),
          fields: [
            { name: "Category", value: notification.category, inline: true },
            { name: "CVSS", value: String(notification.cvssScore ?? "N/A"), inline: true },
            { name: "Endpoint", value: notification.endpoint || "N/A", inline: true },
          ],
          footer: {
            text: `VulnHunter AI | Scan: ${notification.scanId}`,
          },
          timestamp: new Date().toISOString(),
        },
      ],
    };

    const response = await fetch(this.webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      throw new Error(`Discord webhook error ${response.status}`);
    }

    log.info({ title: notification.title }, "Discord alert sent");
  }

  async sendScanComplete(scanId: string, stats: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    target: string;
    duration: string;
  }): Promise<void> {
    if (!this.webhookUrl) return;

    const payload = {
      embeds: [
        {
          title: "Scan Complete",
          color: stats.critical > 0 ? 0xdc2626 : stats.high > 0 ? 0xea580c : 0x16a34a,
          fields: [
            { name: "Target", value: stats.target, inline: true },
            { name: "Duration", value: stats.duration, inline: true },
            { name: "Total", value: String(stats.total), inline: true },
            { name: "Critical", value: String(stats.critical), inline: true },
            { name: "High", value: String(stats.high), inline: true },
            { name: "Medium", value: String(stats.medium), inline: true },
          ],
          footer: { text: `VulnHunter AI | ${scanId}` },
          timestamp: new Date().toISOString(),
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
