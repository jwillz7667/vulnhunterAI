import { prisma } from "@vulnhunter/core";

export async function generateReport(args: {
  scanId: string;
  format?: string;
  complianceFrameworks?: string[];
}): Promise<{ content: Array<{ type: "text"; text: string }> }> {
  const format = (args.format || "markdown").toUpperCase();

  try {
    const scan = await prisma.scan.findUnique({
      where: { id: args.scanId },
      include: { target: true, vulnerabilities: true },
    });

    if (!scan) {
      return {
        content: [{ type: "text" as const, text: JSON.stringify({ error: `Scan ${args.scanId} not found` }, null, 2) }],
      };
    }

    if (scan.status !== "COMPLETED") {
      return {
        content: [{ type: "text" as const, text: JSON.stringify({ error: `Scan ${args.scanId} not completed (status: ${scan.status})` }, null, 2) }],
      };
    }

    // Generate report content
    let content: string;
    try {
      const { generateMarkdown, generateHtml, generateJson } = await import("@vulnhunter/reporter");
      const reportData = {
        id: scan.id,
        target: scan.target.value,
        scanType: scan.type,
        startTime: scan.startedAt?.toISOString() ?? scan.createdAt.toISOString(),
        endTime: scan.completedAt?.toISOString(),
        findings: scan.vulnerabilities.map((v) => ({
          vulnerability: {
            id: v.id,
            title: v.title,
            description: v.description,
            severity: v.severity.toLowerCase(),
            category: v.category.toLowerCase(),
            cvssScore: v.cvssScore ?? 0,
            target: scan.target.value,
            endpoint: v.endpoint ?? undefined,
            references: typeof v.references === "string" ? JSON.parse(v.references as string) : (v.references as string[]) ?? [],
            confirmed: v.confirmed,
            falsePositive: v.falsePositive,
            discoveredAt: v.createdAt.toISOString(),
          },
          module: v.module,
          confidence: v.confidence,
          timestamp: v.createdAt.toISOString(),
        })),
        stats: {
          totalRequests: 0,
          endpointsDiscovered: 0,
          findingsBySeverity: { critical: scan.criticalCount, high: scan.highCount, medium: scan.mediumCount, low: scan.lowCount, info: scan.infoCount },
          findingsByCategory: {},
          confirmedFindings: scan.vulnerabilities.filter((v) => v.confirmed).length,
          falsePositives: scan.vulnerabilities.filter((v) => v.falsePositive).length,
          exploitChainsFound: 0,
          durationMs: (scan.duration ?? 0) * 1000,
          modulesCompleted: [],
          modulesFailed: [],
        },
      };

      switch (format) {
        case "HTML": content = generateHtml(reportData as any); break;
        case "JSON": content = generateJson(reportData as any); break;
        default: content = generateMarkdown(reportData as any); break;
      }
    } catch {
      content = `# Security Report: ${scan.target.value}\n\nScan completed with ${scan.findingsCount} findings.\n- Critical: ${scan.criticalCount}\n- High: ${scan.highCount}\n- Medium: ${scan.mediumCount}\n- Low: ${scan.lowCount}\n- Info: ${scan.infoCount}`;
    }

    // Persist report to DB
    const riskScore = Math.min(100, scan.criticalCount * 15 + scan.highCount * 8 + scan.mediumCount * 3 + scan.lowCount * 1);

    const report = await prisma.report.create({
      data: {
        scanId: scan.id,
        format,
        title: `${scan.target.value} - Security Assessment Report`,
        executiveSummary: `Security assessment identified ${scan.findingsCount} vulnerabilities (${scan.criticalCount} critical, ${scan.highCount} high).`,
        content,
        statistics: {
          totalFindings: scan.findingsCount,
          riskScore,
          severityBreakdown: { critical: scan.criticalCount, high: scan.highCount, medium: scan.mediumCount, low: scan.lowCount, info: scan.infoCount },
        },
      },
    });

    return {
      content: [
        {
          type: "text" as const,
          text: JSON.stringify(
            {
              reportId: report.id,
              scanId: scan.id,
              format: format.toLowerCase(),
              title: report.title,
              riskScore,
              totalFindings: scan.findingsCount,
              content: content.slice(0, 5000),
              message: `Report generated successfully. ${content.length > 5000 ? `(truncated, full report is ${content.length} chars)` : ""}`,
            },
            null,
            2,
          ),
        },
      ],
    };
  } catch (error) {
    const errMsg = error instanceof Error ? error.message : String(error);
    return {
      content: [{ type: "text" as const, text: JSON.stringify({ error: errMsg }, null, 2) }],
    };
  }
}
