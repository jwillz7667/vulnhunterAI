import { prisma } from "@vulnhunter/core";
import type { Prisma } from "@prisma/client";

export async function getVulnerabilities(args: {
  scanId?: string;
  severity?: string;
  category?: string;
  confirmedOnly?: boolean;
}): Promise<{ content: Array<{ type: "text"; text: string }> }> {
  try {
    const where: Prisma.VulnerabilityWhereInput = {};

    if (args.scanId) where.scanId = args.scanId;
    if (args.severity && args.severity !== "all") where.severity = args.severity.toUpperCase();
    if (args.category && args.category !== "all") where.category = args.category.toUpperCase();
    if (args.confirmedOnly) where.confirmed = true;

    const vulnerabilities = await prisma.vulnerability.findMany({
      where,
      include: { scan: { include: { target: true } } },
      orderBy: { cvssScore: "desc" },
      take: 50,
    });

    const result = {
      filters: {
        scanId: args.scanId || "all",
        severity: args.severity || "all",
        category: args.category || "all",
        confirmedOnly: args.confirmedOnly || false,
      },
      total: vulnerabilities.length,
      vulnerabilities: vulnerabilities.map((v) => ({
        id: v.id,
        scanId: v.scanId,
        title: v.title,
        description: v.description,
        severity: v.severity.toLowerCase(),
        category: v.category.toLowerCase(),
        cvssScore: v.cvssScore,
        cweId: v.cweId,
        target: v.scan.target.value,
        endpoint: v.endpoint,
        method: v.method,
        remediation: v.remediation,
        confirmed: v.confirmed,
        confidence: v.confidence,
        module: v.module,
        discoveredAt: v.createdAt.toISOString(),
      })),
    };

    return {
      content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
    };
  } catch (error) {
    const errMsg = error instanceof Error ? error.message : String(error);
    return {
      content: [
        {
          type: "text" as const,
          text: JSON.stringify({ error: errMsg, message: `Failed to query vulnerabilities: ${errMsg}` }, null, 2),
        },
      ],
    };
  }
}
