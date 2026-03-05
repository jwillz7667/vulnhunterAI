import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getAuthSession, tenantFilter, scanTenantFilter } from "@/lib/auth-guard";

/**
 * GET /api/stats
 * Returns dashboard statistics computed from real data.
 */
export async function GET() {
  const { session, error } = await getAuthSession();
  if (error) return error;

  const userFilter = tenantFilter(session);
  const scanFilter = scanTenantFilter(session);

  const [
    totalScans,
    totalVulnerabilities,
    totalTargets,
    severityAgg,
    recentScans,
  ] = await Promise.all([
    prisma.scan.count({ where: userFilter }),
    prisma.vulnerability.count({ where: scanFilter }),
    prisma.target.count({ where: userFilter }),
    prisma.vulnerability.groupBy({
      by: ["severity"],
      where: scanFilter,
      _count: true,
    }),
    prisma.scan.findMany({
      where: userFilter,
      orderBy: { createdAt: "desc" },
      take: 7,
      select: {
        createdAt: true,
        findingsCount: true,
        criticalCount: true,
        highCount: true,
        mediumCount: true,
        lowCount: true,
        infoCount: true,
      },
    }),
  ]);

  const severityDistribution: Record<string, number> = {
    critical: 0, high: 0, medium: 0, low: 0, info: 0,
  };
  for (const row of severityAgg) {
    const key = row.severity.toLowerCase();
    if (key in severityDistribution) severityDistribution[key] = row._count;
  }

  const riskScore =
    totalVulnerabilities > 0
      ? Math.min(
          100,
          Math.round(
            ((severityDistribution.critical * 10 +
              severityDistribution.high * 7 +
              severityDistribution.medium * 4 +
              severityDistribution.low * 1) /
              Math.max(totalVulnerabilities, 1)) *
              10,
          ),
        )
      : 0;

  const weeklyTrend = recentScans.map((s) => ({
    date: s.createdAt.toISOString().slice(0, 10),
    findings: s.findingsCount,
    critical: s.criticalCount,
    high: s.highCount,
    medium: s.mediumCount,
    low: s.lowCount,
  }));

  return NextResponse.json({
    totalScans,
    totalVulnerabilities,
    totalTargets,
    riskScore,
    severityDistribution,
    weeklyTrend,
  });
}
