import { NextResponse, type NextRequest } from "next/server";
import { prisma } from "@/lib/prisma";
import type { Prisma } from "@prisma/client";
import { getAuthSession, scanTenantFilter } from "@/lib/auth-guard";

/**
 * GET /api/vulnerabilities
 */
export async function GET(request: NextRequest) {
  const { session, error } = await getAuthSession();
  if (error) return error;

  const { searchParams } = request.nextUrl;

  const severity = searchParams.get("severity");
  const category = searchParams.get("category");
  const confirmed = searchParams.get("confirmed");
  const scanId = searchParams.get("scanId");
  const search = searchParams.get("search");
  const minCvss = searchParams.get("minCvss");
  const sortBy = searchParams.get("sortBy") ?? "createdAt";
  const sortDir = (searchParams.get("sortDir") ?? "desc") as "asc" | "desc";
  const limit = Math.min(parseInt(searchParams.get("limit") ?? "50", 10), 100);
  const offset = parseInt(searchParams.get("offset") ?? "0", 10);

  const where: Prisma.VulnerabilityWhereInput = {
    ...scanTenantFilter(session),
  };

  if (severity) where.severity = severity.toUpperCase();
  if (category) where.category = category.toUpperCase();
  if (confirmed === "true") where.confirmed = true;
  if (confirmed === "false") where.confirmed = false;
  if (scanId) where.scanId = scanId;
  if (minCvss) {
    const min = parseFloat(minCvss);
    if (!isNaN(min)) where.cvssScore = { gte: min };
  }
  if (search) {
    where.OR = [
      { title: { contains: search } },
      { endpoint: { contains: search } },
      { description: { contains: search } },
    ];
  }

  const orderByField = sortBy === "cvssScore" ? "cvssScore" : sortBy === "confidence" ? "confidence" : "createdAt";

  const [results, total] = await Promise.all([
    prisma.vulnerability.findMany({
      where,
      include: { scan: { include: { target: true } } },
      orderBy: { [orderByField]: sortDir },
      skip: offset,
      take: limit,
    }),
    prisma.vulnerability.count({ where }),
  ]);

  // Severity aggregation
  const allForAgg = await prisma.vulnerability.groupBy({
    by: ["severity"],
    where,
    _count: true,
  });

  const severityCounts: Record<string, number> = {
    critical: 0, high: 0, medium: 0, low: 0, info: 0,
  };
  for (const row of allForAgg) {
    const key = row.severity.toLowerCase();
    if (key in severityCounts) severityCounts[key] = row._count;
  }

  const data = results.map((v) => ({
    id: v.id,
    scanId: v.scanId,
    title: v.title,
    description: v.description,
    severity: v.severity.toLowerCase(),
    category: v.category.toLowerCase(),
    cvssScore: v.cvssScore ?? 0,
    cvssVector: v.cvssVector,
    cweId: v.cweId,
    target: v.scan.target.value,
    endpoint: v.endpoint ?? "",
    method: v.method,
    evidence: v.evidence,
    remediation: v.remediation,
    references: typeof v.references === "string" ? JSON.parse(v.references as string) : v.references,
    confirmed: v.confirmed,
    falsePositive: v.falsePositive,
    module: v.module,
    confidence: v.confidence,
    discoveredAt: v.createdAt.toISOString(),
  }));

  return NextResponse.json({
    data,
    aggregations: { severityCounts },
    pagination: { total, limit, offset, hasMore: offset + limit < total },
  });
}
