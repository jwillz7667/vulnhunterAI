import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getAuthSession, scanTenantFilter, isAdmin } from "@/lib/auth-guard";

/**
 * GET /api/reports
 */
export async function GET(request: NextRequest) {
  const { session, error } = await getAuthSession();
  if (error) return error;

  const { searchParams } = request.nextUrl;

  const scanId = searchParams.get("scanId");
  const format = searchParams.get("format");
  const sortBy = searchParams.get("sortBy") ?? "generatedAt";
  const sortDir = (searchParams.get("sortDir") ?? "desc") as "asc" | "desc";
  const limit = Math.min(parseInt(searchParams.get("limit") ?? "50", 10), 100);
  const offset = parseInt(searchParams.get("offset") ?? "0", 10);

  const where: Record<string, unknown> = {
    ...scanTenantFilter(session),
  };
  if (scanId) where.scanId = scanId;
  if (format) where.format = format.toUpperCase();

  const orderByField = sortBy === "generatedAt" ? "generatedAt" : "createdAt";

  const [results, total] = await Promise.all([
    prisma.report.findMany({
      where,
      include: { scan: { include: { target: true } } },
      orderBy: { [orderByField]: sortDir },
      skip: offset,
      take: limit,
    }),
    prisma.report.count({ where }),
  ]);

  const data = results.map((r) => {
    const stats = r.statistics as Record<string, unknown>;
    return {
      id: r.id,
      scanId: r.scanId,
      title: r.title,
      target: r.scan.target.value,
      format: r.format.toLowerCase(),
      generatedAt: r.generatedAt.toISOString(),
      totalVulnerabilities: (stats?.totalFindings as number) ?? r.scan.findingsCount,
      riskScore: (stats?.riskScore as number) ?? 0,
      fileSizeBytes: r.content.length,
      formats: [r.format.toLowerCase()],
    };
  });

  return NextResponse.json({
    data,
    pagination: { total, limit, offset, hasMore: offset + limit < total },
  });
}

/**
 * POST /api/reports
 */
export async function POST(request: NextRequest) {
  const { session, error } = await getAuthSession();
  if (error) return error;

  let body: Record<string, unknown>;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const { scanId, title, format } = body as {
    scanId?: string;
    title?: string;
    format?: string;
  };

  if (!scanId || typeof scanId !== "string") {
    return NextResponse.json(
      { error: 'Field "scanId" is required and must be a string.' },
      { status: 400 },
    );
  }

  const scan = await prisma.scan.findUnique({
    where: { id: scanId },
    include: { target: true, vulnerabilities: true },
  });

  if (!scan) {
    return NextResponse.json({ error: `Scan "${scanId}" not found.` }, { status: 404 });
  }

  // Verify ownership
  if (scan.userId !== session.user.id && !isAdmin(session)) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  if (scan.status !== "COMPLETED") {
    return NextResponse.json(
      { error: `Scan "${scanId}" has not completed yet (status: ${scan.status}).` },
      { status: 400 },
    );
  }

  const reportFormat = (format ?? "markdown").toUpperCase();
  const riskScore = Math.min(
    100,
    scan.criticalCount * 15 + scan.highCount * 8 + scan.mediumCount * 3 + scan.lowCount * 1,
  );

  let content: string;
  try {
    const { generateMarkdown, generateHtml, generateJson } = await import(/* webpackIgnore: true */ "@vulnhunter/reporter");

    const reportData = {
      id: scanId,
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
        findingsBySeverity: {
          critical: scan.criticalCount,
          high: scan.highCount,
          medium: scan.mediumCount,
          low: scan.lowCount,
          info: scan.infoCount,
        },
        findingsByCategory: {},
        confirmedFindings: scan.vulnerabilities.filter((v) => v.confirmed).length,
        falsePositives: scan.vulnerabilities.filter((v) => v.falsePositive).length,
        exploitChainsFound: 0,
        durationMs: (scan.duration ?? 0) * 1000,
        modulesCompleted: [],
        modulesFailed: [],
      },
    };

    switch (reportFormat) {
      case "HTML":
        content = generateHtml(reportData as any);
        break;
      case "JSON":
        content = generateJson(reportData as any);
        break;
      default:
        content = generateMarkdown(reportData as any);
        break;
    }
  } catch {
    content = `# Security Report: ${scan.target.value}\n\nScan completed with ${scan.findingsCount} findings.\n\n- Critical: ${scan.criticalCount}\n- High: ${scan.highCount}\n- Medium: ${scan.mediumCount}\n- Low: ${scan.lowCount}\n- Info: ${scan.infoCount}`;
  }

  const report = await prisma.report.create({
    data: {
      scanId,
      format: reportFormat,
      title: title?.trim() || `${scan.target.value} - Security Assessment Report`,
      executiveSummary: `Security assessment of ${scan.target.value} identified ${scan.findingsCount} vulnerabilities (${scan.criticalCount} critical, ${scan.highCount} high).`,
      content,
      statistics: {
        totalFindings: scan.findingsCount,
        riskScore,
        severityBreakdown: {
          critical: scan.criticalCount,
          high: scan.highCount,
          medium: scan.mediumCount,
          low: scan.lowCount,
          info: scan.infoCount,
        },
      },
      userId: session.user.id,
    },
  });

  return NextResponse.json(
    {
      data: {
        id: report.id,
        scanId,
        title: report.title,
        target: scan.target.value,
        format: reportFormat.toLowerCase(),
        generatedAt: report.generatedAt.toISOString(),
        totalVulnerabilities: scan.findingsCount,
        riskScore,
        fileSizeBytes: content.length,
        formats: [reportFormat.toLowerCase()],
      },
      message: "Report generated successfully.",
    },
    { status: 201 },
  );
}
