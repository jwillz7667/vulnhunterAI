import { NextResponse, type NextRequest } from "next/server";
import { prisma } from "@/lib/prisma";
import { getAuthSession, tenantFilter } from "@/lib/auth-guard";

/**
 * GET /api/scans
 */
export async function GET(request: NextRequest) {
  const { session, error } = await getAuthSession();
  if (error) return error;

  const { searchParams } = request.nextUrl;

  const status = searchParams.get("status");
  const type = searchParams.get("type");
  const limit = Math.min(parseInt(searchParams.get("limit") ?? "50", 10), 100);
  const offset = parseInt(searchParams.get("offset") ?? "0", 10);

  const where: Record<string, unknown> = { ...tenantFilter(session) };
  if (status) where.status = status.toUpperCase();
  if (type) where.type = type.toUpperCase();

  const [results, total] = await Promise.all([
    prisma.scan.findMany({
      where,
      include: { target: true },
      orderBy: { createdAt: "desc" },
      skip: offset,
      take: limit,
    }),
    prisma.scan.count({ where }),
  ]);

  const data = results.map((s) => ({
    id: s.id,
    target: s.target.value,
    targetName: s.target.name,
    scanType: s.type.toLowerCase(),
    status: s.status.toLowerCase(),
    progress: s.progress,
    currentPhase: s.currentPhase,
    findingsCount: s.findingsCount,
    criticalCount: s.criticalCount,
    highCount: s.highCount,
    mediumCount: s.mediumCount,
    lowCount: s.lowCount,
    infoCount: s.infoCount,
    durationMs: s.duration ? s.duration * 1000 : 0,
    startTime: s.startedAt?.toISOString() ?? s.createdAt.toISOString(),
    endTime: s.completedAt?.toISOString() ?? null,
  }));

  return NextResponse.json({
    data,
    pagination: { total, limit, offset, hasMore: offset + limit < total },
  });
}

/**
 * POST /api/scans
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

  const { target, scanType } = body as { target?: string; scanType?: string };

  if (!target || typeof target !== "string" || target.trim().length === 0) {
    return NextResponse.json(
      { error: 'Missing or invalid "target" field' },
      { status: 400 },
    );
  }

  const validTypes = ["full", "recon", "web", "code", "network", "cloud", "smart_contract"];
  if (!scanType || !validTypes.includes(scanType)) {
    return NextResponse.json(
      { error: `Invalid "scanType". Must be one of: ${validTypes.join(", ")}` },
      { status: 400 },
    );
  }

  // Detect target type
  const targetValue = target.trim();
  let targetType = "DOMAIN";
  if (targetValue.startsWith("http")) targetType = "URL";
  else if (/^\d+\.\d+\.\d+\.\d+\/\d+$/.test(targetValue)) targetType = "CIDR";
  else if (/^\d+\.\d+\.\d+\.\d+$/.test(targetValue)) targetType = "IP";

  // Upsert target
  const dbTarget = await prisma.target.upsert({
    where: { id: targetValue },
    update: { updatedAt: new Date() },
    create: {
      name: targetValue,
      type: targetType,
      value: targetValue,
      userId: session.user.id,
    },
  });

  // Create scan record
  const scan = await prisma.scan.create({
    data: {
      targetId: dbTarget.id,
      type: scanType.toUpperCase(),
      status: "QUEUED",
      config: { target: targetValue, scanType, options: body.options ?? {} },
      userId: session.user.id,
    },
  });

  // Fire-and-forget: start the scan in the background
  import(/* webpackIgnore: true */ "@vulnhunter/core").then(({ executeScanWithPersistence }) => {
    executeScanWithPersistence({
      target: targetValue,
      scanType: scanType as any,
      options: {
        maxDepth: 10, rateLimit: 10, requestTimeoutMs: 30000, scanTimeoutMs: 300000,
        maxConcurrency: 10, maxRedirects: 5, enableCookies: true,
        scopeRestrictions: [], enabledModules: [],
        aiPayloadGeneration: false, exploitChainDetection: false,
        ...(typeof body.options === "object" ? body.options : {}),
      },
    }).catch((err: Error) => {
      console.error(`[scan-api] Background scan ${scan.id} failed:`, err.message);
    });
  });

  return NextResponse.json(
    {
      data: {
        id: scan.id,
        target: targetValue,
        scanType,
        status: "queued",
        findingsCount: 0,
        criticalCount: 0, highCount: 0, mediumCount: 0, lowCount: 0, infoCount: 0,
        durationMs: 0,
        startTime: scan.createdAt.toISOString(),
        endTime: null,
      },
      message: "Scan queued successfully",
    },
    { status: 201 },
  );
}
