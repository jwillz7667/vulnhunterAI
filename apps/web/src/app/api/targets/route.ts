import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getAuthSession, tenantFilter } from "@/lib/auth-guard";

/**
 * GET /api/targets
 * Lists all targets with scan counts and last scan info.
 */
export async function GET(request: NextRequest) {
  const { session, error } = await getAuthSession();
  if (error) return error;

  const { searchParams } = request.nextUrl;
  const limit = Math.min(parseInt(searchParams.get("limit") ?? "50", 10), 100);
  const offset = parseInt(searchParams.get("offset") ?? "0", 10);

  const where = tenantFilter(session);

  const [results, total] = await Promise.all([
    prisma.target.findMany({
      where,
      include: {
        scans: {
          orderBy: { createdAt: "desc" },
          take: 1,
          select: { id: true, status: true, createdAt: true, findingsCount: true },
        },
        _count: { select: { scans: true } },
      },
      orderBy: { createdAt: "desc" },
      skip: offset,
      take: limit,
    }),
    prisma.target.count({ where }),
  ]);

  const data = results.map((t) => ({
    id: t.id,
    name: t.name,
    type: t.type.toLowerCase(),
    value: t.value,
    tags: typeof t.tags === "string" ? JSON.parse(t.tags as string) : t.tags,
    scanCount: t._count.scans,
    lastScan: t.scans[0]
      ? {
          id: t.scans[0].id,
          status: t.scans[0].status.toLowerCase(),
          date: t.scans[0].createdAt.toISOString(),
          findingsCount: t.scans[0].findingsCount,
        }
      : null,
    createdAt: t.createdAt.toISOString(),
  }));

  return NextResponse.json({
    data,
    pagination: { total, limit, offset, hasMore: offset + limit < total },
  });
}

/**
 * POST /api/targets
 * Creates a new target.
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

  const { name, type, value, tags } = body as {
    name?: string;
    type?: string;
    value?: string;
    tags?: string[];
  };

  if (!value || typeof value !== "string") {
    return NextResponse.json({ error: '"value" is required' }, { status: 400 });
  }

  const target = await prisma.target.create({
    data: {
      name: name ?? value,
      type: (type ?? "DOMAIN").toUpperCase(),
      value: value.trim(),
      tags: JSON.stringify(tags ?? []),
      userId: session.user.id,
    },
  });

  return NextResponse.json(
    {
      data: {
        id: target.id,
        name: target.name,
        type: target.type.toLowerCase(),
        value: target.value,
        tags: typeof target.tags === "string" ? JSON.parse(target.tags as string) : target.tags,
        scanCount: 0,
        lastScan: null,
        createdAt: target.createdAt.toISOString(),
      },
    },
    { status: 201 },
  );
}

/**
 * DELETE /api/targets?id=xxx
 * Deletes a target by ID.
 */
export async function DELETE(request: NextRequest) {
  const { session, error } = await getAuthSession();
  if (error) return error;

  const id = request.nextUrl.searchParams.get("id");
  if (!id) {
    return NextResponse.json({ error: '"id" query parameter is required' }, { status: 400 });
  }

  // Verify ownership (admin can delete any)
  const target = await prisma.target.findUnique({ where: { id } });
  if (!target) {
    return NextResponse.json({ error: "Target not found" }, { status: 404 });
  }
  if (target.userId !== session.user.id && session.user.role !== "ADMIN") {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  await prisma.target.delete({ where: { id } });
  return NextResponse.json({ message: "Target deleted" });
}
