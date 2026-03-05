import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getAuthSession, tenantFilter } from "@/lib/auth-guard";

/**
 * GET /api/bounties
 * Returns bounty programs and submissions from the database.
 */
export async function GET(request: NextRequest) {
  const { session, error } = await getAuthSession();
  if (error) return error;

  const { searchParams } = request.nextUrl;
  const type = searchParams.get("type");

  if (type === "submissions") {
    const submissions = await prisma.submission.findMany({
      where: {
        ...tenantFilter(session),
      },
      include: {
        program: true,
        vulnerability: true,
      },
      orderBy: { createdAt: "desc" },
      take: 50,
    });

    return NextResponse.json({
      data: submissions.map((s) => ({
        id: s.id,
        programId: s.programId,
        programName: s.program.name,
        platform: s.program.platform.toLowerCase(),
        vulnerabilityId: s.vulnerabilityId,
        vulnerabilityTitle: s.vulnerability.title,
        status: s.status.toLowerCase(),
        reward: s.reward,
        reportUrl: s.reportUrl,
        submittedAt: s.submittedAt?.toISOString() ?? null,
        resolvedAt: s.resolvedAt?.toISOString() ?? null,
      })),
    });
  }

  // Default: return programs
  const programs = await prisma.bountyProgram.findMany({
    where: tenantFilter(session),
    include: {
      _count: { select: { submissions: true } },
    },
    orderBy: { createdAt: "desc" },
    take: 50,
  });

  return NextResponse.json({
    data: programs.map((p) => ({
      id: p.id,
      platform: p.platform.toLowerCase(),
      name: p.name,
      url: p.url,
      bountyRange: p.bountyMin && p.bountyMax ? `$${p.bountyMin} - $${p.bountyMax}` : null,
      avgPayout: p.avgPayout,
      avgResponseHours: p.avgResponseHours,
      active: p.active,
      submissionCount: p._count.submissions,
      createdAt: p.createdAt.toISOString(),
    })),
  });
}
