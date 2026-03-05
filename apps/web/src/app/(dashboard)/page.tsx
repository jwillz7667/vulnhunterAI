import { StatCard } from "@/components/dashboard/stat-card";
import {
  SeverityPieChart,
  WeeklyTrendChart,
  ActivityChart,
} from "@/components/dashboard/severity-chart";
import { RecentScans } from "@/components/dashboard/recent-scans";
import { RecentFindings } from "@/components/dashboard/recent-findings";
import { prisma } from "@/lib/prisma";
import { auth } from "@/lib/auth";
import { redirect } from "next/navigation";
import { tenantFilter, scanTenantFilter } from "@/lib/auth-guard";
import {
  AlertTriangle,
  Bug,
  Radar,
  ShieldCheck,
} from "lucide-react";

export const dynamic = "force-dynamic";

export default async function DashboardPage() {
  const session = await auth();
  if (!session?.user) redirect("/login");

  const userFilter = tenantFilter(session);
  const scanFilter = scanTenantFilter(session);

  const [totalScans, totalVulnerabilities, severityAgg, recentScansData, recentVulnsData] =
    await Promise.all([
      prisma.scan.count({ where: userFilter }),
      prisma.vulnerability.count({ where: scanFilter }),
      prisma.vulnerability.groupBy({ by: ["severity"], where: scanFilter, _count: true }),
      prisma.scan.findMany({
        where: userFilter,
        include: { target: true },
        orderBy: { createdAt: "desc" },
        take: 5,
      }),
      prisma.vulnerability.findMany({
        where: scanFilter,
        include: { scan: { include: { target: true } } },
        orderBy: { createdAt: "desc" },
        take: 6,
      }),
    ]);

  const sevCounts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const row of severityAgg) {
    const key = row.severity.toLowerCase();
    if (key in sevCounts) sevCounts[key] = row._count;
  }

  const criticalHighCount = sevCounts.critical + sevCounts.high;
  const riskScore =
    totalVulnerabilities > 0
      ? Math.min(
          100,
          Math.round(
            ((sevCounts.critical * 10 + sevCounts.high * 7 + sevCounts.medium * 4 + sevCounts.low * 1) /
              Math.max(totalVulnerabilities, 1)) * 10,
          ),
        )
      : 0;

  const severityDistribution = [
    { name: "Critical", value: sevCounts.critical, color: "#ef4444" },
    { name: "High", value: sevCounts.high, color: "#f97316" },
    { name: "Medium", value: sevCounts.medium, color: "#eab308" },
    { name: "Low", value: sevCounts.low, color: "#3b82f6" },
    { name: "Info", value: sevCounts.info, color: "#6b7280" },
  ];

  const weeklyTrend = recentScansData.map((s) => ({
    week: s.createdAt.toISOString().slice(5, 10),
    critical: s.criticalCount,
    high: s.highCount,
    medium: s.mediumCount,
    low: s.lowCount,
    info: s.infoCount,
  }));

  const scans = recentScansData.map((s) => ({
    id: s.id,
    target: s.target.value,
    scanType: s.type.toLowerCase(),
    status: s.status.toLowerCase(),
    findingsCount: s.findingsCount,
    durationMs: (s.duration ?? 0) * 1000,
    startTime: (s.startedAt ?? s.createdAt).toISOString(),
  }));

  const findings = recentVulnsData.map((v) => ({
    id: v.id,
    title: v.title,
    severity: v.severity.toLowerCase(),
    endpoint: v.endpoint ?? "",
    cvssScore: v.cvssScore ?? 0,
    confirmed: v.confirmed,
    discoveredAt: v.createdAt.toISOString(),
  }));

  return (
    <div className="space-y-8 animate-fade-in">
      <div>
        <h1 className="text-2xl font-bold text-slate-100">Dashboard</h1>
        <p className="text-sm text-slate-400 mt-1">
          Overview of your security research activity and findings.
        </p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Scans"
          value={totalScans}
          icon={Radar}
          iconColor="text-blue-400"
          glowColor="from-blue-500/10"
        />
        <StatCard
          title="Vulnerabilities Found"
          value={totalVulnerabilities}
          icon={Bug}
          iconColor="text-cyan-400"
          glowColor="from-cyan-500/10"
        />
        <StatCard
          title="Critical / High"
          value={criticalHighCount}
          icon={AlertTriangle}
          iconColor="text-orange-400"
          glowColor="from-orange-500/10"
        />
        <StatCard
          title="Risk Score"
          value={`${riskScore}/100`}
          icon={ShieldCheck}
          iconColor="text-emerald-400"
          glowColor="from-emerald-500/10"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <SeverityPieChart data={severityDistribution} />
        <WeeklyTrendChart data={weeklyTrend} />
        <ActivityChart />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <RecentScans scans={scans} />
        <RecentFindings findings={findings} />
      </div>
    </div>
  );
}
