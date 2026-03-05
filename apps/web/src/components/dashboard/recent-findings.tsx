import { Badge, severityVariant } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { formatCvss, formatRelativeTime } from '@/lib/utils';
import {
  AlertTriangle,
  CheckCircle2,
  ExternalLink,
  Shield,
  ShieldAlert,
} from 'lucide-react';

interface FindingItem {
  id: string;
  title: string;
  severity: string;
  endpoint: string;
  cvssScore: number;
  confirmed: boolean;
  discoveredAt: string;
}

export function RecentFindings({ findings }: { findings: FindingItem[] }) {
  if (findings.length === 0) {
    return (
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle className="text-base">Recent Findings</CardTitle>
          <a
            href="/vulnerabilities"
            className="text-xs text-slate-400 hover:text-blue-400 transition-colors flex items-center gap-1"
          >
            View all
            <ExternalLink className="h-3 w-3" />
          </a>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-slate-500 py-8 text-center">
            No findings yet. Complete a scan to see vulnerabilities here.
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle className="text-base">Recent Findings</CardTitle>
        <a
          href="/vulnerabilities"
          className="text-xs text-slate-400 hover:text-blue-400 transition-colors flex items-center gap-1"
        >
          View all
          <ExternalLink className="h-3 w-3" />
        </a>
      </CardHeader>
      <CardContent className="space-y-0">
        {findings.map((vuln) => (
          <div
            key={vuln.id}
            className="flex items-center justify-between py-3 border-b border-slate-700/30 last:border-0"
          >
            <div className="flex items-center gap-3 min-w-0">
              <div className="shrink-0">
                {vuln.severity === 'critical' ? (
                  <ShieldAlert className="h-5 w-5 text-red-400" />
                ) : vuln.severity === 'high' ? (
                  <AlertTriangle className="h-5 w-5 text-orange-400" />
                ) : (
                  <Shield className="h-5 w-5 text-slate-400" />
                )}
              </div>
              <div className="min-w-0">
                <p className="text-sm font-medium text-slate-200 truncate max-w-[280px]">
                  {vuln.title}
                </p>
                <div className="flex items-center gap-2 mt-0.5">
                  <span className="text-xs text-slate-500 font-mono truncate max-w-[200px]">
                    {vuln.endpoint}
                  </span>
                </div>
              </div>
            </div>
            <div className="flex items-center gap-3 shrink-0">
              <div className="flex items-center gap-1.5">
                <span className="text-xs font-mono text-slate-400">
                  CVSS {formatCvss(vuln.cvssScore)}
                </span>
              </div>
              {vuln.confirmed && (
                <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
              )}
              <Badge variant={severityVariant(vuln.severity)} className="text-[10px] w-16 justify-center">
                {vuln.severity}
              </Badge>
              <span className="text-xs text-slate-500 w-16 text-right">
                {formatRelativeTime(vuln.discoveredAt)}
              </span>
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}
