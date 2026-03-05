import { Badge, statusVariant } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { formatDuration, formatRelativeTime } from '@/lib/utils';
import {
  Clock,
  ExternalLink,
  Globe,
  Network,
  Code2,
  FileCode2,
  Search,
  Cpu,
} from 'lucide-react';

const scanTypeIcon: Record<string, React.ReactNode> = {
  full: <Globe className="h-4 w-4 text-blue-400" />,
  web: <Globe className="h-4 w-4 text-cyan-400" />,
  network: <Network className="h-4 w-4 text-purple-400" />,
  code: <Code2 className="h-4 w-4 text-green-400" />,
  recon: <Search className="h-4 w-4 text-yellow-400" />,
  smart_contract: <FileCode2 className="h-4 w-4 text-orange-400" />,
  cloud: <Cpu className="h-4 w-4 text-indigo-400" />,
};

interface ScanItem {
  id: string;
  target: string;
  scanType: string;
  status: string;
  findingsCount: number;
  durationMs: number;
  startTime: string;
}

export function RecentScans({ scans }: { scans: ScanItem[] }) {
  if (scans.length === 0) {
    return (
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle className="text-base">Recent Scans</CardTitle>
          <a
            href="/scans"
            className="text-xs text-slate-400 hover:text-blue-400 transition-colors flex items-center gap-1"
          >
            View all
            <ExternalLink className="h-3 w-3" />
          </a>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-slate-500 py-8 text-center">
            No scans yet. Start a scan to see results here.
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle className="text-base">Recent Scans</CardTitle>
        <a
          href="/scans"
          className="text-xs text-slate-400 hover:text-blue-400 transition-colors flex items-center gap-1"
        >
          View all
          <ExternalLink className="h-3 w-3" />
        </a>
      </CardHeader>
      <CardContent className="space-y-0">
        {scans.map((scan) => (
          <div
            key={scan.id}
            className="flex items-center justify-between py-3 border-b border-slate-700/30 last:border-0"
          >
            <div className="flex items-center gap-3 min-w-0">
              <div className="rounded-lg bg-slate-700/30 p-2 ring-1 ring-slate-700/50 shrink-0">
                {scanTypeIcon[scan.scanType] ?? (
                  <Globe className="h-4 w-4 text-slate-400" />
                )}
              </div>
              <div className="min-w-0">
                <p className="text-sm font-medium text-slate-200 truncate max-w-[220px]">
                  {scan.target}
                </p>
                <div className="flex items-center gap-2 mt-0.5">
                  <span className="text-xs text-slate-500 uppercase">
                    {scan.scanType.replace('_', ' ')}
                  </span>
                  {scan.findingsCount > 0 && (
                    <>
                      <span className="text-slate-600">·</span>
                      <span className="text-xs text-slate-400">
                        {scan.findingsCount} findings
                      </span>
                    </>
                  )}
                </div>
              </div>
            </div>
            <div className="flex items-center gap-3 shrink-0">
              {scan.durationMs > 0 && (
                <div className="flex items-center gap-1 text-xs text-slate-500">
                  <Clock className="h-3 w-3" />
                  {formatDuration(scan.durationMs)}
                </div>
              )}
              <Badge variant={statusVariant(scan.status)} className="text-[10px]">
                {scan.status}
              </Badge>
              <span className="text-xs text-slate-500 w-16 text-right">
                {formatRelativeTime(scan.startTime)}
              </span>
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}
