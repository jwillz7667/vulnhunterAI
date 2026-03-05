'use client';

import { Badge, statusVariant } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { formatDate, formatDuration } from '@/lib/utils';
import { Loader2, Plus, Radar } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';

interface Scan {
  id: string;
  target: string;
  targetName?: string;
  scanType: string;
  status: string;
  progress: number;
  findingsCount: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  durationMs: number;
  startTime: string;
  endTime: string | null;
}

const statusTabs = ['all', 'completed', 'running', 'queued', 'failed'] as const;
type StatusTab = (typeof statusTabs)[number];

export function ScansClient() {
  const [activeTab, setActiveTab] = useState<StatusTab>('all');
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);

  const fetchScans = useCallback(async () => {
    try {
      const params = new URLSearchParams();
      if (activeTab !== 'all') params.set('status', activeTab);
      params.set('limit', '50');
      const res = await fetch(`/api/scans?${params}`);
      const json = await res.json();
      setScans(json.data ?? []);
      setTotal(json.pagination?.total ?? 0);
    } catch (err) {
      console.error('Failed to fetch scans:', err);
    } finally {
      setLoading(false);
    }
  }, [activeTab]);

  useEffect(() => {
    setLoading(true);
    fetchScans();
  }, [fetchScans]);

  // Poll for updates when there are running scans
  useEffect(() => {
    const hasRunning = scans.some((s) => s.status === 'running' || s.status === 'queued');
    if (!hasRunning) return;
    const interval = setInterval(fetchScans, 5000);
    return () => clearInterval(interval);
  }, [scans, fetchScans]);

  return (
    <div className="space-y-8 animate-fade-in">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">Scans</h1>
          <p className="text-sm text-slate-400 mt-1">
            Manage and monitor security scans across your targets.
          </p>
        </div>
        <Button className="gap-2" onClick={() => window.location.href = '/scan'}>
          <Plus className="h-4 w-4" />
          New Scan
        </Button>
      </div>

      {/* Status filter tabs */}
      <div className="flex items-center gap-1 p-1 bg-slate-800/50 rounded-lg border border-slate-700/50 w-fit">
        {statusTabs.map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-3 py-1.5 rounded-md text-xs font-medium capitalize transition-all duration-200 ${
              activeTab === tab
                ? 'bg-slate-700 text-slate-100 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            {tab}
          </button>
        ))}
      </div>

      {/* Scans table */}
      <Card>
        <CardContent className="p-0">
          {loading ? (
            <div className="flex items-center justify-center py-16">
              <Loader2 className="h-6 w-6 animate-spin text-slate-400" />
              <span className="ml-2 text-sm text-slate-400">Loading scans...</span>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead>Scan ID</TableHead>
                  <TableHead>Target</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-center">Findings</TableHead>
                  <TableHead>Duration</TableHead>
                  <TableHead>Date</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {scans.map((scan) => (
                  <TableRow key={scan.id}>
                    <TableCell className="font-mono text-xs text-slate-400">
                      {scan.id.slice(0, 8)}
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <Radar className="h-4 w-4 text-slate-500 shrink-0" />
                        <span className="font-medium text-slate-200 truncate max-w-[240px]">
                          {scan.target}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <span className="text-xs uppercase text-slate-400 font-medium">
                        {scan.scanType.replace('_', ' ')}
                      </span>
                    </TableCell>
                    <TableCell>
                      <Badge variant={statusVariant(scan.status)} className="text-[10px]">
                        {scan.status}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-center">
                      {scan.findingsCount > 0 ? (
                        <div className="flex items-center justify-center gap-1">
                          <span className="text-sm font-semibold text-slate-200">
                            {scan.findingsCount}
                          </span>
                          {scan.criticalCount > 0 && (
                            <span className="text-[10px] text-red-400 font-medium">
                              ({scan.criticalCount}C)
                            </span>
                          )}
                        </div>
                      ) : (
                        <span className="text-slate-500">--</span>
                      )}
                    </TableCell>
                    <TableCell className="text-slate-400 text-sm">
                      {scan.durationMs > 0 ? formatDuration(scan.durationMs) : '--'}
                    </TableCell>
                    <TableCell className="text-slate-400 text-sm">
                      {formatDate(scan.startTime)}
                    </TableCell>
                  </TableRow>
                ))}
                {scans.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center py-12 text-slate-500">
                      No scans found. Start a new scan to see results here.
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {!loading && (
        <div className="text-xs text-slate-500">
          Showing {scans.length} of {total} scans
        </div>
      )}
    </div>
  );
}
