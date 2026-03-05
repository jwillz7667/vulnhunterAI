'use client';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { formatDate } from '@/lib/utils';
import {
  Download,
  Eye,
  FileBarChart,
  FileJson,
  FileText,
  FileCode,
  AlertTriangle,
  Loader2,
  Shield,
} from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';

interface ReportItem {
  id: string;
  scanId: string;
  title: string;
  target: string;
  format: string;
  generatedAt: string;
  totalVulnerabilities: number;
  riskScore: number;
  fileSizeBytes: number;
  formats: string[];
}

const formatIcons: Record<string, React.ReactNode> = {
  pdf: <FileBarChart className="h-4 w-4" />,
  html: <FileCode className="h-4 w-4" />,
  json: <FileJson className="h-4 w-4" />,
  markdown: <FileText className="h-4 w-4" />,
};

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function riskScoreColor(score: number): string {
  if (score >= 80) return 'text-red-400';
  if (score >= 60) return 'text-orange-400';
  if (score >= 40) return 'text-yellow-400';
  return 'text-emerald-400';
}

function riskScoreBg(score: number): string {
  if (score >= 80) return 'from-red-500/20 to-red-500/5';
  if (score >= 60) return 'from-orange-500/20 to-orange-500/5';
  if (score >= 40) return 'from-yellow-500/20 to-yellow-500/5';
  return 'from-emerald-500/20 to-emerald-500/5';
}

export function ReportsClient() {
  const [reports, setReports] = useState<ReportItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedReport, setSelectedReport] = useState<string | null>(null);

  const fetchReports = useCallback(async () => {
    try {
      const res = await fetch('/api/reports');
      const json = await res.json();
      const data = json.data ?? [];
      setReports(data);
      if (data.length > 0 && !selectedReport) {
        setSelectedReport(data[0].id);
      }
    } catch (err) {
      console.error('Failed to fetch reports:', err);
    } finally {
      setLoading(false);
    }
  }, [selectedReport]);

  useEffect(() => {
    fetchReports();
  }, [fetchReports]);

  const selected = reports.find((r) => r.id === selectedReport);

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="h-6 w-6 animate-spin text-slate-400" />
        <span className="ml-2 text-sm text-slate-400">Loading reports...</span>
      </div>
    );
  }

  return (
    <div className="space-y-8 animate-fade-in">
      {/* Page header */}
      <div>
        <h1 className="text-2xl font-bold text-slate-100">Reports</h1>
        <p className="text-sm text-slate-400 mt-1">
          View and download security assessment reports.
        </p>
      </div>

      {reports.length === 0 ? (
        <Card>
          <CardContent className="flex items-center justify-center py-20">
            <div className="text-center">
              <FileBarChart className="h-12 w-12 text-slate-600 mx-auto mb-3" />
              <p className="text-sm text-slate-400">
                No reports generated yet. Complete a scan and generate a report.
              </p>
            </div>
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
          {/* Report list */}
          <div className="xl:col-span-1 space-y-3">
            {reports.map((report) => (
              <button
                key={report.id}
                onClick={() => setSelectedReport(report.id)}
                className={`w-full text-left rounded-xl border p-4 transition-all duration-200 ${
                  selectedReport === report.id
                    ? 'border-blue-500/30 bg-blue-500/5 shadow-glow-blue'
                    : 'border-slate-700/50 bg-slate-800/50 hover:bg-slate-800/70 hover:border-slate-600/50'
                }`}
              >
                <div className="flex items-start justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <FileBarChart className="h-4 w-4 text-blue-400 shrink-0" />
                    <span className="text-sm font-medium text-slate-200 line-clamp-1">
                      {report.title}
                    </span>
                  </div>
                </div>
                <div className="flex items-center gap-3 text-xs text-slate-400">
                  <span>{formatDate(report.generatedAt)}</span>
                  <span className="text-slate-600">|</span>
                  <span>{report.totalVulnerabilities} vulns</span>
                  <span className="text-slate-600">|</span>
                  <span className={riskScoreColor(report.riskScore)}>
                    Risk: {report.riskScore}
                  </span>
                </div>
              </button>
            ))}
          </div>

          {/* Report preview */}
          <div className="xl:col-span-2">
            {selected ? (
              <Card>
                <CardHeader className="flex flex-row items-start justify-between">
                  <div>
                    <CardTitle className="text-lg">{selected.title}</CardTitle>
                    <p className="text-sm text-slate-400 mt-1">
                      Generated on {formatDate(selected.generatedAt)} from scan{' '}
                      <span className="font-mono text-slate-500">
                        {selected.scanId.slice(0, 8)}
                      </span>
                    </p>
                  </div>
                  <Button variant="outline" size="sm" className="gap-2">
                    <Eye className="h-3.5 w-3.5" />
                    Preview
                  </Button>
                </CardHeader>
                <CardContent className="space-y-6">
                  {/* Risk score display */}
                  <div
                    className={`rounded-xl border border-slate-700/50 bg-gradient-to-br ${riskScoreBg(
                      selected.riskScore
                    )} p-6`}
                  >
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm text-slate-400 mb-1">
                          Overall Risk Score
                        </p>
                        <p
                          className={`text-5xl font-bold ${riskScoreColor(
                            selected.riskScore
                          )}`}
                        >
                          {selected.riskScore}
                          <span className="text-lg text-slate-500">/100</span>
                        </p>
                      </div>
                      <div className="text-right space-y-1">
                        <div className="flex items-center gap-2">
                          <AlertTriangle className="h-4 w-4 text-slate-400" />
                          <span className="text-sm text-slate-300">
                            {selected.totalVulnerabilities} vulnerabilities
                          </span>
                        </div>
                        <div className="flex items-center gap-2">
                          <Shield className="h-4 w-4 text-slate-400" />
                          <span className="text-sm text-slate-300">
                            Target: {selected.target}
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Report details */}
                  <div className="grid grid-cols-2 gap-4">
                    <div className="rounded-lg bg-slate-800/30 border border-slate-700/30 p-4">
                      <p className="text-xs text-slate-500 uppercase tracking-wider mb-1">
                        File Size
                      </p>
                      <p className="text-sm font-medium text-slate-200">
                        {formatFileSize(selected.fileSizeBytes)}
                      </p>
                    </div>
                    <div className="rounded-lg bg-slate-800/30 border border-slate-700/30 p-4">
                      <p className="text-xs text-slate-500 uppercase tracking-wider mb-1">
                        Formats Available
                      </p>
                      <div className="flex items-center gap-1.5 mt-0.5">
                        {selected.formats.map((fmt) => (
                          <Badge key={fmt} variant="default" className="text-[10px]">
                            {fmt.toUpperCase()}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  </div>

                  {/* Download buttons */}
                  <div>
                    <p className="text-sm font-medium text-slate-300 mb-3">
                      Download Report
                    </p>
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                      {selected.formats.map((fmt) => (
                        <Button
                          key={fmt}
                          variant="outline"
                          size="sm"
                          className="gap-2 justify-start"
                        >
                          {formatIcons[fmt] ?? (
                            <FileText className="h-4 w-4" />
                          )}
                          <span className="uppercase text-xs">{fmt}</span>
                          <Download className="h-3 w-3 ml-auto text-slate-500" />
                        </Button>
                      ))}
                    </div>
                  </div>
                </CardContent>
              </Card>
            ) : (
              <Card>
                <CardContent className="flex items-center justify-center py-20">
                  <div className="text-center">
                    <FileBarChart className="h-12 w-12 text-slate-600 mx-auto mb-3" />
                    <p className="text-sm text-slate-400">
                      Select a report to view details.
                    </p>
                  </div>
                </CardContent>
              </Card>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
