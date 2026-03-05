'use client';

import { Badge, severityVariant } from '@/components/ui/badge';
import { Card, CardContent } from '@/components/ui/card';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { formatRelativeTime, formatUsd } from '@/lib/utils';
import {
  Award,
  Clock,
  DollarSign,
  ExternalLink,
  Loader2,
  Send,
  Trophy,
} from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';

interface BountyProgram {
  id: string;
  platform: string;
  name: string;
  url: string;
  bountyRange: string | null;
  avgPayout: number | null;
  avgResponseHours: number | null;
  active: boolean;
  submissionCount: number;
}

interface Submission {
  id: string;
  programName: string;
  platform: string;
  vulnerabilityTitle: string;
  status: string;
  reward: number | null;
  submittedAt: string | null;
  resolvedAt: string | null;
}

function submissionStatusVariant(status: string) {
  switch (status) {
    case 'accepted': case 'resolved': return 'success' as const;
    case 'triaged': return 'brand' as const;
    case 'submitted': return 'default' as const;
    case 'duplicate': return 'warning' as const;
    case 'informative': return 'outline' as const;
    case 'not_applicable': return 'destructive' as const;
    default: return 'default' as const;
  }
}

export function BountiesClient() {
  const [view, setView] = useState<'programs' | 'submissions'>('programs');
  const [programs, setPrograms] = useState<BountyProgram[]>([]);
  const [submissions, setSubmissions] = useState<Submission[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchData = useCallback(async () => {
    try {
      const [progRes, subRes] = await Promise.all([
        fetch('/api/bounties'),
        fetch('/api/bounties?type=submissions'),
      ]);
      const progJson = await progRes.json();
      const subJson = await subRes.json();
      setPrograms(progJson.data ?? []);
      setSubmissions(subJson.data ?? []);
    } catch (err) {
      console.error('Failed to fetch bounties:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  const totalEarnings = submissions.filter((s) => s.reward !== null).reduce((sum, s) => sum + (s.reward ?? 0), 0);
  const pendingSubmissions = submissions.filter((s) => s.status === 'submitted' || s.status === 'triaged').length;
  const acceptedSubmissions = submissions.filter((s) => s.status === 'accepted' || s.status === 'resolved').length;

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="h-6 w-6 animate-spin text-slate-400" />
        <span className="ml-2 text-sm text-slate-400">Loading bounty data...</span>
      </div>
    );
  }

  return (
    <div className="space-y-8 animate-fade-in">
      <div>
        <h1 className="text-2xl font-bold text-slate-100">Bug Bounties</h1>
        <p className="text-sm text-slate-400 mt-1">Track bounty programs, submissions, and earnings.</p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="relative overflow-hidden rounded-xl border border-slate-700/50 bg-slate-800/50 backdrop-blur-xl p-5">
          <div className="relative flex items-center gap-3">
            <div className="rounded-lg bg-emerald-500/10 p-2.5 ring-1 ring-emerald-500/20"><DollarSign className="h-5 w-5 text-emerald-400" /></div>
            <div><p className="text-xs text-slate-400">Total Earnings</p><p className="text-2xl font-bold text-emerald-400">{formatUsd(totalEarnings)}</p></div>
          </div>
        </div>
        <div className="relative overflow-hidden rounded-xl border border-slate-700/50 bg-slate-800/50 backdrop-blur-xl p-5">
          <div className="relative flex items-center gap-3">
            <div className="rounded-lg bg-blue-500/10 p-2.5 ring-1 ring-blue-500/20"><Send className="h-5 w-5 text-blue-400" /></div>
            <div><p className="text-xs text-slate-400">Pending Review</p><p className="text-2xl font-bold text-blue-400">{pendingSubmissions}</p></div>
          </div>
        </div>
        <div className="relative overflow-hidden rounded-xl border border-slate-700/50 bg-slate-800/50 backdrop-blur-xl p-5">
          <div className="relative flex items-center gap-3">
            <div className="rounded-lg bg-cyan-500/10 p-2.5 ring-1 ring-cyan-500/20"><Trophy className="h-5 w-5 text-cyan-400" /></div>
            <div><p className="text-xs text-slate-400">Accepted Reports</p><p className="text-2xl font-bold text-cyan-400">{acceptedSubmissions}</p></div>
          </div>
        </div>
      </div>

      <div className="flex items-center gap-1 p-1 bg-slate-800/50 rounded-lg border border-slate-700/50 w-fit">
        <button onClick={() => setView('programs')}
          className={`px-4 py-1.5 rounded-md text-xs font-medium transition-all duration-200 ${view === 'programs' ? 'bg-slate-700 text-slate-100 shadow-sm' : 'text-slate-400 hover:text-slate-200'}`}>
          Programs ({programs.length})
        </button>
        <button onClick={() => setView('submissions')}
          className={`px-4 py-1.5 rounded-md text-xs font-medium transition-all duration-200 ${view === 'submissions' ? 'bg-slate-700 text-slate-100 shadow-sm' : 'text-slate-400 hover:text-slate-200'}`}>
          Submissions ({submissions.length})
        </button>
      </div>

      {view === 'programs' && (
        <Card>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead>Program</TableHead>
                  <TableHead>Platform</TableHead>
                  <TableHead>Bounty Range</TableHead>
                  <TableHead>Avg Payout</TableHead>
                  <TableHead>Response</TableHead>
                  <TableHead>Submissions</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {programs.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={8} className="text-center py-12 text-slate-500">
                      No bounty programs tracked yet.
                    </TableCell>
                  </TableRow>
                ) : programs.map((program) => (
                  <TableRow key={program.id}>
                    <TableCell>
                      <div className="flex items-center gap-2.5">
                        <div className="rounded-lg bg-slate-700/30 p-1.5 ring-1 ring-slate-700/50 shrink-0"><Award className="h-4 w-4 text-yellow-400" /></div>
                        <span className="font-medium text-slate-200 text-sm">{program.name}</span>
                      </div>
                    </TableCell>
                    <TableCell><Badge variant="default" className="text-[10px] capitalize">{program.platform}</Badge></TableCell>
                    <TableCell><span className="text-sm text-slate-300">{program.bountyRange ?? '--'}</span></TableCell>
                    <TableCell><span className="text-sm font-semibold text-emerald-400">{program.avgPayout ? formatUsd(program.avgPayout) : '--'}</span></TableCell>
                    <TableCell>
                      {program.avgResponseHours ? (
                        <div className="flex items-center gap-1.5 text-slate-400"><Clock className="h-3.5 w-3.5" /><span className="text-xs">{program.avgResponseHours}h</span></div>
                      ) : <span className="text-slate-500">--</span>}
                    </TableCell>
                    <TableCell className="text-center"><span className="text-sm text-slate-300">{program.submissionCount}</span></TableCell>
                    <TableCell>{program.active ? <Badge variant="success" className="text-[10px]">Active</Badge> : <Badge variant="default" className="text-[10px]">Inactive</Badge>}</TableCell>
                    <TableCell>
                      <a href={program.url} target="_blank" rel="noopener noreferrer" className="text-slate-500 hover:text-blue-400 transition-colors"><ExternalLink className="h-4 w-4" /></a>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      {view === 'submissions' && (
        <Card>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead>Vulnerability</TableHead>
                  <TableHead>Program</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Reward</TableHead>
                  <TableHead>Submitted</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {submissions.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={5} className="text-center py-12 text-slate-500">
                      No submissions yet.
                    </TableCell>
                  </TableRow>
                ) : submissions.map((sub) => (
                  <TableRow key={sub.id}>
                    <TableCell><span className="font-medium text-slate-200 text-sm line-clamp-1 max-w-[280px]">{sub.vulnerabilityTitle}</span></TableCell>
                    <TableCell><span className="text-sm text-slate-400">{sub.programName}</span></TableCell>
                    <TableCell><Badge variant={submissionStatusVariant(sub.status)} className="text-[10px] capitalize">{sub.status.replace('_', ' ')}</Badge></TableCell>
                    <TableCell>{sub.reward !== null ? <span className="text-sm font-semibold text-emerald-400">{formatUsd(sub.reward)}</span> : <span className="text-sm text-slate-500">Pending</span>}</TableCell>
                    <TableCell className="text-slate-400 text-sm">{sub.submittedAt ? formatRelativeTime(sub.submittedAt) : '--'}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
