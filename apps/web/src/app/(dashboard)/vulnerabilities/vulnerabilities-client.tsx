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
import { formatCvss, formatRelativeTime } from '@/lib/utils';
import { CheckCircle2, Loader2, Search, XCircle } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';

interface VulnItem {
  id: string;
  scanId: string;
  title: string;
  description: string;
  severity: string;
  category: string;
  cvssScore: number;
  endpoint: string;
  target: string;
  confidence: number;
  confirmed: boolean;
  discoveredAt: string;
}

const severityFilters = ['all', 'critical', 'high', 'medium', 'low', 'info'] as const;
type SeverityFilter = (typeof severityFilters)[number];

const categoryLabels: Record<string, string> = {
  all: 'All Categories',
  xss: 'XSS',
  sqli: 'SQL Injection',
  ssrf: 'SSRF',
  idor: 'IDOR',
  auth_bypass: 'Auth Bypass',
  cors: 'CORS',
  header_misconfig: 'Header Misconfig',
  graphql: 'GraphQL',
  rce: 'RCE',
  lfi: 'LFI',
  open_redirect: 'Open Redirect',
  xxe: 'XXE',
  information_disclosure: 'Info Disclosure',
  cryptographic: 'Cryptographic',
  smart_contract: 'Smart Contract',
  api_vuln: 'API Vuln',
};

const categories = Object.keys(categoryLabels);

export function VulnerabilitiesClient() {
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('all');
  const [categoryFilter, setCategoryFilter] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [vulns, setVulns] = useState<VulnItem[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [severityCounts, setSeverityCounts] = useState<Record<string, number>>({});

  const fetchVulns = useCallback(async () => {
    try {
      const params = new URLSearchParams();
      if (severityFilter !== 'all') params.set('severity', severityFilter);
      if (categoryFilter !== 'all') params.set('category', categoryFilter);
      if (searchQuery) params.set('search', searchQuery);
      params.set('limit', '100');
      const res = await fetch(`/api/vulnerabilities?${params}`);
      const json = await res.json();
      setVulns(json.data ?? []);
      setTotal(json.pagination?.total ?? 0);
      setSeverityCounts(json.aggregations?.severityCounts ?? {});
    } catch (err) {
      console.error('Failed to fetch vulnerabilities:', err);
    } finally {
      setLoading(false);
    }
  }, [severityFilter, categoryFilter, searchQuery]);

  useEffect(() => {
    setLoading(true);
    const debounce = setTimeout(fetchVulns, searchQuery ? 300 : 0);
    return () => clearTimeout(debounce);
  }, [fetchVulns, searchQuery]);

  return (
    <div className="space-y-8 animate-fade-in">
      {/* Page header */}
      <div>
        <h1 className="text-2xl font-bold text-slate-100">Vulnerabilities</h1>
        <p className="text-sm text-slate-400 mt-1">
          Browse and filter all discovered vulnerabilities across your targets.
        </p>
      </div>

      {/* Filters row */}
      <div className="flex flex-col lg:flex-row gap-4">
        {/* Severity pills */}
        <div className="flex items-center gap-1 p-1 bg-slate-800/50 rounded-lg border border-slate-700/50 w-fit">
          {severityFilters.map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={`px-3 py-1.5 rounded-md text-xs font-medium capitalize transition-all duration-200 ${
                severityFilter === sev
                  ? 'bg-slate-700 text-slate-100 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {sev}
              {sev !== 'all' && severityCounts[sev] !== undefined && (
                <span className="ml-1 text-slate-500">({severityCounts[sev]})</span>
              )}
            </button>
          ))}
        </div>

        {/* Category dropdown */}
        <select
          value={categoryFilter}
          onChange={(e) => setCategoryFilter(e.target.value)}
          className="px-3 py-2 rounded-lg bg-slate-800/50 border border-slate-700/50 text-sm text-slate-300 focus:outline-none focus:ring-2 focus:ring-blue-500/50 w-fit"
        >
          {categories.map((cat) => (
            <option key={cat} value={cat}>
              {categoryLabels[cat] || cat}
            </option>
          ))}
        </select>

        {/* Search input */}
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500" />
          <input
            type="text"
            placeholder="Search vulnerabilities..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-2 rounded-lg bg-slate-800/50 border border-slate-700/50 text-sm text-slate-300 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50"
          />
        </div>
      </div>

      {/* Vulnerability table */}
      <Card>
        <CardContent className="p-0">
          {loading ? (
            <div className="flex items-center justify-center py-16">
              <Loader2 className="h-6 w-6 animate-spin text-slate-400" />
              <span className="ml-2 text-sm text-slate-400">Loading vulnerabilities...</span>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead>Severity</TableHead>
                  <TableHead>Title</TableHead>
                  <TableHead>Category</TableHead>
                  <TableHead>Endpoint</TableHead>
                  <TableHead>CVSS</TableHead>
                  <TableHead>Confidence</TableHead>
                  <TableHead>Confirmed</TableHead>
                  <TableHead>Discovered</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {vulns.map((vuln) => (
                  <TableRow key={vuln.id}>
                    <TableCell>
                      <Badge
                        variant={severityVariant(vuln.severity)}
                        className="text-[10px] w-16 justify-center"
                      >
                        {vuln.severity}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <span className="font-medium text-slate-200 text-sm">
                        {vuln.title}
                      </span>
                    </TableCell>
                    <TableCell>
                      <span className="text-xs uppercase text-slate-400 font-medium">
                        {vuln.category.replace('_', ' ')}
                      </span>
                    </TableCell>
                    <TableCell>
                      <span className="font-mono text-xs text-slate-400 truncate max-w-[200px] block">
                        {vuln.endpoint}
                      </span>
                    </TableCell>
                    <TableCell>
                      <span
                        className={`text-sm font-mono font-semibold ${
                          vuln.cvssScore >= 9
                            ? 'text-red-400'
                            : vuln.cvssScore >= 7
                              ? 'text-orange-400'
                              : vuln.cvssScore >= 4
                                ? 'text-yellow-400'
                                : 'text-blue-400'
                        }`}
                      >
                        {formatCvss(vuln.cvssScore)}
                      </span>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <div className="w-16 h-1.5 rounded-full bg-slate-700 overflow-hidden">
                          <div
                            className="h-full rounded-full bg-gradient-to-r from-blue-500 to-cyan-500"
                            style={{ width: `${vuln.confidence}%` }}
                          />
                        </div>
                        <span className="text-xs text-slate-400">{vuln.confidence}%</span>
                      </div>
                    </TableCell>
                    <TableCell className="text-center">
                      {vuln.confirmed ? (
                        <CheckCircle2 className="h-4 w-4 text-emerald-400 mx-auto" />
                      ) : (
                        <XCircle className="h-4 w-4 text-slate-600 mx-auto" />
                      )}
                    </TableCell>
                    <TableCell className="text-slate-400 text-sm">
                      {formatRelativeTime(vuln.discoveredAt)}
                    </TableCell>
                  </TableRow>
                ))}
                {vulns.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={8} className="text-center py-12 text-slate-500">
                      No vulnerabilities found. Run a scan to discover vulnerabilities.
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
          Showing {vulns.length} of {total} vulnerabilities
        </div>
      )}
    </div>
  );
}
