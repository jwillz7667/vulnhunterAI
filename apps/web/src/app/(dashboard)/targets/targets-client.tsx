'use client';

import { Badge } from '@/components/ui/badge';
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
import { formatRelativeTime } from '@/lib/utils';
import {
  CheckCircle2,
  Clock,
  Code2,
  FileCode2,
  Globe,
  Loader2,
  Network,
  Plus,
  Search,
  Server,
  Target,
  Trash2,
  X,
  XCircle,
} from 'lucide-react';
import { useCallback, useEffect, useMemo, useState } from 'react';

/* -------------------------------------------------------------------------- */
/*  Types                                                                     */
/* -------------------------------------------------------------------------- */

interface TargetItem {
  id: string;
  name: string;
  type: string;
  value: string;
  tags: string[];
  scanCount: number;
  lastScan: { id: string; status: string; date: string; findingsCount: number } | null;
  createdAt: string;
}

/* -------------------------------------------------------------------------- */
/*  Constants                                                                 */
/* -------------------------------------------------------------------------- */

const typeFilters = ['all', 'url', 'domain', 'ip', 'cidr', 'repository', 'smart_contract'] as const;
type TypeFilter = (typeof typeFilters)[number];

const typeIcons: Record<string, React.ReactNode> = {
  url: <Globe className="h-4 w-4 text-blue-400" />,
  domain: <Server className="h-4 w-4 text-cyan-400" />,
  ip: <Network className="h-4 w-4 text-purple-400" />,
  cidr: <Network className="h-4 w-4 text-indigo-400" />,
  repository: <Code2 className="h-4 w-4 text-green-400" />,
  smart_contract: <FileCode2 className="h-4 w-4 text-orange-400" />,
};

const typeLabels: Record<string, string> = {
  all: 'All Types',
  url: 'URL',
  domain: 'Domain',
  ip: 'IP',
  cidr: 'CIDR',
  repository: 'Repository',
  smart_contract: 'Smart Contract',
};

const typePlaceholders: Record<string, string> = {
  url: 'https://api.example.com',
  domain: 'example.com',
  ip: '192.168.1.1',
  cidr: '10.0.0.0/24',
  repository: 'https://github.com/org/repo',
  smart_contract: '0x742d35Cc6634C0532925a3b...',
};

/* -------------------------------------------------------------------------- */
/*  Add Target Modal                                                          */
/* -------------------------------------------------------------------------- */

const addableTypes = ['url', 'domain', 'ip', 'cidr', 'repository', 'smart_contract'] as const;

function AddTargetModal({
  open,
  onClose,
  onAdd,
}: {
  open: boolean;
  onClose: () => void;
  onAdd: (data: { name: string; type: string; value: string; tags: string[] }) => void;
}) {
  const [name, setName] = useState('');
  const [type, setType] = useState<string>('url');
  const [value, setValue] = useState('');
  const [tags, setTags] = useState('');
  const [error, setError] = useState<string | null>(null);

  if (!open) return null;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (!name.trim()) { setError('Target name is required.'); return; }
    if (!value.trim()) { setError('Target value is required.'); return; }
    if (type === 'url' && !value.trim().startsWith('http')) {
      setError('URL must start with http:// or https://'); return;
    }
    onAdd({
      name: name.trim(),
      type,
      value: value.trim(),
      tags: tags.split(',').map((t) => t.trim()).filter(Boolean),
    });
    setName(''); setType('url'); setValue(''); setTags(''); setError(null);
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div className="relative z-10 w-full max-w-lg rounded-xl border border-slate-700/50 bg-slate-900 shadow-2xl animate-slide-up">
        <div className="flex items-center justify-between border-b border-slate-700/50 px-6 py-4">
          <h2 className="text-lg font-semibold text-slate-100">Add Scan Target</h2>
          <button onClick={onClose} className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-800 hover:text-slate-200 transition-colors">
            <X className="h-4 w-4" />
          </button>
        </div>
        <form onSubmit={handleSubmit} className="p-6 space-y-5">
          {error && (
            <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-2.5 text-sm text-red-400">{error}</div>
          )}
          <div>
            <label className="block text-xs font-medium text-slate-400 uppercase tracking-wider mb-1.5">Target Name</label>
            <input type="text" value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g., Production API"
              className="w-full px-4 py-2.5 rounded-lg bg-slate-800/50 border border-slate-700/50 text-sm text-slate-200 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50 transition-all" required />
          </div>
          <div>
            <label className="block text-xs font-medium text-slate-400 uppercase tracking-wider mb-1.5">Target Type</label>
            <div className="grid grid-cols-3 gap-2">
              {addableTypes.map((t) => (
                <button key={t} type="button" onClick={() => { setType(t); setValue(''); }}
                  className={`flex items-center gap-2 rounded-lg border px-3 py-2.5 text-xs font-medium transition-all duration-200 ${
                    type === t ? 'border-blue-500/30 bg-blue-500/10 text-blue-400 shadow-sm'
                      : 'border-slate-700/50 bg-slate-800/30 text-slate-400 hover:border-slate-600/50 hover:text-slate-300'
                  }`}>
                  {typeIcons[t]}
                  <span>{typeLabels[t]}</span>
                </button>
              ))}
            </div>
          </div>
          <div>
            <label className="block text-xs font-medium text-slate-400 uppercase tracking-wider mb-1.5">{typeLabels[type] || 'Value'}</label>
            <input type="text" value={value} onChange={(e) => setValue(e.target.value)} placeholder={typePlaceholders[type] || 'Target value'}
              className="w-full px-4 py-2.5 rounded-lg bg-slate-800/50 border border-slate-700/50 text-sm text-slate-200 placeholder:text-slate-500 font-mono focus:outline-none focus:ring-2 focus:ring-blue-500/50 transition-all" required />
          </div>
          <div>
            <label className="block text-xs font-medium text-slate-400 uppercase tracking-wider mb-1.5">Tags <span className="text-slate-600 ml-1 normal-case tracking-normal font-normal">(comma separated)</span></label>
            <input type="text" value={tags} onChange={(e) => setTags(e.target.value)} placeholder="production, api, priority"
              className="w-full px-4 py-2.5 rounded-lg bg-slate-800/50 border border-slate-700/50 text-sm text-slate-200 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50 transition-all" />
          </div>
          <div className="flex items-center justify-end gap-3 pt-1">
            <Button type="button" variant="ghost" onClick={onClose}>Cancel</Button>
            <Button type="submit" className="gap-2"><Plus className="h-4 w-4" />Add Target</Button>
          </div>
        </form>
      </div>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/*  TargetsClient                                                             */
/* -------------------------------------------------------------------------- */

export function TargetsClient() {
  const [targets, setTargets] = useState<TargetItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [typeFilter, setTypeFilter] = useState<TypeFilter>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [showAddModal, setShowAddModal] = useState(false);

  const fetchTargets = useCallback(async () => {
    try {
      const res = await fetch('/api/targets');
      const json = await res.json();
      setTargets(json.data ?? []);
    } catch (err) {
      console.error('Failed to fetch targets:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchTargets(); }, [fetchTargets]);

  const filtered = useMemo(() => {
    return targets.filter((t) => {
      if (typeFilter !== 'all' && t.type !== typeFilter) return false;
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        if (!t.name.toLowerCase().includes(q) && !t.value.toLowerCase().includes(q) &&
            !t.tags.some((tag) => tag.toLowerCase().includes(q))) return false;
      }
      return true;
    });
  }, [targets, typeFilter, searchQuery]);

  const handleAddTarget = async (data: { name: string; type: string; value: string; tags: string[] }) => {
    try {
      const res = await fetch('/api/targets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      });
      if (res.ok) {
        const json = await res.json();
        setTargets((prev) => [json.data, ...prev]);
      }
    } catch (err) {
      console.error('Failed to add target:', err);
    }
  };

  const handleRemoveTarget = async (id: string) => {
    try {
      const res = await fetch(`/api/targets?id=${id}`, { method: 'DELETE' });
      if (res.ok) {
        setTargets((prev) => prev.filter((t) => t.id !== id));
      }
    } catch (err) {
      console.error('Failed to delete target:', err);
    }
  };

  const totalScans = targets.reduce((sum, t) => sum + t.scanCount, 0);
  const scannedTargets = targets.filter((t) => t.lastScan !== null).length;
  const pendingTargets = targets.filter((t) => t.lastScan === null).length;

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="h-6 w-6 animate-spin text-slate-400" />
        <span className="ml-2 text-sm text-slate-400">Loading targets...</span>
      </div>
    );
  }

  return (
    <div className="space-y-8 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">Targets</h1>
          <p className="text-sm text-slate-400 mt-1">Manage your scanning targets and scope definitions.</p>
        </div>
        <Button className="gap-2" onClick={() => setShowAddModal(true)}>
          <Plus className="h-4 w-4" />Add Target
        </Button>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="relative overflow-hidden rounded-xl border border-slate-700/50 bg-slate-800/50 backdrop-blur-xl p-5">
          <div className="relative flex items-center gap-3">
            <div className="rounded-lg bg-blue-500/10 p-2.5 ring-1 ring-blue-500/20"><Target className="h-4 w-4 text-blue-400" /></div>
            <div><p className="text-2xl font-bold text-slate-100">{targets.length}</p><p className="text-xs text-slate-400">Total Targets</p></div>
          </div>
        </div>
        <div className="relative overflow-hidden rounded-xl border border-slate-700/50 bg-slate-800/50 backdrop-blur-xl p-5">
          <div className="relative flex items-center gap-3">
            <div className="rounded-lg bg-emerald-500/10 p-2.5 ring-1 ring-emerald-500/20"><CheckCircle2 className="h-4 w-4 text-emerald-400" /></div>
            <div><p className="text-2xl font-bold text-slate-100">{scannedTargets}</p><p className="text-xs text-slate-400">Scanned</p></div>
          </div>
        </div>
        <div className="relative overflow-hidden rounded-xl border border-slate-700/50 bg-slate-800/50 backdrop-blur-xl p-5">
          <div className="relative flex items-center gap-3">
            <div className="rounded-lg bg-yellow-500/10 p-2.5 ring-1 ring-yellow-500/20"><Clock className="h-4 w-4 text-yellow-400" /></div>
            <div><p className="text-2xl font-bold text-slate-100">{pendingTargets}</p><p className="text-xs text-slate-400">Pending Scan</p></div>
          </div>
        </div>
        <div className="relative overflow-hidden rounded-xl border border-slate-700/50 bg-slate-800/50 backdrop-blur-xl p-5">
          <div className="relative flex items-center gap-3">
            <div className="rounded-lg bg-cyan-500/10 p-2.5 ring-1 ring-cyan-500/20"><Globe className="h-4 w-4 text-cyan-400" /></div>
            <div><p className="text-2xl font-bold text-slate-100">{totalScans}</p><p className="text-xs text-slate-400">Total Scans Run</p></div>
          </div>
        </div>
      </div>

      <div className="flex flex-col sm:flex-row gap-4">
        <div className="flex items-center gap-1 p-1 bg-slate-800/50 rounded-lg border border-slate-700/50 w-fit flex-wrap">
          {typeFilters.map((type) => {
            const count = type === 'all' ? targets.length : targets.filter((t) => t.type === type).length;
            if (type !== 'all' && count === 0) return null;
            return (
              <button key={type} onClick={() => setTypeFilter(type)}
                className={`px-3 py-1.5 rounded-md text-xs font-medium transition-all duration-200 ${
                  typeFilter === type ? 'bg-slate-700 text-slate-100 shadow-sm' : 'text-slate-400 hover:text-slate-200'
                }`}>
                {typeLabels[type]}<span className="ml-1 text-slate-500">({count})</span>
              </button>
            );
          })}
        </div>
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500" />
          <input type="text" placeholder="Search targets, values, or tags..." value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-2 rounded-lg bg-slate-800/50 border border-slate-700/50 text-sm text-slate-300 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50" />
        </div>
      </div>

      <Card>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead>Name</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Value</TableHead>
                <TableHead>Tags</TableHead>
                <TableHead className="text-center">Scans</TableHead>
                <TableHead>Last Scanned</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.map((target) => (
                <TableRow key={target.id}>
                  <TableCell>
                    <div className="flex items-center gap-2.5">
                      <div className="rounded-lg bg-slate-700/30 p-1.5 ring-1 ring-slate-700/50 shrink-0">
                        {typeIcons[target.type] ?? <Target className="h-4 w-4 text-slate-400" />}
                      </div>
                      <span className="font-medium text-slate-200">{target.name}</span>
                    </div>
                  </TableCell>
                  <TableCell><span className="text-xs uppercase text-slate-400 font-medium">{target.type.replace('_', ' ')}</span></TableCell>
                  <TableCell><span className="font-mono text-xs text-slate-400 truncate max-w-[260px] block">{target.value}</span></TableCell>
                  <TableCell>
                    <div className="flex items-center gap-1 flex-wrap">
                      {(target.tags ?? []).map((tag) => (<Badge key={tag} variant="default" className="text-[10px]">{tag}</Badge>))}
                    </div>
                  </TableCell>
                  <TableCell className="text-center"><span className="text-sm font-semibold text-slate-200">{target.scanCount}</span></TableCell>
                  <TableCell>
                    {target.lastScan ? (
                      <div className="flex items-center gap-1.5">
                        <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
                        <span className="text-sm text-slate-400">{formatRelativeTime(target.lastScan.date)}</span>
                      </div>
                    ) : (
                      <div className="flex items-center gap-1.5">
                        <XCircle className="h-3.5 w-3.5 text-slate-600 shrink-0" />
                        <span className="text-sm text-slate-500">Never</span>
                      </div>
                    )}
                  </TableCell>
                  <TableCell className="text-right">
                    <button onClick={() => handleRemoveTarget(target.id)}
                      className="rounded-lg p-2 text-slate-500 hover:bg-red-500/10 hover:text-red-400 transition-all duration-200" title="Remove target">
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </TableCell>
                </TableRow>
              ))}
              {filtered.length === 0 && (
                <TableRow>
                  <TableCell colSpan={7} className="text-center py-12 text-slate-500">
                    No targets found. Add a target to get started.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <div className="text-xs text-slate-500">
        Showing {filtered.length} of {targets.length} targets
      </div>

      <AddTargetModal open={showAddModal} onClose={() => setShowAddModal(false)} onAdd={handleAddTarget} />
    </div>
  );
}
