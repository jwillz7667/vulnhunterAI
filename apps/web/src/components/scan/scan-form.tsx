'use client';

import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Code2,
  FileCode2,
  Globe,
  Loader2,
  Network,
  Play,
  Radar,
  Search,
  Settings2,
  X,
} from 'lucide-react';
import { useState } from 'react';

/* -------------------------------------------------------------------------- */
/*  Types                                                                     */
/* -------------------------------------------------------------------------- */

export interface ScanFormData {
  target: string;
  scanType: string;
  options: {
    depth: number;
    rateLimit: number;
    modules: string[];
    followRedirects: boolean;
    includeSubdomains: boolean;
    aggressive: boolean;
  };
}

interface ScanFormProps {
  /** Called when the form is submitted with valid data */
  onSubmit: (data: ScanFormData) => void | Promise<void>;
  /** Called when the user cancels / closes the form */
  onCancel?: () => void;
  /** Whether the form is in a submitting state */
  loading?: boolean;
  /** Whether to render as a modal overlay instead of inline */
  modal?: boolean;
}

/* -------------------------------------------------------------------------- */
/*  Scan type configuration                                                   */
/* -------------------------------------------------------------------------- */

const scanTypes = [
  {
    id: 'full',
    label: 'Full Scan',
    description: 'Comprehensive scan covering all vectors',
    icon: Radar,
    iconColor: 'text-blue-400',
    bgColor: 'bg-blue-500/10 ring-blue-500/20',
  },
  {
    id: 'web',
    label: 'Web App',
    description: 'OWASP Top 10, XSS, SQLi, SSRF, etc.',
    icon: Globe,
    iconColor: 'text-cyan-400',
    bgColor: 'bg-cyan-500/10 ring-cyan-500/20',
  },
  {
    id: 'network',
    label: 'Network',
    description: 'Port scanning, service discovery, CVEs',
    icon: Network,
    iconColor: 'text-purple-400',
    bgColor: 'bg-purple-500/10 ring-purple-500/20',
  },
  {
    id: 'code',
    label: 'Code Review',
    description: 'Static analysis, secrets, dependency audit',
    icon: Code2,
    iconColor: 'text-green-400',
    bgColor: 'bg-green-500/10 ring-green-500/20',
  },
  {
    id: 'recon',
    label: 'Recon',
    description: 'Subdomain enum, tech fingerprinting',
    icon: Search,
    iconColor: 'text-yellow-400',
    bgColor: 'bg-yellow-500/10 ring-yellow-500/20',
  },
  {
    id: 'smart_contract',
    label: 'Smart Contract',
    description: 'Reentrancy, overflow, access control',
    icon: FileCode2,
    iconColor: 'text-orange-400',
    bgColor: 'bg-orange-500/10 ring-orange-500/20',
  },
] as const;

/* -------------------------------------------------------------------------- */
/*  Module options per scan type                                              */
/* -------------------------------------------------------------------------- */

const modulesByType: Record<string, { id: string; label: string }[]> = {
  full: [
    { id: 'xss', label: 'XSS Detection' },
    { id: 'sqli', label: 'SQL Injection' },
    { id: 'ssrf', label: 'SSRF' },
    { id: 'auth', label: 'Authentication' },
    { id: 'cors', label: 'CORS Misconfig' },
    { id: 'headers', label: 'Security Headers' },
    { id: 'ports', label: 'Port Scan' },
    { id: 'cve', label: 'CVE Lookup' },
  ],
  web: [
    { id: 'xss', label: 'XSS Detection' },
    { id: 'sqli', label: 'SQL Injection' },
    { id: 'ssrf', label: 'SSRF' },
    { id: 'csrf', label: 'CSRF' },
    { id: 'idor', label: 'IDOR' },
    { id: 'cors', label: 'CORS Misconfig' },
    { id: 'headers', label: 'Security Headers' },
    { id: 'graphql', label: 'GraphQL Introspection' },
  ],
  network: [
    { id: 'ports', label: 'Port Scan' },
    { id: 'services', label: 'Service Discovery' },
    { id: 'cve', label: 'CVE Lookup' },
    { id: 'tls', label: 'TLS Analysis' },
    { id: 'dns', label: 'DNS Enumeration' },
    { id: 'snmp', label: 'SNMP Scan' },
  ],
  code: [
    { id: 'sast', label: 'Static Analysis' },
    { id: 'secrets', label: 'Secret Detection' },
    { id: 'deps', label: 'Dependency Audit' },
    { id: 'license', label: 'License Check' },
    { id: 'iac', label: 'IaC Security' },
  ],
  recon: [
    { id: 'subdomains', label: 'Subdomain Enum' },
    { id: 'tech', label: 'Tech Fingerprint' },
    { id: 'dns', label: 'DNS Records' },
    { id: 'whois', label: 'WHOIS Lookup' },
    { id: 'wayback', label: 'Wayback Analysis' },
  ],
  smart_contract: [
    { id: 'reentrancy', label: 'Reentrancy' },
    { id: 'overflow', label: 'Integer Overflow' },
    { id: 'access', label: 'Access Control' },
    { id: 'gas', label: 'Gas Optimization' },
    { id: 'frontrun', label: 'Front-running' },
  ],
};

/* -------------------------------------------------------------------------- */
/*  Component                                                                 */
/* -------------------------------------------------------------------------- */

export function ScanForm({
  onSubmit,
  onCancel,
  loading = false,
  modal = false,
}: ScanFormProps) {
  const [target, setTarget] = useState('');
  const [scanType, setScanType] = useState('full');
  const [depth, setDepth] = useState(3);
  const [rateLimit, setRateLimit] = useState(50);
  const [selectedModules, setSelectedModules] = useState<string[]>([]);
  const [followRedirects, setFollowRedirects] = useState(true);
  const [includeSubdomains, setIncludeSubdomains] = useState(true);
  const [aggressive, setAggressive] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const availableModules = modulesByType[scanType] ?? [];

  const handleScanTypeChange = (newType: string) => {
    setScanType(newType);
    setSelectedModules([]); // Reset modules when type changes
  };

  const toggleModule = (moduleId: string) => {
    setSelectedModules((prev) =>
      prev.includes(moduleId)
        ? prev.filter((m) => m !== moduleId)
        : [...prev, moduleId]
    );
  };

  const selectAllModules = () => {
    setSelectedModules(availableModules.map((m) => m.id));
  };

  const clearAllModules = () => {
    setSelectedModules([]);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    // Validation
    if (!target.trim()) {
      setError('Target is required.');
      return;
    }

    if (
      (scanType === 'web' || scanType === 'full') &&
      !target.trim().startsWith('http') &&
      !target.trim().match(/^\d/)
    ) {
      setError(
        'Web and full scans require a URL starting with http:// or https://'
      );
      return;
    }

    const formData: ScanFormData = {
      target: target.trim(),
      scanType,
      options: {
        depth,
        rateLimit,
        modules:
          selectedModules.length > 0
            ? selectedModules
            : availableModules.map((m) => m.id),
        followRedirects,
        includeSubdomains,
        aggressive,
      },
    };

    // POST to API and call onSubmit callback
    try {
      const res = await fetch('/api/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target: formData.target,
          scanType: formData.scanType,
          options: formData.options,
        }),
      });
      if (!res.ok) {
        const err = await res.json();
        setError(err.error || 'Failed to start scan');
        return;
      }
      await onSubmit(formData);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Network error');
    }
  };

  const selectedType = scanTypes.find((t) => t.id === scanType);

  const formContent = (
    <form onSubmit={handleSubmit} className="space-y-6">
      {/* Error banner */}
      {error && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-2.5 text-sm text-red-400 animate-slide-down">
          {error}
        </div>
      )}

      {/* Target URL input */}
      <div>
        <label className="block text-xs font-medium text-slate-400 uppercase tracking-wider mb-1.5">
          Target
        </label>
        <div className="relative">
          <Radar className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500" />
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder={
              scanType === 'network'
                ? '192.168.1.0/24'
                : scanType === 'code'
                  ? 'https://github.com/org/repo'
                  : scanType === 'smart_contract'
                    ? '0x742d35Cc6634C0532925a3b...'
                    : 'https://target.example.com'
            }
            className="w-full pl-10 pr-4 py-3 rounded-lg bg-slate-800/50 border border-slate-700/50 text-sm text-slate-200 placeholder:text-slate-500 font-mono focus:outline-none focus:ring-2 focus:ring-blue-500/50 transition-all"
            required
            disabled={loading}
          />
        </div>
      </div>

      {/* Scan type selector */}
      <div>
        <label className="block text-xs font-medium text-slate-400 uppercase tracking-wider mb-2">
          Scan Type
        </label>
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
          {scanTypes.map((type) => {
            const Icon = type.icon;
            const isSelected = scanType === type.id;
            return (
              <button
                key={type.id}
                type="button"
                onClick={() => handleScanTypeChange(type.id)}
                disabled={loading}
                className={`flex items-start gap-3 rounded-xl border p-3 text-left transition-all duration-200 ${
                  isSelected
                    ? 'border-blue-500/30 bg-blue-500/5 shadow-sm'
                    : 'border-slate-700/50 bg-slate-800/30 hover:border-slate-600/50 hover:bg-slate-800/50'
                }`}
              >
                <div
                  className={`rounded-lg p-2 ring-1 shrink-0 ${
                    isSelected ? type.bgColor : 'bg-slate-700/30 ring-slate-700/50'
                  }`}
                >
                  <Icon
                    className={`h-4 w-4 ${
                      isSelected ? type.iconColor : 'text-slate-400'
                    }`}
                  />
                </div>
                <div className="min-w-0">
                  <p
                    className={`text-sm font-medium ${
                      isSelected ? 'text-slate-100' : 'text-slate-300'
                    }`}
                  >
                    {type.label}
                  </p>
                  <p className="text-[11px] text-slate-500 mt-0.5 line-clamp-1">
                    {type.description}
                  </p>
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Module selection */}
      {availableModules.length > 0 && (
        <div>
          <div className="flex items-center justify-between mb-2">
            <label className="block text-xs font-medium text-slate-400 uppercase tracking-wider">
              Modules
              <span className="text-slate-600 ml-1 normal-case tracking-normal font-normal">
                ({selectedModules.length}/{availableModules.length} selected)
              </span>
            </label>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={selectAllModules}
                className="text-[11px] text-blue-400 hover:text-blue-300 transition-colors"
                disabled={loading}
              >
                Select all
              </button>
              <span className="text-slate-600">|</span>
              <button
                type="button"
                onClick={clearAllModules}
                className="text-[11px] text-slate-500 hover:text-slate-400 transition-colors"
                disabled={loading}
              >
                Clear
              </button>
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            {availableModules.map((mod) => {
              const isSelected = selectedModules.includes(mod.id);
              return (
                <button
                  key={mod.id}
                  type="button"
                  onClick={() => toggleModule(mod.id)}
                  disabled={loading}
                  className={`rounded-lg border px-3 py-1.5 text-xs font-medium transition-all duration-200 ${
                    isSelected
                      ? 'border-blue-500/30 bg-blue-500/15 text-blue-400'
                      : 'border-slate-700/50 bg-slate-800/30 text-slate-400 hover:border-slate-600/50 hover:text-slate-300'
                  }`}
                >
                  {mod.label}
                </button>
              );
            })}
          </div>
        </div>
      )}

      {/* Advanced options toggle */}
      <button
        type="button"
        onClick={() => setShowAdvanced(!showAdvanced)}
        className="flex items-center gap-2 text-xs text-slate-400 hover:text-slate-300 transition-colors"
        disabled={loading}
      >
        <Settings2 className="h-3.5 w-3.5" />
        <span>{showAdvanced ? 'Hide' : 'Show'} advanced options</span>
      </button>

      {/* Advanced options panel */}
      {showAdvanced && (
        <div className="rounded-xl border border-slate-700/30 bg-slate-800/20 p-5 space-y-5 animate-slide-down">
          {/* Depth slider */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="text-xs font-medium text-slate-400 uppercase tracking-wider">
                Crawl Depth
              </label>
              <span className="text-sm font-mono text-slate-300">{depth}</span>
            </div>
            <input
              type="range"
              min={1}
              max={10}
              value={depth}
              onChange={(e) => setDepth(parseInt(e.target.value, 10))}
              className="w-full h-1.5 bg-slate-700 rounded-full appearance-none cursor-pointer accent-blue-500"
              disabled={loading}
            />
            <div className="flex justify-between text-[10px] text-slate-600 mt-1">
              <span>1 (shallow)</span>
              <span>5 (moderate)</span>
              <span>10 (deep)</span>
            </div>
          </div>

          {/* Rate limit slider */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="text-xs font-medium text-slate-400 uppercase tracking-wider">
                Rate Limit
              </label>
              <span className="text-sm font-mono text-slate-300">
                {rateLimit} req/s
              </span>
            </div>
            <input
              type="range"
              min={1}
              max={200}
              value={rateLimit}
              onChange={(e) => setRateLimit(parseInt(e.target.value, 10))}
              className="w-full h-1.5 bg-slate-700 rounded-full appearance-none cursor-pointer accent-blue-500"
              disabled={loading}
            />
            <div className="flex justify-between text-[10px] text-slate-600 mt-1">
              <span>1 (stealth)</span>
              <span>100 (balanced)</span>
              <span>200 (fast)</span>
            </div>
          </div>

          {/* Toggle options */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <label className="flex items-center gap-2.5 text-sm text-slate-300 cursor-pointer rounded-lg border border-slate-700/30 bg-slate-800/20 p-3">
              <input
                type="checkbox"
                checked={followRedirects}
                onChange={(e) => setFollowRedirects(e.target.checked)}
                className="rounded border-slate-600 bg-slate-800 text-blue-500 focus:ring-blue-500/50 focus:ring-offset-slate-900"
                disabled={loading}
              />
              Follow redirects
            </label>
            <label className="flex items-center gap-2.5 text-sm text-slate-300 cursor-pointer rounded-lg border border-slate-700/30 bg-slate-800/20 p-3">
              <input
                type="checkbox"
                checked={includeSubdomains}
                onChange={(e) => setIncludeSubdomains(e.target.checked)}
                className="rounded border-slate-600 bg-slate-800 text-blue-500 focus:ring-blue-500/50 focus:ring-offset-slate-900"
                disabled={loading}
              />
              Include subdomains
            </label>
            <label className="flex items-center gap-2.5 text-sm text-slate-300 cursor-pointer rounded-lg border border-slate-700/30 bg-slate-800/20 p-3">
              <input
                type="checkbox"
                checked={aggressive}
                onChange={(e) => setAggressive(e.target.checked)}
                className="rounded border-slate-600 bg-slate-800 text-blue-500 focus:ring-blue-500/50 focus:ring-offset-slate-900"
                disabled={loading}
              />
              <span>
                Aggressive
                <span className="text-orange-400 text-xs ml-1">(noisy)</span>
              </span>
            </label>
          </div>
        </div>
      )}

      {/* Actions */}
      <div className="flex items-center justify-between pt-2">
        <div className="text-xs text-slate-500">
          {selectedType && (
            <span>
              Scan type:{' '}
              <span className="text-slate-300">{selectedType.label}</span>
              {selectedModules.length > 0 && (
                <>
                  {' '}
                  with{' '}
                  <span className="text-slate-300">
                    {selectedModules.length} modules
                  </span>
                </>
              )}
            </span>
          )}
        </div>
        <div className="flex items-center gap-3">
          {onCancel && (
            <Button
              type="button"
              variant="ghost"
              onClick={onCancel}
              disabled={loading}
            >
              Cancel
            </Button>
          )}
          <Button type="submit" disabled={loading} className="gap-2">
            {loading ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Play className="h-4 w-4" />
            )}
            {loading ? 'Starting...' : 'Start Scan'}
          </Button>
        </div>
      </div>
    </form>
  );

  // Render as modal or inline card
  if (modal) {
    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center">
        <div
          className="absolute inset-0 bg-black/60 backdrop-blur-sm"
          onClick={onCancel}
        />
        <div className="relative z-10 w-full max-w-2xl max-h-[90vh] overflow-y-auto rounded-xl border border-slate-700/50 bg-slate-900 shadow-2xl animate-slide-up">
          <div className="flex items-center justify-between border-b border-slate-700/50 px-6 py-4 sticky top-0 bg-slate-900/95 backdrop-blur-sm z-10">
            <h2 className="text-lg font-semibold text-slate-100">
              New Security Scan
            </h2>
            <button
              onClick={onCancel}
              className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-800 hover:text-slate-200 transition-colors"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
          <div className="p-6">{formContent}</div>
        </div>
      </div>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base flex items-center gap-2">
          <Radar className="h-5 w-5 text-blue-400" />
          New Security Scan
        </CardTitle>
      </CardHeader>
      <CardContent>{formContent}</CardContent>
    </Card>
  );
}
