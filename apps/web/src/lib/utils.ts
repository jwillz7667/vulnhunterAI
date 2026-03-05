import { type ClassValue, clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

/**
 * Merges class names using clsx for conditional classes and tailwind-merge
 * to resolve Tailwind CSS conflicts intelligently.
 */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}

/**
 * Formats a number with K/M/B suffixes for compact display.
 */
export function formatNumber(value: number): string {
  if (value >= 1_000_000_000) return `${(value / 1_000_000_000).toFixed(1)}B`;
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(1)}M`;
  if (value >= 1_000) return `${(value / 1_000).toFixed(1)}K`;
  return value.toString();
}

/**
 * Formats a duration in milliseconds to a human-readable string.
 */
export function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  const seconds = Math.floor(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = seconds % 60;
  if (minutes < 60) return `${minutes}m ${remainingSeconds}s`;
  const hours = Math.floor(minutes / 60);
  const remainingMinutes = minutes % 60;
  return `${hours}h ${remainingMinutes}m`;
}

/**
 * Formats an ISO date string to a relative time string.
 */
export function formatRelativeTime(isoDate: string): string {
  const now = Date.now();
  const then = new Date(isoDate).getTime();
  const diffMs = now - then;
  const diffSeconds = Math.floor(diffMs / 1000);
  const diffMinutes = Math.floor(diffSeconds / 60);
  const diffHours = Math.floor(diffMinutes / 60);
  const diffDays = Math.floor(diffHours / 24);

  if (diffSeconds < 60) return 'just now';
  if (diffMinutes < 60) return `${diffMinutes}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 7) return `${diffDays}d ago`;
  return new Date(isoDate).toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: diffDays > 365 ? 'numeric' : undefined,
  });
}

/**
 * Formats an ISO date string to a short display format.
 */
export function formatDate(isoDate: string): string {
  return new Date(isoDate).toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  });
}

/**
 * Formats a CVSS score to a single-decimal string.
 */
export function formatCvss(score: number): string {
  return score.toFixed(1);
}

/**
 * Returns the color class for a severity level.
 */
export function severityColor(severity: string): string {
  switch (severity) {
    case 'critical':
      return 'text-red-400';
    case 'high':
      return 'text-orange-400';
    case 'medium':
      return 'text-yellow-400';
    case 'low':
      return 'text-blue-400';
    case 'info':
      return 'text-slate-400';
    default:
      return 'text-slate-400';
  }
}

/**
 * Returns the background color class for a severity badge.
 */
export function severityBgColor(severity: string): string {
  switch (severity) {
    case 'critical':
      return 'bg-red-500/15 text-red-400 border-red-500/30';
    case 'high':
      return 'bg-orange-500/15 text-orange-400 border-orange-500/30';
    case 'medium':
      return 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30';
    case 'low':
      return 'bg-blue-500/15 text-blue-400 border-blue-500/30';
    case 'info':
      return 'bg-slate-500/15 text-slate-400 border-slate-500/30';
    default:
      return 'bg-slate-500/15 text-slate-400 border-slate-500/30';
  }
}

/**
 * Returns the color class for a scan status.
 */
export function statusColor(status: string): string {
  switch (status) {
    case 'completed':
      return 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30';
    case 'running':
      return 'bg-blue-500/15 text-blue-400 border-blue-500/30';
    case 'queued':
      return 'bg-slate-500/15 text-slate-400 border-slate-500/30';
    case 'failed':
      return 'bg-red-500/15 text-red-400 border-red-500/30';
    case 'paused':
      return 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30';
    case 'cancelled':
      return 'bg-slate-500/15 text-slate-400 border-slate-500/30';
    default:
      return 'bg-slate-500/15 text-slate-400 border-slate-500/30';
  }
}

/**
 * Formats USD currency values.
 */
export function formatUsd(value: number): string {
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: 'USD',
    minimumFractionDigits: 0,
    maximumFractionDigits: 0,
  }).format(value);
}
