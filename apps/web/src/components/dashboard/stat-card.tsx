import { cn } from '@/lib/utils';
import { type LucideIcon, TrendingDown, TrendingUp } from 'lucide-react';

interface StatCardProps {
  title: string;
  value: string | number;
  icon: LucideIcon;
  trend?: number;
  trendLabel?: string;
  iconColor?: string;
  glowColor?: string;
}

export function StatCard({
  title,
  value,
  icon: Icon,
  trend,
  trendLabel = 'vs last week',
  iconColor = 'text-blue-400',
  glowColor = 'from-blue-500/10',
}: StatCardProps) {
  const isPositiveTrend = trend !== undefined && trend > 0;
  const isNegativeTrend = trend !== undefined && trend < 0;

  return (
    <div className="relative overflow-hidden rounded-xl border border-slate-700/50 bg-slate-800/50 backdrop-blur-xl p-6">
      {/* Background glow effect */}
      <div
        className={cn(
          'absolute -top-12 -right-12 h-32 w-32 rounded-full opacity-20 blur-3xl bg-gradient-to-br',
          glowColor,
          'to-transparent'
        )}
      />

      <div className="relative flex items-start justify-between">
        <div className="space-y-2">
          <p className="text-sm font-medium text-slate-400">{title}</p>
          <p className="text-3xl font-bold text-slate-100 tracking-tight">
            {value}
          </p>
          {trend !== undefined && (
            <div className="flex items-center gap-1.5">
              {isPositiveTrend ? (
                <TrendingUp className="h-3.5 w-3.5 text-emerald-400" />
              ) : isNegativeTrend ? (
                <TrendingDown className="h-3.5 w-3.5 text-red-400" />
              ) : null}
              <span
                className={cn(
                  'text-xs font-medium',
                  isPositiveTrend && 'text-emerald-400',
                  isNegativeTrend && 'text-red-400',
                  !isPositiveTrend && !isNegativeTrend && 'text-slate-400'
                )}
              >
                {isPositiveTrend ? '+' : ''}
                {trend}%
              </span>
              <span className="text-xs text-slate-500">{trendLabel}</span>
            </div>
          )}
        </div>
        <div
          className={cn(
            'rounded-lg bg-slate-700/30 p-2.5 ring-1 ring-slate-700/50',
            iconColor
          )}
        >
          <Icon className="h-5 w-5" />
        </div>
      </div>
    </div>
  );
}
