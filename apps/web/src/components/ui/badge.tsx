import { cn } from '@/lib/utils';
import { type VariantProps, cva } from 'class-variance-authority';
import { type HTMLAttributes, forwardRef } from 'react';

const badgeVariants = cva(
  'inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-semibold transition-colors uppercase tracking-wider',
  {
    variants: {
      variant: {
        default: 'border-slate-700/50 bg-slate-800/50 text-slate-300',
        critical: 'border-red-500/30 bg-red-500/15 text-red-400',
        high: 'border-orange-500/30 bg-orange-500/15 text-orange-400',
        medium: 'border-yellow-500/30 bg-yellow-500/15 text-yellow-400',
        low: 'border-blue-500/30 bg-blue-500/15 text-blue-400',
        info: 'border-slate-500/30 bg-slate-500/15 text-slate-400',
        success: 'border-emerald-500/30 bg-emerald-500/15 text-emerald-400',
        warning: 'border-amber-500/30 bg-amber-500/15 text-amber-400',
        destructive: 'border-red-500/30 bg-red-500/15 text-red-400',
        outline: 'border-slate-600 text-slate-300',
        brand: 'border-blue-500/30 bg-gradient-to-r from-blue-500/15 to-cyan-500/15 text-cyan-400',
      },
    },
    defaultVariants: {
      variant: 'default',
    },
  }
);

export interface BadgeProps
  extends HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

const Badge = forwardRef<HTMLDivElement, BadgeProps>(
  ({ className, variant, ...props }, ref) => {
    return (
      <div
        ref={ref}
        className={cn(badgeVariants({ variant }), className)}
        {...props}
      />
    );
  }
);
Badge.displayName = 'Badge';

/**
 * Returns the appropriate badge variant for a severity string.
 */
export function severityVariant(
  severity: string
): VariantProps<typeof badgeVariants>['variant'] {
  switch (severity) {
    case 'critical':
      return 'critical';
    case 'high':
      return 'high';
    case 'medium':
      return 'medium';
    case 'low':
      return 'low';
    case 'info':
      return 'info';
    default:
      return 'default';
  }
}

/**
 * Returns the appropriate badge variant for a scan status string.
 */
export function statusVariant(
  status: string
): VariantProps<typeof badgeVariants>['variant'] {
  switch (status) {
    case 'completed':
      return 'success';
    case 'running':
      return 'brand';
    case 'queued':
      return 'default';
    case 'failed':
      return 'destructive';
    case 'paused':
      return 'warning';
    case 'cancelled':
      return 'outline';
    default:
      return 'default';
  }
}

export { Badge, badgeVariants };
