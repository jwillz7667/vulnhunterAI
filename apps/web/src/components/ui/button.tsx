import { cn } from '@/lib/utils';
import { Slot } from '@radix-ui/react-slot';
import { type VariantProps, cva } from 'class-variance-authority';
import { type ButtonHTMLAttributes, forwardRef } from 'react';

const buttonVariants = cva(
  'inline-flex items-center justify-center whitespace-nowrap rounded-lg text-sm font-medium transition-all duration-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500/50 focus-visible:ring-offset-2 focus-visible:ring-offset-slate-900 disabled:pointer-events-none disabled:opacity-50',
  {
    variants: {
      variant: {
        default:
          'bg-gradient-to-r from-blue-500 to-cyan-500 text-white shadow-md hover:from-blue-600 hover:to-cyan-600 hover:shadow-glow-blue active:scale-[0.98]',
        destructive:
          'bg-red-500/15 text-red-400 border border-red-500/30 hover:bg-red-500/25 hover:border-red-500/50',
        outline:
          'border border-slate-700 bg-transparent text-slate-300 hover:bg-slate-800/60 hover:text-slate-100 hover:border-slate-600',
        secondary:
          'bg-slate-800 text-slate-300 border border-slate-700/50 hover:bg-slate-700 hover:text-slate-100',
        ghost:
          'text-slate-400 hover:bg-slate-800/60 hover:text-slate-200',
        link:
          'text-blue-400 underline-offset-4 hover:underline hover:text-blue-300',
      },
      size: {
        default: 'h-10 px-4 py-2',
        sm: 'h-8 rounded-md px-3 text-xs',
        lg: 'h-11 rounded-lg px-8 text-base',
        icon: 'h-10 w-10',
      },
    },
    defaultVariants: {
      variant: 'default',
      size: 'default',
    },
  }
);

export interface ButtonProps
  extends ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean;
}

const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, ...props }, ref) => {
    const Comp = asChild ? Slot : 'button';
    return (
      <Comp
        className={cn(buttonVariants({ variant, size, className }))}
        ref={ref}
        {...props}
      />
    );
  }
);
Button.displayName = 'Button';

export { Button, buttonVariants };
