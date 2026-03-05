import { cn } from '@/lib/utils';
import { type HTMLAttributes, forwardRef } from 'react';

/* -------------------------------------------------------------------------- */
/*  Card (glassmorphism container)                                            */
/* -------------------------------------------------------------------------- */

const Card = forwardRef<HTMLDivElement, HTMLAttributes<HTMLDivElement>>(
  ({ className, ...props }, ref) => (
    <div
      ref={ref}
      className={cn(
        'rounded-xl border border-slate-700/50 bg-slate-800/50 backdrop-blur-xl shadow-lg',
        className
      )}
      {...props}
    />
  )
);
Card.displayName = 'Card';

/* -------------------------------------------------------------------------- */
/*  Card Header                                                               */
/* -------------------------------------------------------------------------- */

const CardHeader = forwardRef<HTMLDivElement, HTMLAttributes<HTMLDivElement>>(
  ({ className, ...props }, ref) => (
    <div
      ref={ref}
      className={cn('flex flex-col space-y-1.5 p-6', className)}
      {...props}
    />
  )
);
CardHeader.displayName = 'CardHeader';

/* -------------------------------------------------------------------------- */
/*  Card Title                                                                */
/* -------------------------------------------------------------------------- */

const CardTitle = forwardRef<HTMLHeadingElement, HTMLAttributes<HTMLHeadingElement>>(
  ({ className, ...props }, ref) => (
    <h3
      ref={ref}
      className={cn(
        'text-lg font-semibold leading-none tracking-tight text-slate-100',
        className
      )}
      {...props}
    />
  )
);
CardTitle.displayName = 'CardTitle';

/* -------------------------------------------------------------------------- */
/*  Card Description                                                          */
/* -------------------------------------------------------------------------- */

const CardDescription = forwardRef<
  HTMLParagraphElement,
  HTMLAttributes<HTMLParagraphElement>
>(({ className, ...props }, ref) => (
  <p
    ref={ref}
    className={cn('text-sm text-slate-400', className)}
    {...props}
  />
));
CardDescription.displayName = 'CardDescription';

/* -------------------------------------------------------------------------- */
/*  Card Content                                                              */
/* -------------------------------------------------------------------------- */

const CardContent = forwardRef<HTMLDivElement, HTMLAttributes<HTMLDivElement>>(
  ({ className, ...props }, ref) => (
    <div ref={ref} className={cn('p-6 pt-0', className)} {...props} />
  )
);
CardContent.displayName = 'CardContent';

/* -------------------------------------------------------------------------- */
/*  Card Footer                                                               */
/* -------------------------------------------------------------------------- */

const CardFooter = forwardRef<HTMLDivElement, HTMLAttributes<HTMLDivElement>>(
  ({ className, ...props }, ref) => (
    <div
      ref={ref}
      className={cn('flex items-center p-6 pt-0', className)}
      {...props}
    />
  )
);
CardFooter.displayName = 'CardFooter';

export { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter };
