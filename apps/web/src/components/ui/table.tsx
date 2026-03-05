import { cn } from '@/lib/utils';
import { type HTMLAttributes, type TdHTMLAttributes, type ThHTMLAttributes, forwardRef } from 'react';

/* -------------------------------------------------------------------------- */
/*  Table                                                                     */
/* -------------------------------------------------------------------------- */

const Table = forwardRef<HTMLTableElement, HTMLAttributes<HTMLTableElement>>(
  ({ className, ...props }, ref) => (
    <div className="relative w-full overflow-auto">
      <table
        ref={ref}
        className={cn('w-full caption-bottom text-sm', className)}
        {...props}
      />
    </div>
  )
);
Table.displayName = 'Table';

/* -------------------------------------------------------------------------- */
/*  Table Header                                                              */
/* -------------------------------------------------------------------------- */

const TableHeader = forwardRef<
  HTMLTableSectionElement,
  HTMLAttributes<HTMLTableSectionElement>
>(({ className, ...props }, ref) => (
  <thead
    ref={ref}
    className={cn('[&_tr]:border-b [&_tr]:border-slate-700/50', className)}
    {...props}
  />
));
TableHeader.displayName = 'TableHeader';

/* -------------------------------------------------------------------------- */
/*  Table Body                                                                */
/* -------------------------------------------------------------------------- */

const TableBody = forwardRef<
  HTMLTableSectionElement,
  HTMLAttributes<HTMLTableSectionElement>
>(({ className, ...props }, ref) => (
  <tbody
    ref={ref}
    className={cn('[&_tr:last-child]:border-0', className)}
    {...props}
  />
));
TableBody.displayName = 'TableBody';

/* -------------------------------------------------------------------------- */
/*  Table Footer                                                              */
/* -------------------------------------------------------------------------- */

const TableFooter = forwardRef<
  HTMLTableSectionElement,
  HTMLAttributes<HTMLTableSectionElement>
>(({ className, ...props }, ref) => (
  <tfoot
    ref={ref}
    className={cn(
      'border-t border-slate-700/50 bg-slate-800/30 font-medium [&>tr]:last:border-b-0',
      className
    )}
    {...props}
  />
));
TableFooter.displayName = 'TableFooter';

/* -------------------------------------------------------------------------- */
/*  Table Row                                                                 */
/* -------------------------------------------------------------------------- */

const TableRow = forwardRef<HTMLTableRowElement, HTMLAttributes<HTMLTableRowElement>>(
  ({ className, ...props }, ref) => (
    <tr
      ref={ref}
      className={cn(
        'border-b border-slate-700/30 transition-colors hover:bg-slate-800/40 data-[state=selected]:bg-slate-800/60',
        className
      )}
      {...props}
    />
  )
);
TableRow.displayName = 'TableRow';

/* -------------------------------------------------------------------------- */
/*  Table Head (th)                                                           */
/* -------------------------------------------------------------------------- */

const TableHead = forwardRef<HTMLTableCellElement, ThHTMLAttributes<HTMLTableCellElement>>(
  ({ className, ...props }, ref) => (
    <th
      ref={ref}
      className={cn(
        'h-11 px-4 text-left align-middle font-medium text-slate-400 text-xs uppercase tracking-wider [&:has([role=checkbox])]:pr-0',
        className
      )}
      {...props}
    />
  )
);
TableHead.displayName = 'TableHead';

/* -------------------------------------------------------------------------- */
/*  Table Cell (td)                                                           */
/* -------------------------------------------------------------------------- */

const TableCell = forwardRef<HTMLTableCellElement, TdHTMLAttributes<HTMLTableCellElement>>(
  ({ className, ...props }, ref) => (
    <td
      ref={ref}
      className={cn(
        'px-4 py-3 align-middle text-slate-300 [&:has([role=checkbox])]:pr-0',
        className
      )}
      {...props}
    />
  )
);
TableCell.displayName = 'TableCell';

/* -------------------------------------------------------------------------- */
/*  Table Caption                                                             */
/* -------------------------------------------------------------------------- */

const TableCaption = forwardRef<
  HTMLTableCaptionElement,
  HTMLAttributes<HTMLTableCaptionElement>
>(({ className, ...props }, ref) => (
  <caption
    ref={ref}
    className={cn('mt-4 text-sm text-slate-400', className)}
    {...props}
  />
));
TableCaption.displayName = 'TableCaption';

export {
  Table,
  TableHeader,
  TableBody,
  TableFooter,
  TableHead,
  TableRow,
  TableCell,
  TableCaption,
};
