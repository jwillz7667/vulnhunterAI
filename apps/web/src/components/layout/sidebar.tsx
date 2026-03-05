'use client';

import { cn } from '@/lib/utils';
import {
  Bug,
  ChevronLeft,
  FileBarChart,
  LayoutDashboard,
  LogOut,
  Radar,
  Shield,
  Target,
  Trophy,
} from 'lucide-react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useState } from 'react';
import { useSession, signOut } from 'next-auth/react';

const navigation = [
  {
    name: 'Dashboard',
    href: '/',
    icon: LayoutDashboard,
  },
  {
    name: 'Scans',
    href: '/scans',
    icon: Radar,
  },
  {
    name: 'Vulnerabilities',
    href: '/vulnerabilities',
    icon: Bug,
  },
  {
    name: 'Reports',
    href: '/reports',
    icon: FileBarChart,
  },
  {
    name: 'Targets',
    href: '/targets',
    icon: Target,
  },
  {
    name: 'Bounties',
    href: '/bounties',
    icon: Trophy,
  },
];

export function Sidebar() {
  const pathname = usePathname();
  const [collapsed, setCollapsed] = useState(false);
  const { data: session } = useSession();

  const user = session?.user;
  const initials = user?.name
    ? user.name
        .split(' ')
        .map((n) => n[0])
        .join('')
        .toUpperCase()
        .slice(0, 2)
    : '??';

  return (
    <aside
      className={cn(
        'glass-sidebar flex flex-col h-full transition-all duration-300 ease-in-out shrink-0',
        collapsed ? 'w-[72px]' : 'w-[240px]'
      )}
    >
      {/* Logo / Brand */}
      <div className="flex items-center gap-3 px-4 py-6 border-b border-slate-700/50">
        <div className="relative shrink-0">
          <div className="h-9 w-9 rounded-lg bg-gradient-to-br from-blue-500 to-cyan-500 flex items-center justify-center shadow-glow-blue">
            <Shield className="h-5 w-5 text-white" />
          </div>
          {/* Animated pulse ring */}
          <div className="absolute inset-0 rounded-lg bg-gradient-to-br from-blue-500 to-cyan-500 opacity-20 animate-ping" />
        </div>
        {!collapsed && (
          <div className="min-w-0">
            <h1 className="text-base font-bold gradient-text leading-tight">
              VulnHunter
            </h1>
            <p className="text-[10px] font-medium text-slate-500 uppercase tracking-widest">
              AI Security
            </p>
          </div>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
        {navigation.map((item) => {
          const isActive =
            item.href === '/'
              ? pathname === '/'
              : pathname.startsWith(item.href);

          return (
            <Link
              key={item.name}
              href={item.href}
              className={cn(
                'nav-item',
                isActive && 'nav-item-active',
                collapsed && 'justify-center px-2'
              )}
              title={collapsed ? item.name : undefined}
            >
              <item.icon className={cn('h-[18px] w-[18px] shrink-0', isActive && 'text-blue-400')} />
              {!collapsed && <span>{item.name}</span>}
            </Link>
          );
        })}
      </nav>

      {/* Collapse toggle */}
      <div className="px-3 py-4 border-t border-slate-700/50">
        <button
          onClick={() => setCollapsed(!collapsed)}
          className={cn(
            'nav-item w-full',
            collapsed && 'justify-center px-2'
          )}
        >
          <ChevronLeft
            className={cn(
              'h-[18px] w-[18px] shrink-0 transition-transform duration-300',
              collapsed && 'rotate-180'
            )}
          />
          {!collapsed && <span>Collapse</span>}
        </button>
      </div>

      {/* User section */}
      {user && (
        <div className="px-3 py-3 border-t border-slate-700/50">
          <div className={cn('flex items-center gap-3', collapsed && 'justify-center')}>
            {user.image ? (
              <img
                src={user.image}
                alt={user.name ?? 'Avatar'}
                className="h-8 w-8 rounded-full shrink-0 ring-2 ring-slate-700"
              />
            ) : (
              <div className="h-8 w-8 rounded-full shrink-0 bg-gradient-to-br from-blue-500 to-cyan-500 flex items-center justify-center text-[11px] font-bold text-white ring-2 ring-slate-700">
                {initials}
              </div>
            )}
            {!collapsed && (
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-1.5">
                  <p className="text-xs font-medium text-slate-200 truncate">
                    {user.name}
                  </p>
                  {user.role === 'ADMIN' && (
                    <span className="shrink-0 rounded bg-blue-500/20 px-1.5 py-0.5 text-[9px] font-bold text-blue-400 uppercase tracking-wider">
                      Admin
                    </span>
                  )}
                </div>
                <p className="text-[10px] text-slate-500 truncate">
                  {user.email}
                </p>
              </div>
            )}
          </div>
          {!collapsed && (
            <button
              onClick={() => signOut({ callbackUrl: '/login' })}
              className="nav-item w-full mt-2 text-red-400/70 hover:text-red-400 hover:bg-red-500/10"
            >
              <LogOut className="h-[16px] w-[16px] shrink-0" />
              <span className="text-xs">Sign Out</span>
            </button>
          )}
          {collapsed && (
            <button
              onClick={() => signOut({ callbackUrl: '/login' })}
              className="nav-item w-full mt-2 justify-center px-2 text-red-400/70 hover:text-red-400 hover:bg-red-500/10"
              title="Sign Out"
            >
              <LogOut className="h-[16px] w-[16px] shrink-0" />
            </button>
          )}
        </div>
      )}

      {/* Status bar */}
      {!collapsed && (
        <div className="px-4 py-3 border-t border-slate-700/50">
          <div className="flex items-center gap-2">
            <div className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse-slow" />
            <span className="text-xs text-slate-500">System Operational</span>
          </div>
        </div>
      )}
    </aside>
  );
}
