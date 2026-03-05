'use client';

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

/* -------------------------------------------------------------------------- */
/*  Custom Tooltip                                                            */
/* -------------------------------------------------------------------------- */

function CustomTooltip({
  active,
  payload,
  label,
}: {
  active?: boolean;
  payload?: Array<{ name: string; value: number; color: string }>;
  label?: string;
}) {
  if (!active || !payload) return null;
  return (
    <div className="rounded-lg border border-slate-700/50 bg-slate-800/95 backdrop-blur-xl px-4 py-3 shadow-xl">
      {label && (
        <p className="text-xs font-medium text-slate-400 mb-2">{label}</p>
      )}
      {payload.map((entry, index) => (
        <div key={index} className="flex items-center gap-2 text-xs">
          <div
            className="h-2 w-2 rounded-full"
            style={{ backgroundColor: entry.color }}
          />
          <span className="text-slate-300">{entry.name}:</span>
          <span className="font-semibold text-slate-100">{entry.value}</span>
        </div>
      ))}
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/*  Severity Pie Chart                                                        */
/* -------------------------------------------------------------------------- */

interface SeverityItem {
  name: string;
  value: number;
  color: string;
}

export function SeverityPieChart({ data }: { data: SeverityItem[] }) {
  const total = data.reduce((sum, d) => sum + d.value, 0);

  if (total === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Severity Distribution</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-center h-[180px] text-sm text-slate-500">
            No vulnerabilities found yet
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Severity Distribution</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="flex items-center gap-6">
          <div className="h-[180px] w-[180px]">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={data}
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={80}
                  paddingAngle={3}
                  dataKey="value"
                  stroke="none"
                >
                  {data.map((entry, index) => (
                    <Cell key={index} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip content={<CustomTooltip />} />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="flex-1 space-y-2.5">
            {data.map((item) => (
              <div key={item.name} className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div
                    className="h-2.5 w-2.5 rounded-full"
                    style={{ backgroundColor: item.color }}
                  />
                  <span className="text-sm text-slate-300">{item.name}</span>
                </div>
                <div className="flex items-center gap-3">
                  <span className="text-sm font-semibold text-slate-100">
                    {item.value}
                  </span>
                  <span className="text-xs text-slate-500 w-10 text-right">
                    {Math.round((item.value / total) * 100)}%
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

/* -------------------------------------------------------------------------- */
/*  Weekly Trend Chart                                                        */
/* -------------------------------------------------------------------------- */

interface TrendItem {
  week: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export function WeeklyTrendChart({ data }: { data: TrendItem[] }) {
  if (data.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Weekly Findings Trend</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-center h-[180px] text-sm text-slate-500">
            No scan data yet
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Weekly Findings Trend</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="h-[180px]">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data} barCategoryGap="20%">
              <XAxis
                dataKey="week"
                axisLine={false}
                tickLine={false}
                tick={{ fill: '#64748b', fontSize: 12 }}
              />
              <YAxis
                axisLine={false}
                tickLine={false}
                tick={{ fill: '#64748b', fontSize: 12 }}
                width={30}
              />
              <Tooltip content={<CustomTooltip />} />
              <Bar dataKey="critical" stackId="a" fill="#ef4444" radius={[0, 0, 0, 0]} name="Critical" />
              <Bar dataKey="high" stackId="a" fill="#f97316" radius={[0, 0, 0, 0]} name="High" />
              <Bar dataKey="medium" stackId="a" fill="#eab308" radius={[0, 0, 0, 0]} name="Medium" />
              <Bar dataKey="low" stackId="a" fill="#3b82f6" radius={[0, 0, 0, 0]} name="Low" />
              <Bar dataKey="info" stackId="a" fill="#6b7280" radius={[4, 4, 0, 0]} name="Info" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  );
}

/* -------------------------------------------------------------------------- */
/*  Activity Sparkline                                                        */
/* -------------------------------------------------------------------------- */

const activityData = [
  { day: 'Mon', scans: 3 },
  { day: 'Tue', scans: 5 },
  { day: 'Wed', scans: 2 },
  { day: 'Thu', scans: 8 },
  { day: 'Fri', scans: 6 },
  { day: 'Sat', scans: 1 },
  { day: 'Sun', scans: 4 },
];

export function ActivityChart() {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Scan Activity</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="h-[180px]">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={activityData}>
              <defs>
                <linearGradient id="scanGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#3b82f6" stopOpacity={0.3} />
                  <stop offset="100%" stopColor="#3b82f6" stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis
                dataKey="day"
                axisLine={false}
                tickLine={false}
                tick={{ fill: '#64748b', fontSize: 12 }}
              />
              <YAxis
                axisLine={false}
                tickLine={false}
                tick={{ fill: '#64748b', fontSize: 12 }}
                width={30}
              />
              <Tooltip content={<CustomTooltip />} />
              <Area
                type="monotone"
                dataKey="scans"
                stroke="#3b82f6"
                strokeWidth={2}
                fill="url(#scanGradient)"
                name="Scans"
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  );
}
