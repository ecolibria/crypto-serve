"use client";

import { useEffect, useState, useCallback } from "react";
import { Activity, Clock, TrendingUp, Database } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { AdminLayout } from "@/components/admin-layout";
import { LineChart } from "@/components/charts/line-chart";
import { BarChart } from "@/components/charts/bar-chart";
import { DonutChart } from "@/components/charts/donut-chart";
import { api, TrendDataPoint, TeamUsage, AuditStats } from "@/lib/api";
import { cn } from "@/lib/utils";

type TimeRange = 7 | 30 | 90;

export default function AdminAnalyticsPage() {
  const [trends, setTrends] = useState<TrendDataPoint[]>([]);
  const [teamUsage, setTeamUsage] = useState<TeamUsage[]>([]);
  const [stats, setStats] = useState<AuditStats | null>(null);
  const [timeRange, setTimeRange] = useState<TimeRange>(30);
  const [loading, setLoading] = useState(true);

  const loadData = useCallback(async () => {
    try {
      setLoading(true);
      const [trendsData, teamsData, statsData] = await Promise.all([
        api.getOperationTrends(timeRange),
        api.getTeamUsage(10),
        api.getAuditStats(),
      ]);
      setTrends(trendsData);
      setTeamUsage(teamsData);
      setStats(statsData);
    } catch (error) {
      console.error("Failed to load analytics:", error);
    } finally {
      setLoading(false);
    }
  }, [timeRange]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Transform data for charts
  const operationsChartData = trends.map((t) => ({
    date: new Date(t.date).toLocaleDateString("en-US", { month: "short", day: "numeric" }),
    encrypt: t.encrypt_count,
    decrypt: t.decrypt_count,
  }));

  const successFailureChartData = trends.map((t) => ({
    date: new Date(t.date).toLocaleDateString("en-US", { month: "short", day: "numeric" }),
    success: t.success_count,
    failed: t.failed_count,
  }));

  const teamChartData = teamUsage.map((t) => ({
    team: t.team,
    operations: t.operation_count,
  }));

  const contextChartData = stats
    ? Object.entries(stats.operations_by_context).map(([name, value]) => ({
        name,
        value,
      }))
    : [];

  const timeRangeOptions: { value: TimeRange; label: string }[] = [
    { value: 7, label: "7 days" },
    { value: 30, label: "30 days" },
    { value: 90, label: "90 days" },
  ];

  if (loading) {
    return (
      <AdminLayout title="Analytics" subtitle="Loading...">
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
        </div>
      </AdminLayout>
    );
  }

  // Calculate totals
  const totalOperations = trends.reduce((sum, t) => sum + t.encrypt_count + t.decrypt_count, 0);
  const totalSuccess = trends.reduce((sum, t) => sum + t.success_count, 0);
  const totalFailed = trends.reduce((sum, t) => sum + t.failed_count, 0);
  const successRate = totalOperations > 0 ? Math.round((totalSuccess / totalOperations) * 100) : 100;

  return (
    <AdminLayout
      title="Analytics"
      subtitle="Usage patterns and performance metrics"
      onRefresh={loadData}
      actions={
        <div className="flex gap-2">
          {timeRangeOptions.map((option) => (
            <button
              key={option.value}
              onClick={() => setTimeRange(option.value)}
              className={cn(
                "px-3 py-1.5 rounded-lg text-sm font-medium transition-colors",
                timeRange === option.value
                  ? "bg-slate-900 text-white"
                  : "bg-slate-100 text-slate-600 hover:bg-slate-200"
              )}
            >
              {option.label}
            </button>
          ))}
        </div>
      }
    >
      {/* Summary Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="h-10 w-10 rounded-lg bg-blue-100 flex items-center justify-center">
                <Activity className="h-5 w-5 text-blue-600" />
              </div>
              <div>
                <p className="text-2xl font-bold">{totalOperations.toLocaleString()}</p>
                <p className="text-sm text-slate-500">Total Operations</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="h-10 w-10 rounded-lg bg-green-100 flex items-center justify-center">
                <TrendingUp className="h-5 w-5 text-green-600" />
              </div>
              <div>
                <p className="text-2xl font-bold">{successRate}%</p>
                <p className="text-sm text-slate-500">Success Rate</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="h-10 w-10 rounded-lg bg-red-100 flex items-center justify-center">
                <Clock className="h-5 w-5 text-red-600" />
              </div>
              <div>
                <p className="text-2xl font-bold">{totalFailed.toLocaleString()}</p>
                <p className="text-sm text-slate-500">Failed Operations</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="h-10 w-10 rounded-lg bg-purple-100 flex items-center justify-center">
                <Database className="h-5 w-5 text-purple-600" />
              </div>
              <div>
                <p className="text-2xl font-bold">{contextChartData.length}</p>
                <p className="text-sm text-slate-500">Active Contexts</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Charts Row 1 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        {/* Operations Over Time */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Operations Over Time</CardTitle>
          </CardHeader>
          <CardContent>
            {operationsChartData.length > 0 ? (
              <LineChart
                data={operationsChartData}
                xAxisKey="date"
                lines={[
                  { dataKey: "encrypt", name: "Encrypt", color: "#3b82f6" },
                  { dataKey: "decrypt", name: "Decrypt", color: "#10b981" },
                ]}
                height={300}
              />
            ) : (
              <div className="h-[300px] flex items-center justify-center text-slate-500 text-sm">
                No operation data
              </div>
            )}
          </CardContent>
        </Card>

        {/* Success vs Failed */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Success vs Failed</CardTitle>
          </CardHeader>
          <CardContent>
            {successFailureChartData.length > 0 ? (
              <LineChart
                data={successFailureChartData}
                xAxisKey="date"
                lines={[
                  { dataKey: "success", name: "Success", color: "#10b981" },
                  { dataKey: "failed", name: "Failed", color: "#ef4444" },
                ]}
                height={300}
              />
            ) : (
              <div className="h-[300px] flex items-center justify-center text-slate-500 text-sm">
                No data available
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Charts Row 2 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        {/* Usage by Team */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Top Teams by Usage</CardTitle>
          </CardHeader>
          <CardContent>
            {teamChartData.length > 0 ? (
              <BarChart
                data={teamChartData}
                dataKey="operations"
                nameKey="team"
                height={300}
                layout="vertical"
              />
            ) : (
              <div className="h-[300px] flex items-center justify-center text-slate-500 text-sm">
                No team data
              </div>
            )}
          </CardContent>
        </Card>

        {/* Usage by Context */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Operations by Context</CardTitle>
          </CardHeader>
          <CardContent>
            {contextChartData.length > 0 ? (
              <DonutChart
                data={contextChartData}
                height={300}
              />
            ) : (
              <div className="h-[300px] flex items-center justify-center text-slate-500 text-sm">
                No context data
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Data Tables */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Identities */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Top Identities by Usage</CardTitle>
          </CardHeader>
          <CardContent>
            {stats && Object.keys(stats.operations_by_identity).length > 0 ? (
              <div className="space-y-3">
                {Object.entries(stats.operations_by_identity)
                  .sort((a, b) => b[1] - a[1])
                  .slice(0, 10)
                  .map(([identity, count], index) => (
                    <div key={identity} className="flex items-center gap-3">
                      <span className="text-sm font-medium text-slate-400 w-6">
                        {index + 1}.
                      </span>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium truncate">{identity}</p>
                      </div>
                      <span className="text-sm font-medium tabular-nums">
                        {count.toLocaleString()}
                      </span>
                    </div>
                  ))}
              </div>
            ) : (
              <div className="h-48 flex items-center justify-center text-slate-500 text-sm">
                No identity data
              </div>
            )}
          </CardContent>
        </Card>

        {/* Context Breakdown */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Context Breakdown</CardTitle>
          </CardHeader>
          <CardContent>
            {stats && Object.keys(stats.operations_by_context).length > 0 ? (
              <div className="space-y-3">
                {Object.entries(stats.operations_by_context)
                  .sort((a, b) => b[1] - a[1])
                  .map(([context, count]) => {
                    const percentage = Math.round(
                      (count / stats.total_operations) * 100
                    );
                    return (
                      <div key={context} className="space-y-1">
                        <div className="flex items-center justify-between text-sm">
                          <span className="font-medium">{context}</span>
                          <span className="text-slate-500">
                            {count.toLocaleString()} ({percentage}%)
                          </span>
                        </div>
                        <div className="h-2 bg-slate-100 rounded-full overflow-hidden">
                          <div
                            className="h-full bg-blue-500 rounded-full transition-all"
                            style={{ width: `${percentage}%` }}
                          />
                        </div>
                      </div>
                    );
                  })}
              </div>
            ) : (
              <div className="h-48 flex items-center justify-center text-slate-500 text-sm">
                No context data
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </AdminLayout>
  );
}
