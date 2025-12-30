"use client";

import { useEffect, useState } from "react";
import { CheckCircle, XCircle, Clock } from "lucide-react";
import { DashboardLayout } from "@/components/dashboard-layout";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { api, AuditLog, Identity } from "@/lib/api";

export default function AuditPage() {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [identities, setIdentities] = useState<Identity[]>([]);
  const [loading, setLoading] = useState(true);

  // Filters
  const [identityFilter, setIdentityFilter] = useState("");
  const [contextFilter, setContextFilter] = useState("");
  const [successFilter, setSuccessFilter] = useState<string>("");

  useEffect(() => {
    Promise.all([api.listIdentities()])
      .then(([ids]) => {
        setIdentities(ids);
      })
      .catch(console.error);
  }, []);

  useEffect(() => {
    setLoading(true);
    api
      .listAuditLogs({
        identity_id: identityFilter || undefined,
        context: contextFilter || undefined,
        success: successFilter === "" ? undefined : successFilter === "true",
        limit: 100,
      })
      .then(setLogs)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [identityFilter, contextFilter, successFilter]);

  const formatTime = (timestamp: string) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diff = now.getTime() - date.getTime();

    if (diff < 60000) return "Just now";
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
    if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
    return date.toLocaleDateString();
  };

  const uniqueContexts = Array.from(new Set(logs.map((l) => l.context)));

  return (
    <DashboardLayout>
      <div className="space-y-8">
        <div>
          <h1 className="text-2xl font-bold">Audit Log</h1>
          <p className="text-slate-600">
            View all cryptographic operations performed by your identities
          </p>
        </div>

        {/* Filters */}
        <Card>
          <CardContent className="py-4">
            <div className="flex flex-wrap gap-4">
              <div>
                <label className="block text-sm font-medium mb-1">
                  Identity
                </label>
                <select
                  className="px-3 py-2 border rounded-lg text-sm"
                  value={identityFilter}
                  onChange={(e) => setIdentityFilter(e.target.value)}
                >
                  <option value="">All identities</option>
                  {identities.map((id) => (
                    <option key={id.id} value={id.id}>
                      {id.name}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium mb-1">
                  Context
                </label>
                <select
                  className="px-3 py-2 border rounded-lg text-sm"
                  value={contextFilter}
                  onChange={(e) => setContextFilter(e.target.value)}
                >
                  <option value="">All contexts</option>
                  {uniqueContexts.map((ctx) => (
                    <option key={ctx} value={ctx}>
                      {ctx}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium mb-1">Status</label>
                <select
                  className="px-3 py-2 border rounded-lg text-sm"
                  value={successFilter}
                  onChange={(e) => setSuccessFilter(e.target.value)}
                >
                  <option value="">All</option>
                  <option value="true">Success</option>
                  <option value="false">Failed</option>
                </select>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Logs */}
        {loading ? (
          <div className="flex justify-center py-12">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
          </div>
        ) : logs.length === 0 ? (
          <Card>
            <CardContent className="py-12 text-center">
              <p className="text-slate-600">No operations recorded yet.</p>
              <p className="text-sm text-slate-500 mt-2">
                Operations will appear here when you use the SDK.
              </p>
            </CardContent>
          </Card>
        ) : (
          <Card>
            <CardHeader>
              <CardTitle>Recent Operations</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b">
                      <th className="text-left py-3 px-2">Time</th>
                      <th className="text-left py-3 px-2">Operation</th>
                      <th className="text-left py-3 px-2">Context</th>
                      <th className="text-left py-3 px-2">Identity</th>
                      <th className="text-left py-3 px-2">Status</th>
                      <th className="text-left py-3 px-2">Latency</th>
                      <th className="text-left py-3 px-2">Size</th>
                    </tr>
                  </thead>
                  <tbody>
                    {logs.map((log) => (
                      <tr key={log.id} className="border-b hover:bg-slate-50">
                        <td className="py-3 px-2 text-slate-500">
                          <div className="flex items-center gap-1">
                            <Clock className="h-3 w-3" />
                            {formatTime(log.timestamp)}
                          </div>
                        </td>
                        <td className="py-3 px-2">
                          <Badge variant="outline">{log.operation}</Badge>
                        </td>
                        <td className="py-3 px-2 font-mono text-xs">
                          {log.context}
                        </td>
                        <td className="py-3 px-2">
                          <div>
                            <p className="font-medium">{log.identity_name}</p>
                            <p className="text-xs text-slate-500">{log.team}</p>
                          </div>
                        </td>
                        <td className="py-3 px-2">
                          {log.success ? (
                            <div className="flex items-center gap-1 text-green-600">
                              <CheckCircle className="h-4 w-4" />
                              <span>Success</span>
                            </div>
                          ) : (
                            <div className="flex items-center gap-1 text-red-600">
                              <XCircle className="h-4 w-4" />
                              <span title={log.error_message || ""}>Failed</span>
                            </div>
                          )}
                        </td>
                        <td className="py-3 px-2 text-slate-500">
                          {log.latency_ms ? `${log.latency_ms}ms` : "-"}
                        </td>
                        <td className="py-3 px-2 text-slate-500 text-xs">
                          {log.input_size_bytes
                            ? `${log.input_size_bytes}B → ${log.output_size_bytes}B`
                            : "-"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </DashboardLayout>
  );
}
