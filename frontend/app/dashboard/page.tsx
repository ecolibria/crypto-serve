"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Key, Activity, CheckCircle, XCircle, Plus } from "lucide-react";
import { DashboardLayout } from "@/components/dashboard-layout";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { api, Identity, AuditStats } from "@/lib/api";

export default function DashboardPage() {
  const [identities, setIdentities] = useState<Identity[]>([]);
  const [stats, setStats] = useState<AuditStats | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([api.listIdentities(), api.getAuditStats()])
      .then(([ids, s]) => {
        setIdentities(ids);
        setStats(s);
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  const activeIdentities = identities.filter((i) => i.status === "active");

  return (
    <DashboardLayout>
      <div className="space-y-8">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold">Dashboard</h1>
            <p className="text-slate-600">
              Overview of your cryptographic operations
            </p>
          </div>
          <Link href="/identities">
            <Button>
              <Plus className="h-4 w-4 mr-2" />
              New Identity
            </Button>
          </Link>
        </div>

        {loading ? (
          <div className="flex justify-center py-12">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
          </div>
        ) : (
          <>
            {/* Stats cards */}
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
              <Card>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">
                    Active Identities
                  </CardTitle>
                  <Key className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">
                    {activeIdentities.length}
                  </div>
                  <p className="text-xs text-muted-foreground">
                    {identities.length} total
                  </p>
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">
                    Total Operations
                  </CardTitle>
                  <Activity className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">
                    {stats?.total_operations || 0}
                  </div>
                  <p className="text-xs text-muted-foreground">
                    encrypt & decrypt calls
                  </p>
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">
                    Successful
                  </CardTitle>
                  <CheckCircle className="h-4 w-4 text-green-500" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">
                    {stats?.successful_operations || 0}
                  </div>
                  <p className="text-xs text-muted-foreground">
                    {stats && stats.total_operations > 0
                      ? `${Math.round(
                          (stats.successful_operations / stats.total_operations) *
                            100
                        )}% success rate`
                      : "No operations yet"}
                  </p>
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">Failed</CardTitle>
                  <XCircle className="h-4 w-4 text-red-500" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">
                    {stats?.failed_operations || 0}
                  </div>
                  <p className="text-xs text-muted-foreground">
                    Check audit log for details
                  </p>
                </CardContent>
              </Card>
            </div>

            {/* Quick start */}
            {activeIdentities.length === 0 && (
              <Card>
                <CardHeader>
                  <CardTitle>Get Started</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p className="text-slate-600">
                    Create your first identity to get a personalized SDK.
                  </p>
                  <Link href="/identities">
                    <Button>
                      <Plus className="h-4 w-4 mr-2" />
                      Create Identity
                    </Button>
                  </Link>
                </CardContent>
              </Card>
            )}

            {/* Recent identities */}
            {activeIdentities.length > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle>Recent Identities</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {activeIdentities.slice(0, 5).map((identity) => (
                      <div
                        key={identity.id}
                        className="flex items-center justify-between p-4 border rounded-lg"
                      >
                        <div>
                          <p className="font-medium">{identity.name}</p>
                          <p className="text-sm text-slate-500">
                            {identity.team} / {identity.environment}
                          </p>
                        </div>
                        <div className="text-right">
                          <p className="text-sm text-slate-500">
                            {identity.allowed_contexts.length} contexts
                          </p>
                          <p className="text-xs text-slate-400">
                            Expires{" "}
                            {new Date(identity.expires_at).toLocaleDateString()}
                          </p>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Operations by context */}
            {stats && Object.keys(stats.operations_by_context).length > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle>Operations by Context</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    {Object.entries(stats.operations_by_context).map(
                      ([context, count]) => (
                        <div
                          key={context}
                          className="flex items-center justify-between"
                        >
                          <span className="font-mono text-sm">{context}</span>
                          <span className="text-slate-600">{count}</span>
                        </div>
                      )
                    )}
                  </div>
                </CardContent>
              </Card>
            )}
          </>
        )}
      </div>
    </DashboardLayout>
  );
}
