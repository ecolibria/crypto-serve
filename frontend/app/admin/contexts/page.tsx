"use client";

import { useEffect, useState, useCallback } from "react";
import {
  Shield,
  Key,
  Users,
  Activity,
  RotateCw,
  Lock,
  AlertTriangle,
  CheckCircle2,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { AdminLayout } from "@/components/admin-layout";
import { api, AdminContextStats } from "@/lib/api";
import { cn } from "@/lib/utils";

export default function AdminContextsPage() {
  const [contexts, setContexts] = useState<AdminContextStats[]>([]);
  const [loading, setLoading] = useState(true);
  const [rotating, setRotating] = useState<string | null>(null);

  const loadContexts = useCallback(async () => {
    try {
      setLoading(true);
      const data = await api.getContextsWithStats();
      setContexts(data);
    } catch (error) {
      console.error("Failed to load contexts:", error);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadContexts();
  }, [loadContexts]);

  const handleRotateKey = async (contextName: string) => {
    if (!confirm(`Are you sure you want to rotate the encryption key for "${contextName}"? This action will create a new key version. Existing encrypted data will continue to be decryptable.`)) {
      return;
    }
    setRotating(contextName);
    try {
      await api.rotateContextKey(contextName);
      await loadContexts();
    } catch (error) {
      console.error("Failed to rotate key:", error);
      alert("Failed to rotate key. Please try again.");
    } finally {
      setRotating(null);
    }
  };

  const getDaysSinceRotation = (lastRotation: string | null) => {
    if (!lastRotation) return null;
    const days = Math.floor(
      (Date.now() - new Date(lastRotation).getTime()) / (1000 * 60 * 60 * 24)
    );
    return days;
  };

  const getRotationStatus = (lastRotation: string | null) => {
    const days = getDaysSinceRotation(lastRotation);
    if (days === null) return { status: "unknown", color: "slate" };
    if (days > 90) return { status: "overdue", color: "red" };
    if (days > 60) return { status: "due-soon", color: "amber" };
    return { status: "healthy", color: "green" };
  };

  if (loading) {
    return (
      <AdminLayout title="Context Management" subtitle="Loading...">
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
        </div>
      </AdminLayout>
    );
  }

  return (
    <AdminLayout
      title="Context Management"
      subtitle={`${contexts.length} encryption contexts configured`}
      onRefresh={loadContexts}
    >
      {/* Contexts Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
        {contexts.map((context) => {
          const rotationStatus = getRotationStatus(context.last_key_rotation);
          const daysSince = getDaysSinceRotation(context.last_key_rotation);

          return (
            <Card key={context.name} className="overflow-hidden">
              <CardHeader className="pb-2">
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-2">
                    <div className="h-10 w-10 rounded-lg bg-blue-100 flex items-center justify-center">
                      <Lock className="h-5 w-5 text-blue-600" />
                    </div>
                    <div>
                      <CardTitle className="text-base">{context.display_name}</CardTitle>
                      <p className="text-xs text-slate-500 font-mono">{context.name}</p>
                    </div>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                {/* Description */}
                <p className="text-sm text-slate-600">{context.description}</p>

                {/* Compliance Tags */}
                {context.compliance_tags && context.compliance_tags.length > 0 && (
                  <div className="flex flex-wrap gap-1">
                    {context.compliance_tags.map((tag) => (
                      <span
                        key={tag}
                        className="px-2 py-0.5 rounded text-xs font-medium bg-emerald-100 text-emerald-700"
                      >
                        {tag}
                      </span>
                    ))}
                  </div>
                )}

                {/* Algorithm */}
                <div className="flex items-center justify-between text-sm">
                  <span className="text-slate-500">Algorithm</span>
                  <span className="font-mono text-xs bg-slate-100 px-2 py-1 rounded">
                    {context.algorithm}
                  </span>
                </div>

                {/* Stats */}
                <div className="grid grid-cols-2 gap-4 pt-2 border-t">
                  <div className="flex items-center gap-2">
                    <Activity className="h-4 w-4 text-slate-400" />
                    <div>
                      <p className="text-lg font-semibold">{context.operation_count.toLocaleString()}</p>
                      <p className="text-xs text-slate-500">Operations</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Users className="h-4 w-4 text-slate-400" />
                    <div>
                      <p className="text-lg font-semibold">{context.identity_count}</p>
                      <p className="text-xs text-slate-500">Identities</p>
                    </div>
                  </div>
                </div>

                {/* Key Info */}
                <div className="pt-3 border-t space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-slate-500">Key Version</span>
                    <span className="text-sm font-medium">v{context.key_version}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-slate-500">Last Rotation</span>
                    <div className="flex items-center gap-2">
                      {rotationStatus.status === "overdue" && (
                        <AlertTriangle className="h-4 w-4 text-red-500" />
                      )}
                      {rotationStatus.status === "due-soon" && (
                        <AlertTriangle className="h-4 w-4 text-amber-500" />
                      )}
                      {rotationStatus.status === "healthy" && (
                        <CheckCircle2 className="h-4 w-4 text-green-500" />
                      )}
                      <span className={cn(
                        "text-sm font-medium",
                        rotationStatus.status === "overdue" && "text-red-600",
                        rotationStatus.status === "due-soon" && "text-amber-600",
                        rotationStatus.status === "healthy" && "text-green-600"
                      )}>
                        {daysSince !== null ? `${daysSince} days ago` : "Never"}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Actions */}
                <div className="pt-3 border-t">
                  <Button
                    variant="outline"
                    size="sm"
                    className="w-full"
                    onClick={() => handleRotateKey(context.name)}
                    disabled={rotating === context.name}
                  >
                    {rotating === context.name ? (
                      <>
                        <span className="animate-spin h-4 w-4 border-2 border-slate-600 border-t-transparent rounded-full mr-2" />
                        Rotating...
                      </>
                    ) : (
                      <>
                        <RotateCw className="h-4 w-4 mr-2" />
                        Rotate Key
                      </>
                    )}
                  </Button>
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {contexts.length === 0 && (
        <div className="text-center py-12">
          <Shield className="h-12 w-12 text-slate-300 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-slate-900 mb-2">No contexts configured</h3>
          <p className="text-slate-500">Encryption contexts define data types and their security policies.</p>
        </div>
      )}
    </AdminLayout>
  );
}
