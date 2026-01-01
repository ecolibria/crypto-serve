"use client";

import { useEffect, useState } from "react";
import { AdminLayout } from "@/components/admin-layout";
import { api } from "@/lib/api";
import { Key, Clock, Shield, AlertCircle, CheckCircle2, XCircle } from "lucide-react";

interface Application {
  id: string;
  name: string;
  description: string | null;
  team: string;
  environment: string;
  allowed_contexts: string[];
  status: string;
  created_at: string;
  expires_at: string;
  last_used_at: string | null;
  key_created_at: string;
  has_refresh_token: boolean;
  refresh_token_expires_at: string | null;
}

export default function ApplicationsPage() {
  const [applications, setApplications] = useState<Application[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchApplications = async () => {
    try {
      setLoading(true);
      const data = await api.listApplications();
      setApplications(data);
      setError(null);
    } catch (err) {
      setError("Failed to load applications");
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchApplications();
  }, []);

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "active":
        return <CheckCircle2 className="h-4 w-4 text-green-500" />;
      case "revoked":
        return <XCircle className="h-4 w-4 text-red-500" />;
      default:
        return <AlertCircle className="h-4 w-4 text-yellow-500" />;
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString("en-US", {
      year: "numeric",
      month: "short",
      day: "numeric",
    });
  };

  const isExpired = (expiresAt: string) => {
    return new Date(expiresAt) < new Date();
  };

  return (
    <AdminLayout
      title="Applications"
      subtitle="Manage registered SDK applications and their credentials"
      onRefresh={fetchApplications}
    >
      {error && (
        <div className="mb-6 bg-red-500/20 border border-red-500/50 rounded-lg p-4 flex items-center gap-3">
          <AlertCircle className="h-5 w-5 text-red-400" />
          <p className="text-red-200">{error}</p>
        </div>
      )}

      {loading ? (
        <div className="flex items-center justify-center py-12">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500" />
        </div>
      ) : applications.length === 0 ? (
        <div className="text-center py-12">
          <Key className="h-12 w-12 text-slate-500 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-white mb-2">No applications yet</h3>
          <p className="text-slate-400 max-w-md mx-auto">
            Register applications using the CLI to get personalized SDK credentials.
          </p>
          <pre className="mt-4 bg-slate-800 rounded-lg p-4 text-left max-w-md mx-auto text-sm text-slate-300">
            <code>pip install cryptoserve{"\n"}cryptoserve register my-app</code>
          </pre>
        </div>
      ) : (
        <div className="grid gap-4">
          {applications.map((app) => (
            <div
              key={app.id}
              className="bg-slate-800/50 border border-slate-700 rounded-lg p-4"
            >
              <div className="flex items-start justify-between">
                <div className="flex items-center gap-3">
                  <div className="h-10 w-10 bg-blue-500/20 rounded-lg flex items-center justify-center">
                    <Key className="h-5 w-5 text-blue-400" />
                  </div>
                  <div>
                    <h3 className="font-medium text-white">{app.name}</h3>
                    <p className="text-sm text-slate-400">
                      {app.team} / {app.environment}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  {getStatusIcon(app.status)}
                  <span
                    className={`text-sm ${
                      app.status === "active"
                        ? "text-green-400"
                        : app.status === "revoked"
                        ? "text-red-400"
                        : "text-yellow-400"
                    }`}
                  >
                    {app.status}
                  </span>
                </div>
              </div>

              <div className="mt-4 grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                <div>
                  <p className="text-slate-500">Created</p>
                  <p className="text-slate-300">{formatDate(app.created_at)}</p>
                </div>
                <div>
                  <p className="text-slate-500">Expires</p>
                  <p
                    className={
                      isExpired(app.expires_at) ? "text-red-400" : "text-slate-300"
                    }
                  >
                    {formatDate(app.expires_at)}
                    {isExpired(app.expires_at) && " (expired)"}
                  </p>
                </div>
                <div>
                  <p className="text-slate-500">Last Used</p>
                  <p className="text-slate-300">
                    {app.last_used_at ? formatDate(app.last_used_at) : "Never"}
                  </p>
                </div>
                <div>
                  <p className="text-slate-500">Contexts</p>
                  <div className="flex flex-wrap gap-1">
                    {app.allowed_contexts.map((ctx) => (
                      <span
                        key={ctx}
                        className="px-2 py-0.5 bg-slate-700 rounded text-xs text-slate-300"
                      >
                        {ctx}
                      </span>
                    ))}
                  </div>
                </div>
              </div>

              <div className="mt-3 pt-3 border-t border-slate-700 flex items-center justify-between text-xs text-slate-500">
                <span className="font-mono">{app.id}</span>
                {app.has_refresh_token && (
                  <span className="flex items-center gap-1">
                    <Shield className="h-3 w-3" />
                    Refresh token active
                  </span>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </AdminLayout>
  );
}
