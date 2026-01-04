"use client";

import { useEffect, useState } from "react";
import { DashboardLayout } from "@/components/dashboard-layout";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  AlertCircle,
  CheckCircle2,
  Clock,
  Filter,
  RefreshCw,
  ChevronDown,
  ChevronUp,
  ExternalLink,
} from "lucide-react";
import { api, FindingSummary, FindingStatus } from "@/lib/api";
import { cn } from "@/lib/utils";

type SeverityLevel = "critical" | "high" | "medium" | "low" | "info";

const getSeverityColor = (severity: SeverityLevel) => {
  switch (severity) {
    case "critical":
      return "bg-red-100 text-red-800 border-red-200";
    case "high":
      return "bg-orange-100 text-orange-800 border-orange-200";
    case "medium":
      return "bg-yellow-100 text-yellow-800 border-yellow-200";
    case "low":
      return "bg-blue-100 text-blue-800 border-blue-200";
    default:
      return "bg-slate-100 text-slate-800 border-slate-200";
  }
};

const getStatusStyle = (status: FindingStatus) => {
  switch (status) {
    case "open":
      return { color: "text-blue-600 bg-blue-50 border-blue-200", icon: AlertCircle };
    case "resolved":
      return { color: "text-green-600 bg-green-50 border-green-200", icon: CheckCircle2 };
    case "in_progress":
      return { color: "text-amber-600 bg-amber-50 border-amber-200", icon: Clock };
    case "accepted":
      return { color: "text-slate-600 bg-slate-50 border-slate-200", icon: CheckCircle2 };
    case "false_positive":
      return { color: "text-slate-500 bg-slate-50 border-slate-200", icon: ShieldCheck };
    default:
      return { color: "text-slate-600 bg-slate-50 border-slate-200", icon: AlertCircle };
  }
};

export default function DeveloperSecurityPage() {
  const [findings, setFindings] = useState<FindingSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<"all" | "open" | "resolved">("all");
  const [expandedFindings, setExpandedFindings] = useState<Set<number>>(new Set());

  const fetchFindings = async () => {
    setLoading(true);
    try {
      const data = await api.listSecurityFindings({ days: 90, limit: 100 });
      setFindings(data);
    } catch (error) {
      console.error("Failed to fetch findings:", error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFindings();
  }, []);

  const toggleExpanded = (id: number) => {
    setExpandedFindings((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  const filteredFindings = findings.filter((f) => {
    if (filter === "open") return f.status === "open" || f.status === "in_progress";
    if (filter === "resolved") return f.status === "resolved" || f.status === "accepted";
    return true;
  });

  const openCount = findings.filter((f) => f.status === "open" || f.status === "in_progress").length;
  const resolvedCount = findings.filter((f) => f.status === "resolved").length;
  const criticalCount = findings.filter((f) => f.severity === "critical" && f.status === "open").length;
  const highCount = findings.filter((f) => f.severity === "high" && f.status === "open").length;

  const formatDate = (dateStr: string | null) => {
    if (!dateStr) return null;
    return new Date(dateStr).toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
      year: "numeric",
    });
  };

  return (
    <DashboardLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-slate-900">Security Findings</h1>
            <p className="text-slate-500 mt-1">
              Review vulnerabilities and recommendations for your applications
            </p>
          </div>
          <Button onClick={fetchFindings} variant="outline" size="sm">
            <RefreshCw className={cn("h-4 w-4 mr-2", loading && "animate-spin")} />
            Refresh
          </Button>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <Card>
            <CardContent className="pt-4">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-blue-100">
                  <AlertCircle className="h-5 w-5 text-blue-600" />
                </div>
                <div>
                  <p className="text-2xl font-bold text-slate-900">{openCount}</p>
                  <p className="text-sm text-slate-500">Open Issues</p>
                </div>
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-green-100">
                  <CheckCircle2 className="h-5 w-5 text-green-600" />
                </div>
                <div>
                  <p className="text-2xl font-bold text-slate-900">{resolvedCount}</p>
                  <p className="text-sm text-slate-500">Resolved</p>
                </div>
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-red-100">
                  <ShieldAlert className="h-5 w-5 text-red-600" />
                </div>
                <div>
                  <p className="text-2xl font-bold text-slate-900">{criticalCount}</p>
                  <p className="text-sm text-slate-500">Critical</p>
                </div>
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-orange-100">
                  <AlertTriangle className="h-5 w-5 text-orange-600" />
                </div>
                <div>
                  <p className="text-2xl font-bold text-slate-900">{highCount}</p>
                  <p className="text-sm text-slate-500">High Priority</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Filter Tabs */}
        <div className="flex items-center gap-2">
          <Filter className="h-4 w-4 text-slate-400" />
          <div className="flex gap-1 bg-slate-100 rounded-lg p-1">
            {[
              { key: "all", label: "All" },
              { key: "open", label: "Open" },
              { key: "resolved", label: "Resolved" },
            ].map(({ key, label }) => (
              <button
                key={key}
                onClick={() => setFilter(key as typeof filter)}
                className={cn(
                  "px-3 py-1.5 text-sm font-medium rounded-md transition-colors",
                  filter === key
                    ? "bg-white text-slate-900 shadow-sm"
                    : "text-slate-600 hover:text-slate-900"
                )}
              >
                {label}
              </button>
            ))}
          </div>
        </div>

        {/* Findings List */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">
              {filteredFindings.length} Finding{filteredFindings.length !== 1 ? "s" : ""}
            </CardTitle>
          </CardHeader>
          <CardContent>
            {loading ? (
              <div className="flex items-center justify-center py-12">
                <RefreshCw className="h-6 w-6 animate-spin text-slate-400" />
              </div>
            ) : filteredFindings.length === 0 ? (
              <div className="text-center py-12">
                <ShieldCheck className="h-12 w-12 mx-auto mb-3 text-green-400" />
                <p className="font-medium text-slate-700">No findings to show</p>
                <p className="text-sm text-slate-500 mt-1">
                  {filter === "all"
                    ? "Run security scans to detect vulnerabilities"
                    : filter === "open"
                    ? "All issues have been resolved"
                    : "No resolved findings yet"}
                </p>
              </div>
            ) : (
              <div className="space-y-3">
                {filteredFindings.map((finding) => {
                  const statusStyle = getStatusStyle(finding.status);
                  const StatusIcon = statusStyle.icon;
                  const isExpanded = expandedFindings.has(finding.id);

                  return (
                    <div
                      key={finding.id}
                      className={cn(
                        "border rounded-lg transition-all",
                        finding.status === "resolved" && "opacity-60"
                      )}
                    >
                      {/* Finding Header - Always visible */}
                      <div
                        className="p-4 cursor-pointer hover:bg-slate-50"
                        onClick={() => toggleExpanded(finding.id)}
                      >
                        <div className="flex items-start justify-between gap-4">
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 flex-wrap mb-2">
                              <span
                                className={cn(
                                  "px-2 py-0.5 text-xs font-medium rounded border",
                                  getSeverityColor(finding.severity as SeverityLevel)
                                )}
                              >
                                {finding.severity.toUpperCase()}
                              </span>
                              <span className="text-xs text-slate-500 capitalize">
                                {finding.scan_type}
                              </span>
                              {finding.is_new && (
                                <span className="px-1.5 py-0.5 text-xs font-medium rounded bg-blue-100 text-blue-700">
                                  New
                                </span>
                              )}
                              <span className="text-xs text-slate-400">•</span>
                              <span className="text-xs font-medium text-slate-600">
                                {finding.target_name}
                              </span>
                            </div>
                            <p className="font-medium text-slate-900">{finding.title}</p>
                            {finding.description && (
                              <p className="text-sm text-slate-600 mt-1 line-clamp-1">
                                {finding.description}
                              </p>
                            )}
                          </div>
                          <div className="flex items-center gap-3">
                            <div
                              className={cn(
                                "flex items-center gap-1 px-2 py-1 rounded text-xs font-medium border",
                                statusStyle.color
                              )}
                            >
                              <StatusIcon className="h-3 w-3" />
                              <span className="capitalize">{finding.status.replace("_", " ")}</span>
                            </div>
                            {isExpanded ? (
                              <ChevronUp className="h-5 w-5 text-slate-400" />
                            ) : (
                              <ChevronDown className="h-5 w-5 text-slate-400" />
                            )}
                          </div>
                        </div>
                      </div>

                      {/* Expanded Details */}
                      {isExpanded && (
                        <div className="px-4 pb-4 border-t bg-slate-50">
                          <div className="grid md:grid-cols-2 gap-6 pt-4">
                            {/* Left: Details */}
                            <div className="space-y-3">
                              <h4 className="text-sm font-medium text-slate-700">Details</h4>
                              <div className="space-y-2 text-sm">
                                {finding.file_path && (
                                  <div>
                                    <span className="text-slate-500">Location: </span>
                                    <code className="bg-slate-200 px-1.5 py-0.5 rounded text-slate-700">
                                      {finding.file_path}
                                      {finding.line_number ? `:${finding.line_number}` : ""}
                                    </code>
                                  </div>
                                )}
                                {finding.algorithm && (
                                  <div>
                                    <span className="text-slate-500">Algorithm: </span>
                                    <code className="bg-slate-200 px-1.5 py-0.5 rounded text-slate-700">
                                      {finding.algorithm}
                                    </code>
                                  </div>
                                )}
                                {finding.library && (
                                  <div>
                                    <span className="text-slate-500">Library: </span>
                                    <code className="bg-slate-200 px-1.5 py-0.5 rounded text-slate-700">
                                      {finding.library}
                                    </code>
                                  </div>
                                )}
                                <div className="pt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-500">
                                  {finding.first_detected_at && (
                                    <span>First detected: {formatDate(finding.first_detected_at)}</span>
                                  )}
                                  {finding.resolved_at && (
                                    <span>Resolved: {formatDate(finding.resolved_at)}</span>
                                  )}
                                  {!finding.first_detected_at && (
                                    <span>Scanned: {formatDate(finding.scanned_at)}</span>
                                  )}
                                </div>
                                {finding.status_reason && (
                                  <div className="pt-2">
                                    <span className="text-slate-500 italic">{finding.status_reason}</span>
                                  </div>
                                )}
                              </div>
                            </div>

                            {/* Right: Recommendation */}
                            <div className="space-y-3">
                              <h4 className="text-sm font-medium text-slate-700">Recommendation</h4>
                              <div className="p-3 bg-white rounded-lg border border-slate-200">
                                <p className="text-sm text-slate-700 leading-relaxed">
                                  {finding.recommendation || "No specific recommendation available."}
                                </p>
                              </div>
                              {finding.recommendation?.includes("context") && (
                                <a
                                  href="/dashboard/contexts"
                                  className="inline-flex items-center gap-1 text-sm text-blue-600 hover:text-blue-700"
                                >
                                  View available contexts
                                  <ExternalLink className="h-3 w-3" />
                                </a>
                              )}
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  );
}
