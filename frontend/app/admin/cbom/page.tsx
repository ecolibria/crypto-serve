"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { FileText, Shield, AlertTriangle, CheckCircle, Clock, GitBranch, GitCommit, Package, ChevronRight, Users } from "lucide-react";
import { AdminLayout } from "@/components/admin-layout";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { api, CBOMReport } from "@/lib/api";

export default function AdminCBOMPage() {
  const [reports, setReports] = useState<CBOMReport[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // TODO: Use admin endpoint to get all users' CBOM reports
    api.listCBOMReports(100)
      .then(setReports)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  const getQuantumReadinessBadge = (score: number) => {
    if (score >= 80) {
      return <Badge className="bg-green-100 text-green-800 hover:bg-green-100">Quantum Ready</Badge>;
    } else if (score >= 50) {
      return <Badge className="bg-yellow-100 text-yellow-800 hover:bg-yellow-100">Partially Ready</Badge>;
    } else {
      return <Badge className="bg-red-100 text-red-800 hover:bg-red-100">Vulnerable</Badge>;
    }
  };

  const getScoreIcon = (score: number) => {
    if (score >= 80) {
      return <CheckCircle className="h-5 w-5 text-green-500" />;
    } else if (score >= 50) {
      return <AlertTriangle className="h-5 w-5 text-yellow-500" />;
    } else {
      return <AlertTriangle className="h-5 w-5 text-red-500" />;
    }
  };

  const formatDate = (dateStr: string) => {
    const date = new Date(dateStr);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 1) return "Just now";
    if (diffMins < 60) return `${diffMins} min ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    if (diffDays < 7) return `${diffDays}d ago`;
    return date.toLocaleDateString();
  };

  const getScoreColor = (score: number) => {
    if (score >= 80) return "text-green-600";
    if (score >= 50) return "text-yellow-600";
    return "text-red-600";
  };

  // Calculate aggregate stats
  const totalLibraries = reports.reduce((sum, r) => sum + r.libraryCount, 0);
  const totalAlgorithms = reports.reduce((sum, r) => sum + r.algorithmCount, 0);
  const avgScore = reports.length > 0
    ? Math.round(reports.reduce((sum, r) => sum + r.quantumReadinessScore, 0) / reports.length)
    : 0;
  const vulnerableCount = reports.filter(r => r.quantumReadinessScore < 50).length;

  return (
    <AdminLayout
      title="CBOM Reports"
      subtitle="Organization-wide cryptographic inventory"
    >
      {loading ? (
        <div className="flex justify-center py-12">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
        </div>
      ) : (
        <div className="space-y-6">
          {/* Summary Stats */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
            <Card>
              <CardContent className="py-4">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-blue-100 rounded-lg">
                    <FileText className="h-5 w-5 text-blue-600" />
                  </div>
                  <div>
                    <p className="text-2xl font-bold">{reports.length}</p>
                    <p className="text-sm text-slate-600">Total Scans</p>
                  </div>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="py-4">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-purple-100 rounded-lg">
                    <Package className="h-5 w-5 text-purple-600" />
                  </div>
                  <div>
                    <p className="text-2xl font-bold">{totalLibraries}</p>
                    <p className="text-sm text-slate-600">Libraries Tracked</p>
                  </div>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="py-4">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-indigo-100 rounded-lg">
                    <Shield className="h-5 w-5 text-indigo-600" />
                  </div>
                  <div>
                    <p className="text-2xl font-bold">{totalAlgorithms}</p>
                    <p className="text-sm text-slate-600">Algorithms</p>
                  </div>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="py-4">
                <div className="flex items-center gap-3">
                  <div className={`p-2 rounded-lg ${avgScore >= 80 ? 'bg-green-100' : avgScore >= 50 ? 'bg-yellow-100' : 'bg-red-100'}`}>
                    {avgScore >= 80 ? (
                      <CheckCircle className="h-5 w-5 text-green-600" />
                    ) : (
                      <AlertTriangle className={`h-5 w-5 ${avgScore >= 50 ? 'text-yellow-600' : 'text-red-600'}`} />
                    )}
                  </div>
                  <div>
                    <p className={`text-2xl font-bold ${getScoreColor(avgScore)}`}>{avgScore}%</p>
                    <p className="text-sm text-slate-600">Avg Quantum Score</p>
                  </div>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="py-4">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-red-100 rounded-lg">
                    <AlertTriangle className="h-5 w-5 text-red-600" />
                  </div>
                  <div>
                    <p className="text-2xl font-bold text-red-600">{vulnerableCount}</p>
                    <p className="text-sm text-slate-600">Vulnerable</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          {reports.length === 0 ? (
            <Card>
              <CardContent className="py-12 text-center">
                <FileText className="h-12 w-12 mx-auto text-slate-400 mb-4" />
                <h3 className="text-lg font-medium mb-2">No CBOM reports yet</h3>
                <p className="text-slate-600">
                  Developers can use the CLI to scan projects and upload CBOM reports
                </p>
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardHeader>
                <CardTitle className="text-base">All CBOM Scans</CardTitle>
              </CardHeader>
              <CardContent className="p-0">
                <div className="divide-y">
                  {reports.map((report) => (
                    <Link key={report.id} href={`/cbom/${report.id}`}>
                      <div className="px-6 py-4 hover:bg-slate-50 transition-colors cursor-pointer">
                        <div className="flex items-center justify-between">
                          <div className="flex items-start gap-4">
                            <div className="mt-1">{getScoreIcon(report.quantumReadinessScore)}</div>
                            <div className="space-y-1">
                              <div className="flex items-center gap-2">
                                <h3 className="font-semibold">
                                  {report.scanName || report.scanPath || `Scan #${report.id}`}
                                </h3>
                                {getQuantumReadinessBadge(report.quantumReadinessScore)}
                                {report.hasPqc && (
                                  <Badge className="bg-purple-100 text-purple-800 hover:bg-purple-100">PQC</Badge>
                                )}
                              </div>
                              <div className="flex items-center gap-4 text-sm text-slate-500">
                                <span className="flex items-center gap-1">
                                  <Package className="h-3 w-3" />
                                  {report.libraryCount} libraries
                                </span>
                                <span>{report.algorithmCount} algorithms</span>
                                {report.gitBranch && (
                                  <span className="flex items-center gap-1">
                                    <GitBranch className="h-3 w-3" />
                                    {report.gitBranch}
                                  </span>
                                )}
                                {report.gitCommit && (
                                  <span className="flex items-center gap-1">
                                    <GitCommit className="h-3 w-3" />
                                    {report.gitCommit.substring(0, 7)}
                                  </span>
                                )}
                              </div>
                            </div>
                          </div>
                          <div className="flex items-center gap-6">
                            <div className="text-right">
                              <p className={`text-lg font-bold ${getScoreColor(report.quantumReadinessScore)}`}>
                                {report.quantumReadinessScore}%
                              </p>
                              <p className="text-xs text-slate-500">Quantum Score</p>
                            </div>
                            <div className="text-right text-sm text-slate-500">
                              <div className="flex items-center gap-1 justify-end">
                                <Clock className="h-3 w-3" />
                                <span>{formatDate(report.scannedAt)}</span>
                              </div>
                            </div>
                            <ChevronRight className="h-5 w-5 text-slate-400" />
                          </div>
                        </div>
                      </div>
                    </Link>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </AdminLayout>
  );
}
