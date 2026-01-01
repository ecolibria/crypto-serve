"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import {
  ArrowLeft, Shield, AlertTriangle, CheckCircle, Package,
  GitBranch, GitCommit, Clock, FileText, Lock, Unlock,
  Download
} from "lucide-react";
import { DashboardLayout } from "@/components/dashboard-layout";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { api, CBOMReportDetail } from "@/lib/api";

export default function CBOMDetailPage() {
  const params = useParams();
  const router = useRouter();
  const [report, setReport] = useState<CBOMReportDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const reportId = parseInt(params.id as string);
    if (isNaN(reportId)) {
      setError("Invalid report ID");
      setLoading(false);
      return;
    }

    api.getCBOMReport(reportId)
      .then(setReport)
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, [params.id]);

  const getQuantumRiskBadge = (risk?: string) => {
    switch (risk?.toLowerCase()) {
      case "high":
      case "critical":
        return <Badge className="bg-red-100 text-red-800 hover:bg-red-100">High Risk</Badge>;
      case "low":
        return <Badge className="bg-yellow-100 text-yellow-800 hover:bg-yellow-100">Low Risk</Badge>;
      case "none":
        return <Badge className="bg-green-100 text-green-800 hover:bg-green-100">Quantum Safe</Badge>;
      default:
        return <Badge className="bg-gray-100 text-gray-800 hover:bg-gray-100">Unknown</Badge>;
    }
  };

  const getScoreColor = (score: number) => {
    if (score >= 80) return "text-green-600";
    if (score >= 50) return "text-yellow-600";
    return "text-red-600";
  };

  const getScoreBgColor = (score: number) => {
    if (score >= 80) return "bg-green-100";
    if (score >= 50) return "bg-yellow-100";
    return "bg-red-100";
  };

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleString();
  };

  const handleDownloadCBOM = () => {
    if (!report?.cbomData) return;

    const blob = new Blob([JSON.stringify(report.cbomData, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `cbom-${report.id}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  if (loading) {
    return (
      <DashboardLayout>
        <div className="flex justify-center py-12">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
        </div>
      </DashboardLayout>
    );
  }

  if (error || !report) {
    return (
      <DashboardLayout>
        <div className="space-y-4">
          <Link href="/cbom">
            <Button variant="ghost" size="sm">
              <ArrowLeft className="h-4 w-4 mr-2" />
              Back to CBOM Reports
            </Button>
          </Link>
          <Card>
            <CardContent className="py-12 text-center">
              <AlertTriangle className="h-12 w-12 mx-auto text-red-400 mb-4" />
              <h3 className="text-lg font-medium mb-2">Report Not Found</h3>
              <p className="text-slate-600">{error || "The requested CBOM report could not be found."}</p>
            </CardContent>
          </Card>
        </div>
      </DashboardLayout>
    );
  }

  return (
    <DashboardLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Link href="/cbom">
              <Button variant="ghost" size="sm">
                <ArrowLeft className="h-4 w-4 mr-2" />
                Back
              </Button>
            </Link>
            <div>
              <h1 className="text-2xl font-bold">
                {report.scanName || report.scanPath || `CBOM Report #${report.id}`}
              </h1>
              <p className="text-slate-600 flex items-center gap-2 mt-1">
                <Clock className="h-4 w-4" />
                Scanned {formatDate(report.scannedAt)}
              </p>
            </div>
          </div>
          {report.cbomData && (
            <Button variant="outline" onClick={handleDownloadCBOM}>
              <Download className="h-4 w-4 mr-2" />
              Download CBOM
            </Button>
          )}
        </div>

        {/* Quantum Readiness Score */}
        <Card>
          <CardContent className="py-6">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-6">
                <div className={`p-4 rounded-full ${getScoreBgColor(report.quantumReadinessScore)}`}>
                  {report.quantumReadinessScore >= 80 ? (
                    <Shield className={`h-8 w-8 ${getScoreColor(report.quantumReadinessScore)}`} />
                  ) : (
                    <AlertTriangle className={`h-8 w-8 ${getScoreColor(report.quantumReadinessScore)}`} />
                  )}
                </div>
                <div>
                  <p className={`text-4xl font-bold ${getScoreColor(report.quantumReadinessScore)}`}>
                    {report.quantumReadinessScore}%
                  </p>
                  <p className="text-slate-600">Quantum Readiness Score</p>
                </div>
              </div>
              <div className="grid grid-cols-4 gap-8 text-center">
                <div>
                  <p className="text-2xl font-bold">{report.metrics.libraryCount}</p>
                  <p className="text-sm text-slate-600">Libraries</p>
                </div>
                <div>
                  <p className="text-2xl font-bold">{report.metrics.algorithmCount}</p>
                  <p className="text-sm text-slate-600">Algorithms</p>
                </div>
                <div>
                  <p className="text-2xl font-bold text-green-600">{report.metrics.quantumSafeCount}</p>
                  <p className="text-sm text-slate-600">Quantum Safe</p>
                </div>
                <div>
                  <p className="text-2xl font-bold text-red-600">{report.metrics.quantumVulnerableCount}</p>
                  <p className="text-sm text-slate-600">Vulnerable</p>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Git Info */}
        {(report.git.commit || report.git.branch || report.git.repo) && (
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Git Information</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex gap-6 text-sm">
                {report.git.repo && (
                  <div className="flex items-center gap-2">
                    <FileText className="h-4 w-4 text-slate-400" />
                    <span className="text-slate-600">Repository:</span>
                    <span className="font-mono">{report.git.repo}</span>
                  </div>
                )}
                {report.git.branch && (
                  <div className="flex items-center gap-2">
                    <GitBranch className="h-4 w-4 text-slate-400" />
                    <span className="text-slate-600">Branch:</span>
                    <span className="font-mono">{report.git.branch}</span>
                  </div>
                )}
                {report.git.commit && (
                  <div className="flex items-center gap-2">
                    <GitCommit className="h-4 w-4 text-slate-400" />
                    <span className="text-slate-600">Commit:</span>
                    <span className="font-mono">{report.git.commit}</span>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Libraries */}
        {report.libraries.length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Package className="h-5 w-5" />
                Cryptographic Libraries ({report.libraries.length})
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {report.libraries.map((lib, idx) => (
                  <div key={idx} className="flex items-center justify-between py-2 border-b last:border-0">
                    <div className="flex items-center gap-3">
                      <div className="p-1.5 bg-slate-100 rounded">
                        <Package className="h-4 w-4 text-slate-600" />
                      </div>
                      <div>
                        <p className="font-medium">
                          {lib.name}
                          {lib.version && <span className="text-slate-500 ml-1">v{lib.version}</span>}
                        </p>
                        <p className="text-sm text-slate-500">{lib.category}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      {lib.isDeprecated && (
                        <Badge variant="outline" className="text-orange-600 border-orange-200">Deprecated</Badge>
                      )}
                      {lib.quantumRisk && getQuantumRiskBadge(lib.quantumRisk)}
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Algorithms */}
        {report.algorithms.length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Lock className="h-5 w-5" />
                Detected Algorithms ({report.algorithms.length})
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                {report.algorithms.map((algo, idx) => (
                  <div key={idx} className="flex items-center gap-3 p-3 bg-slate-50 rounded-lg">
                    <Lock className="h-4 w-4 text-slate-500" />
                    <div>
                      <p className="font-medium">{algo.name}</p>
                      <p className="text-xs text-slate-500">
                        {algo.category}
                        {algo.library && ` - ${algo.library}`}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Metrics Summary */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Additional Metrics</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="p-4 bg-slate-50 rounded-lg text-center">
                <p className="text-2xl font-bold">{report.metrics.deprecatedCount}</p>
                <p className="text-sm text-slate-600">Deprecated</p>
              </div>
              <div className="p-4 bg-slate-50 rounded-lg text-center">
                <div className="flex items-center justify-center gap-1">
                  {report.metrics.hasPqc ? (
                    <CheckCircle className="h-5 w-5 text-green-500" />
                  ) : (
                    <Unlock className="h-5 w-5 text-slate-400" />
                  )}
                </div>
                <p className="text-sm text-slate-600 mt-1">
                  {report.metrics.hasPqc ? "PQC Enabled" : "No PQC"}
                </p>
              </div>
              <div className="p-4 bg-slate-50 rounded-lg text-center">
                <p className="text-2xl font-bold text-green-600">{report.metrics.quantumSafeCount}</p>
                <p className="text-sm text-slate-600">Safe Algorithms</p>
              </div>
              <div className="p-4 bg-slate-50 rounded-lg text-center">
                <p className="text-2xl font-bold text-red-600">{report.metrics.quantumVulnerableCount}</p>
                <p className="text-sm text-slate-600">Vulnerable Algorithms</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  );
}
