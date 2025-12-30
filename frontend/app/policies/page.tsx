"use client";

import { useEffect, useState } from "react";
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  Info,
  AlertTriangle,
  Ban,
  CheckCircle2,
  XCircle,
  Play,
  ChevronDown,
} from "lucide-react";
import { DashboardLayout } from "@/components/dashboard-layout";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  api,
  Policy,
  PolicyEvaluationRequest,
  PolicyEvaluationResponse,
  Context,
} from "@/lib/api";
import { cn } from "@/lib/utils";

type SeverityFilter = "all" | "block" | "warn" | "info";

export default function PoliciesPage() {
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [defaultPolicies, setDefaultPolicies] = useState<Policy[]>([]);
  const [contexts, setContexts] = useState<Context[]>([]);
  const [loading, setLoading] = useState(true);
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("all");
  const [showEvaluator, setShowEvaluator] = useState(false);

  // Evaluation state
  const [evalAlgorithm, setEvalAlgorithm] = useState("AES-256-GCM");
  const [evalContext, setEvalContext] = useState("");
  const [evalSensitivity, setEvalSensitivity] = useState<"low" | "medium" | "high" | "critical">("medium");
  const [evalPii, setEvalPii] = useState(false);
  const [evalPhi, setEvalPhi] = useState(false);
  const [evalPci, setEvalPci] = useState(false);
  const [evalResult, setEvalResult] = useState<PolicyEvaluationResponse | null>(null);
  const [evaluating, setEvaluating] = useState(false);

  useEffect(() => {
    Promise.all([
      api.listPolicies(),
      api.getDefaultPolicies(),
      api.listContexts(),
    ])
      .then(([p, dp, c]) => {
        setPolicies(p);
        setDefaultPolicies(dp);
        setContexts(c);
        if (c.length > 0) setEvalContext(c[0].name);
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  const allPolicies = [...defaultPolicies, ...policies];
  const filteredPolicies =
    severityFilter === "all"
      ? allPolicies
      : allPolicies.filter((p) => p.severity === severityFilter);

  const handleEvaluate = async () => {
    if (!evalContext) return;
    setEvaluating(true);
    try {
      const result = await api.evaluatePolicies({
        algorithm: evalAlgorithm,
        context_name: evalContext,
        sensitivity: evalSensitivity,
        pii: evalPii,
        phi: evalPhi,
        pci: evalPci,
        operation: "encrypt",
      });
      setEvalResult(result);
    } catch (error) {
      console.error("Evaluation failed:", error);
    } finally {
      setEvaluating(false);
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case "block":
        return <Ban className="h-4 w-4 text-red-500" />;
      case "warn":
        return <AlertTriangle className="h-4 w-4 text-amber-500" />;
      default:
        return <Info className="h-4 w-4 text-blue-500" />;
    }
  };

  const getSeverityBadge = (severity: string) => {
    const styles: Record<string, string> = {
      block: "bg-red-100 text-red-700",
      warn: "bg-amber-100 text-amber-700",
      info: "bg-blue-100 text-blue-700",
    };
    return (
      <span className={cn("px-2 py-0.5 rounded text-xs font-medium", styles[severity] || styles.info)}>
        {severity}
      </span>
    );
  };

  const blockCount = allPolicies.filter((p) => p.severity === "block" && p.enabled).length;
  const warnCount = allPolicies.filter((p) => p.severity === "warn" && p.enabled).length;
  const infoCount = allPolicies.filter((p) => p.severity === "info" && p.enabled).length;

  return (
    <DashboardLayout>
      <div className="space-y-8">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold">Policies</h1>
            <p className="text-slate-600">
              Cryptographic policies that govern algorithm usage
            </p>
          </div>
          <Button
            variant={showEvaluator ? "default" : "outline"}
            onClick={() => setShowEvaluator(!showEvaluator)}
          >
            <Play className="h-4 w-4 mr-2" />
            Test Policies
          </Button>
        </div>

        {loading ? (
          <div className="flex justify-center py-12">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
          </div>
        ) : (
          <>
            {/* Policy Evaluator */}
            {showEvaluator && (
              <Card className="border-2 border-primary/20">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Shield className="h-5 w-5" />
                    Policy Evaluator
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p className="text-sm text-slate-600">
                    Test how policies will evaluate for a given algorithm and context configuration.
                  </p>

                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                    {/* Algorithm */}
                    <div>
                      <label className="text-sm font-medium text-slate-700 block mb-1">
                        Algorithm
                      </label>
                      <select
                        value={evalAlgorithm}
                        onChange={(e) => setEvalAlgorithm(e.target.value)}
                        className="w-full px-3 py-2 border rounded-md text-sm"
                      >
                        <option value="AES-256-GCM">AES-256-GCM</option>
                        <option value="AES-128-GCM">AES-128-GCM</option>
                        <option value="ChaCha20-Poly1305">ChaCha20-Poly1305</option>
                        <option value="CRYSTALS-Kyber">CRYSTALS-Kyber (PQC)</option>
                      </select>
                    </div>

                    {/* Context */}
                    <div>
                      <label className="text-sm font-medium text-slate-700 block mb-1">
                        Context
                      </label>
                      <select
                        value={evalContext}
                        onChange={(e) => setEvalContext(e.target.value)}
                        className="w-full px-3 py-2 border rounded-md text-sm"
                      >
                        {contexts.map((ctx) => (
                          <option key={ctx.name} value={ctx.name}>
                            {ctx.display_name}
                          </option>
                        ))}
                      </select>
                    </div>

                    {/* Sensitivity */}
                    <div>
                      <label className="text-sm font-medium text-slate-700 block mb-1">
                        Sensitivity
                      </label>
                      <select
                        value={evalSensitivity}
                        onChange={(e) => setEvalSensitivity(e.target.value as any)}
                        className="w-full px-3 py-2 border rounded-md text-sm"
                      >
                        <option value="low">Low</option>
                        <option value="medium">Medium</option>
                        <option value="high">High</option>
                        <option value="critical">Critical</option>
                      </select>
                    </div>

                    {/* Data Types */}
                    <div>
                      <label className="text-sm font-medium text-slate-700 block mb-1">
                        Data Types
                      </label>
                      <div className="flex gap-4">
                        <label className="flex items-center gap-1 text-sm">
                          <input
                            type="checkbox"
                            checked={evalPii}
                            onChange={(e) => setEvalPii(e.target.checked)}
                            className="rounded"
                          />
                          PII
                        </label>
                        <label className="flex items-center gap-1 text-sm">
                          <input
                            type="checkbox"
                            checked={evalPhi}
                            onChange={(e) => setEvalPhi(e.target.checked)}
                            className="rounded"
                          />
                          PHI
                        </label>
                        <label className="flex items-center gap-1 text-sm">
                          <input
                            type="checkbox"
                            checked={evalPci}
                            onChange={(e) => setEvalPci(e.target.checked)}
                            className="rounded"
                          />
                          PCI
                        </label>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-4">
                    <Button onClick={handleEvaluate} disabled={evaluating || !evalContext}>
                      {evaluating ? (
                        <span className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full mr-2" />
                      ) : (
                        <Play className="h-4 w-4 mr-2" />
                      )}
                      Evaluate
                    </Button>

                    {evalResult && (
                      <div className="flex items-center gap-3">
                        {evalResult.allowed ? (
                          <div className="flex items-center gap-2 text-green-600">
                            <CheckCircle2 className="h-5 w-5" />
                            <span className="font-medium">Allowed</span>
                          </div>
                        ) : (
                          <div className="flex items-center gap-2 text-red-600">
                            <XCircle className="h-5 w-5" />
                            <span className="font-medium">Blocked</span>
                          </div>
                        )}
                        <span className="text-sm text-slate-500">
                          {evalResult.blocking_violations} blocking, {evalResult.warning_violations} warnings
                        </span>
                      </div>
                    )}
                  </div>

                  {/* Evaluation Results */}
                  {evalResult && evalResult.results.length > 0 && (
                    <div className="mt-4 border rounded-lg overflow-hidden">
                      <table className="w-full text-sm">
                        <thead className="bg-slate-50">
                          <tr>
                            <th className="px-4 py-2 text-left font-medium text-slate-600">Policy</th>
                            <th className="px-4 py-2 text-left font-medium text-slate-600">Result</th>
                            <th className="px-4 py-2 text-left font-medium text-slate-600">Severity</th>
                            <th className="px-4 py-2 text-left font-medium text-slate-600">Message</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y">
                          {evalResult.results.map((r, i) => (
                            <tr key={i} className={cn(!r.passed && "bg-red-50/50")}>
                              <td className="px-4 py-2 font-mono text-xs">{r.policy_name}</td>
                              <td className="px-4 py-2">
                                {r.passed ? (
                                  <CheckCircle2 className="h-4 w-4 text-green-500" />
                                ) : (
                                  <XCircle className="h-4 w-4 text-red-500" />
                                )}
                              </td>
                              <td className="px-4 py-2">{getSeverityBadge(r.severity)}</td>
                              <td className="px-4 py-2 text-slate-600">{r.message || "-"}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </CardContent>
              </Card>
            )}

            {/* Stats */}
            <div className="grid gap-4 md:grid-cols-4">
              <Card>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">Total Policies</CardTitle>
                  <Shield className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{allPolicies.length}</div>
                  <p className="text-xs text-muted-foreground">
                    {defaultPolicies.length} default, {policies.length} custom
                  </p>
                </CardContent>
              </Card>

              <Card
                className={cn("cursor-pointer transition-colors", severityFilter === "block" && "ring-2 ring-red-500")}
                onClick={() => setSeverityFilter(severityFilter === "block" ? "all" : "block")}
              >
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">Blocking</CardTitle>
                  <Ban className="h-4 w-4 text-red-500" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{blockCount}</div>
                  <p className="text-xs text-muted-foreground">Will prevent operations</p>
                </CardContent>
              </Card>

              <Card
                className={cn("cursor-pointer transition-colors", severityFilter === "warn" && "ring-2 ring-amber-500")}
                onClick={() => setSeverityFilter(severityFilter === "warn" ? "all" : "warn")}
              >
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">Warnings</CardTitle>
                  <AlertTriangle className="h-4 w-4 text-amber-500" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{warnCount}</div>
                  <p className="text-xs text-muted-foreground">Logged but allowed</p>
                </CardContent>
              </Card>

              <Card
                className={cn("cursor-pointer transition-colors", severityFilter === "info" && "ring-2 ring-blue-500")}
                onClick={() => setSeverityFilter(severityFilter === "info" ? "all" : "info")}
              >
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">Informational</CardTitle>
                  <Info className="h-4 w-4 text-blue-500" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{infoCount}</div>
                  <p className="text-xs text-muted-foreground">For monitoring</p>
                </CardContent>
              </Card>
            </div>

            {/* Policy List */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center justify-between">
                  <span>
                    {severityFilter === "all" ? "All Policies" : `${severityFilter.charAt(0).toUpperCase() + severityFilter.slice(1)} Policies`}
                  </span>
                  {severityFilter !== "all" && (
                    <Button variant="ghost" size="sm" onClick={() => setSeverityFilter("all")}>
                      Clear filter
                    </Button>
                  )}
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {filteredPolicies.map((policy) => (
                    <div
                      key={policy.name}
                      className={cn(
                        "p-4 border rounded-lg",
                        !policy.enabled && "opacity-50"
                      )}
                    >
                      <div className="flex items-start justify-between">
                        <div className="flex items-start gap-3">
                          {getSeverityIcon(policy.severity)}
                          <div>
                            <div className="flex items-center gap-2">
                              <h3 className="font-medium">{policy.name}</h3>
                              {getSeverityBadge(policy.severity)}
                              {!policy.enabled && (
                                <span className="px-2 py-0.5 rounded text-xs font-medium bg-slate-100 text-slate-600">
                                  disabled
                                </span>
                              )}
                            </div>
                            <p className="text-sm text-slate-600 mt-1">
                              {policy.description}
                            </p>
                            <p className="text-xs font-mono text-slate-400 mt-2">
                              {policy.rule}
                            </p>
                          </div>
                        </div>
                        {policy.contexts.length > 0 && (
                          <div className="flex flex-wrap gap-1">
                            {policy.contexts.map((ctx) => (
                              <span
                                key={ctx}
                                className="px-1.5 py-0.5 rounded text-[10px] bg-slate-100 text-slate-600"
                              >
                                {ctx}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  ))}

                  {filteredPolicies.length === 0 && (
                    <div className="text-center py-8 text-slate-500">
                      No policies found with this filter
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          </>
        )}
      </div>
    </DashboardLayout>
  );
}
