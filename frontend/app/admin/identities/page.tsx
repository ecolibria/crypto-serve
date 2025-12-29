"use client";

import { useEffect, useState, useCallback } from "react";
import { Key, Ban, Clock, CheckCircle2, XCircle, AlertTriangle } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { AdminLayout } from "@/components/admin-layout";
import { SearchInput } from "@/components/ui/search-input";
import { DataTable } from "@/components/ui/data-table";
import { api, AdminIdentitySummary } from "@/lib/api";
import { cn } from "@/lib/utils";

type StatusFilter = "all" | "active" | "expired" | "revoked" | "expiring";

export default function AdminIdentitiesPage() {
  const [identities, setIdentities] = useState<AdminIdentitySummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [page, setPage] = useState(0);
  const [hasMore, setHasMore] = useState(true);
  const [revoking, setRevoking] = useState<string | null>(null);
  const pageSize = 25;

  const loadIdentities = useCallback(async () => {
    try {
      setLoading(true);
      const data = await api.listAllIdentities({
        search: search || undefined,
        status: statusFilter === "all" ? undefined : statusFilter,
        limit: pageSize,
        offset: page * pageSize,
      });
      setIdentities(data);
      setHasMore(data.length === pageSize);
    } catch (error) {
      console.error("Failed to load identities:", error);
    } finally {
      setLoading(false);
    }
  }, [search, statusFilter, page]);

  useEffect(() => {
    loadIdentities();
  }, [loadIdentities]);

  const handleSearchChange = (value: string) => {
    setSearch(value);
    setPage(0);
  };

  const handleStatusChange = (status: StatusFilter) => {
    setStatusFilter(status);
    setPage(0);
  };

  const handleRevoke = async (identityId: string) => {
    if (!confirm("Are you sure you want to revoke this identity? This action cannot be undone.")) {
      return;
    }
    setRevoking(identityId);
    try {
      await api.adminRevokeIdentity(identityId);
      await loadIdentities();
    } catch (error) {
      console.error("Failed to revoke identity:", error);
      alert("Failed to revoke identity");
    } finally {
      setRevoking(null);
    }
  };

  const getStatusBadge = (status: string, expiresAt: string) => {
    const now = new Date();
    const expires = new Date(expiresAt);
    const daysUntilExpiry = Math.ceil((expires.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
    const isExpiringSoon = status === "active" && daysUntilExpiry <= 7 && daysUntilExpiry > 0;

    if (isExpiringSoon) {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium bg-amber-100 text-amber-700">
          <AlertTriangle className="h-3 w-3" />
          Expires in {daysUntilExpiry}d
        </span>
      );
    }

    switch (status) {
      case "active":
        return (
          <span className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium bg-green-100 text-green-700">
            <CheckCircle2 className="h-3 w-3" />
            Active
          </span>
        );
      case "expired":
        return (
          <span className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium bg-slate-100 text-slate-600">
            <Clock className="h-3 w-3" />
            Expired
          </span>
        );
      case "revoked":
        return (
          <span className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium bg-red-100 text-red-700">
            <XCircle className="h-3 w-3" />
            Revoked
          </span>
        );
      default:
        return (
          <span className="px-2 py-1 rounded text-xs font-medium bg-slate-100 text-slate-600">
            {status}
          </span>
        );
    }
  };

  const formatDate = (dateStr: string | null) => {
    if (!dateStr) return "-";
    return new Date(dateStr).toLocaleDateString();
  };

  const columns = [
    {
      key: "name",
      header: "Identity",
      sortable: true,
      render: (identity: AdminIdentitySummary) => (
        <div>
          <p className="font-medium">{identity.name}</p>
          <p className="text-xs text-slate-500">
            by @{identity.user_name}
          </p>
        </div>
      ),
    },
    {
      key: "team",
      header: "Team",
      sortable: true,
      render: (identity: AdminIdentitySummary) => (
        <span className="text-slate-600">{identity.team}</span>
      ),
    },
    {
      key: "type",
      header: "Type",
      render: (identity: AdminIdentitySummary) => (
        <span className={cn(
          "px-2 py-1 rounded text-xs font-medium",
          identity.type === "service"
            ? "bg-purple-100 text-purple-700"
            : "bg-blue-100 text-blue-700"
        )}>
          {identity.type}
        </span>
      ),
    },
    {
      key: "environment",
      header: "Env",
      render: (identity: AdminIdentitySummary) => (
        <span className={cn(
          "px-2 py-1 rounded text-xs font-medium",
          identity.environment === "production"
            ? "bg-red-50 text-red-700"
            : identity.environment === "staging"
            ? "bg-amber-50 text-amber-700"
            : "bg-slate-100 text-slate-600"
        )}>
          {identity.environment}
        </span>
      ),
    },
    {
      key: "allowed_contexts",
      header: "Contexts",
      render: (identity: AdminIdentitySummary) => (
        <div className="flex flex-wrap gap-1">
          {identity.allowed_contexts.slice(0, 2).map((ctx) => (
            <span
              key={ctx}
              className="px-1.5 py-0.5 rounded text-[10px] bg-slate-100 text-slate-600"
            >
              {ctx}
            </span>
          ))}
          {identity.allowed_contexts.length > 2 && (
            <span className="px-1.5 py-0.5 rounded text-[10px] bg-slate-100 text-slate-600">
              +{identity.allowed_contexts.length - 2}
            </span>
          )}
        </div>
      ),
    },
    {
      key: "status",
      header: "Status",
      sortable: true,
      render: (identity: AdminIdentitySummary) => getStatusBadge(identity.status, identity.expires_at),
    },
    {
      key: "operation_count",
      header: "Ops",
      sortable: true,
      className: "text-right",
      render: (identity: AdminIdentitySummary) => (
        <span className="tabular-nums">
          {identity.operation_count.toLocaleString()}
        </span>
      ),
    },
    {
      key: "expires_at",
      header: "Expires",
      sortable: true,
      render: (identity: AdminIdentitySummary) => (
        <span className="text-xs text-slate-500">
          {formatDate(identity.expires_at)}
        </span>
      ),
    },
    {
      key: "actions",
      header: "",
      className: "w-20",
      render: (identity: AdminIdentitySummary) => (
        identity.status === "active" ? (
          <Button
            variant="ghost"
            size="sm"
            onClick={(e) => {
              e.stopPropagation();
              handleRevoke(identity.id);
            }}
            disabled={revoking === identity.id}
            className="text-red-600 hover:text-red-700 hover:bg-red-50"
          >
            {revoking === identity.id ? (
              <span className="animate-spin h-4 w-4 border-2 border-red-600 border-t-transparent rounded-full" />
            ) : (
              <Ban className="h-4 w-4" />
            )}
          </Button>
        ) : null
      ),
    },
  ];

  const statusFilters: { value: StatusFilter; label: string }[] = [
    { value: "all", label: "All" },
    { value: "active", label: "Active" },
    { value: "expiring", label: "Expiring Soon" },
    { value: "expired", label: "Expired" },
    { value: "revoked", label: "Revoked" },
  ];

  return (
    <AdminLayout
      title="Identity Management"
      subtitle={`${identities.length} identities${search ? ` matching "${search}"` : ""}`}
      onRefresh={loadIdentities}
    >
      {/* Filters */}
      <div className="mb-6 flex flex-col sm:flex-row items-start sm:items-center gap-4">
        <SearchInput
          placeholder="Search by name, team, or ID..."
          value={search}
          onChange={handleSearchChange}
          className="w-full sm:max-w-md"
        />
        <div className="flex gap-2 flex-wrap">
          {statusFilters.map((filter) => (
            <button
              key={filter.value}
              onClick={() => handleStatusChange(filter.value)}
              className={cn(
                "px-3 py-1.5 rounded-lg text-sm font-medium transition-colors",
                statusFilter === filter.value
                  ? "bg-slate-900 text-white"
                  : "bg-slate-100 text-slate-600 hover:bg-slate-200"
              )}
            >
              {filter.label}
            </button>
          ))}
        </div>
      </div>

      {/* Identities Table */}
      <Card>
        <CardContent className="p-0">
          <DataTable
            data={identities}
            columns={columns}
            keyField="id"
            loading={loading}
            emptyMessage={search ? `No identities found matching "${search}"` : "No identities yet"}
          />
        </CardContent>
      </Card>

      {/* Pagination */}
      {(page > 0 || hasMore) && (
        <div className="mt-4 flex items-center justify-between">
          <p className="text-sm text-slate-500">
            Showing {page * pageSize + 1} - {page * pageSize + identities.length} identities
          </p>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setPage(p => p - 1)}
              disabled={page === 0}
            >
              Previous
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setPage(p => p + 1)}
              disabled={!hasMore}
            >
              Next
            </Button>
          </div>
        </div>
      )}
    </AdminLayout>
  );
}
