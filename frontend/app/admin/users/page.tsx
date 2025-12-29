"use client";

import { useEffect, useState, useCallback } from "react";
import { Shield, ShieldOff, ExternalLink } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { AdminLayout } from "@/components/admin-layout";
import { SearchInput } from "@/components/ui/search-input";
import { DataTable } from "@/components/ui/data-table";
import { api, AdminUserSummary } from "@/lib/api";
import { cn } from "@/lib/utils";

export default function AdminUsersPage() {
  const [users, setUsers] = useState<AdminUserSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);
  const [hasMore, setHasMore] = useState(true);
  const pageSize = 25;

  const loadUsers = useCallback(async () => {
    try {
      setLoading(true);
      const data = await api.listAllUsers({
        search: search || undefined,
        limit: pageSize,
        offset: page * pageSize,
      });
      setUsers(data);
      setHasMore(data.length === pageSize);
    } catch (error) {
      console.error("Failed to load users:", error);
    } finally {
      setLoading(false);
    }
  }, [search, page]);

  useEffect(() => {
    loadUsers();
  }, [loadUsers]);

  const handleSearchChange = (value: string) => {
    setSearch(value);
    setPage(0);
  };

  const formatDate = (dateStr: string | null) => {
    if (!dateStr) return "Never";
    const date = new Date(dateStr);
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const hours = Math.floor(diff / (1000 * 60 * 60));
    const days = Math.floor(diff / (1000 * 60 * 60 * 24));

    if (hours < 1) return "Just now";
    if (hours < 24) return `${hours}h ago`;
    if (days < 7) return `${days}d ago`;
    return date.toLocaleDateString();
  };

  const columns = [
    {
      key: "avatar",
      header: "",
      className: "w-12",
      render: (user: AdminUserSummary) => (
        <div className="flex items-center justify-center">
          {user.avatar_url ? (
            <img
              src={user.avatar_url}
              alt={user.github_username}
              className="h-8 w-8 rounded-full"
            />
          ) : (
            <div className="h-8 w-8 rounded-full bg-slate-200 flex items-center justify-center text-slate-600 text-sm font-medium">
              {user.github_username[0].toUpperCase()}
            </div>
          )}
        </div>
      ),
    },
    {
      key: "github_username",
      header: "Username",
      sortable: true,
      render: (user: AdminUserSummary) => (
        <div className="flex items-center gap-2">
          <span className="font-medium">@{user.github_username}</span>
          {user.is_admin && (
            <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-blue-100 text-blue-700">
              Admin
            </span>
          )}
        </div>
      ),
    },
    {
      key: "email",
      header: "Email",
      sortable: true,
      render: (user: AdminUserSummary) => (
        <span className="text-slate-600">{user.email || "-"}</span>
      ),
    },
    {
      key: "identity_count",
      header: "Identities",
      sortable: true,
      className: "text-center",
      render: (user: AdminUserSummary) => (
        <span className={cn(
          "px-2 py-1 rounded text-xs font-medium",
          user.identity_count > 0
            ? "bg-green-100 text-green-700"
            : "bg-slate-100 text-slate-600"
        )}>
          {user.identity_count}
        </span>
      ),
    },
    {
      key: "operation_count",
      header: "Operations",
      sortable: true,
      className: "text-right",
      render: (user: AdminUserSummary) => (
        <span className="tabular-nums">
          {user.operation_count.toLocaleString()}
        </span>
      ),
    },
    {
      key: "last_login_at",
      header: "Last Active",
      sortable: true,
      render: (user: AdminUserSummary) => (
        <span className="text-slate-600">
          {formatDate(user.last_login_at)}
        </span>
      ),
    },
    {
      key: "created_at",
      header: "Joined",
      sortable: true,
      render: (user: AdminUserSummary) => (
        <span className="text-slate-500 text-xs">
          {new Date(user.created_at).toLocaleDateString()}
        </span>
      ),
    },
  ];

  return (
    <AdminLayout
      title="User Management"
      subtitle={`${users.length} users${search ? ` matching "${search}"` : ""}`}
      onRefresh={loadUsers}
    >
      {/* Search */}
      <div className="mb-6 flex items-center gap-4">
        <SearchInput
          placeholder="Search users by username or email..."
          value={search}
          onChange={handleSearchChange}
          className="max-w-md"
        />
      </div>

      {/* Users Table */}
      <Card>
        <CardContent className="p-0">
          <DataTable
            data={users}
            columns={columns}
            keyField="id"
            loading={loading}
            emptyMessage={search ? `No users found matching "${search}"` : "No users yet"}
          />
        </CardContent>
      </Card>

      {/* Pagination */}
      {(page > 0 || hasMore) && (
        <div className="mt-4 flex items-center justify-between">
          <p className="text-sm text-slate-500">
            Showing {page * pageSize + 1} - {page * pageSize + users.length} users
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
