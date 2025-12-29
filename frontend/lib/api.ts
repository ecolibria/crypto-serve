const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

async function fetchApi(endpoint: string, options: RequestInit = {}) {
  const response = await fetch(`${API_URL}${endpoint}`, {
    ...options,
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      ...options.headers,
    },
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: "Request failed" }));
    throw new Error(error.detail || "Request failed");
  }

  return response.json();
}

export interface User {
  id: string;
  github_username: string;
  email: string | null;
  avatar_url: string | null;
}

export interface Context {
  name: string;
  display_name: string;
  description: string;
  data_examples: string[] | null;
  compliance_tags: string[] | null;
  algorithm: string;
}

export interface Identity {
  id: string;
  type: "developer" | "service";
  name: string;
  team: string;
  environment: string;
  allowed_contexts: string[];
  status: "active" | "expired" | "revoked";
  created_at: string;
  expires_at: string;
  last_used_at: string | null;
}

export interface IdentityCreateResponse {
  identity: Identity;
  token: string;
  sdk_download_url: string;
}

export interface AuditLog {
  id: string;
  timestamp: string;
  operation: string;
  context: string;
  success: boolean;
  error_message: string | null;
  identity_id: string;
  identity_name: string | null;
  team: string | null;
  input_size_bytes: number | null;
  output_size_bytes: number | null;
  latency_ms: number | null;
}

export interface AuditStats {
  total_operations: number;
  successful_operations: number;
  failed_operations: number;
  operations_by_context: Record<string, number>;
  operations_by_identity: Record<string, number>;
}

export const api = {
  // User
  getCurrentUser: () => fetchApi("/api/users/me") as Promise<User>,

  // Contexts
  listContexts: () => fetchApi("/api/contexts") as Promise<Context[]>,

  // Identities
  listIdentities: () => fetchApi("/api/identities") as Promise<Identity[]>,
  createIdentity: (data: {
    name: string;
    type: "developer" | "service";
    team: string;
    environment: string;
    allowed_contexts: string[];
    expires_in_days: number;
  }) =>
    fetchApi("/api/identities", {
      method: "POST",
      body: JSON.stringify(data),
    }) as Promise<IdentityCreateResponse>,
  revokeIdentity: (id: string) =>
    fetchApi(`/api/identities/${id}`, { method: "DELETE" }),

  // Audit
  listAuditLogs: (params?: {
    identity_id?: string;
    context?: string;
    success?: boolean;
    limit?: number;
  }) => {
    const query = new URLSearchParams();
    if (params?.identity_id) query.set("identity_id", params.identity_id);
    if (params?.context) query.set("context", params.context);
    if (params?.success !== undefined)
      query.set("success", String(params.success));
    if (params?.limit) query.set("limit", String(params.limit));
    return fetchApi(`/api/audit?${query}`) as Promise<AuditLog[]>;
  },
  getAuditStats: () => fetchApi("/api/audit/stats") as Promise<AuditStats>,

  // Auth
  getLoginUrl: () => `${API_URL}/auth/github`,
  logout: () => fetchApi("/auth/logout", { method: "POST" }),
};
