/**
 * Typed API client for DevPilot backend.
 * All authenticated requests use credentials: "include" so the browser
 * automatically sends the HttpOnly devpilot_token cookie.
 * JWT is never read or stored by JavaScript.
 */

const API_BASE =
  process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

// ─── Response types ────────────────────────────────────────────────────────

export interface User {
  id: string;
  email: string;
  name: string | null;
}

export interface Project {
  id: string;
  name: string;
  user_id: string;
}

export interface Repository {
  id: string;
  name: string;
  url: string;
  project_id: string;
}

export interface Scan {
  id: string;
  repository_id: string;
  status: "pending" | "running" | "completed" | "failed";
  started_at: string | null;
  completed_at: string | null;
}

export interface ScanSummary {
  scan_id: string;
  status: string;
  total_findings: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface Finding {
  id: string;
  scan_id: string;
  severity: "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  file_path: string | null;
  line_number: number | null;
}

// ─── Error type ────────────────────────────────────────────────────────────

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

// ─── Core fetch wrapper ────────────────────────────────────────────────────

async function request<T>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      ...(init.headers ?? {}),
    },
  });

  if (response.status === 204) {
    return undefined as T;
  }

  const body = await response.json().catch(() => ({ detail: response.statusText }));

  if (!response.ok) {
    const message =
      typeof body?.detail === "string"
        ? body.detail
        : Array.isArray(body?.detail)
          ? body.detail.map((e: { msg: string }) => e.msg).join(", ")
          : `HTTP ${response.status}`;
    throw new ApiError(response.status, message);
  }

  return body as T;
}

// ─── Auth ──────────────────────────────────────────────────────────────────

export const auth = {
  me(): Promise<User> {
    return request<User>("/api/auth/me");
  },

  login(email: string, password: string): Promise<User> {
    return request<User>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    });
  },

  register(name: string, email: string, password: string): Promise<User> {
    return request<User>("/api/auth/register", {
      method: "POST",
      body: JSON.stringify({ name, email, password }),
    });
  },

  logout(): Promise<void> {
    return request<void>("/api/auth/logout", { method: "POST" });
  },
};

// ─── Projects ─────────────────────────────────────────────────────────────

export const projects = {
  list(): Promise<Project[]> {
    return request<Project[]>("/api/projects");
  },

  get(projectId: string): Promise<Project> {
    return request<Project>(`/api/projects/${encodeURIComponent(projectId)}`);
  },

  create(name: string): Promise<Project> {
    return request<Project>("/api/projects", {
      method: "POST",
      body: JSON.stringify({ name }),
    });
  },
};

// ─── Repositories ─────────────────────────────────────────────────────────

export const repositories = {
  list(projectId: string): Promise<Repository[]> {
    return request<Repository[]>(
      `/api/repositories?project_id=${encodeURIComponent(projectId)}`,
    );
  },

  get(repositoryId: string): Promise<Repository> {
    return request<Repository>(
      `/api/repositories/${encodeURIComponent(repositoryId)}`,
    );
  },

  create(name: string, url: string, projectId: string): Promise<Repository> {
    return request<Repository>("/api/repositories", {
      method: "POST",
      body: JSON.stringify({ name, url, project_id: projectId }),
    });
  },
};

// ─── Scans ────────────────────────────────────────────────────────────────

export const scans = {
  list(repositoryId: string): Promise<Scan[]> {
    return request<Scan[]>(
      `/api/scans?repository_id=${encodeURIComponent(repositoryId)}`,
    );
  },

  create(repositoryId: string, repositoryPath: string): Promise<Scan> {
    return request<Scan>("/api/scans", {
      method: "POST",
      body: JSON.stringify({
        repository_id: repositoryId,
        repository_path: repositoryPath,
      }),
    });
  },

  get(scanId: string): Promise<Scan> {
    return request<Scan>(`/api/scans/${encodeURIComponent(scanId)}`);
  },

  summary(scanId: string): Promise<ScanSummary> {
    return request<ScanSummary>(
      `/api/scans/${encodeURIComponent(scanId)}/summary`,
    );
  },

  findings(scanId: string): Promise<Finding[]> {
    return request<Finding[]>(
      `/api/scans/${encodeURIComponent(scanId)}/findings`,
    );
  },
};
