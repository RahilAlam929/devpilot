"use client";

import { FormEvent, Suspense, useEffect, useReducer, useRef } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import Link from "next/link";
import { projects as projectsApi, repositories as reposApi } from "@/lib/api";
import type { Project, Repository } from "@/lib/api";
import PageShell from "@/components/layout/PageShell";

// ── State ──────────────────────────────────────────────────────────────────

type State = {
  projects: Project[];
  repos: Repository[];
  selectedProjectId: string;
  projectsState: "idle" | "loading" | "done" | "error";
  reposState: "idle" | "loading" | "done" | "error";
  error: string | null;
  // Create form
  showCreate: boolean;
  createName: string;
  createUrl: string;
  creating: boolean;
  createError: string | null;
};

type Action =
  | { type: "PROJECTS_LOADING" }
  | { type: "PROJECTS_OK"; projects: Project[]; initialId: string }
  | { type: "PROJECTS_ERR"; message: string }
  | { type: "SELECT_PROJECT"; id: string }
  | { type: "REPOS_LOADING" }
  | { type: "REPOS_OK"; repos: Repository[] }
  | { type: "REPOS_ERR"; message: string }
  | { type: "SHOW_CREATE" }
  | { type: "HIDE_CREATE" }
  | { type: "SET_CREATE_NAME"; value: string }
  | { type: "SET_CREATE_URL"; value: string }
  | { type: "CREATING" }
  | { type: "CREATE_OK"; repo: Repository }
  | { type: "CREATE_ERR"; message: string }
  | { type: "CLEAR_ERROR" };

const init: State = {
  projects: [],
  repos: [],
  selectedProjectId: "",
  projectsState: "idle",
  reposState: "idle",
  error: null,
  showCreate: false,
  createName: "",
  createUrl: "",
  creating: false,
  createError: null,
};

function reducer(s: State, a: Action): State {
  switch (a.type) {
    case "PROJECTS_LOADING": return { ...s, projectsState: "loading", error: null };
    case "PROJECTS_OK": return { ...s, projects: a.projects, projectsState: "done", selectedProjectId: a.initialId };
    case "PROJECTS_ERR": return { ...s, projectsState: "error", error: a.message };
    case "SELECT_PROJECT": return { ...s, selectedProjectId: a.id, repos: [], reposState: "idle" };
    case "REPOS_LOADING": return { ...s, reposState: "loading", error: null };
    case "REPOS_OK": return { ...s, repos: a.repos, reposState: "done" };
    case "REPOS_ERR": return { ...s, reposState: "error", error: a.message };
    case "SHOW_CREATE": return { ...s, showCreate: true, createName: "", createUrl: "", createError: null };
    case "HIDE_CREATE": return { ...s, showCreate: false, createName: "", createUrl: "", createError: null };
    case "SET_CREATE_NAME": return { ...s, createName: a.value };
    case "SET_CREATE_URL": return { ...s, createUrl: a.value };
    case "CREATING": return { ...s, creating: true, createError: null };
    case "CREATE_OK": return { ...s, creating: false, showCreate: false, repos: [a.repo, ...s.repos] };
    case "CREATE_ERR": return { ...s, creating: false, createError: a.message };
    case "CLEAR_ERROR": return { ...s, error: null };
    default: return s;
  }
}

// ── Component ──────────────────────────────────────────────────────────────

export default function RepositoriesPage() {
  return (
    <Suspense fallback={<div className="auth-loading"><div className="brand-mark">D</div><p>Loading…</p></div>}>
      <RepositoriesContent />
    </Suspense>
  );
}

function RepositoriesContent() {
  const [state, dispatch] = useReducer(reducer, init);
  const {
    projects, repos, selectedProjectId,
    projectsState, reposState, error,
    showCreate, createName, createUrl, creating, createError,
  } = state;

  const searchParams = useSearchParams();
  const router = useRouter();
  const nameInputRef = useRef<HTMLInputElement>(null);

  function loadProjects() {
    dispatch({ type: "PROJECTS_LOADING" });
    const initialId = searchParams.get("project") ?? "";

    projectsApi.list()
      .then((data) => {
        const first = data[0]?.id ?? "";
        const id = data.find((p) => p.id === initialId) ? initialId : first;
        dispatch({ type: "PROJECTS_OK", projects: data, initialId: id });
      })
      .catch((err: unknown) =>
        dispatch({ type: "PROJECTS_ERR", message: err instanceof Error ? err.message : "Failed to load projects." }),
      );
  }

  // Load repos when project changes
  useEffect(() => {
    if (!selectedProjectId) return;
    let cancelled = false;

    dispatch({ type: "REPOS_LOADING" });
    reposApi.list(selectedProjectId)
      .then((data) => { if (!cancelled) dispatch({ type: "REPOS_OK", repos: data }); })
      .catch((err: unknown) => {
        if (!cancelled)
          dispatch({ type: "REPOS_ERR", message: err instanceof Error ? err.message : "Failed to load repositories." });
      });

    return () => { cancelled = true; };
  }, [selectedProjectId]);

  // Auto-focus name input when modal opens
  useEffect(() => {
    if (showCreate) nameInputRef.current?.focus();
  }, [showCreate]);

  function handleCreate(e: FormEvent) {
    e.preventDefault();
    const name = createName.trim();
    const url = createUrl.trim();
    if (!name || !url || !selectedProjectId) return;

    dispatch({ type: "CREATING" });
    reposApi.create(name, url, selectedProjectId)
      .then((repo) => dispatch({ type: "CREATE_OK", repo }))
      .catch((err: unknown) =>
        dispatch({ type: "CREATE_ERR", message: err instanceof Error ? err.message : "Failed to create repository." }),
      );
  }

  function handleProjectChange(id: string) {
    dispatch({ type: "SELECT_PROJECT", id });
    // Update URL query param
    const params = new URLSearchParams(searchParams.toString());
    params.set("project", id);
    router.replace(`/repositories?${params.toString()}`);
  }

  const selectedProject = projects.find((p) => p.id === selectedProjectId);
  const loadingProjects = projectsState === "loading";
  const loadingRepos = reposState === "loading";

  return (
    <PageShell
      eyebrow="WORKSPACE"
      heading="Repositories"
      subheading="Manage repositories within your projects."
      onUser={loadProjects}
    >
      {/* Error banner */}
      {error && (
        <div className="scan-error" style={{ marginBottom: "14px" }}>
          <strong>Error</strong>
          <span>{error}</span>
          <button onClick={() => dispatch({ type: "CLEAR_ERROR" })}>×</button>
        </div>
      )}

      {/* Project selector */}
      <div className="panel selectors-panel" style={{ marginBottom: "14px" }}>
        <div className="panel-header">
          <div>
            <div className="eyebrow">FILTER BY PROJECT</div>
          </div>
        </div>
        <div style={{ marginTop: "14px" }}>
          <label className="selector-group">
            <span>Project</span>
            <select
              value={selectedProjectId}
              onChange={(e) => handleProjectChange(e.target.value)}
              disabled={loadingProjects || projects.length === 0}
            >
              {projects.length === 0 ? (
                <option value="">No projects available</option>
              ) : (
                projects.map((p) => (
                  <option key={p.id} value={p.id}>{p.name}</option>
                ))
              )}
            </select>
          </label>
        </div>
      </div>

      {/* Repos header */}
      <div className="page-section-header">
        <div>
          <div className="eyebrow">REPOSITORIES</div>
          <p className="page-section-sub">
            {selectedProject
              ? `${loadingRepos ? "…" : repos.length} ${repos.length === 1 ? "repository" : "repositories"} in ${selectedProject.name}`
              : "Select a project"}
          </p>
        </div>
        <button
          className="primary-button"
          onClick={() => dispatch({ type: "SHOW_CREATE" })}
          disabled={!selectedProjectId}
        >
          + Add Repository
        </button>
      </div>

      {/* Repository list */}
      {loadingRepos && <div className="empty-state panel">Loading repositories…</div>}

      {!loadingRepos && selectedProjectId && repos.length === 0 && (
        <div className="empty-state panel">
          No repositories in this project yet. Add one to start scanning.
        </div>
      )}

      {!loadingRepos && !selectedProjectId && (
        <div className="empty-state panel">Select a project to view its repositories.</div>
      )}

      {!loadingRepos && repos.length > 0 && (
        <div className="item-grid">
          {repos.map((repo) => (
            <Link key={repo.id} href={`/scans?repo=${repo.id}&project=${selectedProjectId}`} className="item-card">
              <div className="item-card-icon">{repo.name[0]?.toUpperCase() ?? "R"}</div>
              <div className="item-card-body">
                <strong>{repo.name}</strong>
                <span className="item-card-url">{repo.url}</span>
              </div>
              <div className="item-card-arrow">→</div>
            </Link>
          ))}
        </div>
      )}

      {/* Create modal */}
      {showCreate && (
        <div className="modal-overlay" onClick={() => dispatch({ type: "HIDE_CREATE" })}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div>
                <div className="eyebrow">NEW REPOSITORY</div>
                <h2>Add repository</h2>
              </div>
              <button className="modal-close" onClick={() => dispatch({ type: "HIDE_CREATE" })}>×</button>
            </div>

            <form onSubmit={handleCreate} className="modal-form">
              <label className="field">
                <span>Repository name</span>
                <input
                  ref={nameInputRef}
                  type="text"
                  value={createName}
                  onChange={(e) => dispatch({ type: "SET_CREATE_NAME", value: e.target.value })}
                  placeholder="e.g. my-service"
                  disabled={creating}
                  autoComplete="off"
                />
              </label>

              <label className="field">
                <span>Repository URL</span>
                <input
                  type="text"
                  value={createUrl}
                  onChange={(e) => dispatch({ type: "SET_CREATE_URL", value: e.target.value })}
                  placeholder="https://github.com/org/repo"
                  disabled={creating}
                  autoComplete="off"
                />
              </label>

              {createError && <div className="auth-error">{createError}</div>}

              <div className="modal-actions">
                <button type="button" className="ghost-button" onClick={() => dispatch({ type: "HIDE_CREATE" })} disabled={creating}>
                  Cancel
                </button>
                <button
                  type="submit"
                  className="primary-button"
                  disabled={creating || !createName.trim() || !createUrl.trim()}
                >
                  {creating ? "Adding…" : "Add repository"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </PageShell>
  );
}
