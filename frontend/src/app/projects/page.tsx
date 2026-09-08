"use client";

import { FormEvent, useEffect, useReducer, useRef } from "react";
import Link from "next/link";
import { projects as projectsApi, repositories as reposApi } from "@/lib/api";
import type { Project } from "@/lib/api";
import PageShell from "@/components/layout/PageShell";

// ── State ──────────────────────────────────────────────────────────────────

type ProjectWithCount = Project & { repoCount: number };

type State = {
  items: ProjectWithCount[];
  loadState: "idle" | "loading" | "done" | "error";
  error: string | null;
  showCreate: boolean;
  createName: string;
  creating: boolean;
  createError: string | null;
};

type Action =
  | { type: "LOAD" }
  | { type: "LOAD_OK"; items: ProjectWithCount[] }
  | { type: "LOAD_ERR"; message: string }
  | { type: "SHOW_CREATE" }
  | { type: "HIDE_CREATE" }
  | { type: "SET_NAME"; value: string }
  | { type: "CREATING" }
  | { type: "CREATE_OK"; project: ProjectWithCount }
  | { type: "CREATE_ERR"; message: string }
  | { type: "CLEAR_ERROR" };

const init: State = {
  items: [],
  loadState: "idle",
  error: null,
  showCreate: false,
  createName: "",
  creating: false,
  createError: null,
};

function reducer(s: State, a: Action): State {
  switch (a.type) {
    case "LOAD": return { ...s, loadState: "loading", error: null };
    case "LOAD_OK": return { ...s, loadState: "done", items: a.items };
    case "LOAD_ERR": return { ...s, loadState: "error", error: a.message };
    case "SHOW_CREATE": return { ...s, showCreate: true, createName: "", createError: null };
    case "HIDE_CREATE": return { ...s, showCreate: false, createName: "", createError: null };
    case "SET_NAME": return { ...s, createName: a.value };
    case "CREATING": return { ...s, creating: true, createError: null };
    case "CREATE_OK": return { ...s, creating: false, showCreate: false, createName: "", items: [a.project, ...s.items] };
    case "CREATE_ERR": return { ...s, creating: false, createError: a.message };
    case "CLEAR_ERROR": return { ...s, error: null };
    default: return s;
  }
}

// ── Component ──────────────────────────────────────────────────────────────

export default function ProjectsPage() {
  const [state, dispatch] = useReducer(reducer, init);
  const { items, loadState, error, showCreate, createName, creating, createError } = state;
  const nameInputRef = useRef<HTMLInputElement>(null);

  function loadProjects() {
    dispatch({ type: "LOAD" });

    projectsApi.list()
      .then((data) => {
        // Fetch repo counts in parallel — best-effort (ignore failures)
        return Promise.all(
          data.map((p) =>
            reposApi.list(p.id)
              .then((repos) => ({ ...p, repoCount: repos.length }))
              .catch(() => ({ ...p, repoCount: 0 })),
          ),
        );
      })
      .then((items) => dispatch({ type: "LOAD_OK", items }))
      .catch((err: unknown) =>
        dispatch({ type: "LOAD_ERR", message: err instanceof Error ? err.message : "Failed to load projects." }),
      );
  }

  // Auto-focus name input when modal opens
  useEffect(() => {
    if (showCreate) nameInputRef.current?.focus();
  }, [showCreate]);

  function handleCreate(e: FormEvent) {
    e.preventDefault();
    const name = createName.trim();
    if (!name) return;

    dispatch({ type: "CREATING" });

    projectsApi.create(name)
      .then((project) => dispatch({ type: "CREATE_OK", project: { ...project, repoCount: 0 } }))
      .catch((err: unknown) =>
        dispatch({ type: "CREATE_ERR", message: err instanceof Error ? err.message : "Failed to create project." }),
      );
  }

  return (
    <PageShell
      eyebrow="WORKSPACE"
      heading="Projects"
      subheading="Manage your analysis projects."
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

      {/* Header row */}
      <div className="page-section-header">
        <div>
          <div className="eyebrow">ALL PROJECTS</div>
          <p className="page-section-sub">
            {loadState === "done" ? `${items.length} project${items.length !== 1 ? "s" : ""}` : "Loading…"}
          </p>
        </div>
        <button className="primary-button" onClick={() => dispatch({ type: "SHOW_CREATE" })}>
          + New Project
        </button>
      </div>

      {/* Project list */}
      {loadState === "loading" && (
        <div className="empty-state panel">Loading projects…</div>
      )}

      {loadState === "done" && items.length === 0 && (
        <div className="empty-state panel">
          No projects yet. Create your first project to get started.
        </div>
      )}

      {loadState === "done" && items.length > 0 && (
        <div className="item-grid">
          {items.map((project) => (
            <Link key={project.id} href={`/repositories?project=${project.id}`} className="item-card">
              <div className="item-card-icon">{project.name[0]?.toUpperCase() ?? "P"}</div>
              <div className="item-card-body">
                <strong>{project.name}</strong>
                <span>{project.repoCount} {project.repoCount === 1 ? "repository" : "repositories"}</span>
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
                <div className="eyebrow">NEW PROJECT</div>
                <h2>Create project</h2>
              </div>
              <button className="modal-close" onClick={() => dispatch({ type: "HIDE_CREATE" })}>×</button>
            </div>

            <form onSubmit={handleCreate} className="modal-form">
              <label className="field">
                <span>Project name</span>
                <input
                  ref={nameInputRef}
                  type="text"
                  value={createName}
                  onChange={(e) => dispatch({ type: "SET_NAME", value: e.target.value })}
                  placeholder="e.g. backend-api"
                  disabled={creating}
                  autoComplete="off"
                />
              </label>

              {createError && <div className="auth-error">{createError}</div>}

              <div className="modal-actions">
                <button
                  type="button"
                  className="ghost-button"
                  onClick={() => dispatch({ type: "HIDE_CREATE" })}
                  disabled={creating}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="primary-button"
                  disabled={creating || !createName.trim()}
                >
                  {creating ? "Creating…" : "Create project"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </PageShell>
  );
}
