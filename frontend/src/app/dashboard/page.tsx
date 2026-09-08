"use client";

import { useEffect, useReducer } from "react";
import { projects as projectsApi, repositories as reposApi, scans as scansApi } from "@/lib/api";
import type { Project, Repository, Scan, ScanSummary } from "@/lib/api";
import PageShell from "@/components/layout/PageShell";
import ProjectSelector from "@/components/projects/ProjectSelector";
import RepositorySelector from "@/components/repositories/RepositorySelector";
import ScanPanel from "@/components/scans/ScanPanel";

// ── State ──────────────────────────────────────────────────────────────────

type State = {
  projects: Project[];
  repos: Repository[];
  scansForRepo: Scan[];
  latestSummary: ScanSummary | null;
  selectedProjectId: string;
  selectedRepoId: string;
  projectsState: "idle" | "loading" | "done" | "error";
  reposState: "idle" | "loading" | "done" | "error";
  scansState: "idle" | "loading" | "done";
  error: string | null;
};

type Action =
  | { type: "PROJECTS_LOADING" }
  | { type: "PROJECTS_OK"; projects: Project[] }
  | { type: "PROJECTS_ERR"; message: string }
  | { type: "SELECT_PROJECT"; id: string }
  | { type: "REPOS_LOADING" }
  | { type: "REPOS_OK"; repos: Repository[] }
  | { type: "REPOS_ERR"; message: string }
  | { type: "SELECT_REPO"; id: string }
  | { type: "SCANS_OK"; scans: Scan[]; summary: ScanSummary | null }
  | { type: "ADD_PROJECT"; project: Project }
  | { type: "ADD_REPO"; repo: Repository }
  | { type: "CLEAR_ERROR" };

const init: State = {
  projects: [],
  repos: [],
  scansForRepo: [],
  latestSummary: null,
  selectedProjectId: "",
  selectedRepoId: "",
  projectsState: "idle",
  reposState: "idle",
  scansState: "idle",
  error: null,
};

function reducer(s: State, a: Action): State {
  switch (a.type) {
    case "PROJECTS_LOADING":
      return { ...s, projectsState: "loading", error: null };
    case "PROJECTS_OK": {
      const first = a.projects[0]?.id ?? "";
      return { ...s, projects: a.projects, projectsState: "done", selectedProjectId: first };
    }
    case "PROJECTS_ERR":
      return { ...s, projectsState: "error", error: a.message };
    case "SELECT_PROJECT":
      return { ...s, selectedProjectId: a.id, repos: [], selectedRepoId: "", reposState: "idle", scansForRepo: [], latestSummary: null };
    case "REPOS_LOADING":
      return { ...s, reposState: "loading", error: null };
    case "REPOS_OK": {
      const first = a.repos[0]?.id ?? "";
      return { ...s, repos: a.repos, reposState: "done", selectedRepoId: first };
    }
    case "REPOS_ERR":
      return { ...s, reposState: "error", error: a.message };
    case "SELECT_REPO":
      return { ...s, selectedRepoId: a.id, scansForRepo: [], latestSummary: null };
    case "SCANS_OK":
      return { ...s, scansForRepo: a.scans, latestSummary: a.summary, scansState: "done" };
    case "ADD_PROJECT":
      return { ...s, projects: [a.project, ...s.projects], selectedProjectId: a.project.id, repos: [], selectedRepoId: "", reposState: "idle" };
    case "ADD_REPO":
      return { ...s, repos: [a.repo, ...s.repos], selectedRepoId: a.repo.id };
    case "CLEAR_ERROR":
      return { ...s, error: null };
    default:
      return s;
  }
}

// ── Component ──────────────────────────────────────────────────────────────

export default function DashboardPage() {
  const [state, dispatch] = useReducer(reducer, init);
  const { projects, repos, scansForRepo, latestSummary, selectedProjectId, selectedRepoId, projectsState, reposState, error } = state;

  // Load projects after auth
  function handleUser() {
    dispatch({ type: "PROJECTS_LOADING" });

    projectsApi.list()
      .then((data) => dispatch({ type: "PROJECTS_OK", projects: data }))
      .catch((err: unknown) => dispatch({ type: "PROJECTS_ERR", message: err instanceof Error ? err.message : "Failed to load projects." }));
  }

  // Load repos when project changes
  useEffect(() => {
    if (!selectedProjectId) return;
    let cancelled = false;

    dispatch({ type: "REPOS_LOADING" });

    reposApi.list(selectedProjectId)
      .then((data) => { if (!cancelled) dispatch({ type: "REPOS_OK", repos: data }); })
      .catch((err: unknown) => { if (!cancelled) dispatch({ type: "REPOS_ERR", message: err instanceof Error ? err.message : "Failed to load repositories." }); });

    return () => { cancelled = true; };
  }, [selectedProjectId]);

  // Load scans for stat card when repo changes
  useEffect(() => {
    if (!selectedRepoId) return;
    let cancelled = false;

    scansApi.list(selectedRepoId)
      .then((data) => {
        if (cancelled) return;
        const latest = data[0];
        if (!latest) { dispatch({ type: "SCANS_OK", scans: data, summary: null }); return; }
        return scansApi.summary(latest.id)
          .then((s) => { if (!cancelled) dispatch({ type: "SCANS_OK", scans: data, summary: s }); })
          .catch(() => { if (!cancelled) dispatch({ type: "SCANS_OK", scans: data, summary: null }); });
      })
      .catch(() => { if (!cancelled) dispatch({ type: "SCANS_OK", scans: [], summary: null }); });

    return () => { cancelled = true; };
  }, [selectedRepoId]);

  const loadingProjects = projectsState === "loading";
  const loadingRepos = reposState === "loading";

  return (
    <PageShell
      eyebrow="OVERVIEW"
      heading="Dashboard"
      subheading="Monitor your codebase health and security."
      onUser={handleUser}
    >
      {/* Stats row */}
      <section className="stats-grid">
        <StatCard icon="◈" label="Projects" value={loadingProjects ? "—" : String(projects.length)} />
        <StatCard icon="⌘" label="Repositories" value={loadingRepos ? "—" : String(repos.length)} />
        <StatCard icon="↗" label="Total Scans" value={state.scansState === "done" ? String(scansForRepo.length) : "—"} />
        <StatCard icon="!" label="Findings" value={latestSummary ? String(latestSummary.total_findings) : "—"} />
      </section>

      {error && (
        <div className="scan-error" style={{ marginTop: "14px" }}>
          <strong>Error</strong>
          <span>{error}</span>
          <button onClick={() => dispatch({ type: "CLEAR_ERROR" })}>×</button>
        </div>
      )}

      {/* Selectors */}
      <section className="panel selectors-panel">
        <div className="panel-header">
          <div>
            <div className="eyebrow">WORKSPACE</div>
            <h2>Select project &amp; repository</h2>
          </div>
        </div>

        <div className="selectors-row">
          <ProjectSelector
            projects={projects}
            selectedId={selectedProjectId}
            loading={loadingProjects}
            onSelect={(id) => dispatch({ type: "SELECT_PROJECT", id })}
            onCreated={(project) => dispatch({ type: "ADD_PROJECT", project })}
          />
          <RepositorySelector
            repositories={repos}
            selectedId={selectedRepoId}
            projectId={selectedProjectId}
            loading={loadingRepos}
            disabled={!selectedProjectId}
            onSelect={(id) => dispatch({ type: "SELECT_REPO", id })}
            onCreated={(repo) => dispatch({ type: "ADD_REPO", repo })}
          />
        </div>
      </section>

      {/* Scan section */}
      {selectedRepoId ? (
        <ScanPanel repositoryId={selectedRepoId} repositories={repos} />
      ) : (
        <section className="panel" style={{ marginTop: "14px" }}>
          <div className="empty-state">
            {selectedProjectId ? "Add a repository to start scanning." : "Create or select a project to get started."}
          </div>
        </section>
      )}
    </PageShell>
  );
}

function StatCard({ icon, label, value }: { icon: string; label: string; value: string }) {
  return (
    <article className="stat-card">
      <div className="stat-icon">{icon}</div>
      <div>
        <span>{label}</span>
        <strong>{value}</strong>
      </div>
    </article>
  );
}
