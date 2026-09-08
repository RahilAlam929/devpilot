"use client";

import { Suspense, useEffect, useReducer } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import { projects as projectsApi, repositories as reposApi, scans as scansApi } from "@/lib/api";
import type { Project, Repository, Scan, Finding } from "@/lib/api";
import PageShell from "@/components/layout/PageShell";

type Severity = "all" | "high" | "medium" | "low" | "info";

// ── State ──────────────────────────────────────────────────────────────────

type State = {
  projects: Project[];
  repos: Repository[];
  scanList: Scan[];
  findings: Finding[];
  selectedProjectId: string;
  selectedRepoId: string;
  selectedScanId: string;
  severityFilter: Severity;
  projectsState: "idle" | "loading" | "done" | "error";
  reposState: "idle" | "loading" | "done" | "error";
  scansState: "idle" | "loading" | "done" | "error";
  findingsState: "idle" | "loading" | "done" | "error";
  error: string | null;
};

type Action =
  | { type: "PROJECTS_OK"; projects: Project[]; initialProjectId: string }
  | { type: "PROJECTS_ERR"; message: string }
  | { type: "SELECT_PROJECT"; id: string }
  | { type: "REPOS_OK"; repos: Repository[] }
  | { type: "REPOS_ERR"; message: string }
  | { type: "SELECT_REPO"; id: string }
  | { type: "SCANS_OK"; scans: Scan[]; initialScanId: string }
  | { type: "SCANS_ERR"; message: string }
  | { type: "SELECT_SCAN"; id: string }
  | { type: "FINDINGS_LOADING" }
  | { type: "FINDINGS_OK"; findings: Finding[] }
  | { type: "FINDINGS_ERR"; message: string }
  | { type: "SET_SEVERITY"; severity: Severity }
  | { type: "CLEAR_ERROR" };

const init: State = {
  projects: [],
  repos: [],
  scanList: [],
  findings: [],
  selectedProjectId: "",
  selectedRepoId: "",
  selectedScanId: "",
  severityFilter: "all",
  projectsState: "idle",
  reposState: "idle",
  scansState: "idle",
  findingsState: "idle",
  error: null,
};

function reducer(s: State, a: Action): State {
  switch (a.type) {
    case "PROJECTS_OK": return { ...s, projects: a.projects, projectsState: "done", selectedProjectId: a.initialProjectId };
    case "PROJECTS_ERR": return { ...s, projectsState: "error", error: a.message };
    case "SELECT_PROJECT": return { ...s, selectedProjectId: a.id, repos: [], selectedRepoId: "", reposState: "idle", scanList: [], selectedScanId: "", findings: [], findingsState: "idle" };
    case "REPOS_OK": { const first = a.repos[0]?.id ?? ""; return { ...s, repos: a.repos, reposState: "done", selectedRepoId: first }; }
    case "REPOS_ERR": return { ...s, reposState: "error", error: a.message };
    case "SELECT_REPO": return { ...s, selectedRepoId: a.id, scanList: [], selectedScanId: "", findings: [], findingsState: "idle", scansState: "idle" };
    case "SCANS_OK": {
      const completed = a.scans.filter((sc) => sc.status === "completed");
      const first = completed[0]?.id ?? a.scans[0]?.id ?? "";
      const id = a.scans.find((sc) => sc.id === a.initialScanId) ? a.initialScanId : first;
      return { ...s, scanList: a.scans, scansState: "done", selectedScanId: id };
    }
    case "SCANS_ERR": return { ...s, scansState: "error", error: a.message };
    case "SELECT_SCAN": return { ...s, selectedScanId: a.id, findings: [], findingsState: "idle" };
    case "FINDINGS_LOADING": return { ...s, findingsState: "loading", error: null };
    case "FINDINGS_OK": return { ...s, findingsState: "done", findings: a.findings };
    case "FINDINGS_ERR": return { ...s, findingsState: "error", error: a.message };
    case "SET_SEVERITY": return { ...s, severityFilter: a.severity };
    case "CLEAR_ERROR": return { ...s, error: null };
    default: return s;
  }
}

// ── Component ──────────────────────────────────────────────────────────────

export default function FindingsPage() {
  return (
    <Suspense fallback={<div className="auth-loading"><div className="brand-mark">D</div><p>Loading…</p></div>}>
      <FindingsContent />
    </Suspense>
  );
}

function FindingsContent() {
  const [state, dispatch] = useReducer(reducer, init);
  const {
    projects, repos, scanList, findings,
    selectedProjectId, selectedRepoId, selectedScanId,
    severityFilter, projectsState, reposState, scansState, findingsState, error,
  } = state;

  const searchParams = useSearchParams();
  const router = useRouter();

  function loadProjects() {
    const initialProjectId = searchParams.get("project") ?? "";
    projectsApi.list()
      .then((data) => {
        const first = data[0]?.id ?? "";
        const id = data.find((p) => p.id === initialProjectId) ? initialProjectId : first;
        dispatch({ type: "PROJECTS_OK", projects: data, initialProjectId: id });
      })
      .catch((err: unknown) =>
        dispatch({ type: "PROJECTS_ERR", message: err instanceof Error ? err.message : "Failed to load projects." }),
      );
  }

  // Load repos when project changes
  useEffect(() => {
    if (!selectedProjectId) return;
    let cancelled = false;

    reposApi.list(selectedProjectId)
      .then((data) => { if (!cancelled) dispatch({ type: "REPOS_OK", repos: data }); })
      .catch((err: unknown) => { if (!cancelled) dispatch({ type: "REPOS_ERR", message: err instanceof Error ? err.message : "Failed to load repositories." }); });

    return () => { cancelled = true; };
  }, [selectedProjectId]);

  // Load scans when repo changes
  useEffect(() => {
    if (!selectedRepoId) return;
    let cancelled = false;
    const initialScanId = searchParams.get("scan") ?? "";

    scansApi.list(selectedRepoId)
      .then((data) => { if (!cancelled) dispatch({ type: "SCANS_OK", scans: data, initialScanId }); })
      .catch((err: unknown) => { if (!cancelled) dispatch({ type: "SCANS_ERR", message: err instanceof Error ? err.message : "Failed to load scans." }); });

    return () => { cancelled = true; };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedRepoId]);

  // Load findings when scan changes
  useEffect(() => {
    if (!selectedScanId) return;
    let cancelled = false;

    dispatch({ type: "FINDINGS_LOADING" });
    scansApi.findings(selectedScanId)
      .then((data) => { if (!cancelled) dispatch({ type: "FINDINGS_OK", findings: data }); })
      .catch((err: unknown) => { if (!cancelled) dispatch({ type: "FINDINGS_ERR", message: err instanceof Error ? err.message : "Failed to load findings." }); });

    return () => { cancelled = true; };
  }, [selectedScanId]);

  function updateUrl(projectId: string, scanId: string) {
    const params = new URLSearchParams();
    if (projectId) params.set("project", projectId);
    if (scanId) params.set("scan", scanId);
    router.replace(`/findings?${params.toString()}`);
  }

  const filtered = severityFilter === "all"
    ? findings
    : findings.filter((f) => f.severity === severityFilter);

  const SEVERITIES: Severity[] = ["all", "high", "medium", "low", "info"];

  const severityCount = (sev: Severity) =>
    sev === "all" ? findings.length : findings.filter((f) => f.severity === sev).length;

  const loadingProjects = projectsState === "loading";
  const loadingRepos = reposState === "loading";
  const loadingScans = scansState === "loading";
  const loadingFindings = findingsState === "loading";

  return (
    <PageShell
      eyebrow="RESULTS"
      heading="Findings"
      subheading="Browse and filter security findings from your scans."
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

      {/* Selectors */}
      <div className="panel selectors-panel" style={{ marginBottom: "14px" }}>
        <div className="panel-header">
          <div><div className="eyebrow">SELECT SCAN</div></div>
        </div>

        <div className="selectors-row" style={{ marginTop: "14px" }}>
          <label className="selector-group">
            <span>Project</span>
            <select
              value={selectedProjectId}
              onChange={(e) => { dispatch({ type: "SELECT_PROJECT", id: e.target.value }); updateUrl(e.target.value, ""); }}
              disabled={loadingProjects || projects.length === 0}
            >
              {projects.length === 0
                ? <option value="">No projects</option>
                : projects.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)
              }
            </select>
          </label>

          <label className="selector-group">
            <span>Repository</span>
            <select
              value={selectedRepoId}
              onChange={(e) => dispatch({ type: "SELECT_REPO", id: e.target.value })}
              disabled={loadingRepos || repos.length === 0 || !selectedProjectId}
            >
              {repos.length === 0
                ? <option value="">{!selectedProjectId ? "Select a project first" : "No repositories"}</option>
                : repos.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)
              }
            </select>
          </label>
        </div>

        {selectedRepoId && (
          <div style={{ marginTop: "14px" }}>
            <label className="selector-group">
              <span>Scan</span>
              <select
                value={selectedScanId}
                onChange={(e) => { dispatch({ type: "SELECT_SCAN", id: e.target.value }); updateUrl(selectedProjectId, e.target.value); }}
                disabled={loadingScans || scanList.length === 0}
              >
                {scanList.length === 0
                  ? <option value="">No scans available</option>
                  : scanList.map((sc) => (
                    <option key={sc.id} value={sc.id}>
                      {sc.status.toUpperCase()} — {sc.id.slice(0, 8)}…
                      {sc.completed_at ? ` (${new Date(sc.completed_at).toLocaleDateString()})` : ""}
                    </option>
                  ))
                }
              </select>
            </label>
          </div>
        )}
      </div>

      {/* Severity filter chips */}
      {findingsState === "done" && findings.length > 0 && (
        <div className="filter-chips">
          {SEVERITIES.map((sev) => (
            <button
              key={sev}
              className={`filter-chip${severityFilter === sev ? " filter-chip-active" : ""} filter-chip-${sev}`}
              onClick={() => dispatch({ type: "SET_SEVERITY", severity: sev })}
            >
              {sev === "all" ? "All" : sev.charAt(0).toUpperCase() + sev.slice(1)}
              <span className="filter-chip-count">{severityCount(sev)}</span>
            </button>
          ))}
        </div>
      )}

      {/* Findings list */}
      <section className="panel">
        <div className="panel-header">
          <div>
            <div className="eyebrow">FINDINGS</div>
            <h2>
              {loadingFindings ? "Loading…"
                : findingsState === "done"
                  ? `${filtered.length} finding${filtered.length !== 1 ? "s" : ""}${severityFilter !== "all" ? ` (${severityFilter})` : ""}`
                  : selectedScanId ? "Ready" : "Select a scan above"}
            </h2>
          </div>
        </div>

        {loadingFindings && <div className="empty-state">Loading findings…</div>}

        {!loadingFindings && findingsState === "done" && filtered.length === 0 && (
          <div className="empty-state">
            {findings.length === 0
              ? "No findings for this scan."
              : `No ${severityFilter} findings.`}
          </div>
        )}

        {!loadingFindings && findingsState === "done" && filtered.length > 0 && (
          <div className="findings-list" style={{ marginTop: "8px" }}>
            {filtered.map((f) => (
              <div key={f.id} className="finding-row">
                <span className={`finding-severity ${f.severity}`}>{f.severity}</span>
                <div>
                  <strong>{f.title}</strong>
                  <span>
                    {f.file_path
                      ? `${f.file_path}${f.line_number ? `:${f.line_number}` : ""}`
                      : f.description}
                  </span>
                  {f.description && f.file_path && (
                    <span className="finding-desc">{f.description}</span>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}

        {findingsState === "idle" && !selectedScanId && (
          <div className="empty-state">Select a project, repository, and scan to view findings.</div>
        )}
      </section>
    </PageShell>
  );
}
