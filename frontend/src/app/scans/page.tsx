"use client";

import { Suspense, useEffect, useLayoutEffect, useReducer, useRef } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import { projects as projectsApi, repositories as reposApi, scans as scansApi } from "@/lib/api";
import type { Project, Repository, Scan, ScanSummary, Finding } from "@/lib/api";
import PageShell from "@/components/layout/PageShell";

// ── State ──────────────────────────────────────────────────────────────────

type State = {
  projects: Project[];
  repos: Repository[];
  scanList: Scan[];
  selectedProjectId: string;
  selectedRepoId: string;
  // Scan detail view
  activeScanId: string | null;
  activeSummary: ScanSummary | null;
  activeFindings: Finding[];
  showFindings: boolean;
  // Scan trigger
  scanning: boolean;
  // Load states
  projectsState: "idle" | "loading" | "done" | "error";
  reposState: "idle" | "loading" | "done" | "error";
  scansState: "idle" | "loading" | "done" | "error";
  error: string | null;
};

type Action =
  | { type: "PROJECTS_LOADING" }
  | { type: "PROJECTS_OK"; projects: Project[]; initialProjectId: string; initialRepoId: string }
  | { type: "PROJECTS_ERR"; message: string }
  | { type: "SELECT_PROJECT"; id: string }
  | { type: "REPOS_LOADING" }
  | { type: "REPOS_OK"; repos: Repository[]; initialRepoId: string }
  | { type: "REPOS_ERR"; message: string }
  | { type: "SELECT_REPO"; id: string }
  | { type: "SCANS_LOADING" }
  | { type: "SCANS_OK"; scans: Scan[] }
  | { type: "SCANS_ERR"; message: string }
  | { type: "SCAN_START" }
  | { type: "SCAN_CREATED"; scan: Scan }
  | { type: "SCAN_UPDATED"; scans: Scan[] }
  | { type: "SCAN_POLL_DONE"; summary: ScanSummary; findings: Finding[] }
  | { type: "SCAN_POLL_FAILED" }
  | { type: "SCAN_POLL_ERROR" }
  | { type: "VIEW_SCAN"; scanId: string; summary: ScanSummary; findings: Finding[] }
  | { type: "HIDE_FINDINGS" }
  | { type: "CLEAR_ERROR" }
  | { type: "SET_ERROR"; message: string };

const init: State = {
  projects: [],
  repos: [],
  scanList: [],
  selectedProjectId: "",
  selectedRepoId: "",
  activeScanId: null,
  activeSummary: null,
  activeFindings: [],
  showFindings: false,
  scanning: false,
  projectsState: "idle",
  reposState: "idle",
  scansState: "idle",
  error: null,
};

function reducer(s: State, a: Action): State {
  switch (a.type) {
    case "PROJECTS_LOADING": return { ...s, projectsState: "loading", error: null };
    case "PROJECTS_OK": return {
      ...s, projects: a.projects, projectsState: "done",
      selectedProjectId: a.initialProjectId,
    };
    case "PROJECTS_ERR": return { ...s, projectsState: "error", error: a.message };
    case "SELECT_PROJECT": return {
      ...s, selectedProjectId: a.id,
      repos: [], selectedRepoId: "", reposState: "idle",
      scanList: [], scansState: "idle",
      activeScanId: null, activeSummary: null, activeFindings: [], showFindings: false,
    };
    case "REPOS_LOADING": return { ...s, reposState: "loading" };
    case "REPOS_OK": {
      const first = a.repos[0]?.id ?? "";
      const id = a.repos.find((r) => r.id === a.initialRepoId) ? a.initialRepoId : first;
      return { ...s, repos: a.repos, reposState: "done", selectedRepoId: id };
    }
    case "REPOS_ERR": return { ...s, reposState: "error", error: a.message };
    case "SELECT_REPO": return {
      ...s, selectedRepoId: a.id,
      scanList: [], scansState: "idle",
      activeScanId: null, activeSummary: null, activeFindings: [], showFindings: false,
    };
    case "SCANS_LOADING": return { ...s, scansState: "loading" };
    case "SCANS_OK": return { ...s, scansState: "done", scanList: a.scans };
    case "SCANS_ERR": return { ...s, scansState: "error", error: a.message };
    case "SCAN_START": return { ...s, scanning: true, error: null, activeSummary: null, activeFindings: [], showFindings: false };
    case "SCAN_CREATED": return { ...s, activeScanId: a.scan.id, scanList: [a.scan, ...s.scanList] };
    case "SCAN_UPDATED": return { ...s, scanList: a.scans };
    case "SCAN_POLL_DONE": return { ...s, scanning: false, activeSummary: a.summary, activeFindings: a.findings, showFindings: a.findings.length > 0 };
    case "SCAN_POLL_FAILED": return { ...s, scanning: false, error: "Scan failed. Check backend logs." };
    case "SCAN_POLL_ERROR": return { ...s, scanning: false, error: "Lost connection while polling." };
    case "VIEW_SCAN": return { ...s, activeScanId: a.scanId, activeSummary: a.summary, activeFindings: a.findings, showFindings: true };
    case "HIDE_FINDINGS": return { ...s, showFindings: false };
    case "CLEAR_ERROR": return { ...s, error: null };
    case "SET_ERROR": return { ...s, error: a.message };
    default: return s;
  }
}

// ── Component ──────────────────────────────────────────────────────────────

export default function ScansPage() {
  return (
    <Suspense fallback={<div className="auth-loading"><div className="brand-mark">D</div><p>Loading…</p></div>}>
      <ScansContent />
    </Suspense>
  );
}

function ScansContent() {
  const [state, dispatch] = useReducer(reducer, init);
  const {
    projects, repos, scanList, selectedProjectId, selectedRepoId,
    activeScanId, activeSummary, activeFindings, showFindings,
    scanning, projectsState, reposState, scansState, error,
  } = state;

  const searchParams = useSearchParams();
  const router = useRouter();

  const pollingRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const repoIdRef = useRef(selectedRepoId);
  const dispatchRef = useRef(dispatch);

  useLayoutEffect(() => { repoIdRef.current = selectedRepoId; });
  useLayoutEffect(() => { dispatchRef.current = dispatch; });

  const pollFnRef = useRef<(scanId: string) => void>(() => undefined);
  useLayoutEffect(() => {
    pollFnRef.current = (scanId: string) => {
      const d = dispatchRef.current;
      const repoId = repoIdRef.current;

      Promise.all([
        scansApi.get(scanId),
        scansApi.summary(scanId),
        repoId ? scansApi.list(repoId) : Promise.resolve([]),
      ])
        .then(([scan, summary, updatedScans]) => {
          if (updatedScans.length > 0) d({ type: "SCAN_UPDATED", scans: updatedScans });

          if (scan.status === "pending" || scan.status === "running") {
            pollingRef.current = setTimeout(() => pollFnRef.current(scanId), 1500);
            return;
          }
          if (scan.status === "completed") {
            scansApi.findings(scanId)
              .then((findings) => d({ type: "SCAN_POLL_DONE", summary, findings }))
              .catch(() => d({ type: "SCAN_POLL_DONE", summary, findings: [] }));
          } else {
            d({ type: "SCAN_POLL_FAILED" });
          }
        })
        .catch(() => d({ type: "SCAN_POLL_ERROR" }));
    };
  });

  useEffect(() => () => { if (pollingRef.current) clearTimeout(pollingRef.current); }, []);

  function loadProjects() {
    const initialProjectId = searchParams.get("project") ?? "";
    const initialRepoId = searchParams.get("repo") ?? "";

    dispatch({ type: "PROJECTS_LOADING" });
    projectsApi.list()
      .then((data) => {
        const first = data[0]?.id ?? "";
        const projId = data.find((p) => p.id === initialProjectId) ? initialProjectId : first;
        dispatch({ type: "PROJECTS_OK", projects: data, initialProjectId: projId, initialRepoId });
      })
      .catch((err: unknown) =>
        dispatch({ type: "PROJECTS_ERR", message: err instanceof Error ? err.message : "Failed to load projects." }),
      );
  }

  // Load repos when project changes
  useEffect(() => {
    if (!selectedProjectId) return;
    let cancelled = false;
    const initialRepoId = searchParams.get("repo") ?? "";

    dispatch({ type: "REPOS_LOADING" });
    reposApi.list(selectedProjectId)
      .then((data) => { if (!cancelled) dispatch({ type: "REPOS_OK", repos: data, initialRepoId }); })
      .catch((err: unknown) => {
        if (!cancelled) dispatch({ type: "REPOS_ERR", message: err instanceof Error ? err.message : "Failed to load repositories." });
      });

    return () => { cancelled = true; };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedProjectId]);

  // Load scans when repo changes
  useEffect(() => {
    if (!selectedRepoId) return;
    let cancelled = false;
    if (pollingRef.current) { clearTimeout(pollingRef.current); pollingRef.current = null; }

    dispatch({ type: "SCANS_LOADING" });
    scansApi.list(selectedRepoId)
      .then((data) => { if (!cancelled) dispatch({ type: "SCANS_OK", scans: data }); })
      .catch((err: unknown) => {
        if (!cancelled) dispatch({ type: "SCANS_ERR", message: err instanceof Error ? err.message : "Failed to load scans." });
      });

    return () => { cancelled = true; };
  }, [selectedRepoId]);

  function updateUrl(projectId: string, repoId: string) {
    const params = new URLSearchParams();
    if (projectId) params.set("project", projectId);
    if (repoId) params.set("repo", repoId);
    router.replace(`/scans?${params.toString()}`);
  }

  function handleProjectChange(id: string) {
    dispatch({ type: "SELECT_PROJECT", id });
    updateUrl(id, "");
  }

  function handleRepoChange(id: string) {
    dispatch({ type: "SELECT_REPO", id });
    updateUrl(selectedProjectId, id);
  }

  function runScan() {
    if (!selectedRepoId) { dispatch({ type: "SET_ERROR", message: "Please select a repository." }); return; }

    if (pollingRef.current) clearTimeout(pollingRef.current);
    dispatch({ type: "SCAN_START" });

    scansApi.create(selectedRepoId)
      .then((scan) => {
        dispatch({ type: "SCAN_CREATED", scan });
        pollFnRef.current(scan.id);
      })
      .catch((err: unknown) => {
        dispatch({ type: "SET_ERROR", message: err instanceof Error ? err.message : "Unable to start scan." });
        dispatch({ type: "SCAN_POLL_FAILED" });
      });
  }

  function viewScan(scanId: string) {
    Promise.all([scansApi.summary(scanId), scansApi.findings(scanId)])
      .then(([summary, findings]) => dispatch({ type: "VIEW_SCAN", scanId, summary, findings }))
      .catch((err: unknown) =>
        dispatch({ type: "SET_ERROR", message: err instanceof Error ? err.message : "Failed to load scan details." }),
      );
  }

  const loadingProjects = projectsState === "loading";
  const loadingRepos = reposState === "loading";
  const loadingScans = scansState === "loading";

  return (
    <PageShell
      eyebrow="ANALYSIS"
      heading="Scans"
      subheading="Run and monitor security scans on your repositories."
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
          <div>
            <div className="eyebrow">SELECT TARGET</div>
          </div>
        </div>
        <div className="selectors-row" style={{ marginTop: "14px" }}>
          <label className="selector-group">
            <span>Project</span>
            <select
              value={selectedProjectId}
              onChange={(e) => handleProjectChange(e.target.value)}
              disabled={loadingProjects || projects.length === 0}
            >
              {projects.length === 0
                ? <option value="">No projects available</option>
                : projects.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)
              }
            </select>
          </label>

          <label className="selector-group">
            <span>Repository</span>
            <select
              value={selectedRepoId}
              onChange={(e) => handleRepoChange(e.target.value)}
              disabled={loadingRepos || repos.length === 0 || !selectedProjectId}
            >
              {repos.length === 0
                ? <option value="">{!selectedProjectId ? "Select a project first" : "No repositories"}</option>
                : repos.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)
              }
            </select>
          </label>
        </div>
      </div>

      {/* Scan trigger */}
      {selectedRepoId && (
        <section className="panel scan-control-panel" style={{ marginBottom: "14px" }}>
          <div className="panel-header">
            <div>
              <div className="eyebrow">SCANNER</div>
              <h2>Run security scan</h2>
            </div>
            <span className={scanning ? "live scanning" : "live"}>
              ● {scanning ? "SCANNING" : "READY"}
            </span>
          </div>

          <div className="scan-controls">
            <button
              className="primary-button"
              onClick={runScan}
              disabled={scanning || !selectedRepoId}
            >
              {scanning ? "Scanning…" : "Run Scan →"}
            </button>
          </div>

          {activeScanId && (
            <div className="active-scan">
              <span>Active scan</span>
              <code>{activeScanId.slice(0, 12)}…</code>
            </div>
          )}
        </section>
      )}

      {/* Summary cards */}
      {activeSummary && (
        <div className="main-grid" style={{ marginBottom: "14px" }}>
          <article className="panel">
            <div className="panel-header">
              <div>
                <div className="eyebrow">SECURITY</div>
                <h2>Scan results</h2>
              </div>
              <span className={`scan-status ${activeSummary.status}`}>
                <i />
                {activeSummary.status}
              </span>
            </div>
            <div className="finding-total">
              <strong>{activeSummary.total_findings}</strong>
              <span>total findings</span>
            </div>
            <div className="severity-list">
              <SeverityRow label="High" value={activeSummary.high} colorClass="severity-high" />
              <SeverityRow label="Medium" value={activeSummary.medium} colorClass="severity-medium" />
              <SeverityRow label="Low" value={activeSummary.low} colorClass="severity-low" />
              <SeverityRow label="Info" value={activeSummary.info} colorClass="severity-info" />
            </div>
          </article>

          <article className="panel">
            <div className="panel-header">
              <div>
                <div className="eyebrow">SCAN ID</div>
                <h2>Active scan</h2>
              </div>
            </div>
            <div style={{ marginTop: "20px" }}>
              <code className="scan-id-display">{activeScanId ?? "—"}</code>
            </div>
            {activeSummary.status === "completed" && !showFindings && (
              <button
                className="primary-button"
                style={{ marginTop: "20px" }}
                onClick={() => dispatch({ type: "VIEW_SCAN", scanId: activeScanId!, summary: activeSummary, findings: activeFindings })}
              >
                View findings →
              </button>
            )}
          </article>
        </div>
      )}

      {/* Findings panel */}
      {showFindings && activeFindings.length > 0 && (
        <section className="panel" style={{ marginBottom: "14px" }}>
          <div className="panel-header">
            <div>
              <div className="eyebrow">FINDINGS</div>
              <h2>Detailed results</h2>
            </div>
            <button className="ghost-button" onClick={() => dispatch({ type: "HIDE_FINDINGS" })}>Close ×</button>
          </div>
          <FindingsList findings={activeFindings} />
        </section>
      )}

      {/* Scan history */}
      <section className="panel scans-panel">
        <div className="panel-header">
          <div>
            <div className="eyebrow">HISTORY</div>
            <h2>Scan history</h2>
          </div>
        </div>

        <div className="scan-table">
          <div className="table-head scan-table-head">
            <span>Repository</span>
            <span>Status</span>
            <span>Completed</span>
            <span>Actions</span>
          </div>

          {loadingScans && <div className="empty-state">Loading scans…</div>}

          {!loadingScans && !selectedRepoId && (
            <div className="empty-state">Select a repository to view scan history.</div>
          )}

          {!loadingScans && selectedRepoId && scanList.length === 0 && (
            <div className="empty-state">No scans yet. Run your first scan above.</div>
          )}

          {!loadingScans && scanList.map((scan) => (
            <div className="table-row scan-table-row" key={scan.id}>
              <strong>
                {repos.find((r) => r.id === scan.repository_id)?.name ?? "Repo"}
              </strong>
              <span className={`scan-status ${scan.status}`}>
                <i />
                {scan.status}
              </span>
              <span className="scan-time">
                {scan.completed_at
                  ? new Date(scan.completed_at).toLocaleString()
                  : scan.started_at
                    ? new Date(scan.started_at).toLocaleString()
                    : "—"}
              </span>
              <div className="scan-row-actions">
                <code>{scan.id.slice(0, 8)}…</code>
                {scan.status === "completed" && (
                  <button className="ghost-button" onClick={() => viewScan(scan.id)}>
                    Details
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      </section>
    </PageShell>
  );
}

// ── Sub-components ─────────────────────────────────────────────────────────

function SeverityRow({ label, value, colorClass }: { label: string; value: number; colorClass: string }) {
  return (
    <div className="severity-row">
      <div className="severity-label">
        <i className={colorClass} />
        <span>{label}</span>
      </div>
      <strong>{value}</strong>
    </div>
  );
}

function FindingsList({ findings }: { findings: Finding[] }) {
  return (
    <div className="findings-list" style={{ marginTop: "16px" }}>
      {findings.map((f) => (
        <div key={f.id} className="finding-row">
          <span className={`finding-severity ${f.severity}`}>{f.severity}</span>
          <div>
            <strong>{f.title}</strong>
            <span>
              {f.file_path
                ? `${f.file_path}${f.line_number ? `:${f.line_number}` : ""}`
                : f.description}
            </span>
          </div>
        </div>
      ))}
    </div>
  );
}
