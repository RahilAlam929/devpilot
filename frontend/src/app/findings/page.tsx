"use client";

import { Suspense, useEffect, useReducer, useState } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import { projects as projectsApi, repositories as reposApi, scans as scansApi } from "@/lib/api";
import type { Project, Repository, Scan, Finding } from "@/lib/api";
import PageShell from "@/components/layout/PageShell";

type Severity = "all" | "critical" | "high" | "medium" | "low" | "info";

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

// ── Finding Card ───────────────────────────────────────────────────────────

function FindingCard({ finding }: { finding: Finding }) {
  const [expanded, setExpanded] = useState(false);

  const sevColor: Record<string, string> = {
    critical: "#ff3333",
    high: "#e8553a",
    medium: "#e8953a",
    low: "#6b9e6b",
    info: "#5588bb",
  };
  const color = sevColor[finding.severity] ?? "#888";

  return (
    <div
      style={{
        borderLeft: `3px solid ${color}`,
        background: "var(--surface)",
        borderRadius: "6px",
        marginBottom: "8px",
        padding: "12px 14px",
      }}
    >
      {/* Header row */}
      <div style={{ display: "flex", alignItems: "flex-start", gap: "10px", cursor: "pointer" }} onClick={() => setExpanded((v) => !v)}>
        <span
          className={`finding-severity ${finding.severity}`}
          style={{ flexShrink: 0, minWidth: "60px", textAlign: "center" }}
        >
          {finding.severity}
        </span>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: "8px" }}>
            <strong style={{ fontSize: "0.9rem" }}>{finding.title}</strong>
            {finding.cwe && (
              <span style={{ fontSize: "0.72rem", background: "var(--surface-hover)", padding: "1px 6px", borderRadius: "3px", color: "#999" }}>
                {finding.cwe}
              </span>
            )}
            {finding.confidence != null && (
              <span style={{ fontSize: "0.72rem", color: finding.confidence >= 80 ? "#6b9e6b" : finding.confidence >= 50 ? "#e8953a" : "#888" }}>
                {finding.confidence}% confidence
              </span>
            )}
          </div>
          <div style={{ fontSize: "0.78rem", color: "var(--text-muted)", marginTop: "2px" }}>
            {finding.file_path}
            {finding.line_number ? `:${finding.line_number}` : ""}
            {finding.language ? ` · ${finding.language}` : ""}
            {finding.category ? ` · ${finding.category.replace(/_/g, " ")}` : ""}
          </div>
        </div>
        <span style={{ color: "var(--text-muted)", fontSize: "0.8rem", flexShrink: 0 }}>
          {expanded ? "▲" : "▼"}
        </span>
      </div>

      {/* Expanded detail */}
      {expanded && (
        <div style={{ marginTop: "12px", paddingTop: "12px", borderTop: "1px solid var(--border)" }}>
          {/* Description */}
          <p style={{ fontSize: "0.82rem", color: "var(--text-muted)", marginBottom: "10px" }}>
            {finding.description}
          </p>

          {/* Code snippet */}
          {finding.code_snippet && (
            <DetailSection label="EVIDENCE">
              <pre style={{ margin: 0, fontSize: "0.78rem", overflowX: "auto" }}>
                <code>{finding.code_snippet}</code>
              </pre>
            </DetailSection>
          )}

          {/* Data flow */}
          {finding.data_flow_text && (
            <DetailSection label="DATA FLOW">
              <pre style={{ margin: 0, fontSize: "0.78rem", whiteSpace: "pre-wrap" }}>
                {finding.data_flow_text}
              </pre>
            </DetailSection>
          )}

          {/* Source → Sink */}
          {(finding.source_label || finding.sink_label) && (
            <DetailSection label="SOURCE → SINK">
              {finding.source_label && (
                <div style={{ fontSize: "0.8rem" }}>
                  <span style={{ color: "var(--text-muted)" }}>Source: </span>
                  <code>{finding.source_label}</code>
                </div>
              )}
              {finding.sink_label && (
                <div style={{ fontSize: "0.8rem", marginTop: "4px" }}>
                  <span style={{ color: "var(--text-muted)" }}>Sink: </span>
                  <code>{finding.sink_label}</code>
                </div>
              )}
            </DetailSection>
          )}

          {/* Why risky */}
          {finding.why_risky && (
            <DetailSection label="WHY IS THIS A PROBLEM?">
              <p style={{ margin: 0, fontSize: "0.82rem" }}>{finding.why_risky}</p>
            </DetailSection>
          )}

          {/* Impact */}
          {finding.impact && (
            <DetailSection label="IMPACT">
              <p style={{ margin: 0, fontSize: "0.82rem" }}>{finding.impact}</p>
            </DetailSection>
          )}

          {/* Remediation */}
          {finding.remediation && (
            <DetailSection label="HOW TO FIX">
              <pre style={{ margin: 0, fontSize: "0.78rem", whiteSpace: "pre-wrap" }}>
                {finding.remediation}
              </pre>
            </DetailSection>
          )}

          {/* Fix example */}
          {finding.fix_example && (
            <DetailSection label="CODE EXAMPLE">
              <pre style={{ margin: 0, fontSize: "0.78rem", overflowX: "auto" }}>
                <code>{finding.fix_example}</code>
              </pre>
            </DetailSection>
          )}

          {/* Patch */}
          {finding.patch_available && finding.patch && (
            <DetailSection label="SAFE PATCH">
              <div style={{ fontSize: "0.78rem", marginBottom: "6px", color: "var(--text-muted)" }}>
                {finding.patch.reason}
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px" }}>
                <div>
                  <div style={{ fontSize: "0.7rem", color: "#e8553a", marginBottom: "2px" }}>BEFORE</div>
                  <pre style={{ margin: 0, fontSize: "0.75rem", overflowX: "auto", background: "rgba(232,85,58,0.08)", padding: "6px", borderRadius: "4px" }}>
                    <code>{finding.patch.original}</code>
                  </pre>
                </div>
                <div>
                  <div style={{ fontSize: "0.7rem", color: "#6b9e6b", marginBottom: "2px" }}>AFTER</div>
                  <pre style={{ margin: 0, fontSize: "0.75rem", overflowX: "auto", background: "rgba(107,158,107,0.08)", padding: "6px", borderRadius: "4px" }}>
                    <code>{finding.patch.replacement}</code>
                  </pre>
                </div>
              </div>
            </DetailSection>
          )}

          {finding.patch_available === false && (
            <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", marginTop: "8px" }}>
              Manual review required — no deterministic patch available.
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function DetailSection({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div style={{ marginBottom: "10px" }}>
      <div className="eyebrow" style={{ fontSize: "0.65rem", marginBottom: "4px" }}>{label}</div>
      <div style={{ background: "var(--surface-hover)", borderRadius: "4px", padding: "8px 10px" }}>
        {children}
      </div>
    </div>
  );
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

  useEffect(() => {
    if (!selectedProjectId) return;
    let cancelled = false;
    reposApi.list(selectedProjectId)
      .then((data) => { if (!cancelled) dispatch({ type: "REPOS_OK", repos: data }); })
      .catch((err: unknown) => { if (!cancelled) dispatch({ type: "REPOS_ERR", message: err instanceof Error ? err.message : "Failed to load repositories." }); });
    return () => { cancelled = true; };
  }, [selectedProjectId]);

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

  const SEVERITIES: Severity[] = ["all", "critical", "high", "medium", "low", "info"];
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
      subheading="Browse security findings from your scans. Click any finding to expand details."
      onUser={loadProjects}
    >
      {error && (
        <div className="scan-error" style={{ marginBottom: "14px" }}>
          <strong>Error</strong><span>{error}</span>
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
            <select value={selectedProjectId}
              onChange={(e) => { dispatch({ type: "SELECT_PROJECT", id: e.target.value }); updateUrl(e.target.value, ""); }}
              disabled={loadingProjects || projects.length === 0}>
              {projects.length === 0 ? <option value="">No projects</option> : projects.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
            </select>
          </label>
          <label className="selector-group">
            <span>Repository</span>
            <select value={selectedRepoId}
              onChange={(e) => dispatch({ type: "SELECT_REPO", id: e.target.value })}
              disabled={loadingRepos || repos.length === 0 || !selectedProjectId}>
              {repos.length === 0 ? <option value="">{!selectedProjectId ? "Select a project first" : "No repositories"}</option> : repos.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
            </select>
          </label>
        </div>
        {selectedRepoId && (
          <div style={{ marginTop: "14px" }}>
            <label className="selector-group">
              <span>Scan</span>
              <select value={selectedScanId}
                onChange={(e) => { dispatch({ type: "SELECT_SCAN", id: e.target.value }); updateUrl(selectedProjectId, e.target.value); }}
                disabled={loadingScans || scanList.length === 0}>
                {scanList.length === 0 ? <option value="">No scans available</option>
                  : scanList.map((sc) => (
                    <option key={sc.id} value={sc.id}>
                      {sc.status.toUpperCase()} — {sc.id.slice(0, 8)}…
                      {sc.completed_at ? ` (${new Date(sc.completed_at).toLocaleDateString()})` : ""}
                    </option>
                  ))}
              </select>
            </label>
          </div>
        )}
      </div>

      {/* Severity filter chips */}
      {findingsState === "done" && findings.length > 0 && (
        <div className="filter-chips">
          {SEVERITIES.map((sev) => (
            <button key={sev}
              className={`filter-chip${severityFilter === sev ? " filter-chip-active" : ""} filter-chip-${sev}`}
              onClick={() => dispatch({ type: "SET_SEVERITY", severity: sev })}>
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
            {findings.length === 0 ? "No findings for this scan." : `No ${severityFilter} findings.`}
          </div>
        )}

        {!loadingFindings && findingsState === "done" && filtered.length > 0 && (
          <div style={{ marginTop: "8px" }}>
            {filtered.map((f) => <FindingCard key={f.id} finding={f} />)}
          </div>
        )}

        {findingsState === "idle" && !selectedScanId && (
          <div className="empty-state">Select a project, repository, and scan to view findings.</div>
        )}
      </section>
    </PageShell>
  );
}
