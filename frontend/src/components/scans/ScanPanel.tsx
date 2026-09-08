"use client";

import { useEffect, useLayoutEffect, useReducer, useRef } from "react";
import { scans as scansApi, type Scan, type ScanSummary, type Finding, type Repository } from "@/lib/api";

// ── State ──────────────────────────────────────────────────────────────────

type ScanState = {
  scanList: Scan[];
  summary: ScanSummary | null;
  findings: Finding[];
  scanPath: string;
  scanning: boolean;
  activeScanId: string | null;
  loadingScans: boolean;
  error: string | null;
  showFindings: boolean;
};

type ScanAction =
  | { type: "LOAD_SCANS_OK"; scans: Scan[]; summary: ScanSummary | null }
  | { type: "REPO_CHANGED" }
  | { type: "SET_SCAN_PATH"; path: string }
  | { type: "SCAN_START" }
  | { type: "SCAN_CREATED"; scan: Scan }
  | { type: "SCAN_UPDATED"; scans: Scan[]; summary: ScanSummary }
  | { type: "SCAN_DONE"; findings: Finding[] }
  | { type: "SCAN_FAILED" }
  | { type: "SCAN_POLL_ERROR" }
  | { type: "SHOW_FINDINGS"; findings: Finding[] }
  | { type: "HIDE_FINDINGS" }
  | { type: "CLEAR_ERROR" }
  | { type: "SET_ERROR"; message: string };

const initialState: ScanState = {
  scanList: [],
  summary: null,
  findings: [],
  scanPath: "/tmp/devpilot-scan-test",
  scanning: false,
  activeScanId: null,
  loadingScans: false,
  error: null,
  showFindings: false,
};

function scanReducer(state: ScanState, action: ScanAction): ScanState {
  switch (action.type) {
    case "REPO_CHANGED":
      return {
        ...state,
        scanList: [],
        summary: null,
        findings: [],
        scanning: false,
        activeScanId: null,
        loadingScans: true,
        error: null,
        showFindings: false,
      };
    case "LOAD_SCANS_OK":
      return { ...state, loadingScans: false, scanList: action.scans, summary: action.summary };
    case "SET_SCAN_PATH":
      return { ...state, scanPath: action.path };
    case "SCAN_START":
      return { ...state, scanning: true, error: null, summary: null, findings: [] };
    case "SCAN_CREATED":
      return {
        ...state,
        activeScanId: action.scan.id,
        scanList: [action.scan, ...state.scanList],
      };
    case "SCAN_UPDATED":
      return { ...state, scanList: action.scans, summary: action.summary };
    case "SCAN_DONE":
      return {
        ...state,
        scanning: false,
        findings: action.findings,
        showFindings: action.findings.length > 0,
      };
    case "SCAN_FAILED":
      return { ...state, scanning: false, error: "Scan failed. Check backend logs for details." };
    case "SCAN_POLL_ERROR":
      return { ...state, scanning: false, error: "Lost connection while polling scan status." };
    case "SHOW_FINDINGS":
      return { ...state, findings: action.findings, showFindings: true };
    case "HIDE_FINDINGS":
      return { ...state, showFindings: false };
    case "CLEAR_ERROR":
      return { ...state, error: null };
    case "SET_ERROR":
      return { ...state, error: action.message };
    default:
      return state;
  }
}

// ── Component ──────────────────────────────────────────────────────────────

interface ScanPanelProps {
  repositoryId: string;
  repositories: Repository[];
}

export default function ScanPanel({ repositoryId, repositories }: ScanPanelProps) {
  const [state, dispatch] = useReducer(scanReducer, initialState);
  const {
    scanList, summary, findings, scanPath,
    scanning, activeScanId, loadingScans, error, showFindings,
  } = state;

  const pollingRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Mutable refs kept in sync via useLayoutEffect (not updated during render)
  const repoIdRef = useRef(repositoryId);
  const dispatchRef = useRef(dispatch);

  useLayoutEffect(() => {
    repoIdRef.current = repositoryId;
  });

  useLayoutEffect(() => {
    dispatchRef.current = dispatch;
  });

  // The poll function lives in a ref so it can recurse without being a hook dep
  const pollFnRef = useRef<(scanId: string) => void>(() => undefined);

  // Re-assign poll function whenever dispatch reference changes (stable in practice)
  useLayoutEffect(() => {
    pollFnRef.current = function pollScan(scanId: string) {
      const repoId = repoIdRef.current;
      const d = dispatchRef.current;

      Promise.all([
        scansApi.get(scanId),
        scansApi.summary(scanId),
        repoId ? scansApi.list(repoId) : Promise.resolve([]),
      ])
        .then(([scan, s, updated]) => {
          if (updated.length > 0) {
            d({ type: "SCAN_UPDATED", scans: updated, summary: s });
          }

          if (scan.status === "pending" || scan.status === "running") {
            pollingRef.current = setTimeout(() => pollFnRef.current(scanId), 1500);
            return;
          }

          if (scan.status === "completed") {
            scansApi.findings(scanId)
              .then((f) => d({ type: "SCAN_DONE", findings: f }))
              .catch(() => d({ type: "SCAN_DONE", findings: [] }));
          } else if (scan.status === "failed") {
            d({ type: "SCAN_FAILED" });
          } else {
            d({ type: "SCAN_DONE", findings: [] });
          }
        })
        .catch(() => {
          d({ type: "SCAN_POLL_ERROR" });
        });
    };
  });

  // Cleanup polling on unmount
  useEffect(() => {
    return () => {
      if (pollingRef.current) clearTimeout(pollingRef.current);
    };
  }, []);

  // Load scans when repository changes
  useEffect(() => {
    if (pollingRef.current) {
      clearTimeout(pollingRef.current);
      pollingRef.current = null;
    }

    dispatch({ type: "REPO_CHANGED" });

    if (!repositoryId) return;

    let cancelled = false;

    scansApi.list(repositoryId)
      .then((scans) => {
        if (cancelled) return;
        const latest = scans[0];
        if (!latest) {
          dispatch({ type: "LOAD_SCANS_OK", scans, summary: null });
          return;
        }
        return scansApi.summary(latest.id)
          .then((s) => {
            if (!cancelled) dispatch({ type: "LOAD_SCANS_OK", scans, summary: s });
          })
          .catch(() => {
            if (!cancelled) dispatch({ type: "LOAD_SCANS_OK", scans, summary: null });
          });
      })
      .catch(() => {
        if (!cancelled) dispatch({ type: "LOAD_SCANS_OK", scans: [], summary: null });
      });

    return () => { cancelled = true; };
  }, [repositoryId]);

  function runScan() {
    if (!repositoryId) {
      dispatch({ type: "SET_ERROR", message: "Please select a repository." });
      return;
    }
    if (!scanPath.trim()) {
      dispatch({ type: "SET_ERROR", message: "Please enter a path to scan." });
      return;
    }

    if (pollingRef.current) clearTimeout(pollingRef.current);

    dispatch({ type: "SCAN_START" });

    scansApi.create(repositoryId, scanPath.trim())
      .then((scan) => {
        dispatch({ type: "SCAN_CREATED", scan });
        pollFnRef.current(scan.id);
      })
      .catch((err: unknown) => {
        dispatch({ type: "SET_ERROR", message: err instanceof Error ? err.message : "Unable to start scan." });
        dispatch({ type: "SCAN_FAILED" });
      });
  }

  function loadFindings(scanId: string) {
    scansApi.findings(scanId)
      .then((f) => dispatch({ type: "SHOW_FINDINGS", findings: f }))
      .catch((err: unknown) => {
        dispatch({ type: "SET_ERROR", message: err instanceof Error ? err.message : "Failed to load findings." });
      });
  }

  const repoName = repositories.find((r) => r.id === repositoryId)?.name ?? "Repository";

  return (
    <div className="scan-panel-root">
      {/* ── Scan trigger ────────────────────────────────────── */}
      <section className="panel scan-control-panel">
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
          <label>
            <span>Scan path</span>
            <input
              value={scanPath}
              onChange={(e) => dispatch({ type: "SET_SCAN_PATH", path: e.target.value })}
              placeholder="/absolute/path/to/repository"
              disabled={scanning}
            />
          </label>
          <button
            className="primary-button"
            onClick={runScan}
            disabled={scanning || !repositoryId}
          >
            {scanning ? "Scanning…" : "Run Scan →"}
          </button>
        </div>

        {error && (
          <div className="scan-error">
            <strong>Error</strong>
            <span>{error}</span>
            <button onClick={() => dispatch({ type: "CLEAR_ERROR" })}>×</button>
          </div>
        )}

        {activeScanId && (
          <div className="active-scan">
            <span>Active scan</span>
            <code>{activeScanId.slice(0, 12)}…</code>
          </div>
        )}
      </section>

      {/* ── Summary + workspace ──────────────────────────────── */}
      <div className="main-grid">
        <article className="panel">
          <div className="panel-header">
            <div>
              <div className="eyebrow">SECURITY</div>
              <h2>Finding overview</h2>
            </div>
            <span className="badge">Latest scan</span>
          </div>

          {summary ? (
            <>
              <div className="finding-total">
                <strong>{summary.total_findings}</strong>
                <span>total findings</span>
              </div>
              <div className="severity-list">
                <SeverityRow label="High" value={summary.high} className="severity-high" />
                <SeverityRow label="Medium" value={summary.medium} className="severity-medium" />
                <SeverityRow label="Low" value={summary.low} className="severity-low" />
                <SeverityRow label="Info" value={summary.info} className="severity-info" />
              </div>
            </>
          ) : (
            <div className="empty-state">
              {loadingScans ? "Loading…" : "Run a scan to see findings."}
            </div>
          )}
        </article>

        <article className="panel">
          <div className="panel-header">
            <div>
              <div className="eyebrow">REPOSITORY</div>
              <h2>Active workspace</h2>
            </div>
            <span className="live">● LIVE</span>
          </div>

          <div className="workspace-card">
            <div className="workspace-icon">{repoName[0]?.toUpperCase() ?? "R"}</div>
            <div>
              <strong>{repoName}</strong>
              <span>Selected repository</span>
            </div>
          </div>

          <div className="workspace-meta">
            <div>
              <span>Scans</span>
              <strong>{scanList.length}</strong>
            </div>
            <div>
              <span>Findings</span>
              <strong>{summary?.total_findings ?? "—"}</strong>
            </div>
          </div>
        </article>
      </div>

      {/* ── Recent scans ─────────────────────────────────────── */}
      <section className="panel scans-panel">
        <div className="panel-header">
          <div>
            <div className="eyebrow">ACTIVITY</div>
            <h2>Recent scans</h2>
          </div>
        </div>

        <div className="scan-table">
          <div className="table-head">
            <span>Repository</span>
            <span>Status</span>
            <span>Scan ID</span>
          </div>

          {scanList.length === 0 ? (
            <div className="empty-state">
              {loadingScans ? "Loading scans…" : "No scans yet for this repository."}
            </div>
          ) : (
            scanList.slice(0, 8).map((scan) => (
              <div className="table-row" key={scan.id}>
                <strong>
                  {repositories.find((r) => r.id === scan.repository_id)?.name ?? "Repo"}
                </strong>
                <span className={`scan-status ${scan.status}`}>
                  <i />
                  {scan.status}
                </span>
                <div className="scan-row-actions">
                  <code>{scan.id.slice(0, 8)}…</code>
                  {scan.status === "completed" && (
                    <button className="ghost-button" onClick={() => loadFindings(scan.id)}>
                      Findings
                    </button>
                  )}
                </div>
              </div>
            ))
          )}
        </div>
      </section>

      {/* ── Findings ─────────────────────────────────────────── */}
      {showFindings && findings.length > 0 && (
        <section className="panel">
          <div className="panel-header">
            <div>
              <div className="eyebrow">FINDINGS</div>
              <h2>Detailed results</h2>
            </div>
            <button className="ghost-button" onClick={() => dispatch({ type: "HIDE_FINDINGS" })}>
              Close ×
            </button>
          </div>

          <div className="findings-list">
            {findings.map((finding) => (
              <div key={finding.id} className="finding-row">
                <span className={`finding-severity ${finding.severity}`}>
                  {finding.severity}
                </span>
                <div>
                  <strong>{finding.title}</strong>
                  <span>
                    {finding.file_path
                      ? `${finding.file_path}${finding.line_number ? `:${finding.line_number}` : ""}`
                      : finding.description}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}

function SeverityRow({ label, value, className }: { label: string; value: number; className: string }) {
  return (
    <div className="severity-row">
      <div className="severity-label">
        <i className={className} />
        <span>{label}</span>
      </div>
      <strong>{value}</strong>
    </div>
  );
}
