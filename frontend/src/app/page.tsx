"use client";

import { useCallback, useEffect, useRef, useState } from "react";

const API_URL = "http://127.0.0.1:8000";

type Project = {
  id: string;
  name: string;
};

type Repository = {
  id: string;
  name: string;
  url: string;
};

type Scan = {
  id: string;
  repository_id: string;
  status: string;
  started_at?: string | null;
  completed_at?: string | null;
};

type Summary = {
  total_findings: number;
  high: number;
  medium: number;
  low: number;
  info: number;
};

export default function Home() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [repositories, setRepositories] = useState<Repository[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [summary, setSummary] = useState<Summary>({
    total_findings: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  });
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [activeScanId, setActiveScanId] = useState<string | null>(null);
  const [selectedRepositoryId, setSelectedRepositoryId] = useState("");
  const [scanPath, setScanPath] = useState("/tmp/devpilot-scan-test");
  const [error, setError] = useState<string | null>(null);

  const pollingRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const userId = "af137595-d9d4-4524-ae4a-eee6a308f295";
  const projectId = "635592f4-c955-491f-85ef-e88ac61fac88";

  const loadDashboard = useCallback(async () => {
    try {
      const [projectsRes, reposRes] = await Promise.all([
        fetch(`${API_URL}/api/projects?user_id=${userId}`),
        fetch(`${API_URL}/api/repositories?project_id=${projectId}`),
      ]);

      if (!projectsRes.ok || !reposRes.ok) {
        throw new Error("Failed to load dashboard data.");
      }

      const [projectsData, repositoriesData] = await Promise.all([
        projectsRes.json(),
        reposRes.json(),
      ]);

      setProjects(projectsData);
      setRepositories(repositoriesData);

      const repositoryExists = repositoriesData.some(
        (repository: Repository) => repository.id === selectedRepositoryId,
      );

      const repositoryId =
        repositoryExists
          ? selectedRepositoryId
          : repositoriesData[0]?.id ?? "";

      if (repositoryId !== selectedRepositoryId) {
        setSelectedRepositoryId(repositoryId);
        return;
      }

      if (!repositoryId) {
        setScans([]);
        setSummary({
          total_findings: 0,
          high: 0,
          medium: 0,
          low: 0,
          info: 0,
        });
        return;
      }

      const scansRes = await fetch(
        `${API_URL}/api/scans?repository_id=${repositoryId}`,
      );

      if (!scansRes.ok) {
        throw new Error("Failed to load scans.");
      }

      const scansData = await scansRes.json();
      setScans(scansData);

      if (scansData.length > 0 && !activeScanId) {
        const latest = scansData[0];

        const summaryRes = await fetch(
          `${API_URL}/api/scans/${latest.id}/summary`,
        );

        if (summaryRes.ok) {
          setSummary(await summaryRes.json());
        }
      }
    } catch (err) {
      console.error("Dashboard loading failed:", err);
      setError(
        err instanceof Error
          ? err.message
          : "Failed to load dashboard.",
      );
    } finally {
      setLoading(false);
    }
  }, [activeScanId, selectedRepositoryId]);

  useEffect(() => {
    void loadDashboard();
  }, [loadDashboard]);

  const refreshScan = useCallback(
    async (scanId: string) => {
      const [scanRes, summaryRes, scansRes] = await Promise.all([
        fetch(`${API_URL}/api/scans/${scanId}`),
        fetch(`${API_URL}/api/scans/${scanId}/summary`),
        fetch(
          `${API_URL}/api/scans?repository_id=${selectedRepositoryId}`,
        ),
      ]);

      if (!scanRes.ok) {
        throw new Error("Failed to fetch scan status.");
      }

      const scan: Scan = await scanRes.json();

      if (summaryRes.ok) {
        setSummary(await summaryRes.json());
      }

      if (scansRes.ok) {
        setScans(await scansRes.json());
      }

      return scan;
    },
    [selectedRepositoryId],
  );

  const pollScan = useCallback(
    async (scanId: string) => {
      try {
        const scan = await refreshScan(scanId);

        if (scan.status === "pending" || scan.status === "running") {
          setScanning(true);

          pollingRef.current = setTimeout(() => {
            void pollScan(scanId);
          }, 1000);

          return;
        }

        setScanning(false);

        if (scan.status === "failed") {
          setError("Scan failed. Check the backend logs.");
        }
      } catch (err) {
        console.error("Scan polling failed:", err);
        setScanning(false);
        setError(
          err instanceof Error
            ? err.message
            : "Realtime scan update failed.",
        );
      }
    },
    [refreshScan],
  );

  useEffect(() => {
    return () => {
      if (pollingRef.current) {
        clearTimeout(pollingRef.current);
      }
    };
  }, []);

  async function runScan() {
    if (!selectedRepositoryId) {
      setError("Please select a repository.");
      return;
    }

    if (!scanPath.trim()) {
      setError("Please enter a repository path.");
      return;
    }

    if (pollingRef.current) {
      clearTimeout(pollingRef.current);
    }

    setError(null);
    setScanning(true);
    setSummary({
      total_findings: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    });

    try {
      const response = await fetch(`${API_URL}/api/scans`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          repository_id: selectedRepositoryId,
          repository_path: scanPath.trim(),
        }),
      });

      if (!response.ok) {
        throw new Error("Failed to start scan.");
      }

      const scan: Scan = await response.json();

      setActiveScanId(scan.id);

      await refreshScan(scan.id);
      void pollScan(scan.id);
    } catch (err) {
      console.error("Run scan failed:", err);
      setScanning(false);
      setError(
        err instanceof Error
          ? err.message
          : "Unable to start scan.",
      );
    }
  }

  const stats = [
    {
      label: "Projects",
      value: projects.length,
      icon: "◈",
    },
    {
      label: "Repositories",
      value: repositories.length,
      icon: "⌘",
    },
    {
      label: "Total Scans",
      value: scans.length,
      icon: "↗",
    },
    {
      label: "Findings",
      value: summary.total_findings,
      icon: "!",
    },
  ];

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">D</div>
          <div>
            <div className="brand-name">DevPilot</div>
            <div className="brand-subtitle">Code Intelligence</div>
          </div>
        </div>

        <nav className="nav">
          <div className="nav-section">WORKSPACE</div>

          <a className="nav-item active" href="#">
            <span>⌂</span>
            Dashboard
          </a>

          <a className="nav-item" href="#">
            <span>◈</span>
            Projects
          </a>

          <a className="nav-item" href="#">
            <span>⌘</span>
            Repositories
          </a>

          <a className="nav-item" href="#">
            <span>↗</span>
            Scans
          </a>

          <a className="nav-item" href="#">
            <span>!</span>
            Findings
          </a>

          <div className="nav-section">SYSTEM</div>

          <a className="nav-item" href="#">
            <span>⚙</span>
            Settings
          </a>
        </nav>

        <div className="sidebar-bottom">
          <div className="status-dot" />
          <div>
            <strong>System online</strong>
            <span>API connected</span>
          </div>
        </div>
      </aside>

      <section className="content">
        <header className="topbar">
          <div>
            <div className="eyebrow">OVERVIEW</div>
            <h1>Dashboard</h1>
            <p>Monitor your codebase health and security.</p>
          </div>

          <div className="profile">
            <div className="avatar">MR</div>
            <div>
              <strong>MD Rahil</strong>
              <span>Developer</span>
            </div>
          </div>
        </header>

        <div className="dashboard">
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
                <span>Repository</span>
                <select
                  value={selectedRepositoryId}
                  onChange={(event) => {
                    setSelectedRepositoryId(event.target.value);
                    setActiveScanId(null);
                    setSummary({
                      total_findings: 0,
                      high: 0,
                      medium: 0,
                      low: 0,
                      info: 0,
                    });
                  }}
                  disabled={scanning}
                >
                  {repositories.map((repository) => (
                    <option key={repository.id} value={repository.id}>
                      {repository.name}
                    </option>
                  ))}
                </select>
              </label>

              <label>
                <span>Scan path</span>
                <input
                  value={scanPath}
                  onChange={(event) => setScanPath(event.target.value)}
                  placeholder="/path/to/repository"
                  disabled={scanning}
                />
              </label>

              <button
                className="primary-button"
                onClick={runScan}
                disabled={scanning || repositories.length === 0}
              >
                {scanning ? "Scanning…" : "Run Scan →"}
              </button>
            </div>

            {error && (
              <div className="scan-error">
                <strong>Scan error</strong>
                <span>{error}</span>
                <button onClick={() => setError(null)}>×</button>
              </div>
            )}

            {activeScanId && (
              <div className="active-scan">
                <span>Scan ID</span>
                <code>{activeScanId.slice(0, 12)}…</code>
              </div>
            )}
          </section>

          <section className="stats-grid">
            {stats.map((stat) => (
              <article className="stat-card" key={stat.label}>
                <div className="stat-icon">{stat.icon}</div>
                <div>
                  <span>{stat.label}</span>
                  <strong>{loading ? "—" : stat.value}</strong>
                </div>
              </article>
            ))}
          </section>

          <section className="main-grid">
            <article className="panel">
              <div className="panel-header">
                <div>
                  <div className="eyebrow">SECURITY</div>
                  <h2>Finding overview</h2>
                </div>
                <span className="badge">Latest scan</span>
              </div>

              <div className="finding-total">
                <strong>{summary.total_findings}</strong>
                <span>total findings</span>
              </div>

              <div className="severity-list">
                <Severity
                  label="High"
                  value={summary.high}
                  className="severity-high"
                />
                <Severity
                  label="Medium"
                  value={summary.medium}
                  className="severity-medium"
                />
                <Severity
                  label="Low"
                  value={summary.low}
                  className="severity-low"
                />
                <Severity
                  label="Info"
                  value={summary.info}
                  className="severity-info"
                />
              </div>
            </article>

            <article className="panel">
              <div className="panel-header">
                <div>
                  <div className="eyebrow">PROJECT</div>
                  <h2>Active workspace</h2>
                </div>
                <span className="live">● LIVE</span>
              </div>

              <div className="workspace-card">
                <div className="workspace-icon">D</div>
                <div>
                  <strong>DevPilot Core</strong>
                  <span>Repository security workspace</span>
                </div>
              </div>

              <div className="workspace-meta">
                <div>
                  <span>Repositories</span>
                  <strong>{repositories.length}</strong>
                </div>
                <div>
                  <span>Scans</span>
                  <strong>{scans.length}</strong>
                </div>
              </div>
            </article>
          </section>

          <section className="panel scans-panel">
            <div className="panel-header">
              <div>
                <div className="eyebrow">ACTIVITY</div>
                <h2>Recent scans</h2>
              </div>

              <button className="ghost-button">View all →</button>
            </div>

            <div className="scan-table">
              <div className="table-head">
                <span>Repository</span>
                <span>Status</span>
                <span>Scan ID</span>
              </div>

              {scans.length === 0 ? (
                <div className="empty-state">No scans found.</div>
              ) : (
                scans.slice(0, 5).map((scan) => (
                  <div className="table-row" key={scan.id}>
                    <strong>
                      {repositories.find(
                        (repository) => repository.id === scan.repository_id,
                      )?.name ?? "Repository"}
                    </strong>

                    <span className={`scan-status ${scan.status}`}>
                      <i />
                      {scan.status}
                    </span>

                    <code>{scan.id.slice(0, 8)}…</code>
                  </div>
                ))
              )}
            </div>
          </section>
        </div>
      </section>
    </main>
  );
}

function Severity({
  label,
  value,
  className,
}: {
  label: string;
  value: number;
  className: string;
}) {
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
