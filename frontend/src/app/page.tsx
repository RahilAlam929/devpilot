"use client";

import { useEffect, useState } from "react";

const API_URL = "http://localhost:8000";

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

  const userId = "af137595-d9d4-4524-ae4a-eee6a308f295";
  const projectId = "635592f4-c955-491f-85ef-e88ac61fac88";
  const repositoryId = "2129e2f9-8311-416e-b467-6224c82e81bc";

  useEffect(() => {
    async function loadDashboard() {
      try {
        const [projectsRes, reposRes, scansRes, summaryRes] =
          await Promise.all([
            fetch(`${API_URL}/api/projects?user_id=${userId}`),
            fetch(`${API_URL}/api/repositories?project_id=${projectId}`),
            fetch(`${API_URL}/api/scans?repository_id=${repositoryId}`),
            fetch(
              `${API_URL}/api/scans/13753da4-9bb0-47f7-97b8-fad27500a548/summary`,
            ),
          ]);

        if (projectsRes.ok) setProjects(await projectsRes.json());
        if (reposRes.ok) setRepositories(await reposRes.json());
        if (scansRes.ok) setScans(await scansRes.json());
        if (summaryRes.ok) setSummary(await summaryRes.json());
      } catch (error) {
        console.error("Dashboard loading failed:", error);
      } finally {
        setLoading(false);
      }
    }

    loadDashboard();
  }, []);

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

                    <span className="status-completed">
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
