"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useRouter } from "next/navigation";
import { logout } from "@/lib/auth";

const NAV_ITEMS = [
  { href: "/dashboard", icon: "⌂", label: "Dashboard" },
  { href: "/projects", icon: "◈", label: "Projects" },
  { href: "/repositories", icon: "⌘", label: "Repositories" },
  { href: "/scans", icon: "↗", label: "Scans" },
  { href: "/findings", icon: "!", label: "Findings" },
] as const;

export default function Sidebar() {
  const pathname = usePathname();
  const router = useRouter();

  function handleLogout() {
    logout()
      .catch(() => undefined)
      .finally(() => router.push("/login"));
  }

  return (
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

        {NAV_ITEMS.map(({ href, icon, label }) => (
          <Link
            key={href}
            href={href}
            className={`nav-item${pathname === href || pathname.startsWith(href + "/") ? " active" : ""}`}
          >
            <span>{icon}</span>
            {label}
          </Link>
        ))}

        <div className="nav-section">ACCOUNT</div>

        <button className="nav-item nav-logout" onClick={handleLogout}>
          <span>⎋</span>
          Sign out
        </button>
      </nav>

      <div className="sidebar-bottom">
        <div className="status-dot" />
        <div>
          <strong>System online</strong>
          <span>API connected</span>
        </div>
      </div>
    </aside>
  );
}
