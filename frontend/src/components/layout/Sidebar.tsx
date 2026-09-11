"use client";

import Link from "next/link";
import { useEffect } from "react";
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

interface SidebarProps {
  /** Whether the mobile drawer is open */
  mobileOpen?: boolean;
  /** Called when the drawer should close (backdrop click, nav click, close button, Escape) */
  onClose?: () => void;
}

export default function Sidebar({ mobileOpen = false, onClose }: SidebarProps) {
  const pathname = usePathname();
  const router = useRouter();

  // Close drawer on Escape key
  useEffect(() => {
    if (!mobileOpen) return;
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") onClose?.();
    }
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [mobileOpen, onClose]);

  // Prevent background scrolling while drawer is open
  useEffect(() => {
    if (mobileOpen) {
      document.body.style.overflow = "hidden";
    } else {
      document.body.style.overflow = "";
    }
    return () => {
      document.body.style.overflow = "";
    };
  }, [mobileOpen]);

  function handleLogout() {
    logout()
      .catch(() => undefined)
      .finally(() => router.push("/login"));
  }

  function handleNavClick() {
    // Close mobile drawer when a nav item is tapped
    onClose?.();
  }

  return (
    <>
      {/* Mobile backdrop */}
      {mobileOpen && (
        <div
          className="sidebar-backdrop"
          onClick={onClose}
          aria-hidden="true"
        />
      )}

      <aside
        className={`sidebar${mobileOpen ? " sidebar-open" : ""}`}
        aria-label="Main navigation"
        role="navigation"
      >
        {/* Mobile close button */}
        <button
          className="sidebar-close-btn"
          onClick={onClose}
          aria-label="Close navigation menu"
        >
          ✕
        </button>

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
              onClick={handleNavClick}
            >
              <span aria-hidden="true">{icon}</span>
              {label}
            </Link>
          ))}

          <div className="nav-section">ACCOUNT</div>

          <button className="nav-item nav-logout" onClick={handleLogout}>
            <span aria-hidden="true">⎋</span>
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
    </>
  );
}
