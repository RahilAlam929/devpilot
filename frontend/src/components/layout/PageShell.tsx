"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { getCurrentUser, logout, userInitials } from "@/lib/auth";
import type { User } from "@/lib/api";
import Sidebar from "@/components/layout/Sidebar";

interface PageShellProps {
  /** Page eyebrow label (uppercase, e.g. "OVERVIEW") */
  eyebrow: string;
  /** Page h1 heading */
  heading: string;
  /** Optional subtitle */
  subheading?: string;
  /** Page content */
  children: React.ReactNode;
  /** Called with the authenticated user once resolved */
  onUser?: (user: User) => void;
}

/**
 * Wraps every protected page with:
 * - Auth check → redirect to /login on 401
 * - Sidebar navigation (desktop) / drawer navigation (mobile)
 * - Mobile hamburger header
 * - Consistent topbar with user info + logout
 * - Loading splash while auth resolves
 */
export default function PageShell({
  eyebrow,
  heading,
  subheading,
  children,
  onUser,
}: PageShellProps) {
  const router = useRouter();
  const [user, setUser] = useState<User | null>(null);
  const [checked, setChecked] = useState(false);
  const [drawerOpen, setDrawerOpen] = useState(false);

  useEffect(() => {
    let cancelled = false;

    getCurrentUser()
      .then((u) => {
        if (cancelled) return;
        if (!u) { router.replace("/login"); return; }
        setUser(u);
        setChecked(true);
        onUser?.(u);
      })
      .catch(() => {
        if (!cancelled) router.replace("/login");
      });

    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [router]);

  if (!checked) {
    return (
      <div className="auth-loading">
        <div className="brand-mark">D</div>
        <p>Loading…</p>
      </div>
    );
  }

  const initials = user ? userInitials(user) : "";
  const displayName = user?.name ?? user?.email ?? "";

  function handleLogout() {
    logout()
      .catch(() => undefined)
      .finally(() => router.push("/login"));
  }

  return (
    <div className="app-shell">
      <Sidebar
        mobileOpen={drawerOpen}
        onClose={() => setDrawerOpen(false)}
      />

      <section className="content">
        {/* ── Mobile header (hamburger) ─────────────────────── */}
        <header className="mobile-header" aria-label="Mobile navigation header">
          <button
            className="hamburger-btn"
            onClick={() => setDrawerOpen(true)}
            aria-label="Open navigation menu"
            aria-expanded={drawerOpen}
            aria-controls="sidebar-nav"
          >
            <span className="hamburger-line" />
            <span className="hamburger-line" />
            <span className="hamburger-line" />
          </button>

          <div className="mobile-header-brand">
            <div className="brand-mark brand-mark-sm">D</div>
            <span className="mobile-brand-name">DevPilot</span>
          </div>

          <div className="mobile-header-right">
            <div className="avatar avatar-sm">{initials}</div>
          </div>
        </header>

        {/* ── Desktop topbar ───────────────────────────────── */}
        <header className="topbar" aria-label="Page header">
          <div>
            <div className="eyebrow">{eyebrow}</div>
            <h1>{heading}</h1>
            {subheading && <p>{subheading}</p>}
          </div>

          <div className="topbar-right">
            <div className="profile">
              <div className="avatar">{initials}</div>
              <div>
                <strong>{displayName}</strong>
                <span>{user?.email}</span>
              </div>
            </div>
            <button className="ghost-button logout-btn" onClick={handleLogout}>
              Sign out
            </button>
          </div>
        </header>

        <div className="page-body">
          {children}
        </div>
      </section>
    </div>
  );
}
