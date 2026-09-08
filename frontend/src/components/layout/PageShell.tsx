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
 * - Sidebar navigation
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
      <Sidebar />
      <section className="content">
        <header className="topbar">
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
