"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { getCurrentUser } from "@/lib/auth";

/**
 * Root page — immediately determines auth state and redirects.
 * Authenticated users go to /dashboard.
 * Unauthenticated users go to /login.
 */
export default function RootPage() {
  const router = useRouter();

  useEffect(() => {
    async function redirect() {
      try {
        const user = await getCurrentUser();
        router.replace(user ? "/dashboard" : "/login");
      } catch {
        router.replace("/login");
      }
    }
    void redirect();
  }, [router]);

  return (
    <div className="auth-loading">
      <div className="brand-mark">D</div>
      <p>Loading…</p>
    </div>
  );
}
