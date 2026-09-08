"use client";

import { FormEvent, useState } from "react";
import Link from "next/link";
import { login } from "@/lib/auth";
import { ApiError } from "@/lib/api";

interface LoginFormProps {
  onSuccess: () => void;
}

export default function LoginForm({ onSuccess }: LoginFormProps) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      await login(email.trim(), password);
      onSuccess();
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError("Something went wrong. Please try again.");
      }
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="auth-card">
      <div className="auth-brand">
        <div className="brand-mark">D</div>
        <div>
          <div className="brand-name">DevPilot</div>
          <div className="brand-subtitle">Code Intelligence</div>
        </div>
      </div>

      <h1 className="auth-title">Welcome back</h1>
      <p className="auth-subtitle">Sign in to your workspace</p>

      <form onSubmit={(e) => { void handleSubmit(e); }} className="auth-form" noValidate>
        <label className="field">
          <span>Email address</span>
          <input
            type="email"
            autoComplete="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="you@example.com"
            required
            disabled={loading}
          />
        </label>

        <label className="field">
          <span>Password</span>
          <input
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="••••••••"
            required
            disabled={loading}
          />
        </label>

        {error && (
          <div className="auth-error" role="alert">
            {error}
          </div>
        )}

        <button type="submit" className="primary-button auth-submit" disabled={loading}>
          {loading ? "Signing in…" : "Sign in →"}
        </button>
      </form>

      <p className="auth-footer">
        No account?{" "}
        <Link href="/register" className="auth-link">
          Create one
        </Link>
      </p>
    </div>
  );
}
