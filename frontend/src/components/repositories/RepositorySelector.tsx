"use client";

import { FormEvent, useState } from "react";
import { repositories as reposApi, type Repository } from "@/lib/api";

interface RepositorySelectorProps {
  repositories: Repository[];
  selectedId: string;
  projectId: string;
  loading: boolean;
  disabled?: boolean;
  onSelect: (id: string) => void;
  onCreated: (repo: Repository) => void;
}

export default function RepositorySelector({
  repositories,
  selectedId,
  projectId,
  loading,
  disabled = false,
  onSelect,
  onCreated,
}: RepositorySelectorProps) {
  const [showForm, setShowForm] = useState(false);
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleCreate(e: FormEvent) {
    e.preventDefault();
    if (!name.trim() || !url.trim()) return;
    setError(null);
    setCreating(true);

    try {
      const repo = await reposApi.create(name.trim(), url.trim(), projectId);
      onCreated(repo);
      setName("");
      setUrl("");
      setShowForm(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to add repository.");
    } finally {
      setCreating(false);
    }
  }

  const isDisabled = disabled || loading || !projectId;

  return (
    <div className="selector-group">
      <label>
        <span>Repository</span>
        <select
          value={selectedId}
          onChange={(e) => onSelect(e.target.value)}
          disabled={isDisabled || repositories.length === 0}
        >
          {repositories.length === 0 ? (
            <option value="">
              {!projectId ? "Select a project first" : "No repositories — add one below"}
            </option>
          ) : (
            repositories.map((r) => (
              <option key={r.id} value={r.id}>
                {r.name}
              </option>
            ))
          )}
        </select>
      </label>

      {!showForm ? (
        <button
          type="button"
          className="ghost-button"
          onClick={() => setShowForm(true)}
          disabled={!projectId}
        >
          + Add repository
        </button>
      ) : (
        <form
          onSubmit={(e) => { void handleCreate(e); }}
          className="inline-form repo-form"
        >
          <input
            type="text"
            placeholder="Repository name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            autoFocus
            disabled={creating}
          />
          <input
            type="url"
            placeholder="https://github.com/user/repo"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            disabled={creating}
          />
          <button
            type="submit"
            className="primary-button"
            disabled={creating || !name.trim() || !url.trim()}
          >
            {creating ? "Adding…" : "Add"}
          </button>
          <button
            type="button"
            className="ghost-button"
            onClick={() => { setShowForm(false); setError(null); }}
          >
            Cancel
          </button>
        </form>
      )}

      {error && <div className="inline-error">{error}</div>}
    </div>
  );
}
