"use client";

import { FormEvent, useState } from "react";
import { projects as projectsApi, type Project } from "@/lib/api";

interface ProjectSelectorProps {
  projects: Project[];
  selectedId: string;
  loading: boolean;
  onSelect: (id: string) => void;
  onCreated: (project: Project) => void;
}

export default function ProjectSelector({
  projects,
  selectedId,
  loading,
  onSelect,
  onCreated,
}: ProjectSelectorProps) {
  const [showForm, setShowForm] = useState(false);
  const [name, setName] = useState("");
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleCreate(e: FormEvent) {
    e.preventDefault();
    if (!name.trim()) return;
    setError(null);
    setCreating(true);

    try {
      const project = await projectsApi.create(name.trim());
      onCreated(project);
      setName("");
      setShowForm(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create project.");
    } finally {
      setCreating(false);
    }
  }

  return (
    <div className="selector-group">
      <label>
        <span>Project</span>
        <select
          value={selectedId}
          onChange={(e) => onSelect(e.target.value)}
          disabled={loading || projects.length === 0}
        >
          {projects.length === 0 ? (
            <option value="">No projects — create one below</option>
          ) : (
            projects.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
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
        >
          + New project
        </button>
      ) : (
        <form
          onSubmit={(e) => { void handleCreate(e); }}
          className="inline-form"
        >
          <input
            type="text"
            placeholder="Project name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            autoFocus
            disabled={creating}
          />
          <button type="submit" className="primary-button" disabled={creating || !name.trim()}>
            {creating ? "Creating…" : "Create"}
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
