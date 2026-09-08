"""
Cross-file import analysis for Python packages.

Builds an import graph from Python source files in a repository and detects:

  1. Circular imports — import cycles between internal modules.
     Circular imports cause subtle initialisation bugs and are always wrong.

  2. Unused internal imports — a module is imported by another internal module
     but never actually referenced (by Name or Attribute) in that file.
     Only internal (same-package) imports are checked; third-party and stdlib
     imports are not tracked here (handled by the per-file AST analyser).

Usage::

    from app.services.scan_engine.import_graph import analyze_imports
    from app.services.scan_engine.analyzers import FindingResult

    findings: list[FindingResult] = analyze_imports(Path("/path/to/repo"))

The function walks the repository for ``*.py`` files, builds the graph, and
returns ``FindingResult`` objects compatible with the rest of the scan engine.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Dict, List, Set, Tuple

from app.services.scan_engine.analyzers import FindingResult, IGNORED_DIRS


# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------

# Fully-qualified dotted module path relative to *root*, e.g. "app.api.auth"
ModuleName = str
# Map: module → set of modules it imports (internal only)
ImportGraph = Dict[ModuleName, Set[ModuleName]]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _path_to_module(root: Path, path: Path) -> ModuleName:
    """Convert an absolute path to a dotted module name relative to *root*.

    e.g. /project/app/api/auth.py → "app.api.auth"
    """
    rel = path.relative_to(root)
    parts = list(rel.parts)
    if parts[-1] == "__init__.py":
        parts = parts[:-1]
    else:
        parts[-1] = parts[-1][:-3]  # strip .py
    return ".".join(parts)


def _collect_python_files(root: Path) -> List[Path]:
    """Return all ``*.py`` files under root, excluding ignored directories."""
    result = []
    for path in root.rglob("*.py"):
        if not any(part in IGNORED_DIRS for part in path.parts):
            result.append(path)
    return result


def _parse_imports(
    source: str,
    module_name: ModuleName,
    known_modules: Set[ModuleName],
) -> List[Tuple[ModuleName, int]]:
    """
    Parse *source* and return ``(imported_module_name, lineno)`` pairs for
    every ``import`` / ``from … import`` statement that references a known
    internal module.

    For ``from .utils import helper``, the relative import is resolved against
    *module_name*.
    """
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        # SyntaxError  — unparseable source.
        # ValueError   — source contains null bytes (binary file with .py suffix).
        return []

    results: List[Tuple[ModuleName, int]] = []
    package = ".".join(module_name.split(".")[:-1])  # parent package

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.name
                if name in known_modules or any(
                    name.startswith(f"{m}.") for m in known_modules
                ):
                    # Use the top-level prefix that matches
                    matched = next(
                        (m for m in known_modules if name == m or name.startswith(f"{m}.")),
                        None,
                    )
                    if matched:
                        results.append((matched, node.lineno))

        elif isinstance(node, ast.ImportFrom):
            level = node.level  # number of leading dots (relative import depth)
            mod = node.module or ""

            if level == 0:
                # Absolute import
                full = mod
            else:
                # Relative import: resolve against current package
                parts = package.split(".") if package else []
                # Go up `level - 1` levels (1 dot = same package)
                up = level - 1
                if up > 0 and len(parts) >= up:
                    parts = parts[:-up]
                base = ".".join(parts)
                full = f"{base}.{mod}" if (base and mod) else base or mod

            if full in known_modules:
                results.append((full, node.lineno))
            elif any(full.startswith(f"{m}.") or full == m for m in known_modules):
                matched = next(
                    (m for m in known_modules if full == m or full.startswith(f"{m}.")),
                    None,
                )
                if matched:
                    results.append((matched, node.lineno))

    return results


# ---------------------------------------------------------------------------
# Cycle detection (DFS)
# ---------------------------------------------------------------------------


def _find_cycles(graph: ImportGraph) -> List[List[ModuleName]]:
    """
    Find all simple cycles in a directed graph using DFS with a colour map.

    Returns a list of cycles, where each cycle is a list of module names
    (the last element is the same as the first to close the loop).

    Only the *first* occurrence of each cycle is returned (smallest canonical
    rotation) to avoid duplicates.
    """
    WHITE, GRAY, BLACK = 0, 1, 2
    colour: dict[ModuleName, int] = {m: WHITE for m in graph}
    stack: list[ModuleName] = []
    cycles: list[list[ModuleName]] = []
    seen_cycles: set[frozenset] = set()

    def dfs(node: ModuleName) -> None:
        colour[node] = GRAY
        stack.append(node)

        for neighbour in graph.get(node, set()):
            if colour.get(neighbour, WHITE) == GRAY:
                # Found a cycle — extract it from the stack.
                idx = stack.index(neighbour)
                cycle = stack[idx:] + [neighbour]
                key = frozenset(cycle)
                if key not in seen_cycles:
                    seen_cycles.add(key)
                    cycles.append(cycle)
            elif colour.get(neighbour, WHITE) == WHITE:
                dfs(neighbour)

        stack.pop()
        colour[node] = BLACK

    for node in list(graph.keys()):
        if colour[node] == WHITE:
            dfs(node)

    return cycles


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def analyze_imports(root: Path) -> List[FindingResult]:
    """
    Build the import graph for the Python package rooted at *root* and return
    a list of ``FindingResult`` objects for:

    - Circular imports (high severity)
    - Unused internal imports (low severity)

    Parameters
    ----------
    root:
        Absolute path to the repository root.

    Returns
    -------
    List[FindingResult]
    """
    py_files = _collect_python_files(root)
    if not py_files:
        return []

    # Map path → module name
    path_to_mod: dict[Path, ModuleName] = {
        p: _path_to_module(root, p) for p in py_files
    }
    known_modules: Set[ModuleName] = set(path_to_mod.values())

    # Build graph: module → set of internally-imported modules
    # Also track: (importer, imported, lineno) for unused-import checks
    graph: ImportGraph = {m: set() for m in known_modules}
    import_edges: list[tuple[ModuleName, ModuleName, int]] = []  # (from, to, line)

    for path, module in path_to_mod.items():
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        for dep, lineno in _parse_imports(source, module, known_modules):
            if dep != module:  # avoid self-loops
                graph[module].add(dep)
                import_edges.append((module, dep, lineno))

    findings: List[FindingResult] = []

    # ── 1. Detect circular imports ────────────────────────────────────────
    cycles = _find_cycles(graph)
    for cycle in cycles:
        cycle_str = " → ".join(cycle)
        # Report the finding at line 1 of the first module in the cycle.
        first_module = cycle[0]
        first_path = next(
            (str(p.relative_to(root)) for p, m in path_to_mod.items() if m == first_module),
            first_module,
        )
        findings.append(
            FindingResult(
                severity="high",
                title="Circular import detected",
                description=(
                    f"Import cycle found: {cycle_str}. "
                    "Circular imports cause unpredictable initialisation order "
                    "and should be resolved by restructuring the code."
                ),
                file_path=first_path,
                line_number=1,
            )
        )

    # ── 2. Detect unused internal imports ─────────────────────────────────
    for path, module in path_to_mod.items():
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        try:
            tree = ast.parse(source)
        except (SyntaxError, ValueError):
            # ValueError covers null bytes in binary files with a .py suffix.
            continue

        # Internal imports in this file.
        local_imports = [
            (dep, lineno)
            for (importer, dep, lineno) in import_edges
            if importer == module
        ]
        if not local_imports:
            continue

        # Collect all names referenced in the module (excluding import stmts).
        referenced: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                continue
            if isinstance(node, ast.Name):
                referenced.add(node.id)
            elif isinstance(node, ast.Attribute):
                root_node = node
                while isinstance(root_node, ast.Attribute):
                    root_node = root_node.value
                if isinstance(root_node, ast.Name):
                    referenced.add(root_node.id)

        # Also respect __all__ for re-exports.
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Assign)
                and any(
                    isinstance(t, ast.Name) and t.id == "__all__"
                    for t in node.targets
                )
                and isinstance(node.value, (ast.List, ast.Tuple, ast.Set))
            ):
                for elt in node.value.elts:
                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                        referenced.add(elt.value)

        # Collect the local names bound by imports in this file.
        # For `import foo.bar as baz`: baz; for `from foo import bar`: bar.
        bound_names: dict[str, tuple[ModuleName, int]] = {}
        for inode in ast.walk(tree):
            if isinstance(inode, ast.Import):
                for alias in inode.names:
                    used_name = alias.asname or alias.name.split(".")[0]
                    dep_mod = alias.name
                    if dep_mod in known_modules or any(
                        dep_mod.startswith(f"{m}.") for m in known_modules
                    ):
                        bound_names[used_name] = (dep_mod, inode.lineno)
            elif isinstance(inode, ast.ImportFrom):
                for alias in inode.names:
                    if alias.name == "*":
                        continue
                    used_name = alias.asname or alias.name
                    # Reconstruct the full module name.
                    level = inode.level
                    mod = inode.module or ""
                    package = ".".join(module.split(".")[:-1])
                    if level > 0:
                        parts = package.split(".") if package else []
                        up = level - 1
                        if up > 0 and len(parts) >= up:
                            parts = parts[:-up]
                        base = ".".join(parts)
                        full = f"{base}.{mod}" if (base and mod) else base or mod
                    else:
                        full = mod
                    if full in known_modules:
                        bound_names[used_name] = (full, inode.lineno)

        for name, (dep_mod, lineno) in bound_names.items():
            if name.startswith("_"):
                continue  # intentional private/underscore import
            if name not in referenced:
                findings.append(
                    FindingResult(
                        severity="low",
                        title="Unused internal import",
                        description=(
                            f"'{name}' (from internal module '{dep_mod}') is "
                            "imported but never used in this file. "
                            "Remove unused imports to keep the module clean."
                        ),
                        file_path=str(path.relative_to(root)),
                        line_number=lineno,
                    )
                )

    return findings
