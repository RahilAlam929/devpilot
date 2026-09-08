"""
Python AST-based static analysis.

Operates on a single Python source file that has already been parsed into an
``ast.Module`` by the caller.  Returns a list of ``FindingResult`` objects.

Rules implemented here require structural understanding that regex cannot
reliably provide:

  1. Unused imports — an ``import`` or ``from … import`` statement where the
     imported name is never referenced in the rest of the module.

  2. Missing return type annotations on public functions — any function whose
     name does not start with ``_`` and that has no ``-> …`` annotation.

  3. Mutable default arguments — a function parameter whose default value is a
     ``list``, ``dict``, or ``set`` literal.  This is a classic Python trap:
     the default is created once and shared across all calls.

  4. Bare ``raise`` outside an except block — ``raise`` with no argument is
     only valid inside an except block; using it elsewhere re-raises whatever
     the current exception happens to be (often None, causing a confusing
     RuntimeError).
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import List


@dataclass
class ASTFinding:
    """A single finding produced by AST analysis."""

    severity: str
    title: str
    description: str
    line_number: int


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def analyze_ast(source: str, filename: str = "<unknown>") -> List[ASTFinding]:
    """
    Parse *source* and run all AST rules.

    Parameters
    ----------
    source:
        The raw Python source code to analyse.
    filename:
        Used only for ``ast.parse``'s ``filename`` parameter (affects the
        text of SyntaxError messages).

    Returns
    -------
    List[ASTFinding]
        Possibly empty list of findings.  SyntaxErrors are silently swallowed
        (the file is simply skipped).
    """
    try:
        tree = ast.parse(source, filename=filename)
    except (SyntaxError, ValueError):
        # SyntaxError  — unparseable Python source.
        # ValueError   — source contains null bytes (e.g. binary data with a
        #                .py extension); ast.parse raises ValueError in that case.
        # In both cases we skip the file gracefully rather than crashing the scan.
        return []

    findings: List[ASTFinding] = []
    findings.extend(_check_unused_imports(tree))
    findings.extend(_check_missing_return_annotations(tree))
    findings.extend(_check_mutable_defaults(tree))
    findings.extend(_check_bare_raise(tree))
    return findings


# ---------------------------------------------------------------------------
# Rule 1 — Unused imports
# ---------------------------------------------------------------------------


def _check_unused_imports(tree: ast.Module) -> List[ASTFinding]:
    """
    Report ``import`` / ``from … import`` names that are never used.

    Limitations (intentional, to avoid false positives):
    - ``from module import *`` is ignored (we cannot track what names it
      introduces without resolving the module).
    - Re-exports in ``__init__.py`` style code: names that appear in
      ``__all__`` are considered "used".
    - ``import module as _alias`` — underscore-prefixed aliases signal that
      the import is intentionally unused (type-checking / side-effect import).
    """
    findings: List[ASTFinding] = []

    # Collect imported names with their source lines.
    # name → (alias used in code, line_number)
    imported: dict[str, tuple[str, int]] = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                used_name = alias.asname if alias.asname else alias.name.split(".")[0]
                if used_name.startswith("_"):
                    continue  # intentional unused import
                imported[used_name] = (alias.asname or alias.name, node.lineno)

        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == "*":
                    continue  # star import — skip
                used_name = alias.asname if alias.asname else alias.name
                if used_name.startswith("_"):
                    continue
                imported[used_name] = (alias.asname or alias.name, node.lineno)

    if not imported:
        return findings

    # Build the set of all names referenced in the module (outside import stmts).
    referenced: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            continue  # skip the import nodes themselves
        if isinstance(node, ast.Name):
            referenced.add(node.id)
        elif isinstance(node, ast.Attribute):
            # Track the root name of attribute chains: ``os.path`` → ``os``
            root = node
            while isinstance(root, ast.Attribute):
                root = root.value
            if isinstance(root, ast.Name):
                referenced.add(root.id)

    # Also check __all__ for intentional re-exports.
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

    for used_name, (original_name, lineno) in imported.items():
        if used_name not in referenced:
            findings.append(
                ASTFinding(
                    severity="low",
                    title="Unused import",
                    description=(
                        f"'{original_name}' is imported but never used. "
                        "Remove unused imports to keep the module clean."
                    ),
                    line_number=lineno,
                )
            )

    return findings


# ---------------------------------------------------------------------------
# Rule 2 — Missing return-type annotation on public functions
# ---------------------------------------------------------------------------


def _check_missing_return_annotations(tree: ast.Module) -> List[ASTFinding]:
    """
    Report public (non-underscore-prefixed) function/method definitions that
    lack a ``-> …`` return-type annotation.

    Only top-level functions and methods defined directly inside a class body
    are checked (nested functions are skipped to reduce noise).
    ``__init__`` is exempt because its return type is always ``None``.
    """
    findings: List[ASTFinding] = []

    # Collect top-level and class-level function definitions.
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _check_fn_annotation(node, findings)
        elif isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    _check_fn_annotation(item, findings)

    return findings


def _check_fn_annotation(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    findings: List[ASTFinding],
) -> None:
    name = node.name
    # Private / dunder methods are exempt.
    if name.startswith("_"):
        return
    if node.returns is None:
        findings.append(
            ASTFinding(
                severity="low",
                title="Missing return type annotation",
                description=(
                    f"Public function '{name}' has no return type annotation. "
                    "Add `-> ReturnType` to improve type-safety and IDE support."
                ),
                line_number=node.lineno,
            )
        )


# ---------------------------------------------------------------------------
# Rule 3 — Mutable default arguments
# ---------------------------------------------------------------------------

# Node types that represent mutable literals in a default value position.
_MUTABLE_NODES = (ast.List, ast.Dict, ast.Set)
_MUTABLE_NAMES = {"list", "dict", "set"}  # bare calls like list()


def _check_mutable_defaults(tree: ast.Module) -> List[ASTFinding]:
    """
    Report function parameters whose default value is a mutable literal
    (``[]``, ``{}``, ``set()``, etc.).

    Using a mutable object as a default argument is a classic Python bug:
    the same object is shared across all calls.
    """
    findings: List[ASTFinding] = []

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        all_args = (
            node.args.args
            + node.args.posonlyargs
            + node.args.kwonlyargs
        )

        # defaults align to the *end* of args; kwonlyargs use kw_defaults.
        num_defaults = len(node.args.defaults)
        offset = len(all_args) - num_defaults

        for i, default in enumerate(node.args.defaults):
            if isinstance(default, _MUTABLE_NODES):
                arg = all_args[offset + i] if (offset + i) < len(all_args) else None
                arg_name = arg.arg if isinstance(arg, ast.arg) else "?"
                findings.append(
                    ASTFinding(
                        severity="medium",
                        title="Mutable default argument",
                        description=(
                            f"Parameter '{arg_name}' in '{node.name}' uses a "
                            "mutable default value. The same object is shared "
                            "across all calls. Use `None` as the default and "
                            "initialise inside the function body."
                        ),
                        line_number=default.lineno,
                    )
                )
            elif (
                isinstance(default, ast.Call)
                and isinstance(default.func, ast.Name)
                and default.func.id in _MUTABLE_NAMES
                and not default.args
                and not default.keywords
            ):
                arg = all_args[offset + i] if (offset + i) < len(all_args) else None
                arg_name = arg.arg if isinstance(arg, ast.arg) else "?"
                findings.append(
                    ASTFinding(
                        severity="medium",
                        title="Mutable default argument",
                        description=(
                            f"Parameter '{arg_name}' in '{node.name}' uses "
                            f"`{default.func.id}()` as a default value. "
                            "This creates one shared mutable object. "
                            "Use `None` as the default instead."
                        ),
                        line_number=default.lineno,
                    )
                )

        # kw_defaults may contain None entries (meaning no default).
        for i, default in enumerate(node.args.kw_defaults):
            if default is None:
                continue
            kw_arg = node.args.kwonlyargs[i] if i < len(node.args.kwonlyargs) else None
            arg_name = kw_arg.arg if isinstance(kw_arg, ast.arg) else "?"
            if isinstance(default, _MUTABLE_NODES):
                findings.append(
                    ASTFinding(
                        severity="medium",
                        title="Mutable default argument",
                        description=(
                            f"Keyword-only parameter '{arg_name}' in '{node.name}' "
                            "uses a mutable default. Use `None` instead."
                        ),
                        line_number=default.lineno,
                    )
                )

    return findings


# ---------------------------------------------------------------------------
# Rule 4 — Bare raise outside except block
# ---------------------------------------------------------------------------


def _check_bare_raise(tree: ast.Module) -> List[ASTFinding]:
    """
    Report bare ``raise`` statements (``raise`` with no expression) that
    appear *outside* of an ``except`` handler body.

    A bare ``raise`` re-raises the active exception.  Outside a handler there
    is no active exception, so it raises a ``RuntimeError: No active exception
    to re-raise`` at runtime.
    """
    findings: List[ASTFinding] = []
    _walk_for_bare_raise(tree, in_handler=False, findings=findings)
    return findings


def _walk_for_bare_raise(
    node: ast.AST,
    in_handler: bool,
    findings: List[ASTFinding],
) -> None:
    """Recursively walk the AST, tracking whether we are inside a handler."""
    if isinstance(node, ast.Raise) and node.exc is None and not in_handler:
        findings.append(
            ASTFinding(
                severity="medium",
                title="Bare raise outside except block",
                description=(
                    "A bare `raise` statement was found outside an except "
                    "handler. There is no active exception to re-raise here, "
                    "which will cause a RuntimeError at runtime."
                ),
                line_number=node.lineno,
            )
        )
        return  # No children to recurse into

    for child in ast.iter_child_nodes(node):
        # When we enter an ExceptHandler, flip the flag for its body.
        if isinstance(child, ast.ExceptHandler):
            _walk_for_bare_raise(child, in_handler=True, findings=findings)
        else:
            _walk_for_bare_raise(child, in_handler=in_handler, findings=findings)
