from dataclasses import dataclass
from pathlib import Path
import re


@dataclass
class FindingResult:
    severity: str
    title: str
    description: str
    file_path: str
    line_number: int


IGNORED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".next",
    "dist",
    "build",
}

ALLOWED_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".java",
    ".go",
    ".rs",
    ".php",
    ".rb",
    ".cpp",
    ".c",
    ".h",
    ".hpp",
}


def should_scan(path: Path) -> bool:
    return (
        path.is_file()
        and path.suffix.lower() in ALLOWED_EXTENSIONS
        and not any(part in IGNORED_DIRS for part in path.parts)
    )


def analyze_file(root: Path, path: Path) -> list[FindingResult]:
    findings: list[FindingResult] = []

    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return findings

    relative_path = str(path.relative_to(root))

    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()

        if "TODO" in stripped or "FIXME" in stripped:
            findings.append(
                FindingResult(
                    severity="info",
                    title="TODO/FIXME comment",
                    description="Unfinished work marker found in source code.",
                    file_path=relative_path,
                    line_number=line_number,
                )
            )

        if path.suffix.lower() == ".py":
            if re.search(r"\bprint\s*\(", line):
                findings.append(
                    FindingResult(
                        severity="low",
                        title="Debug print statement",
                        description="A print() statement was found in Python source code.",
                        file_path=relative_path,
                        line_number=line_number,
                    )
                )

            if re.search(r"except\s+Exception\s*:", line):
                findings.append(
                    FindingResult(
                        severity="medium",
                        title="Broad exception handling",
                        description="Catching Exception broadly can hide unexpected errors.",
                        file_path=relative_path,
                        line_number=line_number,
                    )
                )

        secret_pattern = re.compile(
            r"(API_KEY|SECRET_KEY|ACCESS_TOKEN|PASSWORD)\s*=\s*['\"][^'\"]+['\"]",
            re.IGNORECASE,
        )

        if secret_pattern.search(line):
            findings.append(
                FindingResult(
                    severity="high",
                    title="Possible hardcoded secret",
                    description="A possible credential or secret appears to be hardcoded.",
                    file_path=relative_path,
                    line_number=line_number,
                )
            )

    return findings


def analyze_repository(root: Path) -> list[FindingResult]:
    findings: list[FindingResult] = []

    for path in root.rglob("*"):
        if should_scan(path):
            findings.extend(analyze_file(root, path))

    return findings
