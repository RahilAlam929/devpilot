from datetime import datetime
from pathlib import Path

from sqlalchemy.orm import Session

from app.models import Finding, Repository, Scan
from app.services.scan_engine.analyzers import analyze_repository


class ScanEngine:
    """Run safe static analysis for a repository."""

    def __init__(self, db: Session, scan: Scan, repository: Repository):
        self.db = db
        self.scan = scan
        self.repository = repository

    def run(self, repository_path: str) -> list[Finding]:
        root = Path(repository_path)

        if not root.exists():
            raise FileNotFoundError(
                f"Repository path does not exist: {root}"
            )

        if not root.is_dir():
            raise NotADirectoryError(
                f"Repository path is not a directory: {root}"
            )

        self.scan.status = "running"
        self.scan.started_at = datetime.utcnow()
        self.db.commit()

        try:
            results = analyze_repository(root)

            findings = []

            for result in results:
                finding = Finding(
                    scan_id=self.scan.id,
                    severity=result.severity,
                    title=result.title,
                    description=result.description,
                    file_path=result.file_path,
                    line_number=result.line_number,
                )

                self.db.add(finding)
                findings.append(finding)

            self.scan.status = "completed"
            self.scan.completed_at = datetime.utcnow()

            self.db.commit()

            for finding in findings:
                self.db.refresh(finding)

            self.db.refresh(self.scan)

            return findings

        except Exception:
            self.scan.status = "failed"
            self.scan.completed_at = datetime.utcnow()
            self.db.commit()
            raise
