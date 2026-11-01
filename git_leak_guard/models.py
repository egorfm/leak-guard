"""
Data models for GitLeakGuard.
"""

from __future__ import annotations
import dataclasses
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Any


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        levels = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }
        return levels.get(self, 0)

    @classmethod
    def from_string(cls, val: str) -> Severity:
        try:
            return cls[val.upper()]
        except KeyError:
            return cls.INFO


@dataclass
class Finding:
    rule_id: str
    rule_name: str
    severity: Severity
    description: str
    file_path: str
    line_number: Optional[int] = None
    commit_hash: Optional[str] = None
    commit_author: Optional[str] = None
    commit_date: Optional[str] = None
    masked_secret: str = ""
    raw_snippet: str = ""
    entropy: Optional[float] = None
    remediation_hint: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity.value,
            "description": self.description,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "commit_hash": self.commit_hash,
            "commit_author": self.commit_author,
            "commit_date": self.commit_date,
            "masked_secret": self.masked_secret,
            "raw_snippet": self.raw_snippet,
            "entropy": round(self.entropy, 2) if self.entropy is not None else None,
            "remediation_hint": self.remediation_hint,
        }


@dataclass
class ScanResult:
    repo_name: str
    repo_url: str
    is_fork: bool = False
    default_branch: str = "main"
    stars: int = 0
    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    commits_scanned: int = 0
    duration_seconds: float = 0.0
    error: Optional[str] = None

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0

    @property
    def max_severity(self) -> Optional[Severity]:
        if not self.findings:
            return None
        return max(self.findings, key=lambda f: f.severity.rank).severity

    def to_dict(self) -> Dict[str, Any]:
        return {
            "repo_name": self.repo_name,
            "repo_url": self.repo_url,
            "is_fork": self.is_fork,
            "default_branch": self.default_branch,
            "stars": self.stars,
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "files_scanned": self.files_scanned,
            "commits_scanned": self.commits_scanned,
            "duration_seconds": round(self.duration_seconds, 2),
            "error": self.error,
        }


@dataclass
class AuditSummary:
    target: str
    scan_timestamp: str
    total_repos_scanned: int = 0
    repos_with_findings: int = 0
    total_findings: int = 0
    findings_by_severity: Dict[str, int] = field(default_factory=lambda: {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
    })
    results: List[ScanResult] = field(default_factory=list)
    total_duration_seconds: float = 0.0

    def compute_totals(self) -> None:
        self.total_repos_scanned = len(self.results)
        self.repos_with_findings = sum(1 for r in self.results if r.has_findings)
        self.total_findings = sum(len(r.findings) for r in self.results)
        
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for r in self.results:
            for f in r.findings:
                s = f.severity.value
                counts[s] = counts.get(s, 0) + 1
        self.findings_by_severity = counts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "scan_timestamp": self.scan_timestamp,
            "total_repos_scanned": self.total_repos_scanned,
            "repos_with_findings": self.repos_with_findings,
            "total_findings": self.total_findings,
            "findings_by_severity": self.findings_by_severity,
            "total_duration_seconds": round(self.total_duration_seconds, 2),
            "repositories": [r.to_dict() for r in self.results],
        }
