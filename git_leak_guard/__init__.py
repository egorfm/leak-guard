"""
GitLeakGuard - Public GitHub Repository Secret & Security Auditor
"""

__version__ = "1.0.0"
__author__ = "Egor"

from git_leak_guard.models import Finding, ScanResult, AuditSummary
from git_leak_guard.scanner import RepoScanner
from git_leak_guard.rules import RuleEngine

__all__ = [
    "Finding",
    "ScanResult",
    "AuditSummary",
    "RepoScanner",
    "RuleEngine",
    "__version__",
]
