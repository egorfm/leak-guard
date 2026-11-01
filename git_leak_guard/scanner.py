"""
Repository scanning engine supporting both working tree and deep commit history analysis.
"""

from __future__ import annotations
import os
import subprocess
import tempfile
import time
from pathlib import Path
from typing import List, Optional, Set

from git_leak_guard.models import Finding, ScanResult
from git_leak_guard.rules import RuleEngine

# File extensions to ignore (binaries, assets, compiled code, lockfiles)
IGNORED_EXTENSIONS: Set[str] = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp", ".bmp", ".tiff",
    ".mp3", ".mp4", ".wav", ".avi", ".mov", ".mkv",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".exe", ".dll", ".so", ".dylib", ".bin",
    ".pyc", ".pyo", ".pyd", ".class", ".jar", ".war",
    ".woff", ".woff2", ".ttf", ".eot",
    ".lock",
}

# Directories to ignore
IGNORED_DIRS: Set[str] = {
    ".git", ".svn", ".hg", "node_modules", "vendor", "dist", "build",
    "__pycache__", ".venv", "venv", ".idea", ".vscode", "target",
}

# Filenames to ignore
IGNORED_FILENAMES: Set[str] = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "composer.lock",
    "poetry.lock", "Gemfile.lock", "Cargo.lock",
}

MAX_FILE_SIZE_BYTES = 1 * 1024 * 1024  # 1 MB


def is_binary_file(file_path: Path) -> bool:
    """Check if file appears to be binary by reading the first 1024 bytes."""
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(1024)
            return b"\0" in chunk
    except Exception:
        return True


class RepoScanner:
    def __init__(self, rule_engine: Optional[RuleEngine] = None):
        self.rules = rule_engine or RuleEngine()

    def scan_local_directory(self, target_dir: str | Path) -> ScanResult:
        """Scan a local directory or local git repo."""
        start_time = time.time()
        path = Path(target_dir).resolve()
        repo_name = path.name

        result = ScanResult(
            repo_name=repo_name,
            repo_url=str(path),
        )

        if not path.exists():
            result.error = f"Path {path} does not exist"
            result.duration_seconds = time.time() - start_time
            return result

        files_count = 0
        findings: List[Finding] = []

        for root, dirs, files in os.walk(path):
            # Prune ignored directories in-place
            dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]

            for file in files:
                if file in IGNORED_FILENAMES:
                    continue

                file_path = Path(root) / file
                rel_path = str(file_path.relative_to(path))

                # Check filename rule
                fn_finding = self.rules.scan_filename(rel_path)
                if fn_finding:
                    findings.append(fn_finding)

                # Extension filter
                if file_path.suffix.lower() in IGNORED_EXTENSIONS:
                    continue

                # File size filter
                try:
                    if file_path.stat().st_size > MAX_FILE_SIZE_BYTES:
                        continue
                except OSError:
                    continue

                # Binary check
                if is_binary_file(file_path):
                    continue

                files_count += 1
                try:
                    content = file_path.read_text(encoding="utf-8", errors="ignore")
                    file_findings = self.rules.scan_text(content, file_path=rel_path)
                    findings.extend(file_findings)
                except Exception:
                    continue

        result.files_scanned = files_count
        result.findings = findings
        result.duration_seconds = time.time() - start_time
        return result

    def scan_git_history(self, repo_dir: Path) -> Tuple[List[Finding], int]:
        """Scan commit history using git log -p to catch secrets deleted in previous commits."""
        findings: List[Finding] = []
        commits_scanned = 0

        try:
            # Format: commit hash, author name, date, followed by diff
            cmd = [
                "git", "-C", str(repo_dir), "log", "-p", "--all",
                "--format=COMMIT_METADATA:%H|%an|%ad", "--date=iso-strict"
            ]
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                errors="ignore"
            )

            current_commit: Optional[str] = None
            current_author: Optional[str] = None
            current_date: Optional[str] = None
            current_file = "unknown"

            for line in proc.stdout:
                if line.startswith("COMMIT_METADATA:"):
                    commits_scanned += 1
                    parts = line.strip().split(":", 1)[1].split("|")
                    if len(parts) >= 3:
                        current_commit, current_author, current_date = parts[0], parts[1], parts[2]
                    continue

                if line.startswith("diff --git a/"):
                    parts = line.strip().split(" b/")
                    if len(parts) == 2:
                        current_file = parts[1]
                    continue

                # Only scan added or modified lines in diff
                if line.startswith("+") and not line.startswith("+++"):
                    added_text = line[1:]
                    diff_findings = self.rules.scan_text(
                        added_text,
                        file_path=current_file,
                        commit_hash=current_commit,
                        commit_author=current_author,
                        commit_date=current_date,
                    )
                    findings.extend(diff_findings)

            proc.wait()
        except Exception:
            pass

        return findings, commits_scanned

    def scan_remote_repo(
        self,
        repo_url: str,
        repo_name: str,
        is_fork: bool = False,
        default_branch: str = "main",
        stars: int = 0,
        deep: bool = True,
    ) -> ScanResult:
        """Clone remote repository into a temporary directory and perform security scan."""
        start_time = time.time()
        result = ScanResult(
            repo_name=repo_name,
            repo_url=repo_url,
            is_fork=is_fork,
            default_branch=default_branch,
            stars=stars,
        )

        with tempfile.TemporaryDirectory(prefix="gitleak_") as temp_dir:
            temp_path = Path(temp_dir)
            clone_cmd = ["git", "clone"]
            if not deep:
                clone_cmd.extend(["--depth", "1"])
            clone_cmd.extend([repo_url, str(temp_path)])

            try:
                clone_res = subprocess.run(
                    clone_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=120,
                    text=True,
                )
                if clone_res.returncode != 0:
                    result.error = f"Git clone failed: {clone_res.stderr.strip()}"
                    result.duration_seconds = time.time() - start_time
                    return result
            except subprocess.TimeoutExpired:
                result.error = "Git clone timed out (repository too large)"
                result.duration_seconds = time.time() - start_time
                return result
            except Exception as e:
                result.error = f"Failed to execute git clone: {str(e)}"
                result.duration_seconds = time.time() - start_time
                return result

            # Scan working tree files
            tree_result = self.scan_local_directory(temp_path)
            all_findings = list(tree_result.findings)
            files_scanned = tree_result.files_scanned
            commits_scanned = 1

            # Deep history scan if requested
            if deep:
                history_findings, commits_count = self.scan_git_history(temp_path)
                commits_scanned = max(1, commits_count)
                
                # Deduplicate findings by (rule_id, file_path, masked_secret)
                seen_keys = set()
                deduped = []
                for f in all_findings + history_findings:
                    key = (f.rule_id, f.file_path, f.masked_secret)
                    if key not in seen_keys:
                        seen_keys.add(key)
                        deduped.append(f)
                all_findings = deduped

            result.findings = all_findings
            result.files_scanned = files_scanned
            result.commits_scanned = commits_scanned
            result.duration_seconds = time.time() - start_time

        return result
