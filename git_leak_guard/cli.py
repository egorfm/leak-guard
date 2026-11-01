"""
Command Line Interface for GitLeakGuard.
"""

from __future__ import annotations
import argparse
import datetime
import os
import sys
import time
from typing import List

from git_leak_guard.github_client import GitHubClient
from git_leak_guard.models import AuditSummary, ScanResult, Severity
from git_leak_guard.reporter import ConsoleReporter, ReportExporter
from git_leak_guard.scanner import RepoScanner


def parse_args(args: List[str] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="git-leak-guard",
        description="🛡️ Audit public GitHub repositories for leaked credentials, API keys, and sensitive data.",
    )

    subparsers = parser.add_subparsers(dest="command", help="Target command to run")

    # scan-user command
    user_parser = subparsers.add_parser("scan-user", help="Scan all public repositories of a GitHub user/organization")
    user_parser.add_argument("username", help="GitHub username or organization name")
    _add_common_scan_flags(user_parser)
    user_parser.add_argument("--exclude-forks", action="store_true", help="Exclude forked repositories from scan")

    # scan-repo command
    repo_parser = subparsers.add_parser("scan-repo", help="Scan a single GitHub repository")
    repo_parser.add_argument("repo", help="Repository URL (https://github.com/owner/repo) or 'owner/repo'")
    _add_common_scan_flags(repo_parser)

    # scan-local command
    local_parser = subparsers.add_parser("scan-local", help="Scan a local folder or git repository")
    local_parser.add_argument("path", default=".", nargs="?", help="Path to local folder (default: .)")
    _add_common_scan_flags(local_parser)

    if args is None:
        args = sys.argv[1:]

    # Default to --help if no arguments passed
    if not args:
        parser.print_help()
        sys.exit(0)

    return parser.parse_args(args)


def _add_common_scan_flags(parser: argparse.ArgumentParser):
    parser.add_argument("--token", help="GitHub Personal Access Token (for higher rate limits)")
    parser.add_argument("--fast", action="store_true", help="Shallow scan only (skip deep commit history)")
    parser.add_argument("--output", "-o", help="Save report to file (e.g. report.html, report.json, report.md)")
    parser.add_argument("--format", choices=["terminal", "html", "json", "markdown"], default="terminal", help="Output format")
    parser.add_argument(
        "--min-severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default="LOW",
        help="Minimum severity level to display/report",
    )
    parser.add_argument(
        "--fail-on",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        help="Exit with non-zero code if findings at or above this severity are detected",
    )


def run_audit(args: argparse.Namespace) -> int:
    reporter = ConsoleReporter()
    reporter.print_banner()

    min_sev = Severity.from_string(args.min_severity)
    deep_scan = not args.fast
    start_time = time.time()
    now_iso = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    scanner = RepoScanner()
    results: List[ScanResult] = []
    target_name = ""

    if args.command == "scan-local":
        target_name = f"Local: {args.path}"
        print(f"🔍 Scanning local path: {args.path} ...")
        res = scanner.scan_local_directory(args.path)
        # Filter by severity
        res.findings = [f for f in res.findings if f.severity.rank >= min_sev.rank]
        results.append(res)

    elif args.command == "scan-repo":
        target_name = args.repo
        client = GitHubClient(token=args.token)
        print(f"🔍 Fetching repository metadata for {args.repo} ...")
        try:
            repo_data = client.get_single_repository(args.repo)
        except Exception as e:
            print(f"❌ Error fetching repository: {e}", file=sys.stderr)
            return 1

        clone_url = repo_data.get("clone_url")
        repo_name = repo_data.get("full_name", args.repo)
        print(f"🚀 Scanning {repo_name} (deep history: {deep_scan}) ...")
        res = scanner.scan_remote_repo(
            repo_url=clone_url,
            repo_name=repo_name,
            is_fork=repo_data.get("fork", False),
            default_branch=repo_data.get("default_branch", "main"),
            stars=repo_data.get("stargazers_count", 0),
            deep=deep_scan,
        )
        res.findings = [f for f in res.findings if f.severity.rank >= min_sev.rank]
        results.append(res)

    elif args.command == "scan-user":
        target_name = f"User/Org: {args.username}"
        client = GitHubClient(token=args.token)
        print(f"🔍 Discovering public repositories for {args.username} ...")
        try:
            repos = client.get_user_repositories(args.username, exclude_forks=args.exclude_forks)
        except Exception as e:
            print(f"❌ Error discovering repositories: {e}", file=sys.stderr)
            return 1

        total_repos = len(repos)
        print(f"📦 Found {total_repos} public repositories. Starting audit (deep history: {deep_scan})...\n")

        for idx, r in enumerate(repos, start=1):
            name = r.get("full_name", r.get("name"))
            clone_url = r.get("clone_url")
            print(f"[{idx}/{total_repos}] Auditing {name} ...", end="", flush=True)
            res = scanner.scan_remote_repo(
                repo_url=clone_url,
                repo_name=name,
                is_fork=r.get("fork", False),
                default_branch=r.get("default_branch", "main"),
                stars=r.get("stargazers_count", 0),
                deep=deep_scan,
            )
            res.findings = [f for f in res.findings if f.severity.rank >= min_sev.rank]
            results.append(res)
            if res.has_findings:
                print(f" ⚠️  {len(res.findings)} finding(s) detected!")
            elif res.error:
                print(f" ❌ {res.error}")
            else:
                print(" ✅ Clean")

    summary = AuditSummary(
        target=target_name,
        scan_timestamp=now_iso,
        results=results,
        total_duration_seconds=time.time() - start_time,
    )
    summary.compute_totals()

    # Always render summary to terminal unless pure json/markdown piped
    reporter.render_summary(summary)

    # Export if requested
    if args.output:
        out_ext = os.path.splitext(args.output)[1].lower()
        if out_ext == ".html" or args.format == "html":
            ReportExporter.to_html(summary, args.output)
            print(f"\n📄 HTML report generated: {args.output}")
        elif out_ext == ".json" or args.format == "json":
            ReportExporter.to_json(summary, args.output)
            print(f"\n📄 JSON report generated: {args.output}")
        elif out_ext in [".md", ".markdown"] or args.format == "markdown":
            ReportExporter.to_markdown(summary, args.output)
            print(f"\n📄 Markdown report generated: {args.output}")
        else:
            # Fallback to HTML if unknown extension
            ReportExporter.to_html(summary, args.output)
            print(f"\n📄 Report generated: {args.output}")

    # Check fail-on condition for CI/CD
    if args.fail_on:
        threshold_rank = Severity.from_string(args.fail_on).rank
        for repo in summary.results:
            for f in repo.findings:
                if f.severity.rank >= threshold_rank:
                    print(
                        f"\n❌ Failure condition met: Found {f.severity.value} finding (threshold: {args.fail_on})."
                    )
                    return 1

    return 0


def main():
    args = parse_args()
    code = run_audit(args)
    sys.exit(code)


if __name__ == "__main__":
    main()
