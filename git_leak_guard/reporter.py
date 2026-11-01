"""
Reporting engine for GitLeakGuard: Terminal, JSON, Markdown, and interactive HTML formats.
"""

from __future__ import annotations
import json
import html
from typing import Optional
from pathlib import Path
from git_leak_guard.models import AuditSummary, Finding, Severity

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


SEVERITY_COLORS = {
    Severity.CRITICAL: "red",
    Severity.HIGH: "bright_red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "cyan",
}

ANSI_COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH": "\033[31m",
    "MEDIUM": "\033[33m",
    "LOW": "\033[34m",
    "INFO": "\033[36m",
    "RESET": "\033[0m",
    "BOLD": "\033[1m",
    "GREEN": "\033[32m",
}


class ConsoleReporter:
    def __init__(self):
        self.console = Console() if RICH_AVAILABLE else None

    def print_banner(self):
        banner_text = """
   ____ _ _   _                _      ____                     _ 
  / ___(_) |_| |    ___   __ _| | __ / ___|_   _  __ _ _ __ __| |
 | |  _| | __| |   / _ \\ / _` | |/ /| |  _| | | |/ _` | '__/ _` |
 | |_| | | |_| |__|  __/| (_| |   < | |_| | |_| | (_| | | | (_| |
  \\____|_|\\__|_____\\___| \\__,_|_|\\_\\ \\____|\\__,_|\\__,_|_|  \\__,_|
  Defensive Security Scanner for Public GitHub Repositories v1.0.0
"""
        if RICH_AVAILABLE:
            self.console.print(f"[bold cyan]{banner_text}[/bold cyan]")
        else:
            print(f"{ANSI_COLORS['BOLD']}{ANSI_COLORS['INFO']}{banner_text}{ANSI_COLORS['RESET']}")

    def render_summary(self, summary: AuditSummary):
        if RICH_AVAILABLE:
            self._render_summary_rich(summary)
        else:
            self._render_summary_plain(summary)

    def _render_summary_rich(self, summary: AuditSummary):
        console = self.console
        console.print()

        # Findings table
        if summary.total_findings > 0:
            table = Table(
                title=f"Detected Vulnerabilities & Secrets for [bold cyan]{summary.target}[/bold cyan]",
                box=box.ROUNDED,
                show_header=True,
                header_style="bold magenta",
            )
            table.add_column("Severity", justify="center", width=12)
            table.add_column("Repository", style="cyan", width=22)
            table.add_column("Vulnerability / Rule", style="white", width=26)
            table.add_column("File & Line", style="dim", width=28)
            table.add_column("Masked Secret", style="yellow")
            table.add_column("Commit", style="dim", width=10)

            for repo in summary.results:
                for f in repo.findings:
                    sev_color = SEVERITY_COLORS.get(f.severity, "white")
                    sev_badge = f"[{sev_color} bold][{f.severity.value}][/{sev_color} bold]"
                    loc = f"{f.file_path}"
                    if f.line_number:
                        loc += f":{f.line_number}"
                    commit_short = f.commit_hash[:7] if f.commit_hash else "HEAD"
                    table.add_row(
                        sev_badge,
                        repo.repo_name,
                        f.rule_name,
                        loc,
                        f.masked_secret,
                        commit_short,
                    )

            console.print(table)
            console.print()

        # Overview Stats Card
        stat_table = Table(box=box.SIMPLE, show_header=False)
        stat_table.add_column("Metric", style="bold white", width=28)
        stat_table.add_column("Value", style="bold cyan")

        stat_table.add_row("Total Repositories Scanned:", str(summary.total_repos_scanned))
        stat_table.add_row(
            "Repositories with Secrets:",
            f"[bold red]{summary.repos_with_findings}[/bold red]" if summary.repos_with_findings > 0 else "[bold green]0 (Clean!)[/bold green]"
        )
        stat_table.add_row(
            "Total Leaked Secrets Found:",
            f"[bold red]{summary.total_findings}[/bold red]" if summary.total_findings > 0 else "[bold green]0[/bold green]"
        )
        stat_table.add_row(
            "Critical Findings:",
            f"[bold red]{summary.findings_by_severity.get('CRITICAL', 0)}[/bold red]"
        )
        stat_table.add_row(
            "High Findings:",
            f"[bold bright_red]{summary.findings_by_severity.get('HIGH', 0)}[/bold bright_red]"
        )
        stat_table.add_row(
            "Medium Findings:",
            f"[bold yellow]{summary.findings_by_severity.get('MEDIUM', 0)}[/bold yellow]"
        )
        stat_table.add_row("Scan Duration:", f"{summary.total_duration_seconds:.2f} seconds")

        status_style = "bold green" if summary.total_findings == 0 else "bold red"
        status_title = "AUDIT PASSED - NO SECRETS FOUND" if summary.total_findings == 0 else "SECURITY ALERT - SECRETS DETECTED"
        console.print(
            Panel(
                stat_table,
                title=f"[{status_style}] {status_title} [/{status_style}]",
                border_style="green" if summary.total_findings == 0 else "red",
                expand=False,
            )
        )

    def _render_summary_plain(self, summary: AuditSummary):
        print("\n" + "=" * 70)
        print(f"AUDIT SUMMARY FOR: {summary.target}")
        print("=" * 70)
        print(f"Repositories Scanned : {summary.total_repos_scanned}")
        print(f"Repositories at Risk : {summary.repos_with_findings}")
        print(f"Total Secrets Found  : {summary.total_findings}")
        print(f"  - CRITICAL         : {summary.findings_by_severity.get('CRITICAL', 0)}")
        print(f"  - HIGH             : {summary.findings_by_severity.get('HIGH', 0)}")
        print(f"  - MEDIUM           : {summary.findings_by_severity.get('MEDIUM', 0)}")
        print(f"Duration             : {summary.total_duration_seconds:.2f}s")
        print("=" * 70)

        for repo in summary.results:
            if repo.findings:
                print(f"\n[REPO] {repo.repo_name} ({repo.repo_url})")
                for f in repo.findings:
                    col = ANSI_COLORS.get(f.severity.value, "")
                    reset = ANSI_COLORS["RESET"]
                    line_info = f":{f.line_number}" if f.line_number else ""
                    commit_info = f" (commit {f.commit_hash[:7]})" if f.commit_hash else ""
                    print(f"  [{col}{f.severity.value}{reset}] {f.rule_name} -> {f.file_path}{line_info}{commit_info}")
                    print(f"      Secret: {f.masked_secret}")
                    print(f"      Advice: {f.remediation_hint}")


class ReportExporter:
    @staticmethod
    def to_json(summary: AuditSummary, output_path: str | Path):
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(summary.to_dict(), indent=2), encoding="utf-8")

    @staticmethod
    def to_markdown(summary: AuditSummary, output_path: str | Path):
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        lines = [
            f"# GitLeakGuard Security Audit Report",
            f"",
            f"- **Target**: `{summary.target}`",
            f"- **Date**: {summary.scan_timestamp}",
            f"- **Repositories Scanned**: {summary.total_repos_scanned}",
            f"- **Repositories at Risk**: {summary.repos_with_findings}",
            f"- **Total Secrets Detected**: {summary.total_findings}",
            f"",
            f"| Severity | Count |",
            f"| :--- | :--- |",
            f"| 🔴 CRITICAL | {summary.findings_by_severity.get('CRITICAL', 0)} |",
            f"| 🟠 HIGH | {summary.findings_by_severity.get('HIGH', 0)} |",
            f"| 🟡 MEDIUM | {summary.findings_by_severity.get('MEDIUM', 0)} |",
            f"| 🔵 LOW / INFO | {summary.findings_by_severity.get('LOW', 0) + summary.findings_by_severity.get('INFO', 0)} |",
            f"",
        ]

        if summary.total_findings == 0:
            lines.append("## ✅ No Leaked Secrets Detected! All repositories are clean.")
        else:
            lines.append("## ⚠️ Detected Vulnerabilities")
            lines.append("")
            for repo in summary.results:
                if not repo.findings:
                    continue
                lines.append(f"### 📦 [{repo.repo_name}]({repo.repo_url})")
                lines.append(f"| Severity | Vulnerability | File | Secret | Action |")
                lines.append(f"| :--- | :--- | :--- | :--- | :--- |")
                for f in repo.findings:
                    loc = f"`{f.file_path}" + (f":{f.line_number}`" if f.line_number else "`")
                    lines.append(
                        f"| **{f.severity.value}** | {f.rule_name} | {loc} | `{f.masked_secret}` | {f.remediation_hint} |"
                    )
                lines.append("")

        lines.extend([
            "",
            "## 🛡️ Remediation Checklist",
            "1. **Revoke Keys Immediately**: Any key committed to a public repository should be considered compromised. Revoke it in your provider dashboard.",
            "2. **Purge Commit History**: Deleting the key in a new commit is NOT enough. Use `git-filter-repo` or BFG Repo-Cleaner to rewrite history.",
            "3. **Add Secrets to .gitignore**: Keep credentials in local `.env` files that are strictly gitignored.",
            "4. **Enable GitHub Secret Scanning**: Turn on push protection in repository settings.",
        ])

        path.write_text("\n".join(lines), encoding="utf-8")

    @staticmethod
    def to_html(summary: AuditSummary, output_path: str | Path):
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        data_json = json.dumps(summary.to_dict())

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>GitLeakGuard Security Report - {html.escape(summary.target)}</title>
  <style>
    :root {{
      --bg: #0f172a;
      --card-bg: #1e293b;
      --border: #334155;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --critical: #ef4444;
      --high: #f97316;
      --medium: #eab308;
      --low: #3b82f6;
      --success: #10b981;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }}
    body {{ background: var(--bg); color: var(--text); padding: 32px 16px; line-height: 1.5; }}
    .container {{ max-width: 1200px; margin: 0 auto; }}
    header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 28px; padding-bottom: 20px; border-bottom: 1px solid var(--border); }}
    h1 {{ font-size: 28px; font-weight: 700; display: flex; align-items: center; gap: 12px; }}
    .badge-clean {{ background: rgba(16, 185, 129, 0.2); color: var(--success); padding: 4px 12px; border-radius: 999px; font-size: 14px; font-weight: 600; }}
    .badge-risk {{ background: rgba(239, 68, 68, 0.2); color: var(--critical); padding: 4px 12px; border-radius: 999px; font-size: 14px; font-weight: 600; }}
    .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 32px; }}
    .stat-card {{ background: var(--card-bg); border: 1px solid var(--border); border-radius: 12px; padding: 20px; }}
    .stat-title {{ color: var(--text-muted); font-size: 13px; text-transform: uppercase; font-weight: 600; margin-bottom: 8px; }}
    .stat-value {{ font-size: 32px; font-weight: 700; }}
    .controls {{ display: flex; gap: 12px; margin-bottom: 24px; flex-wrap: wrap; }}
    .search-input {{ flex: 1; min-width: 250px; background: var(--card-bg); border: 1px solid var(--border); color: var(--text); padding: 10px 16px; border-radius: 8px; font-size: 14px; outline: none; }}
    .filter-btn {{ background: var(--card-bg); border: 1px solid var(--border); color: var(--text); padding: 8px 16px; border-radius: 8px; font-size: 14px; cursor: pointer; transition: 0.2s; }}
    .filter-btn.active, .filter-btn:hover {{ background: #3b82f6; border-color: #3b82f6; color: white; }}
    .repo-card {{ background: var(--card-bg); border: 1px solid var(--border); border-radius: 12px; margin-bottom: 20px; overflow: hidden; }}
    .repo-header {{ padding: 16px 20px; background: rgba(255, 255, 255, 0.02); border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; }}
    .repo-title {{ font-size: 18px; font-weight: 600; }}
    .repo-title a {{ color: #60a5fa; text-decoration: none; }}
    .finding-row {{ padding: 16px 20px; border-bottom: 1px solid rgba(255, 255, 255, 0.05); display: flex; flex-direction: column; gap: 8px; }}
    .finding-row:last-child {{ border-bottom: none; }}
    .finding-header {{ display: flex; justify-content: space-between; align-items: center; }}
    .sev-pill {{ font-size: 11px; font-weight: 700; text-transform: uppercase; padding: 3px 8px; border-radius: 6px; letter-spacing: 0.5px; }}
    .sev-CRITICAL {{ background: rgba(239, 68, 68, 0.2); color: var(--critical); border: 1px solid var(--critical); }}
    .sev-HIGH {{ background: rgba(249, 115, 22, 0.2); color: var(--high); border: 1px solid var(--high); }}
    .sev-MEDIUM {{ background: rgba(234, 179, 8, 0.2); color: var(--medium); border: 1px solid var(--medium); }}
    .sev-LOW {{ background: rgba(59, 130, 246, 0.2); color: var(--low); border: 1px solid var(--low); }}
    .file-path {{ font-family: monospace; color: #38bdf8; font-size: 13px; }}
    .code-box {{ background: #0b1120; border-radius: 6px; padding: 10px 14px; font-family: monospace; font-size: 13px; color: #f1f5f9; overflow-x: auto; }}
    .remediation {{ color: var(--text-muted); font-size: 13px; margin-top: 4px; }}
    .clean-message {{ text-align: center; padding: 60px 20px; background: var(--card-bg); border-radius: 12px; border: 1px solid var(--border); }}
    .guide {{ margin-top: 40px; background: var(--card-bg); border: 1px solid var(--border); border-radius: 12px; padding: 24px; }}
    .guide h2 {{ margin-bottom: 16px; font-size: 20px; }}
    .guide ol {{ margin-left: 20px; color: var(--text-muted); }}
    .guide li {{ margin-bottom: 10px; }}
    .guide code {{ background: #0b1120; padding: 2px 6px; border-radius: 4px; color: #38bdf8; font-family: monospace; }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h1>🛡️ GitLeakGuard Security Audit</h1>
        <p style="color: var(--text-muted); margin-top: 4px;">Target: <strong>{html.escape(summary.target)}</strong> | Scanned at {summary.scan_timestamp}</p>
      </div>
      <div>
        {"<span class='badge-clean'>✓ ALL REPOSITORIES CLEAN</span>" if summary.total_findings == 0 else f"<span class='badge-risk'>⚠️ {summary.total_findings} SECRETS FOUND</span>"}
      </div>
    </header>

    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-title">Repositories Scanned</div>
        <div class="stat-value">{summary.total_repos_scanned}</div>
      </div>
      <div class="stat-card">
        <div class="stat-title">Repositories At Risk</div>
        <div class="stat-value" style="color: {'var(--critical)' if summary.repos_with_findings > 0 else 'var(--success)'};">{summary.repos_with_findings}</div>
      </div>
      <div class="stat-card">
        <div class="stat-title">Critical Secrets</div>
        <div class="stat-value" style="color: var(--critical);">{summary.findings_by_severity.get('CRITICAL', 0)}</div>
      </div>
      <div class="stat-card">
        <div class="stat-title">High Severity</div>
        <div class="stat-value" style="color: var(--high);">{summary.findings_by_severity.get('HIGH', 0)}</div>
      </div>
    </div>

    <div class="controls">
      <input type="text" id="searchInput" class="search-input" placeholder="Search by repository, rule, or file path..." oninput="filterResults()">
      <button class="filter-btn active" onclick="setSeverity('ALL', this)">All</button>
      <button class="filter-btn" onclick="setSeverity('CRITICAL', this)">Critical</button>
      <button class="filter-btn" onclick="setSeverity('HIGH', this)">High</button>
      <button class="filter-btn" onclick="setSeverity('MEDIUM', this)">Medium</button>
    </div>

    <div id="resultsContainer"></div>

    <div class="guide">
      <h2>🚨 Immediate Remediation Steps</h2>
      <ol>
        <li><strong>Revoke Compromised Credentials:</strong> Immediately invalidate exposed tokens in their provider consoles (OpenAI, AWS, GitHub, Stripe, etc.).</li>
        <li><strong>Purge from Git History:</strong> Never just delete the file in a new commit. Use <code>git-filter-repo --invert-paths --path &lt;file&gt;</code> or BFG Repo-Cleaner to rewrite history.</li>
        <li><strong>Force Push Safely:</strong> Run <code>git push origin --force --all</code> after purifying history.</li>
        <li><strong>Protect Against Future Leaks:</strong> Add <code>.env*</code> to your global and repository <code>.gitignore</code>, and install pre-commit hooks.</li>
      </ol>
    </div>
  </div>

  <script>
    const reportData = {data_json};
    let currentSeverity = 'ALL';

    function setSeverity(sev, btn) {{
      currentSeverity = sev;
      document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      filterResults();
    }}

    function filterResults() {{
      const query = document.getElementById('searchInput').value.toLowerCase();
      const container = document.getElementById('resultsContainer');
      container.innerHTML = '';

      let matchingRepos = 0;

      reportData.repositories.forEach(repo => {{
        const filteredFindings = repo.findings.filter(f => {{
          const matchesSev = (currentSeverity === 'ALL' || f.severity === currentSeverity);
          const matchesQuery = !query || 
            repo.repo_name.toLowerCase().includes(query) || 
            f.rule_name.toLowerCase().includes(query) || 
            f.file_path.toLowerCase().includes(query);
          return matchesSev && matchesQuery;
        }});

        if (filteredFindings.length > 0) {{
          matchingRepos++;
          const card = document.createElement('div');
          card.className = 'repo-card';

          let findingsHtml = filteredFindings.map(f => `
            <div class="finding-row">
              <div class="finding-header">
                <div>
                  <span class="sev-pill sev-${{f.severity}}">${{f.severity}}</span>
                  <strong style="margin-left: 8px;">${{f.rule_name}}</strong>
                </div>
                <div class="file-path">${{f.file_path}}${{f.line_number ? ':' + f.line_number : ''}}</div>
              </div>
              <div class="code-box"><code>${{escapeHtml(f.raw_snippet)}}</code></div>
              <div class="remediation">
                <span><strong>Masked Token:</strong> <code>${{f.masked_secret}}</code></span> | 
                <span>${{f.remediation_hint}}</span>
                ${{f.commit_hash ? `<span style="float: right;">Commit: <code>${{f.commit_hash.slice(0, 7)}}</code></span>` : ''}}
              </div>
            </div>
          `).join('');

          card.innerHTML = `
            <div class="repo-header">
              <span class="repo-title">📦 <a href="${{repo.repo_url}}" target="_blank">${{repo.repo_name}}</a></span>
              <span style="font-size: 13px; color: var(--text-muted);">${{filteredFindings.length}} finding(s)</span>
            </div>
            ${{findingsHtml}}
          `;
          container.appendChild(card);
        }}
      }});

      if (matchingRepos === 0) {{
        container.innerHTML = `
          <div class="clean-message">
            <h2 style="color: var(--success); margin-bottom: 8px;">🎉 No Matching Findings</h2>
            <p style="color: var(--text-muted);">No leaked credentials matching the current filter were found.</p>
          </div>
        `;
      }}
    }}

    function escapeHtml(text) {{
      const div = document.createElement('div');
      div.innerText = text;
      return div.innerHTML;
    }}

    filterResults();
  </script>
</body>
</html>
"""
        path.write_text(html_content, encoding="utf-8")
