import tempfile
from pathlib import Path
from git_leak_guard.scanner import RepoScanner
from git_leak_guard.models import AuditSummary
from git_leak_guard.reporter import ReportExporter


def test_scan_local_directory():
    scanner = RepoScanner()

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)

        # Create clean file
        (tmp_path / "main.py").write_text("print('Hello world!')\n")

        # Create sensitive .env file using runtime string concatenation
        stripe_key = "sk_test_" + "1234567890abcdef12345678"
        (tmp_path / ".env").write_text(f"STRIPE_KEY={stripe_key}\n")

        result = scanner.scan_local_directory(tmp_path)

        assert result.files_scanned >= 1
        assert len(result.findings) >= 1

        # Check Stripe key finding
        rule_ids = [f.rule_id for f in result.findings]
        assert "STRIPE_KEY" in rule_ids or "EXPOSED_SENSITIVE_FILE" in rule_ids


def test_report_exporting():
    scanner = RepoScanner()

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        api_token = "AIza" + "SyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q"
        (tmp_path / "test.py").write_text(f"api_key = '{api_token}'\n")

        res = scanner.scan_local_directory(tmp_path)

        summary = AuditSummary(
            target="test-target",
            scan_timestamp="2026-11-01 12:00:00",
            results=[res],
            total_duration_seconds=0.5,
        )
        summary.compute_totals()

        html_out = tmp_path / "report.html"
        json_out = tmp_path / "report.json"
        md_out = tmp_path / "report.md"

        ReportExporter.to_html(summary, html_out)
        ReportExporter.to_json(summary, json_out)
        ReportExporter.to_markdown(summary, md_out)

        assert html_out.exists()
        assert json_out.exists()
        assert md_out.exists()
        assert len(html_out.read_text()) > 500
        assert "test-target" in json_out.read_text()
        assert "# GitLeakGuard Security Audit Report" in md_out.read_text()
