"""
Security detection rules for GitLeakGuard.
"""

from __future__ import annotations
import re
from typing import List, Optional, Tuple, Dict, Any
from git_leak_guard.models import Finding, Severity
from git_leak_guard.entropy import shannon_entropy, is_high_entropy


def mask_secret(secret: str) -> str:
    """Mask confidential string for safe logging and display."""
    if not secret:
        return ""
    length = len(secret)
    if length <= 6:
        return "*" * length
    if length <= 12:
        return secret[:2] + ("*" * (length - 4)) + secret[-2:]
    return secret[:4] + ("*" * (length - 8)) + secret[-4:]


# Common false positive tokens and indicators
FALSE_POSITIVE_PHRASES = [
    "YOUR_API_KEY",
    "YOUR_KEY",
    "YOUR_TOKEN",
    "YOUR_SECRET",
    "API_KEY_HERE",
    "SECRET_HERE",
    "TOKEN_HERE",
    "PLACEHOLDER",
    "CHANGE_ME",
    "CHANGEME",
    "INSERT_HERE",
    "REPLACE_ME",
    "<YOUR_",
    "${ENV.",
    "PROCESS.ENV.",
    "OS.ENVIRON.GET",
    "CONFIG::GET",
]

SENSITIVE_FILENAMES = [
    (r"^\.env(\..+)?$", Severity.HIGH, "Environment configuration file containing credentials"),
    (r"^id_(rsa|dsa|ecdsa|ed25519)$", Severity.CRITICAL, "Private SSH Key file"),
    (r"^id_(rsa|dsa|ecdsa|ed25519)\.pub$", Severity.LOW, "Public SSH Key file"),
    (r"^(credentials|serviceAccountKey|service-account|firebase-adminsdk.*)\.json$", Severity.CRITICAL, "Cloud service account credentials"),
    (r"^.*\.(pem|key|pkcs12|pfx|jks|keystore)$", Severity.HIGH, "Certificate or cryptographic keystore file"),
    (r"^wp-config\.php$", Severity.HIGH, "WordPress configuration file with database credentials"),
    (r"^\.htpasswd$", Severity.HIGH, "Apache htpasswd authentication file"),
]

RULE_DEFINITIONS = [
    {
        "id": "OPENAI_API_KEY",
        "name": "OpenAI API Key",
        "severity": Severity.CRITICAL,
        "pattern": r"(?:sk-proj-[A-Za-z0-9_-]{48,}|sk-[a-zA-Z0-9]{32,})",
        "description": "Leaked OpenAI API Key allows unauthorized AI queries and billing charges.",
        "remediation": "Immediately revoke key in OpenAI dashboard -> API Keys and rotate.",
    },
    {
        "id": "ANTHROPIC_API_KEY",
        "name": "Anthropic Claude API Key",
        "severity": Severity.CRITICAL,
        "pattern": r"sk-ant-api03-[A-Za-z0-9_-]{80,}",
        "description": "Anthropic API Key leak grants direct access to Claude models under your account.",
        "remediation": "Revoke key in Anthropic Console -> API Keys and generate a new one.",
    },
    {
        "id": "GOOGLE_API_KEY",
        "name": "Google / Gemini API Key",
        "severity": Severity.CRITICAL,
        "pattern": r"AIza[0-9A-Za-z-_]{35}",
        "description": "Google Cloud / Gemini API key leaked, potentially granting access to billed Google APIs.",
        "remediation": "Revoke or restrict key scope in Google Cloud Console -> Credentials.",
    },
    {
        "id": "GITHUB_PAT",
        "name": "GitHub Personal Access Token",
        "severity": Severity.CRITICAL,
        "pattern": r"(?:ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82}|gho_[0-9a-zA-Z]{36}|ghu_[0-9a-zA-Z]{36}|ghs_[0-9a-zA-Z]{36})",
        "description": "GitHub token grants read/write permissions to repositories, packages, or org assets.",
        "remediation": "Revoke the token in GitHub Settings -> Developer settings -> Personal access tokens.",
    },
    {
        "id": "GITLAB_PAT",
        "name": "GitLab Personal Access Token",
        "severity": Severity.CRITICAL,
        "pattern": r"glpat-[0-9a-zA-Z\-]{20}",
        "description": "GitLab Personal Access Token discovered in source code.",
        "remediation": "Revoke token under GitLab User Settings -> Access Tokens.",
    },
    {
        "id": "AWS_ACCESS_KEY",
        "name": "AWS Access Key ID",
        "severity": Severity.CRITICAL,
        "pattern": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        "description": "AWS IAM Access Key ID exposed, could lead to full cloud infrastructure compromise.",
        "remediation": "Deactivate IAM key in AWS IAM Console and purge from Git history.",
    },
    {
        "id": "AWS_SECRET_KEY",
        "name": "AWS Secret Access Key",
        "severity": Severity.CRITICAL,
        "pattern": r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        "description": "AWS Secret Access Key exposed alongside assignment.",
        "remediation": "Immediately deactivate key in AWS IAM and generate new credentials.",
    },
    {
        "id": "STRIPE_KEY",
        "name": "Stripe API Key",
        "severity": Severity.CRITICAL,
        "pattern": r"(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,34}",
        "description": "Stripe Secret or Restricted Key exposed, could lead to customer data or financial risks.",
        "remediation": "Roll API key immediately in Stripe Developers Dashboard.",
    },
    {
        "id": "SLACK_TOKEN",
        "name": "Slack Bot / User Token",
        "severity": Severity.HIGH,
        "pattern": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*",
        "description": "Slack token leaked, could allow attackers to read channel logs or post messages.",
        "remediation": "Revoke app token in Slack API Developer Portal.",
    },
    {
        "id": "SLACK_WEBHOOK",
        "name": "Slack Incoming Webhook",
        "severity": Severity.HIGH,
        "pattern": r"https://hooks\.slack\.com/services/T[0-9A-Z_]+/B[0-9A-Z_]+/[0-9a-zA-Z_]+",
        "description": "Slack Incoming Webhook URL exposed; can be abused to spam internal channels.",
        "remediation": "Delete webhook from your Slack Workspace Apps configuration.",
    },
    {
        "id": "TELEGRAM_BOT_TOKEN",
        "name": "Telegram Bot Token",
        "severity": Severity.HIGH,
        "pattern": r"\b[0-9]{8,10}:[a-zA-Z0-9_-]{35}\b",
        "description": "Telegram Bot Token leaked, giving attackers full control over the bot.",
        "remediation": "Revoke token by contacting @BotFather on Telegram and requesting /revoke.",
    },
    {
        "id": "DISCORD_WEBHOOK",
        "name": "Discord Webhook URL",
        "severity": Severity.HIGH,
        "pattern": r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_-]{60,}",
        "description": "Discord Webhook exposed; can be abused for spam or phishing in server.",
        "remediation": "Delete the webhook in Discord Server Settings -> Integrations -> Webhooks.",
    },
    {
        "id": "DISCORD_BOT_TOKEN",
        "name": "Discord Bot Token",
        "severity": Severity.HIGH,
        "pattern": r"[MN][A-Za-z\d]{23,25}\.[\w-]{6}\.[\w-]{27,39}",
        "description": "Discord Bot Token leaked, giving unauthorized control over the Discord bot.",
        "remediation": "Reset token in Discord Developer Portal -> Bot -> Reset Token.",
    },
    {
        "id": "PRIVATE_KEY",
        "name": "Private Cryptographic Key",
        "severity": Severity.CRITICAL,
        "pattern": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----",
        "description": "Private SSH/TLS key block discovered directly in source code.",
        "remediation": "Remove key immediately from repo, generate a replacement pair, and revoke old key on servers.",
    },
    {
        "id": "DATABASE_URI",
        "name": "Database Connection URI with Credentials",
        "severity": Severity.CRITICAL,
        "pattern": r"(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^:\s\/]+:[^@\s\/]+@[^\s\/]+",
        "description": "Database connection string with plaintext password exposed in repository.",
        "remediation": "Change database password immediately and move connection strings to secret managers.",
    },
    {
        "id": "JWT_TOKEN",
        "name": "JSON Web Token (JWT)",
        "severity": Severity.MEDIUM,
        "pattern": r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
        "description": "Hardcoded JWT token found. Might contain sensitive claims or be reusable.",
        "remediation": "Invalidate token session, rotate signing secret, and avoid committing auth tokens.",
    },
    {
        "id": "GENERIC_HIGH_ENTROPY_SECRET",
        "name": "Generic High-Entropy Secret Assignment",
        "severity": Severity.MEDIUM,
        "pattern": r"""(?i)(?:api_key|apikey|secret_key|secret|auth_token|access_token|password|passwd|client_secret)\s*[:=]\s*['"]([A-Za-z0-9_\-\+]{16,})['"]""",
        "description": "Variable assignment containing potentially sensitive high-entropy credentials.",
        "remediation": "Verify if this is an active credential. Replace with environment variable.",
    },
]


class RuleEngine:
    def __init__(self):
        self.compiled_rules = []
        for r in RULE_DEFINITIONS:
            self.compiled_rules.append({
                "id": r["id"],
                "name": r["name"],
                "severity": r["severity"],
                "description": r["description"],
                "remediation": r["remediation"],
                "regex": re.compile(r["pattern"]),
            })
        self.filename_rules = [
            (re.compile(pat, re.IGNORECASE), sev, desc) for pat, sev, desc in SENSITIVE_FILENAMES
        ]

    def is_false_positive(self, match_str: str, line_str: str) -> bool:
        """Check if match looks like an obvious placeholder or dummy value."""
        upper_match = match_str.upper()
        upper_line = line_str.upper()
        for fp in FALSE_POSITIVE_PHRASES:
            if fp in upper_match or fp in upper_line:
                return True
        # Check repeated characters like aaaaaa or 000000
        if len(set(match_str)) <= 2 and len(match_str) > 8:
            return True
        return False

    def scan_filename(self, filepath: str) -> Optional[Finding]:
        """Check if file name itself represents an exposed sensitive file."""
        import os
        filename = os.path.basename(filepath)
        for pattern, severity, desc in self.filename_rules:
            if pattern.match(filename):
                return Finding(
                    rule_id="EXPOSED_SENSITIVE_FILE",
                    rule_name=f"Sensitive File Exposed: {filename}",
                    severity=severity,
                    description=desc,
                    file_path=filepath,
                    line_number=None,
                    masked_secret=filename,
                    raw_snippet=f"File committed to repository: {filepath}",
                    remediation_hint="Add this file to .gitignore and remove it from git history.",
                )
        return None

    def scan_text(
        self,
        text: str,
        file_path: str,
        commit_hash: Optional[str] = None,
        commit_author: Optional[str] = None,
        commit_date: Optional[str] = None,
    ) -> List[Finding]:
        """Scan file content or git commit diff for secrets."""
        findings = []
        lines = text.splitlines()

        for line_num, line in enumerate(lines, start=1):
            if len(line) > 2000:
                # Skip minified bundle / minified JSON lines to avoid regex performance issues
                continue

            matched_specific_rule = False
            line_findings = []

            for rule in self.compiled_rules:
                is_generic = (rule["id"] == "GENERIC_HIGH_ENTROPY_SECRET")
                if is_generic and matched_specific_rule:
                    continue

                matches = rule["regex"].finditer(line)
                for m in matches:
                    secret_val = m.group(1) if m.groups() else m.group(0)
                    if self.is_false_positive(secret_val, line):
                        continue

                    ent = shannon_entropy(secret_val)
                    if is_generic:
                        if not is_high_entropy(secret_val, min_length=16, threshold=3.4):
                            continue
                    else:
                        matched_specific_rule = True

                    snippet = line.strip()
                    if len(snippet) > 160:
                        snippet = snippet[:157] + "..."

                    line_findings.append(
                        Finding(
                            rule_id=rule["id"],
                            rule_name=rule["name"],
                            severity=rule["severity"],
                            description=rule["description"],
                            file_path=file_path,
                            line_number=line_num,
                            commit_hash=commit_hash,
                            commit_author=commit_author,
                            commit_date=commit_date,
                            masked_secret=mask_secret(secret_val),
                            raw_snippet=snippet,
                            entropy=ent,
                            remediation_hint=rule["remediation"],
                        )
                    )

            # If specific rule matched, filter out generic secret findings on the same line
            if matched_specific_rule:
                line_findings = [f for f in line_findings if f.rule_id != "GENERIC_HIGH_ENTROPY_SECRET"]

            findings.extend(line_findings)

        return findings
