# 🛡️ GitLeakGuard

[![CI Status](https://github.com/egorfm/git-leak-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/egorfm/git-leak-guard/actions)
[![Python Version](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

> **Defensive Security & Leak Auditor for Public GitHub Repositories**  
> Automatically discover, scan, and audit your public GitHub repositories and deep commit history for accidentally leaked API keys, tokens, database credentials, and confidential files.

---

## ⚡ The Problem

Developers frequently commit sensitive credentials by mistake:
- API keys (OpenAI, Claude, Google Cloud, AWS)
- Database credentials with passwords
- Personal Access Tokens (GitHub, GitLab, Slack, Telegram bots)
- Unversioned `.env`, `serviceAccountKey.json`, or private SSH keys

**Deleting a secret in a subsequent commit does NOT remove it from Git history.** Attackers and automated scrapers actively harvest public commits. **GitLeakGuard** audits your entire GitHub portfolio and traces both current files and historical commit diffs, providing actionable remediation steps and an executive interactive HTML report.

---

## ✨ Features

- 🔍 **Automated GitHub Portfolio Discovery**: Pass a username or organization, and GitLeakGuard automatically scans all public repositories with pagination support.
- 🕰️ **Deep Commit History Scanning**: Uncovers credentials introduced in old commits, even if they were deleted or replaced in subsequent commits.
- 🎯 **High-Precision Secret Rules**:
  - **AI Providers**: OpenAI (`sk-`, `sk-proj-`), Anthropic Claude (`sk-ant-api03-`), Google Gemini (`AIzaSy...`)
  - **Cloud & Infrastructure**: AWS Access Key ID (`AKIA...`), AWS Secret Keys
  - **Dev & VCS**: GitHub PAT (`ghp_`, `github_pat_`), GitLab Personal Tokens
  - **Messaging & Bots**: Slack Tokens & Webhooks, Telegram Bot Tokens, Discord Tokens & Webhooks
  - **Payment & Telecom**: Stripe Secret/Restricted keys, Twilio credentials
  - **Keys & Certificates**: Private RSA, OpenSSH, PGP, EC cryptographic keys
  - **Databases**: Database URIs containing passwords (`postgres://`, `mysql://`, `mongodb://`, `redis://`)
  - **Exposed Sensitive Files**: `.env`, `.env.local`, `id_rsa`, `serviceAccountKey.json`, `credentials.json`, `keystore.jks`
- 🧠 **Shannon Entropy Analysis**: Distinguishes true cryptographic tokens from variable names and ordinary strings to suppress false positives.
- 🧼 **Intelligent Placeholder Suppression**: Automatically filters dummy placeholders like `YOUR_API_KEY_HERE`, `CHANGE_ME`, or `process.env`.
- 📊 **Multiple Output Formats**:
  - **Rich Terminal UI**: Formatted tables, colored severity indicators, and summary metrics.
  - **Interactive HTML Report**: Self-contained HTML with dark/light themes, instant search, severity filtering, and remediation guides.
  - **JSON & Markdown Export**: Seamless integration into CI/CD workflows and automated reporting pipelines.
- 🛑 **CI/CD Integration**: Supports `--fail-on [CRITICAL|HIGH|MEDIUM|LOW]` to enforce zero-leak policies in automated builds.
- 📦 **Zero-Config Standalone Support**: Works with standard Python libraries; enhances output when `rich` is installed.

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/egorfm/git-leak-guard.git
cd git-leak-guard

# Install with pip
pip install -e .

# Or install with dev dependencies (pytest)
pip install -e ".[dev]"
```

---

## 🛠️ Usage Examples

### 1. Audit All Public Repositories of a User

```bash
git-leak-guard scan-user egorfm --output audit_report.html
```

*(To increase GitHub API limits from 60 to 5,000 requests/hr, provide a token via `--token <YOUR_PAT>` or set `export GITHUB_TOKEN=...`)*

### 2. Scan a Single Repository with Deep History

```bash
git-leak-guard scan-repo https://github.com/egorfm/my-project --output report.html
```

### 3. Scan a Local Directory or Repository

```bash
git-leak-guard scan-local ./my-app --min-severity HIGH
```

### 4. Fast Scan (Working Tree Only)

Skip full commit history when checking only the current snapshot:

```bash
git-leak-guard scan-repo egorfm/my-project --fast
```

### 5. Automated CI/CD Quality Gate

Enforce that no critical or high severity secrets exist:

```bash
git-leak-guard scan-local . --fail-on HIGH --output report.json
```

---

## 🖥️ CLI Reference

```
usage: git-leak-guard [-h] {scan-user,scan-repo,scan-local} ...

Target commands:
  scan-user        Scan all public repositories of a GitHub user/organization
  scan-repo        Scan a single GitHub repository
  scan-local       Scan a local folder or git repository

Common Options:
  --token TOKEN              GitHub Personal Access Token (for 5,000 req/hr rate limit)
  --fast                     Shallow scan only (skip deep commit history)
  --exclude-forks            Exclude forked repositories
  --output, -o FILE          Save report to file (.html, .json, .md)
  --format {terminal,html,json,markdown}
  --min-severity {CRITICAL,HIGH,MEDIUM,LOW,INFO}
  --fail-on {CRITICAL,HIGH,MEDIUM,LOW}
```

---

## 📄 Sample Report Preview

When running an audit, GitLeakGuard prints an executive summary:

```
   ____ _ _   _                _      ____                     _ 
  / ___(_) |_| |    ___   __ _| | __ / ___|_   _  __ _ _ __ __| |
 | |  _| | __| |   / _ \ / _` | |/ /| |  _| | | |/ _` | '__/ _` |
 | |_| | | |_| |__|  __/| (_| |   < | |_| | |_| | (_| | | | (_| |
  \____|_|\__|_____\___| \__,_|_|\_\ \____|\__,_|\__,_|_|  \__,_|
  Defensive Security Scanner for Public GitHub Repositories v1.0.0

┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┳━━━━━━━━┓
┃ Severity ┃ Repository             ┃ Vulnerability       ┃ File & Line          ┃ Masked Secret    ┃ Commit ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━╇━━━━━━━━┩
│ CRITICAL │ demo-backend           │ OpenAI API Key      │ backend/ai.py:14     │ sk-p****5678     │ a8f12c │
│ CRITICAL │ demo-backend           │ Database URI        │ config/database.yml  │ post****@db.net  │ HEAD   │
│ HIGH     │ demo-backend           │ Sensitive File      │ .env                 │ .env             │ HEAD   │
└──────────┴────────────────────────┴─────────────────────┴──────────────────────┴──────────────────┴────────┘
```

---

## 🚨 Incident Response & Remediation Guide

If GitLeakGuard discovers an exposed credential in your repository:

### 1. Invalidate / Rotate the Secret Immediately
Never assume a secret hasn't been crawled.
- **OpenAI**: [platform.openai.com/api-keys](https://platform.openai.com/api-keys) -> Revoke Key
- **AWS**: [console.aws.amazon.com/iam](https://console.aws.amazon.com/iam/) -> Deactivate Access Key
- **GitHub**: [github.com/settings/tokens](https://github.com/settings/tokens) -> Delete Token
- **Stripe**: [dashboard.stripe.com/apikeys](https://dashboard.stripe.com/apikeys) -> Roll Key

### 2. Purge History with `git-filter-repo`
Deleting the file in a new commit is not sufficient. Use [git-filter-repo](https://github.com/newren/git-filter-repo):

```bash
# Install git-filter-repo
pip install git-filter-repo

# Completely remove the sensitive file from all branches and tags
git filter-repo --invert-paths --path .env --force

# Force push to remote
git push origin --force --all
git push origin --force --tags
```

### 3. Add to `.gitignore`
Ensure sensitive patterns are never staged again:
```gitignore
# .gitignore
.env*
*.pem
*.key
serviceAccountKey.json
```

---

## 🧪 Testing

Run the test suite:

```bash
pytest
```

---

## 🤝 Contributing

Contributions, rules, and improvements are welcome!
1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingRule`)
3. Commit your Changes (`git commit -m 'Add new secret detection rule'`)
4. Push to the Branch (`git push origin feature/AmazingRule`)
5. Open a Pull Request

---

## ⚖️ License

Distributed under the **MIT License**. See `LICENSE` for more information.
