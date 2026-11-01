"""
GitHub REST API client for repository discovery and metadata retrieval.
"""

from __future__ import annotations
import json
import os
import urllib.request
import urllib.error
from typing import List, Dict, Any, Optional


class GitHubClient:
    BASE_URL = "https://api.github.com"

    def __init__(self, token: Optional[str] = None):
        self.token = token or os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")
        self.user_agent = "GitLeakGuard/1.0"

    def _make_request(self, endpoint: str) -> Tuple[Any, Dict[str, str]]:
        url = endpoint if endpoint.startswith("http") else f"{self.BASE_URL}{endpoint}"
        headers = {
            "User-Agent": self.user_agent,
            "Accept": "application/vnd.github.v3+json",
        }
        if self.token:
            headers["Authorization"] = f"token {self.token}"

        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                resp_headers = dict(resp.headers)
                return data, resp_headers
        except urllib.error.HTTPError as e:
            if e.code == 404:
                raise RuntimeError(f"Resource not found on GitHub: {url}")
            elif e.code == 403:
                rate_limit_reset = e.headers.get("X-RateLimit-Reset", "")
                raise RuntimeError(
                    f"GitHub API rate limit exceeded or access forbidden (HTTP 403). "
                    f"Consider passing a personal access token via --token or GITHUB_TOKEN."
                )
            elif e.code == 401:
                raise RuntimeError("Invalid GitHub token provided.")
            else:
                body = e.read().decode("utf-8", errors="ignore")
                raise RuntimeError(f"GitHub API error HTTP {e.code}: {body}")
        except urllib.error.URLError as e:
            raise RuntimeError(f"Network error connecting to GitHub: {e.reason}")

    def get_user_repositories(
        self, username: str, exclude_forks: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Fetch all public repositories belonging to a user or organization.
        Handles pagination automatically.
        """
        repos = []
        page = 1
        per_page = 100

        while True:
            endpoint = f"/users/{username}/repos?type=public&per_page={per_page}&page={page}"
            try:
                page_data, _ = self._make_request(endpoint)
            except RuntimeError as e:
                # If /users/{username}/repos fails with 404, try /orgs/{username}/repos
                if "404" in str(e) and page == 1:
                    endpoint = f"/orgs/{username}/repos?type=public&per_page={per_page}&page={page}"
                    page_data, _ = self._make_request(endpoint)
                else:
                    raise

            if not page_data or not isinstance(page_data, list):
                break

            for repo in page_data:
                if exclude_forks and repo.get("fork", False):
                    continue
                repos.append(repo)

            if len(page_data) < per_page:
                break
            page += 1

        return repos

    def get_single_repository(self, repo_identifier: str) -> Dict[str, Any]:
        """
        Fetch info for owner/repo or full GitHub URL.
        """
        cleaned = repo_identifier.replace("https://github.com/", "").strip("/")
        if cleaned.endswith(".git"):
            cleaned = cleaned[:-4]

        endpoint = f"/repos/{cleaned}"
        data, _ = self._make_request(endpoint)
        return data
