"""Layer 2 — Hash Verification.

Compares PyPI wheel contents against GitHub source to detect
supply chain tampering (files present in wheel but absent in repo).
"""

from __future__ import annotations

import logging
import zipfile
from io import BytesIO
from pathlib import Path, PurePosixPath
from typing import Any

import httpx

from snareclaw.alerts import AlertEngine
from snareclaw.db import Event
from snareclaw.rules import RulesEngine

log = logging.getLogger("snareclaw.verifier")

PYPI_JSON_API = "https://pypi.org/pypi/{package}/{version}/json"
GITHUB_API = "https://api.github.com"

# Files commonly in wheels but not in source — not suspicious
WHEEL_ONLY_PATTERNS = {
    ".dist-info/",
    "PKG-INFO",
    "METADATA",
    "RECORD",
    "WHEEL",
    "top_level.txt",
    "entry_points.txt",
}


class PackageVerifier:
    def __init__(
        self,
        alert_engine: AlertEngine,
        rules: RulesEngine,
        github_token: str | None = None,
    ) -> None:
        self.alert_engine = alert_engine
        self.rules = rules
        self._client = httpx.Client(timeout=30, follow_redirects=True)
        self._gh_headers: dict[str, str] = {"Accept": "application/vnd.github.v3+json"}
        if github_token:
            self._gh_headers["Authorization"] = f"token {github_token}"

    def verify_package(self, package: str, version: str) -> list[Event]:
        """Full verification pipeline for a single package version."""
        events: list[Event] = []

        pypi_meta = self._fetch_pypi_metadata(package, version)
        if not pypi_meta:
            return events

        # Check for .pth files in wheel
        wheel_files = self._get_wheel_file_list(pypi_meta)
        if wheel_files is not None:
            pth_events = self._check_pth_in_wheel(package, version, wheel_files)
            events.extend(pth_events)

        # Check for source repo and diff file trees
        repo_url = self._extract_repo_url(pypi_meta)
        if repo_url and wheel_files is not None:
            diff_events = self._diff_wheel_vs_source(package, version, wheel_files, repo_url)
            events.extend(diff_events)

        # Check publisher metadata
        pub_events = self._check_publish_anomalies(package, version, pypi_meta)
        events.extend(pub_events)

        return events

    def _fetch_pypi_metadata(self, package: str, version: str) -> dict[str, Any] | None:
        url = PYPI_JSON_API.format(package=package, version=version)
        try:
            resp = self._client.get(url)
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPError:
            log.warning("Failed to fetch PyPI metadata for %s==%s", package, version)
            return None

    def _get_wheel_file_list(self, meta: dict[str, Any]) -> list[str] | None:
        """Download the wheel and list its contents."""
        urls = meta.get("urls", [])
        wheel_url = None
        for u in urls:
            if u.get("packagetype") == "bdist_wheel":
                wheel_url = u["url"]
                break
        if not wheel_url:
            return None
        try:
            resp = self._client.get(wheel_url)
            resp.raise_for_status()
            with zipfile.ZipFile(BytesIO(resp.content)) as zf:
                return zf.namelist()
        except (httpx.HTTPError, zipfile.BadZipFile):
            log.warning("Failed to download/read wheel")
            return None

    def _check_pth_in_wheel(self, package: str, version: str, wheel_files: list[str]) -> list[Event]:
        events: list[Event] = []
        rule_id = "pth-file-in-wheel"
        if not self.rules.is_enabled(rule_id):
            return events
        for f in wheel_files:
            if f.endswith(".pth"):
                ev = Event(
                    severity=self.rules.severity_for(rule_id),
                    rule_id=rule_id,
                    package=package,
                    version=version,
                    message=f"Wheel contains .pth file: {f}",
                    details={"file": f},
                )
                self.alert_engine.fire(ev)
                events.append(ev)
        return events

    def _extract_repo_url(self, meta: dict[str, Any]) -> str | None:
        """Extract GitHub repo URL from PyPI project metadata."""
        info = meta.get("info", {})
        project_urls = info.get("project_urls") or {}
        for key in ("Source", "Source Code", "Repository", "Homepage", "Code"):
            url = project_urls.get(key, "")
            if "github.com" in url:
                return url
        home = info.get("home_page", "")
        if "github.com" in home:
            return home
        return None

    def _parse_github_url(self, url: str) -> tuple[str, str] | None:
        """Extract owner/repo from a GitHub URL."""
        url = url.rstrip("/")
        parts = url.split("github.com/")
        if len(parts) < 2:
            return None
        path = parts[1].split("/")
        if len(path) < 2:
            return None
        return path[0], path[1].split("#")[0].split("?")[0]

    def _get_github_tree(self, owner: str, repo: str, tag: str) -> set[str] | None:
        """Fetch the file tree for a GitHub repo at a given tag."""
        # Try tag formats: v1.0.0, 1.0.0
        for ref in (f"v{tag}", tag):
            url = f"{GITHUB_API}/repos/{owner}/{repo}/git/trees/{ref}?recursive=1"
            try:
                resp = self._client.get(url, headers=self._gh_headers)
                if resp.status_code == 200:
                    data = resp.json()
                    return {item["path"] for item in data.get("tree", []) if item["type"] == "blob"}
            except httpx.HTTPError:
                continue
        return None

    def _diff_wheel_vs_source(
        self, package: str, version: str, wheel_files: list[str], repo_url: str
    ) -> list[Event]:
        events: list[Event] = []
        rule_id = "wheel-source-mismatch"
        if not self.rules.is_enabled(rule_id):
            return events

        parsed = self._parse_github_url(repo_url)
        if not parsed:
            return events
        owner, repo = parsed

        source_tree = self._get_github_tree(owner, repo, version)
        if source_tree is None:
            return events

        # Normalize wheel files — strip dist-info and top-level package prefix
        wheel_meaningful: set[str] = set()
        for f in wheel_files:
            if any(pat in f for pat in WHEEL_ONLY_PATTERNS):
                continue
            # Wheel files are like: package_name/module.py
            wheel_meaningful.add(PurePosixPath(f).name)

        source_names = {PurePosixPath(f).name for f in source_tree}

        # Files in wheel but not in source
        extra_files = wheel_meaningful - source_names
        # Filter out __pycache__, .pyc, etc.
        extra_files = {f for f in extra_files if not f.endswith((".pyc", ".pyo")) and f != "__pycache__"}

        if extra_files:
            ev = Event(
                severity=self.rules.severity_for(rule_id),
                rule_id=rule_id,
                package=package,
                version=version,
                message=f"Wheel contains {len(extra_files)} file(s) not found in source repo",
                details={"extra_files": sorted(extra_files), "repo": repo_url},
            )
            self.alert_engine.fire(ev)
            events.append(ev)
        return events

    def _check_publish_anomalies(
        self, package: str, version: str, meta: dict[str, Any]
    ) -> list[Event]:
        """Check for suspicious publishing patterns."""
        events: list[Event] = []
        # Check if version was yanked
        info = meta.get("info", {})
        if info.get("yanked"):
            ev = Event(
                severity="HIGH",
                rule_id="yanked-version",
                package=package,
                version=version,
                message=f"{package}=={version} has been yanked from PyPI",
                details={"reason": info.get("yanked_reason", "")},
            )
            self.alert_engine.fire(ev)
            events.append(ev)
        return events

    def close(self) -> None:
        self._client.close()
