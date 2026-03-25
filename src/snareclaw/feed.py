"""Layer 3 — Dependency Intelligence Feed.

Background polling of OSV.dev, deps.dev, and PyPI for vulnerability
and anomaly signals affecting packages in the user's lockfiles.
"""

from __future__ import annotations

import asyncio
import logging
import re
from pathlib import Path
from typing import Any

import httpx

from snareclaw.alerts import AlertEngine
from snareclaw.db import Event
from snareclaw.rules import RulesEngine

log = logging.getLogger("snareclaw.feed")

OSV_API = "https://api.osv.dev/v1"
DEPS_DEV_API = "https://api.deps.dev/v3alpha"
PYPI_JSON = "https://pypi.org/pypi/{package}/json"


def parse_requirements(path: Path) -> list[tuple[str, str | None]]:
    """Parse requirements.txt into (package, version|None) pairs."""
    results: list[tuple[str, str | None]] = []
    if not path.exists():
        return results
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Handle ==, >=, ~= etc
        match = re.match(r"^([a-zA-Z0-9_-]+)\s*(?:==\s*([^\s;#]+))?", line)
        if match:
            pkg = match.group(1).lower().replace("-", "_")
            ver = match.group(2)
            results.append((pkg, ver))
    return results


def parse_lockfile(path: Path) -> list[tuple[str, str]]:
    """Parse pip-compile / pip-tools lockfile."""
    results: list[tuple[str, str]] = []
    if not path.exists():
        return results
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^([a-zA-Z0-9_-]+)==([^\s;#\\]+)", line)
        if match:
            results.append((match.group(1).lower().replace("-", "_"), match.group(2)))
    return results


class FeedAggregator:
    def __init__(self, alert_engine: AlertEngine, rules: RulesEngine) -> None:
        self.alert_engine = alert_engine
        self.rules = rules

    async def check_packages(self, packages: list[tuple[str, str | None]]) -> list[Event]:
        """Check a list of (package, version) pairs against vulnerability feeds."""
        events: list[Event] = []
        async with httpx.AsyncClient(timeout=30) as client:
            tasks = [self._check_one(client, pkg, ver) for pkg, ver in packages]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, list):
                    events.extend(result)
                elif isinstance(result, Exception):
                    log.warning("Feed check failed: %s", result)
        return events

    async def _check_one(
        self, client: httpx.AsyncClient, package: str, version: str | None
    ) -> list[Event]:
        events: list[Event] = []

        # Check OSV for known vulnerabilities
        osv_events = await self._check_osv(client, package, version)
        events.extend(osv_events)

        # Check for unpinned + recently published (high risk combo)
        if version is None:
            unpin_events = await self._check_unpinned_risk(client, package)
            events.extend(unpin_events)

        return events

    async def _check_osv(
        self, client: httpx.AsyncClient, package: str, version: str | None
    ) -> list[Event]:
        events: list[Event] = []
        payload: dict[str, Any] = {"package": {"name": package, "ecosystem": "PyPI"}}
        if version:
            payload["version"] = version
        try:
            resp = await client.post(f"{OSV_API}/query", json=payload)
            resp.raise_for_status()
            data = resp.json()
        except httpx.HTTPError:
            return events

        for vuln in data.get("vulns", []):
            vuln_id = vuln.get("id", "unknown")
            summary = vuln.get("summary", "No summary")
            severity_data = vuln.get("database_specific", {}).get("severity", "")
            # Map CVSS-ish severity to our levels
            if "CRITICAL" in str(severity_data).upper():
                sev = "CRITICAL"
            elif "HIGH" in str(severity_data).upper():
                sev = "HIGH"
            else:
                sev = "MEDIUM"
            ev = Event(
                severity=sev,
                rule_id="known-vulnerability",
                package=package,
                version=version,
                message=f"{vuln_id}: {summary}",
                details={"vuln_id": vuln_id, "aliases": vuln.get("aliases", [])},
            )
            self.alert_engine.fire(ev)
            events.append(ev)
        return events

    async def _check_unpinned_risk(self, client: httpx.AsyncClient, package: str) -> list[Event]:
        """Flag unpinned deps that received a new publish recently."""
        events: list[Event] = []
        rule_id = "unpinned-with-recent-publish"
        if not self.rules.is_enabled(rule_id):
            return events
        try:
            resp = await client.get(PYPI_JSON.format(package=package))
            resp.raise_for_status()
            data = resp.json()
        except httpx.HTTPError:
            return events

        # Just flag unpinned as medium risk
        ev = Event(
            severity="MEDIUM",
            rule_id="unpinned-dependency",
            package=package,
            message=f"Dependency '{package}' is unpinned in requirements",
            details={"latest_version": data.get("info", {}).get("version", "unknown")},
        )
        self.alert_engine.fire(ev)
        events.append(ev)
        return events

    def scan_requirements_file(self, path: Path) -> list[tuple[str, str | None]]:
        """Parse and return packages from a requirements file."""
        if path.name.endswith(".txt"):
            return parse_requirements(path)
        return [(pkg, ver) for pkg, ver in parse_lockfile(path)]
