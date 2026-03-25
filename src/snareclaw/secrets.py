"""Layer 4 — Secrets Posture Scanner.

Scans local repos for tokens/keys committed in .env, CI YAML,
or GitHub Actions workflow env blocks.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path

from snareclaw.alerts import AlertEngine
from snareclaw.db import Event
from snareclaw.rules import RulesEngine

log = logging.getLogger("snareclaw.secrets")


@dataclass
class SecretPattern:
    name: str
    pattern: re.Pattern[str]
    severity: str = "MEDIUM"


# Patterns tuned for supply chain attack vectors — PyPI tokens, npm tokens, cloud keys
SECRET_PATTERNS = [
    SecretPattern("PyPI API Token", re.compile(r"pypi-[A-Za-z0-9_-]{16,}")),
    SecretPattern("npm Token", re.compile(r"npm_[A-Za-z0-9]{36}")),
    SecretPattern("GitHub Token", re.compile(r"gh[ps]_[A-Za-z0-9]{36,}")),
    SecretPattern("GitHub Fine-Grained Token", re.compile(r"github_pat_[A-Za-z0-9_]{20,}")),
    SecretPattern("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    SecretPattern("AWS Secret Key", re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}")),
    SecretPattern("Generic API Key", re.compile(r"(?i)(?:api[_-]?key|apikey)\s*[=:]\s*['\"]?[A-Za-z0-9_-]{20,}['\"]?")),
]

# Files to scan
SCAN_GLOBS = [
    ".env",
    ".env.*",
    "*.yml",
    "*.yaml",
    ".github/workflows/*.yml",
    ".github/workflows/*.yaml",
    "docker-compose*.yml",
    "Dockerfile*",
    "Makefile",
    "*.toml",
    "*.cfg",
    "*.ini",
]

# Files to skip
SKIP_PATTERNS = {
    "node_modules",
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    ".tox",
    "dist",
    "build",
    ".egg-info",
}


class SecretsScanner:
    def __init__(self, alert_engine: AlertEngine, rules: RulesEngine) -> None:
        self.alert_engine = alert_engine
        self.rules = rules

    def scan_directory(self, directory: Path) -> list[Event]:
        """Scan a directory tree for exposed secrets."""
        events: list[Event] = []
        if not directory.exists():
            return events

        for glob_pattern in SCAN_GLOBS:
            for filepath in directory.rglob(glob_pattern):
                if self._should_skip(filepath):
                    continue
                if filepath.is_file():
                    file_events = self._scan_file(filepath)
                    events.extend(file_events)
        return events

    def _should_skip(self, path: Path) -> bool:
        return any(skip in path.parts for skip in SKIP_PATTERNS)

    def _scan_file(self, filepath: Path) -> list[Event]:
        events: list[Event] = []
        try:
            content = filepath.read_text(errors="replace")
        except OSError:
            return events

        for line_num, line in enumerate(content.splitlines(), 1):
            for sp in SECRET_PATTERNS:
                match = sp.pattern.search(line)
                if match:
                    # Redact the actual secret value
                    matched = match.group(0)
                    redacted = matched[:8] + "..." + matched[-4:] if len(matched) > 16 else "***"
                    ev = Event(
                        severity=sp.severity,
                        rule_id="exposed-secret",
                        message=f"{sp.name} found in {filepath.name}:{line_num}",
                        details={
                            "file": str(filepath),
                            "line": line_num,
                            "pattern": sp.name,
                            "redacted_match": redacted,
                        },
                    )
                    self.alert_engine.fire(ev)
                    events.append(ev)
                    break  # One match per line is enough
        return events
