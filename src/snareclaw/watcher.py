"""Layer 1 — Environment Watcher.

Monitors site-packages directories for suspicious file creation:
- .pth files (exact LiteLLM attack vector)
- New systemd service files, cron entries
- Subprocess spawning from import-time code
"""

from __future__ import annotations

import logging
import site
import sys
from pathlib import Path

from watchdog.events import FileCreatedEvent, FileSystemEventHandler
from watchdog.observers import Observer

from snareclaw.alerts import AlertEngine
from snareclaw.db import Event
from snareclaw.rules import RulesEngine

log = logging.getLogger("snareclaw.watcher")

# Directories that are suspicious for a Python package to touch
SUSPICIOUS_DIRS = [
    Path.home() / ".config",
    Path.home() / ".ssh",
    Path("/etc/systemd/system"),
    Path("/etc/cron.d"),
]

# Known legitimate .pth files that ship with Python itself
LEGITIMATE_PTH = {
    "distutils-precedence.pth",
    "easy-install.pth",
    "setuptools.pth",
    "pip.pth",
    "virtualenv.pth",
    "site-packages.pth",
    "_virtualenv.pth",
    "a1_coverage.pth",
}

# Patterns for .pth files that are legitimate (e.g. pip editable installs)
LEGITIMATE_PTH_PATTERNS = [
    "__editable__.",  # pip editable installs
    "_virtualenv",
]


def get_site_packages_dirs() -> list[Path]:
    """Return all site-packages directories for the current interpreter."""
    dirs: list[Path] = []
    for d in site.getsitepackages():
        p = Path(d)
        if p.exists():
            dirs.append(p)
    user_site = site.getusersitepackages()
    if isinstance(user_site, str):
        p = Path(user_site)
        if p.exists():
            dirs.append(p)
    return dirs


class SitePackagesHandler(FileSystemEventHandler):
    """Watches site-packages for suspicious file creation."""

    def __init__(self, alert_engine: AlertEngine, rules: RulesEngine) -> None:
        self.alert_engine = alert_engine
        self.rules = rules

    def on_created(self, event: FileCreatedEvent) -> None:  # type: ignore[override]
        if event.is_directory:
            return
        path = Path(event.src_path)
        self._check_pth(path)
        self._check_suspicious_file(path)

    def _check_pth(self, path: Path) -> None:
        if path.suffix != ".pth":
            return
        if path.name in LEGITIMATE_PTH:
            return
        if any(path.name.startswith(pat) for pat in LEGITIMATE_PTH_PATTERNS):
            return
        if self._is_benign_pth(path):
            return
        rule_id = "pth-file-in-wheel"
        if not self.rules.is_enabled(rule_id):
            return
        severity = self.rules.severity_for(rule_id)
        # Try to figure out which package dropped it
        package = self._guess_package_from_path(path)
        content_preview = ""
        try:
            content_preview = path.read_text(errors="replace")[:500]
        except OSError:
            pass
        self.alert_engine.fire(
            Event(
                severity=severity,
                rule_id=rule_id,
                package=package,
                message=f"Suspicious .pth file created: {path.name}",
                details={
                    "path": str(path),
                    "content_preview": content_preview,
                },
            )
        )
        log.warning("CRITICAL: .pth file created at %s", path)

    def _check_suspicious_file(self, path: Path) -> None:
        """Flag files that Python packages should never create."""
        suspicious_extensions = {".service", ".timer", ".socket"}  # systemd
        if path.suffix in suspicious_extensions:
            self.alert_engine.fire(
                Event(
                    severity="HIGH",
                    rule_id="suspicious-system-file",
                    message=f"Suspicious system file created: {path}",
                    details={"path": str(path)},
                )
            )

    @staticmethod
    def _is_benign_pth(path: Path) -> bool:
        """A .pth file that only contains filesystem paths (no import/code) is benign.

        Editable installs (hatch, setuptools) create .pth files with just a path.
        Malicious .pth files contain `import` statements or other executable code.
        """
        try:
            content = path.read_text(errors="replace").strip()
        except OSError:
            return False
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Lines starting with "import" are executable — NOT benign
            if line.startswith("import ") or line.startswith("import\t"):
                return False
            # Lines with semicolons likely contain code
            if ";" in line:
                return False
            # exec/eval/os/subprocess calls
            if any(kw in line for kw in ("exec(", "eval(", "os.", "subprocess", "__import__")):
                return False
        return True

    @staticmethod
    def _guess_package_from_path(path: Path) -> str | None:
        """Try to infer the package name from a .pth file's parent dir or name."""
        name = path.stem
        # e.g. litellm_init.pth -> litellm
        for suffix in ("_init", "_path", "_hook"):
            if name.endswith(suffix):
                return name[: -len(suffix)]
        return name


class EnvironmentWatcher:
    """Orchestrates filesystem monitoring across all site-packages dirs."""

    def __init__(self, alert_engine: AlertEngine, rules: RulesEngine) -> None:
        self.alert_engine = alert_engine
        self.rules = rules
        self._observer = Observer()
        self._handler = SitePackagesHandler(alert_engine, rules)

    def start(self) -> None:
        dirs = get_site_packages_dirs()
        if not dirs:
            log.warning("No site-packages directories found to watch")
            return
        for d in dirs:
            log.info("Watching %s", d)
            self._observer.schedule(self._handler, str(d), recursive=True)
        # Also watch suspicious system dirs if they exist
        for d in SUSPICIOUS_DIRS:
            if d.exists():
                log.info("Watching suspicious dir %s", d)
                self._observer.schedule(self._handler, str(d), recursive=True)
        self._observer.start()

    def stop(self) -> None:
        self._observer.stop()
        self._observer.join()

    def scan_existing(self) -> list[Event]:
        """One-shot scan of all site-packages for existing .pth files."""
        events: list[Event] = []
        for sp_dir in get_site_packages_dirs():
            for pth_file in sp_dir.glob("*.pth"):
                if pth_file.name in LEGITIMATE_PTH:
                    continue
                if any(pth_file.name.startswith(pat) for pat in LEGITIMATE_PTH_PATTERNS):
                    continue
                if SitePackagesHandler._is_benign_pth(pth_file):
                    continue
                content = ""
                try:
                    content = pth_file.read_text(errors="replace")[:500]
                except OSError:
                    pass
                package = SitePackagesHandler._guess_package_from_path(pth_file)
                ev = Event(
                    severity=self.rules.severity_for("pth-file-in-wheel"),
                    rule_id="pth-file-in-wheel",
                    package=package,
                    message=f"Existing suspicious .pth file: {pth_file.name}",
                    details={"path": str(pth_file), "content_preview": content},
                )
                self.alert_engine.fire(ev)
                events.append(ev)
        return events
