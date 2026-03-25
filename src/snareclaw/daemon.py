"""Snare Daemon — orchestrates all detection layers."""

from __future__ import annotations

import asyncio
import logging
import signal
import time
from pathlib import Path

from snareclaw.alerts import AlertConfig, AlertEngine, ConsoleNotifier
from snareclaw.db import EventStore
from snareclaw.feed import FeedAggregator, parse_requirements
from snareclaw.rules import RulesEngine
from snareclaw.secrets import SecretsScanner
from snareclaw.watcher import EnvironmentWatcher

log = logging.getLogger("snareclaw.daemon")


class SnareDaemon:
    def __init__(
        self,
        *,
        rules_path: Path | None = None,
        alert_config: AlertConfig | None = None,
        db_path: Path | None = None,
    ) -> None:
        self.store = EventStore(db_path) if db_path else EventStore()
        self.rules = RulesEngine(rules_path)
        config = alert_config or AlertConfig()
        self.alert_engine = AlertEngine(self.store, config)
        # Add console notifier for daemon mode
        self.alert_engine._handlers.append(ConsoleNotifier())

        self.watcher = EnvironmentWatcher(self.alert_engine, self.rules)
        self.feed = FeedAggregator(self.alert_engine, self.rules)
        self.secrets = SecretsScanner(self.alert_engine, self.rules)
        self._running = False

    def run(self, feed_interval: int = 900) -> None:
        """Run the daemon — blocks until SIGINT/SIGTERM."""
        self._running = True
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)

        log.info("SnareClaw daemon starting...")

        # Layer 1: Start filesystem watcher
        self.watcher.start()
        log.info("Filesystem watcher active")

        # Initial scan for existing .pth files
        existing = self.watcher.scan_existing()
        if existing:
            log.warning("Found %d suspicious .pth files in existing environment", len(existing))

        # Main loop — periodic feed checks
        last_feed_check = 0.0
        last_secrets_scan = 0.0
        secrets_interval = 86400  # 24 hours

        try:
            while self._running:
                now = time.time()

                # Layer 3: Periodic feed aggregation
                if now - last_feed_check >= feed_interval:
                    self._run_feed_check()
                    last_feed_check = now

                # Layer 4: Daily secrets scan
                if now - last_secrets_scan >= secrets_interval:
                    self._run_secrets_scan()
                    last_secrets_scan = now

                time.sleep(1)
        finally:
            self.watcher.stop()
            self.store.close()
            log.info("SnareClaw daemon stopped")

    def _run_feed_check(self) -> None:
        """Check lockfiles in CWD for vulnerability feeds."""
        cwd = Path.cwd()
        req_files = list(cwd.glob("requirements*.txt"))
        if not req_files:
            return
        for req_file in req_files:
            packages = parse_requirements(req_file)
            if packages:
                log.info("Checking %d packages from %s", len(packages), req_file.name)
                try:
                    events = asyncio.run(self.feed.check_packages(packages))
                    if events:
                        log.info("Feed check found %d issues", len(events))
                except Exception:
                    log.exception("Feed check failed")

    def _run_secrets_scan(self) -> None:
        """Scan CWD for exposed secrets."""
        cwd = Path.cwd()
        log.info("Running secrets scan on %s", cwd)
        events = self.secrets.scan_directory(cwd)
        if events:
            log.warning("Secrets scan found %d exposed secrets", len(events))

    def _handle_signal(self, signum: int, frame: object) -> None:
        log.info("Received signal %d, shutting down...", signum)
        self._running = False
