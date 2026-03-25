"""Alert engine — dispatches notifications based on severity."""

from __future__ import annotations

import logging
import subprocess
import sys
from dataclasses import dataclass, field

from snareclaw.db import Event, EventStore

log = logging.getLogger("snareclaw.alerts")

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


@dataclass
class AlertConfig:
    min_severity: str = "HIGH"
    desktop_notify: bool = True
    slack_webhook: str | None = None


class AlertEngine:
    def __init__(self, store: EventStore, config: AlertConfig | None = None) -> None:
        self.store = store
        self.config = config or AlertConfig()
        self._handlers: list[AlertHandler] = []
        if self.config.desktop_notify:
            self._handlers.append(DesktopNotifier())
        if self.config.slack_webhook:
            self._handlers.append(SlackNotifier(self.config.slack_webhook))

    def fire(self, event: Event) -> None:
        self.store.record(event)
        if SEVERITY_ORDER.get(event.severity, 99) <= SEVERITY_ORDER.get(self.config.min_severity, 1):
            for handler in self._handlers:
                try:
                    handler.notify(event)
                except Exception:
                    log.exception("Handler %s failed for event %s", handler, event.rule_id)


class AlertHandler:
    def notify(self, event: Event) -> None:
        raise NotImplementedError


class DesktopNotifier(AlertHandler):
    def notify(self, event: Event) -> None:
        title = f"SnareClaw [{event.severity}]"
        body = event.message
        if sys.platform == "darwin":
            subprocess.run(
                [
                    "osascript",
                    "-e",
                    f'display notification "{body}" with title "{title}"',
                ],
                check=False,
                capture_output=True,
            )
        elif sys.platform == "linux":
            subprocess.run(["notify-send", title, body], check=False, capture_output=True)


class SlackNotifier(AlertHandler):
    def __init__(self, webhook_url: str) -> None:
        self.webhook_url = webhook_url

    def notify(self, event: Event) -> None:
        import httpx

        icon = {"CRITICAL": "🚨", "HIGH": "⚠️", "MEDIUM": "📋", "LOW": "ℹ️"}.get(event.severity, "")
        text = f"{icon} *SnareClaw [{event.severity}]* — {event.message}"
        if event.package:
            text += f"\nPackage: `{event.package}`"
            if event.version:
                text += f" v{event.version}"
        try:
            httpx.post(self.webhook_url, json={"text": text}, timeout=10)
        except httpx.HTTPError:
            log.warning("Failed to send Slack notification")


class ConsoleNotifier(AlertHandler):
    """Prints alerts to stderr — used by CLI watch mode."""

    def notify(self, event: Event) -> None:
        from rich.console import Console

        console = Console(stderr=True)
        color = {"CRITICAL": "red bold", "HIGH": "yellow", "MEDIUM": "blue", "LOW": "dim"}.get(
            event.severity, ""
        )
        console.print(f"[{color}][{event.severity}][/{color}] {event.message}")
