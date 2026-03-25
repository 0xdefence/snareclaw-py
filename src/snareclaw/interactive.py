"""Interactive TUI mode for SnareClaw.

Launched with `snare` (no subcommand) — presents a menu-driven interface
for scanning, verifying, browsing history, and monitoring in real time.
"""

from __future__ import annotations

import asyncio
import datetime
import os
import sys
import time
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from snareclaw import __version__
from snareclaw.alerts import AlertConfig, AlertEngine, ConsoleNotifier
from snareclaw.db import Event, EventStore
from snareclaw.feed import FeedAggregator, parse_requirements
from snareclaw.rules import RulesEngine
from snareclaw.secrets import SecretsScanner
from snareclaw.verifier import PackageVerifier
from snareclaw.watcher import EnvironmentWatcher

console = Console()

SEV_STYLES = {
    "CRITICAL": "red bold",
    "HIGH": "yellow",
    "MEDIUM": "blue",
    "LOW": "dim",
}

CRAB = r"""
               █▀     ▀█
              ▐██ ▄█▄ ██▌
               ▀█ ● ● █▀
                ▀█████▀
                ▐█ █ █▌
                 ▀   ▀
"""

LOGO_TEXT = r"""
  █▀▀ █▄ █ █▀█ █▀▄ █▀▀ █▀▀ █   █▀█ █   █
  ▀▀█ █ ▀█ █▀█ ██▀ █▀  █   █   █▀█ █ █ █
  ▀▀▀ ▀  ▀ ▀ ▀ ▀ ▀ ▀▀▀ ▀▀▀ ▀▀▀ ▀ ▀ ▀▀ ▀▀
"""


def _make_engine() -> tuple[EventStore, AlertEngine, RulesEngine]:
    store = EventStore()
    rules = RulesEngine()
    config = AlertConfig(desktop_notify=False)
    engine = AlertEngine(store, config)
    engine._handlers.append(ConsoleNotifier())
    return store, engine, rules


def _pluralize(n: int, singular: str, plural: str | None = None) -> str:
    if n == 1:
        return f"{n} {singular}"
    return f"{n} {plural or singular + 's'}"


def _severity_bar(counts: dict[str, int]) -> str:
    parts = []
    icons = {"CRITICAL": "!!!", "HIGH": "!!", "MEDIUM": "!", "LOW": "."}
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        c = counts.get(sev, 0)
        if c > 0:
            style = SEV_STYLES[sev]
            parts.append(f"[{style}]{icons[sev]}{c}[/{style}]")
    return "  ".join(parts)


def _clear() -> None:
    os.system("cls" if sys.platform == "win32" else "clear")


def _print_banner() -> None:
    console.print("[bold red]" + CRAB.rstrip() + "[/bold red]")
    console.print("[bold red]" + LOGO_TEXT.rstrip() + "[/bold red]")
    console.print(f"  [dim]v{__version__} — Ambient supply chain security monitor[/dim]\n")


def _print_menu() -> None:
    menu = Table(show_header=False, box=None, padding=(0, 2), show_edge=False)
    menu.add_column(style="bold red", width=4, justify="right")
    menu.add_column(style="bold", width=18)
    menu.add_column(style="dim")

    menu.add_row("1", "Scan project", "Scan a directory for .pth injection, secrets, vulns")
    menu.add_row("2", "Verify package", "Diff a PyPI wheel against its GitHub source")
    menu.add_row("3", "Alert history", "Browse recent security events")
    menu.add_row("4", "Status", "Environment health dashboard")
    menu.add_row("5", "Watch", "Start real-time monitoring daemon")
    menu.add_row("6", "Trust package", "Allowlist a known-good package version")
    menu.add_row("", "", "")
    menu.add_row("q", "Quit", "")

    console.print(Panel(menu, border_style="red", title="[bold red]▐●●▌[/bold red] [bold]Menu[/bold]", padding=(1, 2)))


def _prompt() -> str:
    return Prompt.ask("\n  [bold red]▐●●▌[/bold red] Choose", choices=["1", "2", "3", "4", "5", "6", "q"], show_choices=False)


# ─── Scan project ────────────────────────────────────────────────────

def _action_scan() -> None:
    console.print()
    console.rule("[bold]Scan Project[/bold]")
    console.print()

    target = Prompt.ask("  [dim]Path to scan[/dim]", default=".")
    target_path = Path(target).resolve()

    if not target_path.exists():
        console.print(f"  [red]Path not found:[/red] {target}")
        return

    store, engine, rules = _make_engine()
    total_events: list[Event] = []
    display = target_path.name or str(target_path)

    console.print(f"\n  Scanning [bold]{display}/[/bold]\n")

    if target_path.is_dir():
        # 1. .pth check
        console.print("  [dim][1/3][/dim] Checking .pth injections...", end="")
        watcher = EnvironmentWatcher(engine, rules)
        pth_events = watcher.scan_existing()
        total_events.extend(pth_events)
        _step_done(len(pth_events))

        # 2. Secrets
        console.print("  [dim][2/3][/dim] Scanning for exposed secrets...", end="")
        scanner = SecretsScanner(engine, rules)
        secret_events = scanner.scan_directory(target_path)
        total_events.extend(secret_events)
        _step_done(len(secret_events))

        # 3. Deps
        req_files = sorted(target_path.glob("requirements*.txt"))
        if req_files:
            names = ", ".join(f.name for f in req_files)
            console.print(f"  [dim][3/3][/dim] Checking deps ({names})...", end="")
            for req_file in req_files:
                packages = parse_requirements(req_file)
                if packages:
                    feed = FeedAggregator(engine, rules)
                    events = asyncio.run(feed.check_packages(packages))
                    total_events.extend(events)
            dep_count = sum(1 for e in total_events if e.rule_id in ("known-vulnerability", "unpinned-dependency"))
            _step_done(dep_count)
        else:
            console.print("  [dim][3/3][/dim] No requirements files, skipped")
    elif target_path.is_file():
        console.print("  [dim][1/1][/dim] Checking vulnerability feeds...", end="")
        packages = parse_requirements(target_path)
        if packages:
            feed = FeedAggregator(engine, rules)
            events = asyncio.run(feed.check_packages(packages))
            total_events.extend(events)
        _step_done(len(total_events))

    _print_results(total_events)
    store.close()


def _step_done(count: int) -> None:
    if count == 0:
        console.print(" [green]ok[/green]")
    else:
        console.print(f" [yellow]{_pluralize(count, 'issue')}[/yellow]")


# ─── Verify package ──────────────────────────────────────────────────

def _action_verify() -> None:
    console.print()
    console.rule("[bold]Verify Package[/bold]")
    console.print()

    package = Prompt.ask("  [dim]Package name[/dim]")
    if not package.strip():
        return
    version = Prompt.ask("  [dim]Version[/dim]")
    if not version.strip():
        return

    store, engine, rules = _make_engine()
    github_token = os.environ.get("GITHUB_TOKEN")
    verifier = PackageVerifier(engine, rules, github_token=github_token)

    console.print(f"\n  Verifying [bold]{package}=={version}[/bold]\n")

    with console.status("[dim]  Downloading wheel, diffing against source...[/dim]"):
        events = verifier.verify_package(package, version)
    verifier.close()

    if not events:
        console.print("  [green bold]*[/green bold] [green]Clean[/green] — no issues found\n")
    else:
        _print_results(events)

    store.close()


# ─── Alert history ───────────────────────────────────────────────────

def _action_history() -> None:
    console.print()
    console.rule("[bold]Alert History[/bold]")
    console.print()

    days = IntPrompt.ask("  [dim]Show last N days[/dim]", default=7)
    sev_filter = Prompt.ask(
        "  [dim]Filter severity (enter to skip)[/dim]",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", ""],
        default="",
        show_choices=False,
    )
    pkg_filter = Prompt.ask("  [dim]Filter package (enter to skip)[/dim]", default="")

    store = EventStore()
    since = time.time() - (days * 86400)
    events = store.query(
        severity=sev_filter or None,
        package=pkg_filter or None,
        since=since,
        limit=50,
    )
    store.close()

    console.print()
    if not events:
        console.print(f"  [dim]No events in the last {_pluralize(days, 'day')}[/dim]\n")
        return

    console.print(f"  [dim]{_pluralize(len(events), 'event')} (last {_pluralize(days, 'day')})[/dim]\n")

    for ev in events:
        ts = datetime.datetime.fromtimestamp(ev.timestamp).strftime("%m/%d %H:%M")
        style = SEV_STYLES.get(ev.severity, "")
        pkg = f"[bold]{ev.package}[/bold]" if ev.package else ""
        msg = ev.message
        if ev.package and msg.startswith("Existing suspicious .pth file: "):
            msg = msg.replace("Existing suspicious ", "")
        if ev.package and msg.startswith(f"Dependency '{ev.package}'"):
            msg = msg.replace(f"Dependency '{ev.package}' ", "")
        console.print(f"  [dim]{ts}[/dim]  [{style}]{ev.severity:>8}[/{style}]  {pkg}  [dim]{msg}[/dim]")

    console.print()


# ─── Status ──────────────────────────────────────────────────────────

def _action_status() -> None:
    console.print()
    console.rule("[bold]Environment Status[/bold]")
    console.print()

    store = EventStore()
    since_24h = time.time() - 86400
    since_7d = time.time() - 604800

    recent = store.query(since=since_24h, limit=1000)
    week = store.query(since=since_7d, limit=1000)
    store.close()

    counts_24h: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for ev in recent:
        counts_24h[ev.severity] = counts_24h.get(ev.severity, 0) + 1

    counts_7d: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for ev in week:
        counts_7d[ev.severity] = counts_7d.get(ev.severity, 0) + 1

    total_24h = sum(counts_24h.values())
    total_7d = sum(counts_7d.values())

    if counts_24h["CRITICAL"] > 0:
        health_text = "CRITICAL"
        health_style = "red bold"
        border_style = "red"
    elif counts_24h["HIGH"] > 0:
        health_text = "DEGRADED"
        health_style = "yellow"
        border_style = "yellow"
    elif counts_24h["MEDIUM"] > 0:
        health_text = "FAIR"
        health_style = "blue"
        border_style = "blue"
    else:
        health_text = "HEALTHY"
        health_style = "green bold"
        border_style = "green"

    lines: list[str] = []
    lines.append(f"  [{health_style}]{health_text}[/{health_style}]")
    lines.append("")

    if total_24h == 0 and total_7d == 0:
        lines.append("  No alerts in the last 7 days.")
        lines.append("  Your environment looks clean.")
    else:
        lines.append(f"  [dim]24h:[/dim]  {_severity_bar(counts_24h)}  [dim]({total_24h} total)[/dim]")
        lines.append(f"  [dim] 7d:[/dim]  {_severity_bar(counts_7d)}  [dim]({total_7d} total)[/dim]")

    lines.append("")
    lines.append("  [dim]Event log:  ~/.snareclaw/events.db[/dim]")
    lines.append("  [dim]Rules:      ~/.snareclaw/rules.toml[/dim]")

    console.print(Panel("\n".join(lines), border_style=border_style, padding=(1, 2)))
    console.print()


# ─── Watch ───────────────────────────────────────────────────────────

def _action_watch() -> None:
    from snareclaw.daemon import SnareDaemon

    console.print()
    console.rule("[bold]Real-Time Monitor[/bold]")
    console.print()
    console.print("  Starting filesystem watcher + feed aggregator...")
    console.print("  Press [bold]Ctrl+C[/bold] to return to menu\n")

    config = AlertConfig(desktop_notify=True)
    daemon = SnareDaemon(alert_config=config)

    console.rule("[bold red]▐●●▌[/bold red] [dim]watching[/dim]")
    console.print()

    try:
        daemon.run(feed_interval=900)
    except KeyboardInterrupt:
        console.print("\n  [dim]Stopped watching[/dim]\n")


# ─── Trust ───────────────────────────────────────────────────────────

def _action_trust() -> None:
    console.print()
    console.rule("[bold]Trust Package[/bold]")
    console.print()

    package = Prompt.ask("  [dim]Package name[/dim]")
    if not package.strip():
        return
    version = Prompt.ask("  [dim]Version[/dim]")
    if not version.strip():
        return
    reason = Prompt.ask("  [dim]Reason (optional)[/dim]", default="")

    store = EventStore()
    store.trust_package(package, version, reason or None)
    store.close()

    console.print(f"\n  [green bold]*[/green bold] Trusted [bold]{package}=={version}[/bold]")
    if reason:
        console.print(f"    [dim]Reason:[/dim] {reason}")
    console.print("    [dim]Future scans will skip this version[/dim]\n")


# ─── Results printer ─────────────────────────────────────────────────

def _print_results(events: list[Event]) -> None:
    console.print()
    if not events:
        console.print("  [green bold]*[/green bold] [green]All clear[/green] — no issues found\n")
        return

    counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for ev in events:
        counts[ev.severity] = counts.get(ev.severity, 0) + 1

    total = len(events)
    console.print(f"  {_severity_bar(counts)}  [dim]({_pluralize(total, 'issue')} total)[/dim]\n")


# ─── Main loop ───────────────────────────────────────────────────────

ACTIONS = {
    "1": _action_scan,
    "2": _action_verify,
    "3": _action_history,
    "4": _action_status,
    "5": _action_watch,
    "6": _action_trust,
}


def run_interactive() -> None:
    """Main interactive loop."""
    _clear()
    _print_banner()
    _print_menu()

    while True:
        try:
            choice = _prompt()
        except (KeyboardInterrupt, EOFError):
            console.print("\n")
            break

        if choice == "q":
            console.print("\n  [dim]Bye.[/dim]\n")
            break

        action = ACTIONS.get(choice)
        if action:
            try:
                action()
            except KeyboardInterrupt:
                console.print("\n  [dim]Interrupted[/dim]\n")
            except Exception as e:
                console.print(f"\n  [red]Error:[/red] {e}\n")

            # Show menu again
            _print_menu()
