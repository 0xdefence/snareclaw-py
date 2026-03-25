"""SnareClaw CLI — snare command."""

from __future__ import annotations

import asyncio
import datetime
import logging
import sys
import time
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
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

# ─── 8-bit pixel crab mascot + blocky font ───────────────────────────

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

BANNER_SMALL = "[bold red]▐●●▌[/bold red] [bold]SnareClaw[/bold]"


def _banner(small: bool = False) -> None:
    if small:
        console.print(f"\n  {BANNER_SMALL} [dim]v{__version__}[/dim]\n")
    else:
        console.print("[bold red]" + CRAB.rstrip() + "[/bold red]")
        console.print("[bold red]" + LOGO_TEXT.rstrip() + "[/bold red]")
        console.print(f"  [dim]v{__version__} — Ambient supply chain security monitor[/dim]\n")


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    if not verbose:
        logging.getLogger("httpx").setLevel(logging.WARNING)
        logging.getLogger("httpcore").setLevel(logging.WARNING)


def _make_engine(db_path: Path | None = None) -> tuple[EventStore, AlertEngine, RulesEngine]:
    store = EventStore(db_path) if db_path else EventStore()
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
    """Build a compact inline severity bar like: !!!2  !!4  !12  .3"""
    parts = []
    icons = {"CRITICAL": "!!!", "HIGH": "!!", "MEDIUM": "!", "LOW": "."}
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        c = counts.get(sev, 0)
        if c > 0:
            style = SEV_STYLES[sev]
            parts.append(f"[{style}]{icons[sev]}{c}[/{style}]")
    return "  ".join(parts)


@click.group(invoke_without_command=True)
@click.version_option(__version__, prog_name="snareclaw")
@click.option("-v", "--verbose", is_flag=True, help="Enable debug logging")
@click.pass_context
def main(ctx: click.Context, verbose: bool) -> None:
    """SnareClaw — Ambient supply chain security monitor.

    Run with no subcommand to launch interactive mode.
    """
    _setup_logging(verbose)
    if ctx.invoked_subcommand is None:
        from snareclaw.interactive import run_interactive
        run_interactive()


# ─── watch ────────────────────────────────────────────────────────────

@main.command()
@click.option("--no-notify", is_flag=True, help="Disable desktop notifications")
@click.option("--feed-interval", default=900, help="Feed poll interval in seconds (default: 900)")
def watch(no_notify: bool, feed_interval: int) -> None:
    """Start the SnareClaw daemon (foreground)."""
    from snareclaw.daemon import SnareDaemon

    config = AlertConfig(desktop_notify=not no_notify)
    daemon = SnareDaemon(alert_config=config)

    _banner()
    console.print(f"  [dim]Feed interval:[/dim] {feed_interval}s")
    console.print(f"  [dim]Notifications:[/dim] {'on' if not no_notify else 'off'}")
    console.print(f"  [dim]Event log:[/dim]     ~/.snareclaw/events.db")
    console.print()
    console.rule("[bold red]▐●●▌[/bold red] [dim]watching — Ctrl+C to stop[/dim]")
    console.print()
    daemon.run(feed_interval=feed_interval)


# ─── scan ─────────────────────────────────────────────────────────────

@main.command()
@click.argument("target", default=".")
def scan(target: str) -> None:
    """Scan a requirements file or directory for issues."""
    store, engine, rules = _make_engine()
    target_path = Path(target).resolve()
    total_events: list[Event] = []

    _banner(small=True)

    if target_path.is_file():
        console.print(f"  Scanning [bold]{target_path.name}[/bold]")
        packages = parse_requirements(target_path)
        if packages:
            console.print(f"  [dim]{_pluralize(len(packages), 'package')} found[/dim]\n")
            with console.status("[dim]  Checking vulnerability feeds...[/dim]"):
                feed = FeedAggregator(engine, rules)
                events = asyncio.run(feed.check_packages(packages))
            total_events.extend(events)
        else:
            console.print("  [yellow]No packages found in file[/yellow]")
    elif target_path.is_dir():
        display_name = target_path.name or str(target_path)
        console.print(f"  Target: [bold]{display_name}/[/bold]\n")

        # 1. Most critical first: .pth files
        _step(1, 3, "Checking site-packages for .pth injections")
        watcher = EnvironmentWatcher(engine, rules)
        pth_events = watcher.scan_existing()
        total_events.extend(pth_events)
        _step_result(len(pth_events))

        # 2. Secrets scan
        _step(2, 3, "Scanning for exposed secrets")
        scanner = SecretsScanner(engine, rules)
        secret_events = scanner.scan_directory(target_path)
        total_events.extend(secret_events)
        _step_result(len(secret_events))

        # 3. Requirements / vulnerability feeds
        req_files = sorted(target_path.glob("requirements*.txt"))
        if req_files:
            names = ", ".join(f.name for f in req_files)
            _step(3, 3, f"Checking deps ({names})")
            for req_file in req_files:
                packages = parse_requirements(req_file)
                if packages:
                    feed = FeedAggregator(engine, rules)
                    events = asyncio.run(feed.check_packages(packages))
                    total_events.extend(events)
            _step_result(sum(1 for e in total_events if e.rule_id in ("known-vulnerability", "unpinned-dependency")))
        else:
            _step(3, 3, "No requirements files found, skipped")
            console.print()
    else:
        console.print(f"  [red]Target not found:[/red] {target}")
        sys.exit(1)

    _print_summary(total_events)
    store.close()

    if any(e.severity == "CRITICAL" for e in total_events):
        sys.exit(2)
    if any(e.severity == "HIGH" for e in total_events):
        sys.exit(1)


def _step(n: int, total: int, msg: str) -> None:
    console.print(f"  [dim][{n}/{total}][/dim] {msg}...", end="")


def _step_result(issue_count: int) -> None:
    if issue_count == 0:
        console.print(" [green]ok[/green]")
    else:
        console.print(f" [yellow]{_pluralize(issue_count, 'issue')}[/yellow]")


# ─── verify ───────────────────────────────────────────────────────────

@main.command()
@click.argument("package")
@click.argument("version")
@click.option("--github-token", envvar="GITHUB_TOKEN", help="GitHub API token")
def verify(package: str, version: str, github_token: str | None) -> None:
    """Verify a specific package version against its source."""
    store, engine, rules = _make_engine()
    verifier = PackageVerifier(engine, rules, github_token=github_token)

    _banner(small=True)
    console.print(f"  Verifying [bold]{package}=={version}[/bold]\n")

    with console.status("[dim]  Downloading wheel, diffing against source...[/dim]"):
        events = verifier.verify_package(package, version)
    verifier.close()

    if not events:
        console.print("  [green bold]*[/green bold] [green]Clean[/green] — no issues found\n")
    else:
        _print_summary(events)

    store.close()
    if any(e.severity == "CRITICAL" for e in events):
        sys.exit(2)


# ─── history ──────────────────────────────────────────────────────────

@main.command()
@click.option("--severity", type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"]))
@click.option("--package", help="Filter by package name")
@click.option("--last", "days", default=7, help="Show events from last N days (default: 7)")
@click.option("--limit", default=50, help="Max events to show (default: 50)")
def history(severity: str | None, package: str | None, days: int, limit: int) -> None:
    """Show alert history."""
    store = EventStore()
    since = time.time() - (days * 86400)
    events = store.query(severity=severity, package=package, since=since, limit=limit)
    store.close()

    _banner(small=True)

    if not events:
        console.print("  [dim]No events in the last " + _pluralize(days, "day") + "[/dim]\n")
        return

    day_label = _pluralize(days, "day")
    console.print(f"  [dim]Last {day_label} | {_pluralize(len(events), 'event')} (limit {limit})[/dim]\n")

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


# ─── status ───────────────────────────────────────────────────────────

@main.command()
def status() -> None:
    """Show current environment health summary."""
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

    _banner()

    # Status panel
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
    lines.append(f"  [dim]Event log:  ~/.snareclaw/events.db[/dim]")
    lines.append(f"  [dim]Rules:      ~/.snareclaw/rules.toml[/dim]")

    panel_content = "\n".join(lines)
    console.print(Panel(panel_content, border_style=border_style, padding=(1, 2)))
    console.print()


# ─── trust ────────────────────────────────────────────────────────────

@main.command()
@click.argument("package")
@click.argument("version")
@click.option("--reason", help="Why this version is trusted")
def trust(package: str, version: str, reason: str | None) -> None:
    """Mark a package version as explicitly trusted (allowlisted)."""
    store = EventStore()
    store.trust_package(package, version, reason)
    store.close()
    _banner(small=True)
    console.print(f"  [green bold]*[/green bold] Trusted [bold]{package}=={version}[/bold]")
    if reason:
        console.print(f"    [dim]Reason:[/dim] {reason}")
    console.print(f"    [dim]Future scans will skip this version[/dim]\n")


# ─── shared formatting ───────────────────────────────────────────────

def _print_summary(events: list[Event]) -> None:
    console.print()
    if not events:
        console.print("  [green bold]*[/green bold] [green]All clear[/green] — no issues found\n")
        return

    counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for ev in events:
        counts[ev.severity] = counts.get(ev.severity, 0) + 1

    total = len(events)
    console.print(f"  {_severity_bar(counts)}  [dim]({_pluralize(total, 'issue')} total)[/dim]\n")


if __name__ == "__main__":
    main()
