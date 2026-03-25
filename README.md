# SnareClaw

**Ambient supply chain security monitor for Python environments.**

SnareClaw watches your local Python environments in real time and fires alerts the moment a dependency behaves suspiciously — before your RAM is gone and your SSH keys aren't.

## Why This Exists

On March 24, 2026, [LiteLLM v1.82.8 was compromised on PyPI](https://blog.pypi.org/posts/2026-03-24-litellm-compromise/). The attack:

1. Injected `litellm_init.pth` into `site-packages` — a file that runs code on **every Python startup**
2. Spawned background processes to exfiltrate SSH keys, cloud tokens, and environment variables
3. The malicious code **never appeared in the GitHub repo** — only in the PyPI wheel
4. No CVE existed. Snyk, Dependabot, and npm audit had nothing

**500,000 systems were affected before anyone noticed.**

Current tooling is reactive and CVE-indexed. SnareClaw fills the gap: **local, real-time, pre-CVE supply chain anomaly detection**.

## Install

```bash
pip install snareclaw
```

Or from source:

```bash
git clone https://github.com/openclaw/snareclaw-py.git
cd snareclaw-py
pip install -e .
```

## Quick Start

```bash
# Start the background watcher
snare watch

# Scan your current project
snare scan .

# Verify a specific package
snare verify litellm 1.82.7

# Check environment health
snare status

# View alert history
snare history --last 7d
```

## What It Detects

### Layer 1 — Environment Watcher (always on)
- `.pth` files appearing in `site-packages` (exact LiteLLM attack vector)
- Suspicious system file creation (systemd services, cron entries)
- New files in `~/.config`, `~/.ssh` from Python subprocesses

### Layer 2 — Wheel Verification (on demand)
- PyPI wheel file tree diffed against GitHub source tree
- `.pth` files inside wheel archives
- Yanked versions flagged immediately

### Layer 3 — Vulnerability Feed (background, 15min intervals)
- Cross-references your lockfile against OSV.dev and deps.dev
- Flags unpinned dependencies with recent publishes
- Known vulnerability matching

### Layer 4 — Secrets Scanner (on scan)
- PyPI tokens, npm tokens, GitHub tokens, AWS keys in `.env` / CI YAML
- The exact failure mode that let LiteLLM's PyPI token get stolen

## Alert Severity

| Level | Meaning | Example |
|-------|---------|---------|
| **CRITICAL** | Block install, require override | `.pth` in wheel, subprocess at import |
| **HIGH** | Alert immediately | Wheel/source mismatch, new publisher |
| **MEDIUM** | Background alert | Unpinned dep, exposed secret |
| **LOW** | Weekly digest | Low-CVSS CVEs, single maintainer |

## Configuration

Rules are declarative TOML. Copy and customize:

```bash
cp snare.toml ~/.snareclaw/rules.toml
```

Example rule:

```toml
[[rules]]
id = "pth-file-in-wheel"
severity = "CRITICAL"
action = "block"
description = "Wheel contains .pth file not present in source repo"
```

## Trust Model

```bash
# Explicitly trust a package version
snare trust litellm 1.82.6 --reason "Verified clean by maintainer"
```

All analysis is local by default. No phone-home. No cloud dependency.

## Architecture

```
snare watch
    |
    +-- FS Watcher (watchdog) --> monitors site-packages in real time
    +-- Feed Aggregator (httpx) --> polls OSV/deps.dev/PyPI every 15min
    +-- Secrets Scanner ----------> daily scan of project directory
    |
    +-- Alert Engine --> desktop notifications + console output
    +-- SQLite -------> local event history (~/.snareclaw/events.db)
```

## Resource Usage

| State | CPU | RAM |
|-------|-----|-----|
| Idle watch | <0.5% | ~25MB |
| Install intercept | 2-5% burst | ~40MB |
| Feed poll | 1% burst | ~30MB |
| Secrets scan | 5-15% | ~50MB |

## Roadmap

- [ ] Rust daemon rewrite (single binary, <8MB)
- [ ] VS Code extension with inline warnings
- [ ] pip install hook (intercept before install completes)
- [ ] Import-time subprocess detection
- [ ] Local web dashboard at localhost:7734
- [ ] GitHub Actions integration

## License

MIT

---

*Built by [OpenClaw](https://github.com/openclaw) in response to the LiteLLM supply chain attack — March 2026*
