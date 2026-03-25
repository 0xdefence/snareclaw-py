<div align="center">

```
               █▀     ▀█
              ▐██ ▄█▄ ██▌
               ▀█ ● ● █▀
                ▀█████▀
                ▐█ █ █▌
                 ▀   ▀

  █▀▀ █▄ █ █▀█ █▀▄ █▀▀ █▀▀ █   █▀█ █   █
  ▀▀█ █ ▀█ █▀█ ██▀ █▀  █   █   █▀█ █ █ █
  ▀▀▀ ▀  ▀ ▀ ▀ ▀ ▀ ▀▀▀ ▀▀▀ ▀▀▀ ▀ ▀ ▀▀ ▀▀
```

**Ambient supply chain security monitor for Python environments.**

*Watches your dependencies in real time. Fires alerts before your RAM is gone and your SSH keys aren't.*

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

</div>

---

## Why This Exists

On March 24, 2026, **LiteLLM v1.82.8 was compromised on PyPI**. The attack:

1. Injected `litellm_init.pth` into `site-packages` — a file that runs code on **every Python startup**
2. Spawned background processes to exfiltrate SSH keys, cloud tokens, and environment variables
3. The malicious code **never appeared in the GitHub repo** — only in the PyPI wheel
4. No CVE existed. Snyk, Dependabot, and npm audit had nothing

**500,000 systems were affected before anyone noticed.**

Current tooling is reactive and CVE-indexed. SnareClaw fills the gap: **local, real-time, pre-CVE supply chain anomaly detection**.

## Install

```bash
# One-liner (auto-detects best method)
curl -fsSL https://raw.githubusercontent.com/0xDefence/snareclaw-py/main/install.sh | bash
```

### pip / pipx

```bash
pip install snareclaw       # standard
pipx install snareclaw      # isolated (recommended)
```

### npm / pnpm / bun

```bash
npm install -g snareclaw    # auto-installs Python package on first run
pnpm add -g snareclaw
bun add -g snareclaw
```

### Homebrew (macOS)

```bash
brew tap 0xDefence/tap
brew install snareclaw
```

### From source

```bash
git clone https://github.com/0xDefence/snareclaw-py.git
cd snareclaw-py
pip install -e .
```

## Quick Start

### Interactive Mode

Run `snare` with no arguments to launch the interactive TUI:

```bash
snare
```

```
╭───────────────────────────────── ▐●●▌ Menu ──────────────────────────────────╮
│                                                                              │
│       1    Scan project          Scan a directory for .pth injection,        │
│                                  secrets, vulns                              │
│       2    Verify package        Diff a PyPI wheel against its GitHub        │
│                                  source                                      │
│       3    Alert history         Browse recent security events               │
│       4    Status                Environment health dashboard                │
│       5    Watch                 Start real-time monitoring daemon           │
│       6    Trust package         Allowlist a known-good package version      │
│                                                                              │
│       q    Quit                                                              │
│                                                                              │
╰──────────────────────────────────────────────────────────────────────────────╯
```

### Direct Commands

```bash
snare status                  # Environment health dashboard
snare scan .                  # Scan current project
snare verify litellm 1.82.7   # Diff wheel against source
snare watch                   # Start real-time monitoring
snare history --last 7        # Browse alert history
snare trust requests 2.31.0 --reason "verified clean"
```

### What You'll See

```
  ▐●●▌ SnareClaw v0.1.0

  Target: my-project/

  [1/3] Checking site-packages for .pth injections... ok
  [2/3] Scanning for exposed secrets... ok
  [3/3] Checking deps (requirements.txt)... 2 issues

  !!2  !5  (7 issues total)
```

## Detection Layers

### Layer 1 — Environment Watcher (always on)

Monitors `site-packages/` in real time via filesystem events.

- **`.pth` file injection** — the exact LiteLLM attack vector. Distinguishes malicious `.pth` files (containing `import`, `exec`, `subprocess`) from benign editable installs (path-only)
- **Suspicious system files** — flags systemd services, cron entries, or `~/.ssh` / `~/.config` mutations from Python packages

### Layer 2 — Wheel Verification (on demand)

Downloads the PyPI wheel and diffs it against the GitHub source tree.

- **Wheel vs source mismatch** — files present in the wheel but absent from the repo
- **`.pth` files inside wheels** — should almost never exist in a legitimate package
- **Yanked versions** — flagged immediately from PyPI metadata

### Layer 3 — Vulnerability Feed (background, 15min intervals)

Polls free APIs to check your lockfile against known threats.

- **OSV.dev** — Google-funded vulnerability database (unlimited, free)
- **deps.dev** — package metadata and dependency graphs (unlimited, free)
- **Unpinned dependency risk** — flags deps without version pins that received recent publishes

### Layer 4 — Secrets Scanner (on scan)

Regex-based detection of tokens and keys in project files.

- PyPI publish tokens, npm tokens, GitHub PATs, AWS access keys
- Scans `.env`, CI YAML, GitHub Actions workflows, Dockerfiles
- Redacts matched values in alert output
- This is the exact failure mode that let LiteLLM's `PYPI_PUBLISH` token get exfiltrated

## Alert Severity

| Level | Action | Examples |
|-------|--------|----------|
| **CRITICAL** | Block install, require `--force` override | `.pth` in wheel, subprocess at import, known malicious hash |
| **HIGH** | Alert immediately, allow with warning | Wheel/source mismatch, publisher < 30 days old, yanked version |
| **MEDIUM** | Background alert | Unpinned dep, exposed secret, abandoned package |
| **LOW** | Weekly digest | Low-CVSS CVEs, single-maintainer packages |

## Configuration

Rules are declarative TOML — user-editable, version-controllable:

```bash
cp snare.toml ~/.snareclaw/rules.toml
```

```toml
[[rules]]
id = "pth-file-in-wheel"
severity = "CRITICAL"
action = "block"
description = "Wheel contains .pth file not present in source repo"

[[rules]]
id = "wheel-source-mismatch"
severity = "HIGH"
action = "alert"
description = "Wheel contains files absent from GitHub source"

[[rules]]
id = "exposed-secret"
severity = "MEDIUM"
action = "alert"
description = "Token or key found in local file"
```

14 rules ship by default. See [`snare.toml`](snare.toml) for the full set.

## Trust Model

```bash
# Explicitly trust a verified version
snare trust litellm 1.82.6 --reason "Verified clean by maintainer"

# Future scans skip this version
# Trust entries stored locally in ~/.snareclaw/events.db
```

- **Local-first** — all analysis runs on your machine. No phone-home. No cloud dependency.
- **Allowlist** — trust specific package versions with audit trail
- **Override** — CRITICAL blocks can be bypassed with explicit user action + logged

## Architecture

```
snare watch
  │
  ├── FS Watcher (watchdog)
  │   └── monitors site-packages for .pth injection, suspicious files
  │
  ├── Feed Aggregator (httpx, async)
  │   └── polls OSV.dev / deps.dev / PyPI every 15min
  │
  ├── Secrets Scanner
  │   └── regex scan of .env, CI YAML, workflows
  │
  ├── Alert Engine
  │   ├── macOS native notifications (osascript)
  │   ├── Linux desktop notifications (notify-send)
  │   ├── Slack webhook (optional)
  │   └── Console output (Rich)
  │
  └── SQLite Event Store
      └── ~/.snareclaw/events.db
```

### Tech Stack

| Component | Choice | Why |
|-----------|--------|-----|
| CLI | Click + Rich | Composable commands, styled terminal output |
| FS monitoring | watchdog | Cross-platform (FSEvents/inotify), battle-tested |
| HTTP | httpx (sync + async) | Modern, connection pooling, timeout handling |
| Vuln feeds | OSV.dev, deps.dev, PyPI JSON API | All free, no API keys required |
| Storage | SQLite | Zero infra, queryable history, single file |
| Rules | TOML | Human-readable, git-friendly, no runtime deps |

### Cost of Running

**$0/month.** All external APIs are free tier:

| API | Free Tier |
|-----|-----------|
| OSV.dev | Unlimited (Google-funded) |
| deps.dev | Unlimited (Google-funded) |
| PyPI JSON API | Unlimited |
| GitHub API | 60 req/hr unauth, 5,000/hr with token |

## CLI Reference

| Command | Description |
|---------|-------------|
| `snare` | **Launch interactive TUI** — menu-driven scanning, verification, history |
| `snare status` | Environment health dashboard with severity breakdown |
| `snare scan [TARGET]` | One-shot scan of directory or requirements file |
| `snare verify PKG VER` | Diff a package's PyPI wheel against its GitHub source |
| `snare watch` | Start real-time daemon (FS watcher + feed polling + secrets) |
| `snare history` | Query the local event log with filters |
| `snare trust PKG VER` | Allowlist a known-good package version |

### Global Options

| Flag | Description |
|------|-------------|
| `--version` | Show version |
| `-v, --verbose` | Enable debug logging (includes HTTP request traces) |

### Install Methods

| Method | Command |
|--------|---------|
| pip | `pip install snareclaw` |
| pipx | `pipx install snareclaw` |
| npm | `npm install -g snareclaw` |
| pnpm | `pnpm add -g snareclaw` |
| bun | `bun add -g snareclaw` |
| Homebrew | `brew tap 0xDefence/tap && brew install snareclaw` |
| curl | `curl -fsSL https://raw.githubusercontent.com/0xDefence/snareclaw-py/main/install.sh \| bash` |

## Roadmap

- [ ] Rust daemon rewrite (single binary, <8MB, sub-1% CPU)
- [ ] VS Code extension with inline warnings in `requirements.txt`
- [ ] pip install hook (intercept and verify before install completes)
- [ ] Import-time subprocess detection (fork-bomb signal from LiteLLM)
- [ ] Local web dashboard at `localhost:7734`
- [ ] GitHub Actions integration (scan PRs for lockfile regressions)
- [ ] Team mode — shared trust manifests via git-committed `snare.lock`

## License

MIT

---

<div align="center">

*Made by Eli / [0xDefence](https://github.com/0xDefence) in response to the LiteLLM supply chain attack — March 2026*

</div>
