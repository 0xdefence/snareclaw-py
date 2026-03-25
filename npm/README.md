# SnareClaw

**Ambient supply chain security monitor for Python environments.**

This is the npm/pnpm/bun installer for SnareClaw. It wraps the Python CLI and handles installation automatically.

## Install

```bash
# npm
npm install -g snareclaw

# pnpm
pnpm add -g snareclaw

# bun
bun add -g snareclaw
```

## Usage

```bash
# Launch interactive mode
snareclaw

# Or use direct commands
snareclaw status
snareclaw scan .
snareclaw verify requests 2.31.0
snareclaw watch
snareclaw history --last 7
```

## Requirements

- Python 3.10+ (the wrapper installs the Python package automatically via pip/pipx)

## More Info

See the full documentation at [github.com/0xDefence/snareclaw-py](https://github.com/0xDefence/snareclaw-py)
