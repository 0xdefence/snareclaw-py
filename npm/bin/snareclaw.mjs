#!/usr/bin/env node

/**
 * SnareClaw — npm/pnpm/bun wrapper
 *
 * Thin launcher that ensures the Python snareclaw package is installed
 * (via pipx or pip) and forwards all arguments to the `snare` CLI.
 *
 * Install: npm i -g snareclaw | pnpm add -g snareclaw | bun add -g snareclaw
 * Usage:   snareclaw [args...]   (same as `snare [args...]`)
 */

import { execSync, spawn } from "node:child_process";

const PACKAGE = "snareclaw";
const BIN = "snare";

function commandExists(cmd) {
  try {
    execSync(`command -v ${cmd}`, { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

function ensureInstalled() {
  // Already installed?
  if (commandExists(BIN)) return BIN;

  console.log(`\x1b[31m▐●●▌\x1b[0m \x1b[1mSnareClaw\x1b[0m — first-run setup\n`);

  // Try pipx first (isolated install)
  if (commandExists("pipx")) {
    console.log("  Installing via pipx...");
    try {
      execSync(`pipx install ${PACKAGE}`, { stdio: "inherit" });
      return BIN;
    } catch {
      // Fall through to pip
    }
  }

  // Try pip
  if (commandExists("pip3")) {
    console.log("  Installing via pip3...");
    try {
      execSync(`pip3 install ${PACKAGE}`, { stdio: "inherit" });
      return BIN;
    } catch {
      // Fall through
    }
  }

  if (commandExists("pip")) {
    console.log("  Installing via pip...");
    try {
      execSync(`pip install ${PACKAGE}`, { stdio: "inherit" });
      return BIN;
    } catch {
      // Fall through
    }
  }

  console.error(
    "\n  \x1b[31mError:\x1b[0m Could not install snareclaw.\n" +
    "  Please install Python 3.10+ and run: pip install snareclaw\n"
  );
  process.exit(1);
}

const bin = ensureInstalled();
const args = process.argv.slice(2);

const child = spawn(bin, args, {
  stdio: "inherit",
  env: { ...process.env },
});

child.on("exit", (code) => process.exit(code ?? 0));
child.on("error", (err) => {
  console.error(`  \x1b[31mError:\x1b[0m ${err.message}`);
  process.exit(1);
});
