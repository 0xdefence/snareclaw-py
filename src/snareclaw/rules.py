"""Declarative TOML rules engine."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

DEFAULT_RULES_PATH = Path.home() / ".snareclaw" / "rules.toml"
BUNDLED_RULES_PATH = Path(__file__).parent / "snare.toml"


@dataclass
class Rule:
    id: str
    severity: str
    action: str  # "block" | "alert" | "log"
    description: str
    enabled: bool = True


class RulesEngine:
    def __init__(self, rules_path: Path | None = None) -> None:
        self.rules: dict[str, Rule] = {}
        # Load bundled defaults first, then user overrides
        if BUNDLED_RULES_PATH.exists():
            self._load(BUNDLED_RULES_PATH)
        path = rules_path or DEFAULT_RULES_PATH
        if path.exists():
            self._load(path)

    def _load(self, path: Path) -> None:
        with open(path, "rb") as f:
            data = tomllib.load(f)
        for entry in data.get("rules", []):
            rule = Rule(
                id=entry["id"],
                severity=entry.get("severity", "MEDIUM"),
                action=entry.get("action", "alert"),
                description=entry.get("description", ""),
                enabled=entry.get("enabled", True),
            )
            self.rules[rule.id] = rule

    def get(self, rule_id: str) -> Rule | None:
        return self.rules.get(rule_id)

    def severity_for(self, rule_id: str) -> str:
        rule = self.rules.get(rule_id)
        return rule.severity if rule else "MEDIUM"

    def action_for(self, rule_id: str) -> str:
        rule = self.rules.get(rule_id)
        return rule.action if rule else "alert"

    def is_enabled(self, rule_id: str) -> bool:
        rule = self.rules.get(rule_id)
        return rule.enabled if rule else True
