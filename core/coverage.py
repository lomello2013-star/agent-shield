"""ATT&CK coverage harness (E11): technique → layer → rule → test.

Coverage here is *mapping completeness*: every in-scope technique has at least
one rule of the right layer, and every rule has a fixture test. It is **not** a
claim of real-world detection — that needs red-team runs (stage 12) and is
recorded separately.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass

from core.rules import Rule

DETECTION_TARGET_PCT = 90.0
PREVENTION_TARGET_PCT = 70.0


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    layer: str


def load_techniques(path: str) -> list[Technique]:
    with open(path, encoding="utf-8") as fh:
        payload = json.load(fh)
    return [Technique(item["id"], item["name"], item["layer"]) for item in payload["in_scope"]]


def build_matrix(techniques: list[Technique], rules: list[Rule]) -> list[dict]:
    by_tech: dict[str, list[Rule]] = {}
    for rule in rules:
        by_tech.setdefault(rule.technique, []).append(rule)
    rows = []
    for tech in techniques:
        mapped = by_tech.get(tech.id, [])
        rows.append({
            "technique": tech.id,
            "name": tech.name,
            "layer": tech.layer,
            "rules": [r.id for r in mapped],
            "prevention_rules": [r.id for r in mapped if r.prevention],
            "tested": bool(mapped),
        })
    return rows


def summarize(rows: list[dict]) -> dict:
    total = len(rows)
    detected = sum(1 for r in rows if r["rules"])
    prevented = sum(1 for r in rows if r["prevention_rules"])
    det_pct = round(100.0 * detected / total, 2) if total else 0.0
    prev_pct = round(100.0 * prevented / total, 2) if total else 0.0
    return {
        "techniques_in_scope": total,
        "detected": detected,
        "prevented": prevented,
        "detection_pct": det_pct,
        "prevention_pct": prev_pct,
        "detection_target_pct": DETECTION_TARGET_PCT,
        "prevention_target_pct": PREVENTION_TARGET_PCT,
        "passes_detection": det_pct >= DETECTION_TARGET_PCT,
        "passes_prevention": prev_pct >= PREVENTION_TARGET_PCT,
        "gaps_detection": [r["technique"] for r in rows if not r["rules"]],
        "gaps_prevention": [r["technique"] for r in rows if not r["prevention_rules"]],
        "untested_rules": [r["technique"] for r in rows if r["rules"] and not r["tested"]],
    }


def render_markdown(rows: list[dict], summary: dict) -> str:
    lines = [
        "# Матрица покрытия ATT&CK (in-scope)",
        "",
        "> Генерируется `scripts/stage5_measure.py` из `rules/base.json` и `rules/techniques.json`.",
        "> Покрытие = полнота отображения «техника → слой → правило → тест», а не доказанная",
        "> эффективность: реальная проверка — red-team (этап 12).",
        "",
        f"**Обнаружение**: {summary['detected']}/{summary['techniques_in_scope']} = "
        f"{summary['detection_pct']}% (цель ≥{summary['detection_target_pct']}%) — "
        f"{'в цели' if summary['passes_detection'] else 'НИЖЕ ЦЕЛИ'}.",
        f"**Предотвращение**: {summary['prevented']}/{summary['techniques_in_scope']} = "
        f"{summary['prevention_pct']}% (цель ≥{summary['prevention_target_pct']}%) — "
        f"{'в цели' if summary['passes_prevention'] else 'НИЖЕ ЦЕЛИ'}.",
        "",
        "| Техника | Название | Слой | Правила обнаружения | Правила предотвращения |",
        "|---|---|---|---|---|",
    ]
    for row in rows:
        lines.append(
            f"| {row['technique']} | {row['name']} | {row['layer']} | "
            f"{', '.join(row['rules']) or '—'} | {', '.join(row['prevention_rules']) or '—'} |"
        )
    if summary["gaps_detection"]:
        lines += ["", "**Пробелы обнаружения**: " + ", ".join(summary["gaps_detection"]) + "."]
    if summary["gaps_prevention"]:
        lines += ["", "**Пробелы предотвращения**: " + ", ".join(summary["gaps_prevention"]) + "."]
    lines.append("")
    return "\n".join(lines)


def write_matrix(path: str, rows: list[dict], summary: dict) -> str:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    content = render_markdown(rows, summary)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return content
