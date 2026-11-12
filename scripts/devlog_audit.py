"""F17: audit of the DEVLOG against the spec — without rewriting history.

The log contains entries written in different formats. Rewriting them would falsify
the record, so this script *audits and discloses*: which entries carry the five
required fields, which artifacts they reference, and which are legacy/incomplete.

Writes docs/devlog-audit.md and artifacts/devlog_audit.json.
"""

from __future__ import annotations

import glob
import io
import json
import os
import re
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_MD = os.path.join(HERE, "docs", "devlog-audit.md")
OUT_JSON = os.path.join(HERE, "artifacts", "devlog_audit.json")
FIELDS = ("**Действие", "**Числа", "**Вердикт", "**Проверка", "**Статус")


def main() -> None:
    text = io.open(os.path.join(HERE, "DEVLOG.md"), encoding="utf-8").read()
    blocks = re.split(r"^## \[", text, flags=re.M)[1:]
    entries = []
    for block in blocks:
        header_line = block.splitlines()[0] if block else ""
        match = re.match(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2})\] (.+?) \[(\w+)\]$", header_line)
        if not match:
            continue
        kind = match.group(3)
        missing = [f for f in FIELDS if f not in block]
        artifacts = sorted(set(re.findall(r"artifacts/([A-Za-z0-9_\-]+\.json)", block)))
        existing = [a for a in artifacts if os.path.exists(os.path.join(HERE, "artifacts", a))]
        entries.append({
            "time": match.group(1), "title": match.group(2)[:80], "type": kind,
            "complete": not missing, "missing_fields": missing,
            "artifacts": artifacts, "artifacts_existing": existing,
        })

    complete = [e for e in entries if e["complete"]]
    missing_artifacts = sorted({a for e in entries for a in e["artifacts"]
                                if a not in e["artifacts_existing"]})
    by_type: dict[str, int] = {}
    for entry in entries:
        by_type[entry["type"]] = by_type.get(entry["type"], 0) + 1

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "entries": len(entries),
        "complete": len(complete),
        "incomplete": len(entries) - len(complete),
        "completeness_pct": round(100 * len(complete) / len(entries), 1) if entries else 0.0,
        "by_type": by_type,
        "missing_artifacts": missing_artifacts,
        "legacy_incomplete": [
            {"time": e["time"], "title": e["title"], "missing": e["missing_fields"]}
            for e in entries if not e["complete"]
        ],
        "artifacts_on_disk": len(glob.glob(os.path.join(HERE, "artifacts", "*.json"))),
        "note": "legacy entries are disclosed, not rewritten; new entries are enforced "
                "by docs_consistency (last 10 entries must carry all five fields)",
    }
    with open(OUT_JSON, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)

    lines = [
        "# Аудит DEVLOG",
        "",
        f"> Сгенерировано `scripts/devlog_audit.py` — {report['generated_at'][:16]} UTC.",
        "",
        f"Записей: **{report['entries']}**, полных по формату §8: "
        f"**{report['complete']} ({report['completeness_pct']} %)**, неполных (legacy): "
        f"**{report['incomplete']}**.",
        "",
        "## По типам",
        "",
        "| Тип | Записей |",
        "|---|---|",
    ]
    for kind, count in sorted(report["by_type"].items()):
        lines.append(f"| {kind} | {count} |")
    lines += ["", "## Legacy-записи без полного набора (не переписаны)", "",
              "| Время | Запись | Чего нет |", "|---|---|---|"]
    for entry in report["legacy_incomplete"]:
        missing = ", ".join(m.replace("**", "") for m in entry["missing"])
        lines.append(f"| {entry['time']} | {entry['title']} | {missing} |")
    lines += ["", "## Артефакты"]
    if report["missing_artifacts"]:
        lines += [f"- отсутствуют на диске: {', '.join(report['missing_artifacts'])}"]
    else:
        lines += ["- все упомянутые артефакты существуют на диске"]
    lines += ["", "## Что это значит",
              "Полнота формата — не качество содержания. Legacy-записи оставлены как есть: "
              "переписывать историю измерений нельзя; новые записи проверяются автоматически."]
    with open(OUT_MD, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")

    print(json.dumps({k: report[k] for k in ("entries", "complete", "incomplete",
                                             "completeness_pct", "missing_artifacts")},
                     ensure_ascii=False))


if __name__ == "__main__":
    main()
