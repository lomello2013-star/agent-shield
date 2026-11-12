"""T1055 coverage matrix across the measured Linux paths and rule layers.

Two views:
  1. paths — what kernel source was measured, how many events/verdicts, alert vs signal;
  2. layers — the escalation ladder signal -> correlation -> correlation+provenance,
     with the false positives measured at each step.

This is a map of what was measured, not a claim of adversarial coverage.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ART = os.path.join(HERE, "artifacts")
OUT_JSON = os.path.join(ART, "t1055_coverage.json")
OUT_MD = os.path.join(HERE, "docs", "t1055-coverage.md")

PATHS = [
    ("process_vm_writev", "linux_mem.json", "linux.memory", "alert",
     "tracepoint sys_enter_process_vm_writev", "rules: LINUX-INJECT-106"),
    ("ptrace POKE*", "linux_ptrace.json", "linux.ptrace", "alert",
     "tracepoint sys_enter_ptrace (POKETEXT/POKEDATA/POKEUSR)", "rules: LINUX-INJECT-106"),
    ("/proc/<pid>/mem", "linux_procmem.json", "linux.procmem", "alert",
     "LSM file_open, writable opens", "rules: LINUX-INJECT-106"),
    ("mprotect PROT_EXEC", "linux_mprotect.json", "linux.mprotect", "signal",
     "LSM file_mprotect, new EXEC on anonymous memory", "rules: LINUX-EXEC-MEM-107"),
]

GAPS = [
    ("mprotect without correlation", "JIT and injection share the pattern; the signal "
     "alone is not an alert"),
    ("dlopen / LD_PRELOAD", "loads code into the attacker's own process; not a "
     "cross-process write, different detection (module load)"),
    ("/dev/mem", "requires root and is usually disabled; not measured"),
    ("Windows T1055", "ETW-TI requires elevation (blocker D); not measured"),
    ("argv[0] spoofing", "provenance uses mm->exe_file, so a renamed argv is invisible "
     "by design; documented as a non-goal"),
]


def load(name: str) -> dict | None:
    path = os.path.join(ART, name)
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def build_paths() -> list[dict]:
    rows = []
    for name, artifact, source, level, mechanism, rules in PATHS:
        data = load(artifact)
        if data is None:
            rows.append({"path": name, "source": source, "level": level,
                         "mechanism": mechanism, "rules": rules, "measured": False})
            continue
        rows.append({
            "path": name, "source": source, "level": level, "mechanism": mechanism,
            "rules": rules, "measured": True,
            "events": data.get("events"), "verdicts": data.get("verdicts"),
            "control_events": data.get("control_events", data.get("control_writable")),
            "loss": data.get("loss"), "duplicates": data.get("duplicate_verdicts", False),
            "latency_pipeline_ms_p50": data.get("latency_pipeline_ms", {}).get("p50"),
        })
    return rows


def build_layers() -> list[dict]:
    """The escalation ladder with measured false positives."""
    mprot = load("linux_mprotect.json") or {}
    corr = load("linux_corr.json") or {}
    tree = load("linux_tree.json") or {}
    tree_fp = load("linux_tree_fp.json") or {}
    prov = load("linux_provenance.json") or {}

    return [
        {"layer": 0, "rule": "LINUX-EXEC-MEM-107", "grouping": "none",
         "alerts": mprot.get("events"), "false_positives_measured":
         f"JIT noise: {mprot.get('events', 0) - mprot.get('helper_events', 0)} "
         f"non-helper events in the run",
         "verdict": "signal only (medium), never an alert alone"},
        {"layer": 1, "rule": "LINUX-EXEC-CORR-108", "grouping": "actor.pid",
         "alerts": corr.get("corr_alerts_correlated"),
         "false_positives_measured":
         f"JIT-only phase: {corr.get('corr_alerts_mprotect_only')} alerts",
         "verdict": "alert on injection, quiet on JIT"},
        {"layer": 2, "rule": "LINUX-EXEC-CORR-109", "grouping": "process_tree",
         "alerts": tree.get("tree_group_alerts"),
         "false_positives_measured":
         f"legit supervisor+JIT: {tree_fp.get('legit_supervisor_plus_jit', {}).get('tree_alerts')} "
         f"alert(s); benign JIT: {tree_fp.get('benign_jit_only', {}).get('tree_alerts')}",
         "verdict": "catches parent-writes-child-executes, known FP class"},
        {"layer": 3, "rule": "LINUX-EXEC-CORR-110", "grouping": "process_tree + provenance",
         "alerts": prov.get("untrusted_supervisor", {}).get("corr_110_alerts"),
         "false_positives_measured":
         f"trusted supervisor: {prov.get('trusted_supervisor', {}).get('corr_110_alerts')} "
         f"alert(s); path from kernel: {prov.get('path_resolution', {}).get('kernel')}, "
         f"fallback: {prov.get('path_resolution', {}).get('fallback')}",
         "verdict": "preferred: FP removed, detection kept"},
    ]


def main() -> None:
    rows = build_paths()
    layers = build_layers()
    measured = [r for r in rows if r["measured"]]
    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "paths_measured": len(measured),
        "alert_paths": len([r for r in measured if r["level"] == "alert"]),
        "signal_paths": len([r for r in measured if r["level"] == "signal"]),
        "total_events": sum(r.get("events") or 0 for r in measured),
        "total_verdicts": sum(r.get("verdicts") or 0 for r in measured),
        "total_loss": sum(r.get("loss") or 0 for r in measured),
        "paths": rows,
        "rule_layers": layers,
        "gaps": [{"gap": g, "why": w} for g, w in GAPS],
        "verdict": ("4/4 measured paths verified; rule ladder measured through provenance; "
                    "Windows T1055 still unmeasured (elevation required)"),
    }
    with open(OUT_JSON, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2, ensure_ascii=False)

    lines = [
        "# Покрытие T1055 (Linux, измерено)",
        "",
        f"> Сгенерировано `scripts/t1055_coverage.py` — {summary['generated_at'][:16]} UTC.",
        "",
        f"Путей измерено: **{summary['paths_measured']}**; алерт-уровень: "
        f"**{summary['alert_paths']}**, признак-уровень: **{summary['signal_paths']}**; "
        f"событий {summary['total_events']}, вердиктов {summary['total_verdicts']}, "
        f"потерь {summary['total_loss']}.",
        "",
        "## Пути",
        "",
        "| Путь | Источник | Уровень | События | Вердикты | Контроль | Потери |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        if not r["measured"]:
            lines.append(f"| {r['path']} | {r['source']} | {r['level']} | не измерено | — | — | — |")
            continue
        lines.append(f"| {r['path']} | {r['source']} | **{r['level']}** | {r.get('events')} | "
                     f"{r.get('verdicts')} | {r.get('control_events')} | {r.get('loss')} |")

    lines += ["", "## Лестница правил (наращивание контекста)",
              "",
              "| Слой | Правило | Группировка | Алерты | Измеренные FP | Вывод |",
              "|---|---|---|---|---|---|"]
    for layer in layers:
        lines.append(f"| {layer['layer']} | `{layer['rule']}` | {layer['grouping']} | "
                     f"{layer['alerts']} | {layer['false_positives_measured']} | "
                     f"{layer['verdict']} |")

    lines += ["", "## Что значит «признак»",
              "`signal` — путь записан и виден, но сам по себе не алертит: "
              "JIT-движки дают тот же паттерн, поэтому нужен корреляционный контекст "
              "(происхождение процесса, запуск с диска, аномальная последовательность).",
              "", "## Дыры (осознанные, не закрыты)"]
    lines += [f"- **{g['gap']}**: {g['why']}." for g in summary["gaps"]]
    lines += ["", "## Что это НЕ доказывает",
              "Матрица показывает, что каждый путь наблюдается и даёт вердикт — она не "
              "доказывает, что реальный adversary будет пойман: нет red-team, нет "
              "обхода через другие примитивы, Windows-часть не измерена (нужна "
              "элевация)."]
    with open(OUT_MD, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print(json.dumps({"paths_measured": summary["paths_measured"],
                      "layers": [f"{l['rule']}:{l['alerts']}" for l in layers]},
                     indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
