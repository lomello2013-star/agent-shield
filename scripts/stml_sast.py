"""Lightweight SAST draft for STML/agent Python code.

This is a pattern scan, not a substitute for Bandit/Semgrep or human review.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGETS = [ROOT / "stml", ROOT / "core", ROOT / "scripts"]
PATTERNS = {
    "eval": re.compile(r"(?<![\w.])eval\("),
    "exec": re.compile(r"(?<![\w.])exec\("),
    "pickle_loads": re.compile(r"pickle\.loads\("),
    "shell_true": re.compile(r"shell\s*=\s*True"),
    "yaml_load": re.compile(r"yaml\.load\("),
    "md5": re.compile(r"hashlib\.md5\("),
    "hardcoded_token": re.compile(r"(?i)(token|password|secret)\s*=\s*['\"][A-Za-z0-9_-]{16,}['\"]"),
}


def main() -> int:
    findings = []
    for base in TARGETS:
        for path in base.rglob("*.py"):
            if "__pycache__" in path.parts or "tests" in path.parts:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for name, pattern in PATTERNS.items():
                for match in pattern.finditer(text):
                    line = text.count("\n", 0, match.start()) + 1
                    findings.append({"file": str(path.relative_to(ROOT)),
                                     "line": line, "rule": name,
                                     "excerpt": text.splitlines()[line - 1].strip()[:160]})
    report = {"kind": "sast-draft", "tool": "pattern-scan", "findings": findings,
              "note": "Not a substitute for Bandit/Semgrep or human review."}
    out = ROOT / "artifacts" / "stml_sast_draft.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"findings": len(findings), "report": str(out.relative_to(ROOT))},
                     ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
