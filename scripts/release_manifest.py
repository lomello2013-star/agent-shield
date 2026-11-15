"""Create a release manifest (SBOM-style) for built artifacts."""
from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    dist = root / "dist"
    try:
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    except Exception:
        commit = "unknown"
    artifacts = []
    for path in sorted(dist.rglob("*")):
        if path.is_file() and path.name != "release-manifest.json":
            artifacts.append({
                "path": str(path.relative_to(root)).replace("\\", "/"),
                "size": path.stat().st_size,
                "sha256": sha256(path),
            })
    payload = {
        "name": "aidf-stml-pilot",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "git_commit": commit,
        "python": subprocess.check_output(["python", "--version"], text=True, stderr=subprocess.STDOUT).strip(),
        "artifacts": artifacts,
    }
    out = dist / "release-manifest.json"
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"wrote {out} ({len(artifacts)} artifacts)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
