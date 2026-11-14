"""Local file hardening helpers (best effort, no elevation)."""

from __future__ import annotations

import getpass
import os
import subprocess
from pathlib import Path


def restrict(path: str | Path) -> None:
    """Restrict a local file to the current user where the OS allows it."""
    path = Path(path)
    if not path.exists():
        return
    if os.name == "nt":
        user = os.environ.get("USERNAME") or getpass.getuser()
        try:
            subprocess.run(
                ["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:F"],
                check=False, capture_output=True, timeout=10,
            )
        except (OSError, subprocess.SubprocessError):
            pass
        return
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
