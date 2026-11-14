"""Backup/restore for the STML SQLite MVP + SoftHSM trust directory."""

from __future__ import annotations

import shutil
import sqlite3
import tempfile
import zipfile
from pathlib import Path


def backup(db_path: str | Path, trust_dir: str | Path, out_zip: str | Path) -> dict:
    db_path = Path(db_path)
    trust_dir = Path(trust_dir)
    out_zip = Path(out_zip)
    out_zip.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        snapshot = Path(tmp) / "stml.sqlite3"
        src = sqlite3.connect(db_path)
        dst = sqlite3.connect(snapshot)
        try:
            src.backup(dst)
        finally:
            dst.close()
            src.close()
        with zipfile.ZipFile(out_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.write(snapshot, "stml.sqlite3")
            if trust_dir.exists():
                for path in sorted(trust_dir.rglob("*")):
                    if path.is_file():
                        zf.write(path, "trust/" + path.relative_to(trust_dir).as_posix())
    return {"ok": True, "backup": str(out_zip), "bytes": out_zip.stat().st_size}


def restore(backup_zip: str | Path, db_path: str | Path, trust_dir: str | Path) -> dict:
    backup_zip = Path(backup_zip)
    db_path = Path(db_path)
    trust_dir = Path(trust_dir)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    trust_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        with zipfile.ZipFile(backup_zip) as zf:
            names = zf.namelist()
            if "stml.sqlite3" not in names:
                raise ValueError("backup has no stml.sqlite3")
            zf.extract("stml.sqlite3", tmp)
            for name in names:
                if name.startswith("trust/") and not name.endswith("/"):
                    zf.extract(name, tmp)
        shutil.copyfile(Path(tmp) / "stml.sqlite3", db_path)
        src_trust = Path(tmp) / "trust"
        if src_trust.exists():
            for path in src_trust.rglob("*"):
                if path.is_file():
                    dest = trust_dir / path.relative_to(src_trust)
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(path, dest)
    return {"ok": True, "db": str(db_path), "trust_dir": str(trust_dir)}
