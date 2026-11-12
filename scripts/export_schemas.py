"""Generate JSON Schema artefacts for contracts v3 (docs/data-model-v3.md §1)."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from schemas.v3 import export_json_schemas

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "schemas", "v3", "json_schema")

if __name__ == "__main__":
    files = export_json_schemas(OUT)
    print(f"wrote {len(files)} files to {OUT}")
