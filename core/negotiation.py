"""Capability negotiation and schema compatibility (docs/data-model-v3.md §1, §8).

A module declares ``schemas`` (supported contract versions), ``min_core_version``
and ``requires_capabilities``. The core must refuse an incompatible module
explicitly — ``incompatible_schema`` / ``incompatible_module`` /
``capability_missing`` — and never silently degrade.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from schemas.v3 import SUPPORTED_MAJOR, ModuleManifest, parse_schema_version

OK = "ok"
INCOMPATIBLE_SCHEMA = "incompatible_schema"
INCOMPATIBLE_MODULE = "incompatible_module"
CAPABILITY_MISSING = "capability_missing"


@dataclass(frozen=True)
class NegotiationResult:
    ok: bool
    code: str
    detail: str = ""

    def __bool__(self) -> bool:  # allow `if result:`
        return self.ok


def _parse_semver(value: str) -> tuple[int, int, int]:
    parts = value.split(".")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        raise ValueError(f"not semver: {value!r}")
    return int(parts[0]), int(parts[1]), int(parts[2])


def schema_supported(declared: Iterable[str], core_major: int, core_minor: int) -> bool:
    """True when at least one declared 3.x schema is understood by the core.

    A module that only declares a *newer* minor (e.g. 3.2 vs core 3.0) is not
    compatible: the core does not know the fields it may require.
    """
    for item in declared:
        major, minor = parse_schema_version(item)
        if major == core_major and minor <= core_minor:
            return True
    return False


def negotiate(
    manifest: ModuleManifest,
    core_version: str = "0.1.0",
    core_schema_version: str = "3.0",
    capabilities: Iterable[str] = (),
) -> NegotiationResult:
    """Decide whether a module may load on this core."""
    core_major, core_minor = parse_schema_version(core_schema_version)
    if core_major != SUPPORTED_MAJOR:
        return NegotiationResult(False, INCOMPATIBLE_SCHEMA,
                                 f"core schema {core_schema_version} is not 3.x")

    if not any(parse_schema_version(s)[0] == core_major for s in manifest.schemas):
        return NegotiationResult(
            False, INCOMPATIBLE_SCHEMA,
            f"module schemas {manifest.schemas} do not include major {core_major}",
        )

    if not schema_supported(manifest.schemas, core_major, core_minor):
        return NegotiationResult(
            False, INCOMPATIBLE_SCHEMA,
            f"module requires a newer schema than {core_schema_version}: {manifest.schemas}",
        )

    if _parse_semver(manifest.min_core_version) > _parse_semver(core_version):
        return NegotiationResult(
            False, INCOMPATIBLE_MODULE,
            f"module needs core >= {manifest.min_core_version}, have {core_version}",
        )

    available = set(capabilities)
    missing = sorted(set(manifest.requires_capabilities) - available)
    if missing:
        return NegotiationResult(False, CAPABILITY_MISSING,
                                 f"missing capabilities: {', '.join(missing)}")

    return NegotiationResult(True, OK, "")
