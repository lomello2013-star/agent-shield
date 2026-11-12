import pytest

from core.negotiation import (
    CAPABILITY_MISSING,
    INCOMPATIBLE_MODULE,
    INCOMPATIBLE_SCHEMA,
    OK,
    negotiate,
    schema_supported,
)
from schemas.v3 import ModuleManifest


def manifest(**overrides):
    base = {"name": "file_detector", "version": "1.0.0", "platforms": ["windows", "linux"],
            "requires_capabilities": ["has_etw"], "schemas": ["3.0"],
            "min_core_version": "0.1.0"}
    base.update(overrides)
    return ModuleManifest.model_validate(base)


def test_compatible_module_loads():
    res = negotiate(manifest(), core_version="0.1.0", core_schema_version="3.0",
                    capabilities={"has_etw"})
    assert res.ok and res.code == OK
    assert bool(res) is True


def test_missing_capability_is_explicit():
    res = negotiate(manifest(requires_capabilities=["has_etw", "has_wfp"]),
                    capabilities={"has_etw"})
    assert not res.ok
    assert res.code == CAPABILITY_MISSING
    assert "has_wfp" in res.detail


def test_module_requiring_newer_schema_rejected():
    res = negotiate(manifest(schemas=["3.2"]), core_schema_version="3.0",
                    capabilities={"has_etw"})
    assert not res.ok and res.code == INCOMPATIBLE_SCHEMA


def test_core_with_newer_minor_accepts_old_module():
    res = negotiate(manifest(schemas=["3.0"]), core_schema_version="3.1",
                    capabilities={"has_etw"})
    assert res.ok


def test_core_with_newer_minor_accepts_matching_module():
    res = negotiate(manifest(schemas=["3.0", "3.1"]), core_schema_version="3.1",
                    capabilities={"has_etw"})
    assert res.ok


def test_module_requires_higher_core_version():
    res = negotiate(manifest(min_core_version="9.9.9"), core_version="0.1.0",
                    capabilities={"has_etw"})
    assert not res.ok and res.code == INCOMPATIBLE_MODULE


def test_module_declaring_only_4x_rejected():
    res = negotiate(manifest(schemas=["4.0"]), core_schema_version="3.0",
                    capabilities={"has_etw"})
    assert not res.ok and res.code == INCOMPATIBLE_SCHEMA


def test_core_schema_4x_rejects_everything():
    res = negotiate(manifest(), core_schema_version="4.0", capabilities={"has_etw"})
    assert not res.ok and res.code == INCOMPATIBLE_SCHEMA


def test_no_required_capabilities_is_ok():
    res = negotiate(manifest(requires_capabilities=[]), capabilities=set())
    assert res.ok


def test_schema_supported_matrix():
    assert schema_supported(["3.0"], 3, 0) is True
    assert schema_supported(["3.1"], 3, 0) is False
    assert schema_supported(["3.1", "3.0"], 3, 1) is True
    assert schema_supported(["4.0"], 3, 9) is False


def test_bad_semver_in_module_is_rejected_by_contract():
    with pytest.raises(Exception):
        manifest(min_core_version="latest")
