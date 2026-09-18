"""The capabilities manifest: everything a binding can be generated from, without a tenant."""

from __future__ import annotations

from typing import Any

from .capabilities import (
    ALERT_TYPE_MAP,
    CLASS_BINDINGS,
    DATA_SOURCES,
    MANUAL_CHECKS,
    SERVER,
    operation_ref,
    tool_ref,
    version,
)
from .client import OPERATIONS
from .hunting import HUNTING_TABLES
from .probe import API_CHECKS


def manifest() -> dict[str, Any]:
    """Generated from the operation registry and the static capability tables."""
    by_name = {o.name: o for o in OPERATIONS}
    capabilities: dict[str, list[dict[str, Any]]] = {}
    for binding in CLASS_BINDINGS:
        for option in binding.options:
            described = by_name[option.operation]
            entry: dict[str, Any] = {
                "tool": tool_ref(described.tool),
                "operation": operation_ref(described.name),
                "kind": described.kind,
                "permissions": list(described.permissions),
                "requires_all": list(option.requires_all),
                "requires_any": list(option.requires_any),
            }
            if option.notes:
                entry["notes"] = option.notes
            if option.rollback:
                entry["rollback"] = {
                    "tool": tool_ref(by_name[option.rollback].tool),
                    "operation": operation_ref(option.rollback),
                }
            capabilities.setdefault(binding.klass, []).append(entry)
    return {
        "server": SERVER,
        "version": version(),
        "packages": {"client": "zerosoc-defender-xdr", "mcp_server": "zerosoc-mcp-defender-xdr"},
        "alert_type_map": ALERT_TYPE_MAP,
        "capabilities": capabilities,
        "data_sources": DATA_SOURCES,
        "checks": {"api": sorted(API_CHECKS), "hunting": list(HUNTING_TABLES)},
        "manual_checks": list(MANUAL_CHECKS),
        "tools": [
            {
                "tool": o.tool,
                "operation": operation_ref(o.name),
                "kind": o.kind,
                "api": o.api,
                "permissions": list(o.permissions),
            }
            for o in OPERATIONS
        ],
    }
