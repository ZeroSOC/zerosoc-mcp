"""Every property Graph declares for an evidence item reaches the rows, or the module says why not.

`fixtures/graph_evidence_types.json` holds the declarations of Graph's v1.0 `$metadata` for
`alertEvidence`, the evidence types this module reads and every type they name. One incident is
built from them with an item of each evidence type and every property filled. Each property is then
changed alone: the rows must change, unless the property is left out on purpose and the module's
docstring names it.
"""

from __future__ import annotations

import copy
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from zerosoc_microsoft_security import evidence
from zerosoc_microsoft_security.evidence import inventory

TYPES: dict[str, dict[str, Any]] = json.loads(
    (Path(__file__).parent / "fixtures" / "graph_evidence_types.json").read_text()
)
SECURITY = "microsoft.graph.security."
EVIDENCE = sorted(
    name.removeprefix(SECURITY)
    for name, spec in TYPES.items()
    if spec.get("base") == SECURITY + "alertEvidence"
)
LEFT_OUT = {
    "createdDateTime",
    "fileDetails.md5",
    "fileDetails.sha256Ac",
    "imageFile.md5",
    "imageFile.sha256Ac",
    "parentProcessImageFile.md5",
    "parentProcessImageFile.sha256Ac",
    "userAccount.activeDirectoryObjectGuid",
    "rbacGroupId",
    "vmMetadata.vmId",
    "vmMetadata.subscriptionId",
    "hostName",
    "dnsDomain",
}
"""Paths within an item, the same for every evidence type that has them."""
START = datetime(2026, 9, 10, 10, 0, tzinfo=UTC)


def properties(type_name: str) -> dict[str, str]:
    """A type's properties and their types, its base's included."""
    spec = TYPES[type_name]
    inherited = properties(spec["base"]) if spec.get("base") in TYPES else {}
    return {**inherited, **spec.get("properties", {})}


def leaves(type_name: str, prefix: str = "") -> list[tuple[str, str]]:
    """(path, scalar type) of every value an item of the type can hold. `[]` marks a collection."""
    out: list[tuple[str, str]] = []
    for name, declared in properties(type_name).items():
        many = declared.startswith("Collection(")
        inner = declared.removeprefix("Collection(").removesuffix(")")
        path = f"{prefix}{name}{'[]' if many else ''}"
        if "properties" in TYPES.get(inner, {}):
            out += leaves(inner, path + ".")
        else:
            out.append((path, inner))
    return out


def value(scalar: str, n: int, flipped: bool = False) -> Any:
    """A value of the type, the n-th of its kind; `flipped` gives another one."""
    k = n + (1000 if flipped else 0)
    if "enum" in TYPES.get(scalar, {}):
        members = TYPES[scalar]["enum"]
        return members[(n + (1 if flipped else 0)) % len(members)]
    if scalar == "Edm.DateTimeOffset":
        moment = START + timedelta(minutes=n, seconds=1 if flipped else 0)
        return moment.isoformat().replace("+00:00", "Z")
    if scalar in ("Edm.Int32", "Edm.Int64"):
        return k
    if scalar == "Edm.Double":
        return k + 0.5
    if scalar == "Edm.Boolean":
        return not flipped
    if scalar == "Edm.Guid":
        return f"00000000-0000-4000-8000-{k:012d}"
    return f"v{k}"


def put(item: dict[str, Any], path: str, scalar: str, n: int, flipped: bool = False) -> None:
    *parents, last = path.split(".")
    node: Any = item
    for part in parents:
        if part.endswith("[]"):
            node = node.setdefault(part[:-2], [{}])[0]
        else:
            node = node.setdefault(part, {})
    if last.endswith("[]"):
        node[last[:-2]] = [value(scalar, n, flipped)]
    else:
        node[last] = value(scalar, n, flipped)


def incident() -> tuple[list[dict[str, Any]], list[tuple[int, str, str, str, int]]]:
    """One alert citing an item of every evidence type, every property filled; and each property as
    (item index, evidence type, path, scalar type, n)."""
    items, filled, n = [], [], 0
    for i, kind in enumerate(EVIDENCE):
        item: dict[str, Any] = {"@odata.type": f"#{SECURITY}{kind}"}
        for path, scalar in leaves(SECURITY + kind):
            n += 1
            put(item, path, scalar, n)
            filled.append((i, kind, path, scalar, n))
        items.append(item)
    return [{"id": "da-1", "evidence": items}], filled


def rows(alerts: list[dict[str, Any]]) -> str:
    return json.dumps(inventory(alerts)["entities"], sort_keys=True)


def test_every_declared_property_reaches_the_rows_or_is_left_out_on_purpose() -> None:
    alerts, filled = incident()
    base = rows(alerts)
    dropped, kept = [], []
    for i, kind, path, scalar, n in filled:
        changed = copy.deepcopy(alerts)
        put(changed[0]["evidence"][i], path, scalar, n, flipped=True)
        (kept if rows(changed) != base else dropped).append((kind, path))

    assert [f"{kind}.{path}" for kind, path in dropped if path not in LEFT_OUT] == []
    assert [f"{kind}.{path}" for kind, path in kept if path in LEFT_OUT] == []
    assert len(filled) > 150 and len(EVIDENCE) == 10


def test_the_docstring_names_every_property_left_out() -> None:
    doc = " ".join((evidence.__doc__ or "").split())
    for path in LEFT_OUT:
        assert f"`{path.split('.')[-1]}`" in doc or f"`{path}`" in doc, path


def _registry(value_type: str, data: str) -> dict[str, Any]:
    item = {
        "@odata.type": f"#{SECURITY}registryValueEvidence",
        "registryHive": "HKEY_LOCAL_MACHINE",
        "registryKey": "SYSTEM\\CurrentControlSet\\Services\\Updater",
        "registryValueName": "ImagePath",
        "registryValueType": value_type,
        "registryValue": data,
    }
    return inventory([{"id": "da-1", "evidence": [item]}])["entities"][0]  # type: ignore[no-any-return]


def _hex(text: str) -> str:
    return "-".join(f"{b:02X}" for b in text.encode("utf-16-le"))


def test_a_text_registry_value_sent_as_bytes_is_decoded_beside_its_data() -> None:
    path = "C:\\Windows\\Temp\\upd.exe -k netsvcs"
    row = _registry("ExpandString", _hex(path + "\0"))
    assert row["value_type"] == "ExpandString"
    assert row["value_data"].startswith("43-00-3A-00-5C-00")
    assert row["value_text"] == path

    multi = _registry("MultiString", _hex("first\0second\0\0"))
    assert multi["value_text"] == ["first", "second"]
    assert _registry("REG_SZ", _hex("plain"))["value_text"] == "plain"


def test_a_registry_value_that_is_not_text_bytes_is_left_as_sent() -> None:
    assert "value_text" not in _registry("String", "C:\\Users\\Public\\upd.exe")
    assert "value_text" not in _registry("Binary", _hex("C:\\x"))
    assert "value_text" not in _registry("ExpandString", "01-00-02-00")  # control characters
    assert "value_text" not in _registry("ExpandString", "41-00-42")  # an odd number of bytes


def _device(**fields: Any) -> dict[str, Any]:
    return {"@odata.type": f"#{SECURITY}deviceEvidence", **fields}


def test_a_device_without_a_dns_name_is_named_by_its_host_name() -> None:
    def name(**fields: Any) -> Any:
        return inventory([{"id": "a1", "evidence": [_device(**fields)]}])["entities"][0]["name"]

    assert name(hostName="ws09", dnsDomain="lab.example", mdeDeviceId="m9") == "ws09.lab.example"
    assert name(hostName="ws09", mdeDeviceId="m9") == "ws09"
    assert name(dnsDomain="lab.example", mdeDeviceId="m9") == "m9"
    assert name(deviceDnsName="ws09.lab", hostName="other", mdeDeviceId="m9") == "ws09.lab"


def _file(**extra: Any) -> dict[str, Any]:
    return {
        "@odata.type": f"#{SECURITY}fileEvidence",
        "mdeDeviceId": "m1",
        "fileDetails": {"fileName": "upd.exe", "sha256": "f" * 64},
        **extra,
    }


DEVICE = _device(deviceDnsName="ws01", mdeDeviceId="m1")


def test_a_merged_entity_gives_each_alert_its_own_verdict_where_they_differ() -> None:
    result = inventory(
        [
            {
                "id": "a1",
                "evidence": [DEVICE, _file(verdict="malicious", remediationStatus="active")],
            },
            {
                "id": "a2",
                "evidence": [DEVICE, _file(verdict="suspicious", remediationStatus="active")],
            },
            {
                "id": "a3",
                "evidence": [DEVICE, _file(remediationStatus="blocked", tags=["Quarantined"])],
            },
        ]
    )
    file = next(e for e in result["entities"] if e["type"] == "file")
    assert (file["verdict"], file["remediation_status"]) == ("malicious", "active")
    assert file["by_alert"] == {
        "a1": {"verdict": "malicious", "remediation_status": "active"},
        "a2": {"verdict": "suspicious", "remediation_status": "active"},
        "a3": {"remediation_status": "blocked"},
    }
    assert file["tags"] == ["Quarantined"]


def test_alerts_that_agree_on_an_entity_give_no_values_by_alert() -> None:
    result = inventory(
        [
            {"id": "a1", "evidence": [DEVICE, _file(verdict="malicious", roles=["attacker"])]},
            {"id": "a2", "evidence": [DEVICE, _file(verdict="malicious", roles=["attacker"])]},
        ]
    )
    assert all("by_alert" not in e for e in result["entities"])


def test_a_process_row_names_who_signed_its_image_and_its_parents() -> None:
    signed = {
        "filePublisher": "Contoso Ltd",
        "signer": "Contoso Code Signing",
        "issuer": "Contoso CA",
    }
    process = {
        "@odata.type": f"#{SECURITY}processEvidence",
        "processId": 4312,
        "mdeDeviceId": "m1",
        "imageFile": {"fileName": "upd.exe", "filePath": "C:\\Users\\Public", **signed},
        "parentProcessImageFile": {
            "fileName": "explorer.exe",
            "filePath": "C:\\Windows",
            "sha1": "c" * 40,
            "sha256": "d" * 64,
            "fileSize": 5_000_000,
            "signer": "Microsoft Windows",
        },
    }
    row = next(
        e
        for e in inventory([{"id": "a1", "evidence": [DEVICE, process]}])["entities"]
        if e["type"] == "process"
    )
    assert (row["publisher"], row["signer"], row["issuer"]) == (
        "Contoso Ltd",
        "Contoso Code Signing",
        "Contoso CA",
    )
    assert (row["parent_name"], row["parent_path"], row["parent_signer"]) == (
        "explorer.exe",
        "C:\\Windows",
        "Microsoft Windows",
    )
    assert (row["parent_sha1"], row["parent_sha256"], row["parent_size"]) == (
        "c" * 40,
        "d" * 64,
        5_000_000,
    )
