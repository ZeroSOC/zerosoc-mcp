"""The evidence inventory of an incident: every entity its alerts cite, once, joined to its device.

Pure functions over the alert resources of the Microsoft Graph security API. The output rows use the
keys the ZeroSOC skills' `evidence_inventory.py` reads (`type`, `name`, `device`, `alert_ids` and the
identity keys `pid`, `created`, `sha1`, `sha256`, `path`, `key`), so the inventory can be recorded in
a ledger unchanged and its count compared with the portal's list of unique evidence items.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Iterable, Mapping
from typing import Any

from .decode import decode_layers, to_utc

Row = dict[str, Any]
Evidence = Mapping[str, Any]

_PREFIX = "#microsoft.graph.security."
_IDENTITY = ("sha256", "sha1", "pid", "created", "path", "key")
_SCOPED = frozenset({"process", "file", "registry"})
"""The same name on two devices is two entities."""


def inventory(alerts: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """De-duplicated entities of the given alerts, with the counts to reconcile against the source."""
    alerts = list(alerts)
    device_names = _device_names(alerts)
    rows = [
        _joined(_row(item, str(alert.get("id", ""))), alert, device_names)
        for alert in alerts
        for item in alert.get("evidence") or []
    ]
    entities = _merge(rows)
    instances = _link_processes(entities)
    return {
        "alertCount": len(alerts),
        "rowCount": len(rows),
        "entityCount": len(entities),
        "countsByType": dict(Counter(e["type"] for e in entities)),
        "withoutDevice": sum(1 for e in entities if e["type"] != "device" and "device" not in e),
        "processInstanceCount": len(instances),
        "sameProcess": [
            {
                "instance": instance,
                "rows": len(group),
                "names": sorted({e["name"] for e in group if e["name"] != "(unnamed)"}),
                "verdicts": sorted({str(e["verdict"]) for e in group if e.get("verdict")}),
            }
            for instance, group in instances.items()
            if len(group) > 1
        ],
        "entities": entities,
    }


# --- one evidence item -> one row ----------------------------------------------------------------


def _row(item: Evidence, alert_id: str) -> Row:
    kind = str(item.get("@odata.type", "")).removeprefix(_PREFIX).removesuffix("Evidence")
    build = _BUILDERS.get(kind, _unknown)
    row: Row = {"type": _TYPE_NAMES.get(kind, kind.lower() or "unknown"), **build(item)}
    row.update(
        roles=item.get("roles"),
        detailed_roles=item.get("detailedRoles"),
        verdict=item.get("verdict"),
        remediation_status=item.get("remediationStatus"),
        detection_status=item.get("detectionStatus"),
        alert_ids=[alert_id] if alert_id else [],
    )
    row = {k: v for k, v in row.items() if v not in (None, "", [], {})}
    row.setdefault("name", "(unnamed)")
    row.setdefault("alert_ids", [])
    return row


def _file(details: Evidence | None) -> Row:
    details = details or {}
    return {
        "name": details.get("fileName"),
        "path": details.get("filePath"),
        "sha1": details.get("sha1"),
        "sha256": details.get("sha256"),
        "size": details.get("fileSize"),
    }


def _account(account: Evidence | None) -> Row:
    account = account or {}
    name, domain = account.get("accountName"), account.get("domainName")
    return {
        "account": f"{domain}\\{name}" if name and domain else name,
        "user_sid": account.get("userSid"),
        "upn": account.get("userPrincipalName"),
        "aad_user_id": account.get("azureAdUserId"),
    }


def _utc(value: Any) -> str | None:
    if not value:
        return None
    try:
        return to_utc(str(value))
    except ValueError:
        return str(value)


def _decoding(command_line: Any) -> Row:
    """The decoded command and how many rounds it took: one layer hides it, each further layer is a choice."""
    if not command_line:
        return {"decoded_command": None}
    layers = decode_layers(str(command_line))
    row: Row = {"decoded_command": layers["decoded"]}
    if layers["rounds"] > 1:
        row["decode_rounds"] = layers["rounds"]
    if layers["capped"]:
        row["decode_capped"] = True
    return row


def _process(item: Evidence) -> Row:
    command_line = item.get("processCommandLine")
    parent = item.get("parentProcessImageFile") or {}
    return {
        **_file(item.get("imageFile")),
        **_account(item.get("userAccount")),
        "pid": item.get("processId"),
        "parent_pid": item.get("parentProcessId"),
        "parent_name": parent.get("fileName"),
        "created": _utc(item.get("processCreationDateTime")),
        "parent_created": _utc(item.get("parentProcessCreationDateTime")),
        "command_line": command_line,
        **_decoding(command_line),
        "mde_device_id": item.get("mdeDeviceId"),
    }


def _device(item: Evidence) -> Row:
    users = [
        "\\".join(p for p in (u.get("domainName"), u.get("accountName")) if p)
        for u in item.get("loggedOnUsers") or []
    ]
    return {
        "name": item.get("deviceDnsName") or item.get("mdeDeviceId") or item.get("azureAdDeviceId"),
        "mde_device_id": item.get("mdeDeviceId"),
        "aad_device_id": item.get("azureAdDeviceId"),
        "os": item.get("osPlatform"),
        "risk_score": item.get("riskScore"),
        "logged_on_users": users,
        "first_seen": _utc(item.get("firstSeenDateTime")),
    }


def _user(item: Evidence) -> Row:
    account = _account(item.get("userAccount"))
    return {"name": account["upn"] or account["account"] or account["user_sid"], **account}


def _registry(item: Evidence) -> Row:
    key = "\\".join(p for p in (item.get("registryHive"), item.get("registryKey")) if p)
    value_name = item.get("registryValueName")
    return {
        "name": f"{key}:{value_name}" if value_name else key,
        "key": key,
        "value_name": value_name,
        "value_data": item.get("registryValue"),
        "mde_device_id": item.get("mdeDeviceId"),
    }


def _mailbox(item: Evidence) -> Row:
    address = item.get("primaryAddress") or item.get("upn")
    return {
        "name": address,
        "address": address,
        "upn": item.get("upn"),
        **{k: v for k, v in _account(item.get("userAccount")).items() if v},
    }


def _unknown(item: Evidence) -> Row:
    """A type this client does not model is never dropped: the count must still reconcile."""
    skipped = {
        "@odata.type",
        "createdDateTime",
        "verdict",
        "remediationStatus",
        "roles",
        "remediationStatusDetails",
        "detailedRoles",
        "tags",
        "detectionStatus",
    }
    attributes = {k: v for k, v in item.items() if k not in skipped and v not in (None, "", [], {})}
    label = next(
        (
            str(attributes[k])
            for k in (
                "displayName",
                "name",
                "url",
                "id",
                "appId",
                "urn",
                "networkMessageId",
                "clusterByValue",
                "resourceId",
            )
            if attributes.get(k)
        ),
        None,
    ) or next((str(v) for v in attributes.values() if isinstance(v, str | int)), None)
    return {"name": label, "attributes": attributes}


_TYPE_NAMES = {"registryKey": "registry", "registryValue": "registry"}
"""A key and a value are both `registry` rows, the type the skills script scopes by device; the value
row carries `value_name`, and its name ends in `:<value name>`."""
_BUILDERS: dict[str, Callable[[Evidence], Row]] = {
    "process": _process,
    "device": _device,
    "user": _user,
    "file": lambda item: {
        **_file(item.get("fileDetails")),
        "mde_device_id": item.get("mdeDeviceId"),
    },
    "ip": lambda item: {
        "name": item.get("ipAddress"),
        "ip": item.get("ipAddress"),
        "country": item.get("countryLetterCode"),
    },
    "url": lambda item: {"name": item.get("url"), "url": item.get("url")},
    "registryKey": _registry,
    "registryValue": _registry,
    "mailbox": _mailbox,
}


# --- device join ---------------------------------------------------------------------------------


def _device_names(alerts: Iterable[Mapping[str, Any]]) -> dict[str, str]:
    """Defender for Endpoint device id -> device name, from every device the incident cites."""
    names: dict[str, str] = {}
    for alert in alerts:
        for item in alert.get("evidence") or []:
            if str(item.get("@odata.type", "")).endswith("deviceEvidence") and item.get(
                "mdeDeviceId"
            ):
                names.setdefault(str(item["mdeDeviceId"]), _device(item)["name"])
    return names


def _joined(row: Row, alert: Mapping[str, Any], device_names: Mapping[str, str]) -> Row:
    """Attach the device: by the row's device id first, else when the alert cites exactly one."""
    if row["type"] == "device":
        return row
    device = device_names.get(str(row.get("mde_device_id", "")))
    if device is None:
        cited = {
            _device(item)["name"]
            for item in alert.get("evidence") or []
            if str(item.get("@odata.type", "")).endswith("deviceEvidence")
        }
        device = next(iter(cited)) if len(cited) == 1 else None
    if device:
        row["device"] = device
    return row


# --- one process, several evidence items -----------------------------------------------------------


def _link_processes(entities: list[Row]) -> dict[str, list[Row]]:
    """Mark the rows of one process with the same `instance` (device, PID, creation time: PIDs are
    reused, that triple is not). The source lists a process once per distinct description of it, and
    the descriptions can carry different verdicts, so the rows are linked and never merged."""
    instances: dict[str, list[Row]] = {}
    for entity in entities:
        if entity["type"] == "process" and "pid" in entity and "created" in entity:
            entity["instance"] = f"{entity.get('device', '?')}|{entity['pid']}|{entity['created']}"
            instances.setdefault(entity["instance"], []).append(entity)
    return instances


# --- de-duplication ------------------------------------------------------------------------------


def _identity(row: Row) -> tuple[str, ...]:
    """The source's own notion of one evidence item: every field exact, a missing one a difference.

    Checked against a test incident (32 alerts, 143 evidence rows): this identity, and no looser
    one, reproduces the portal's evidence list on every type. It is the identity of the skills'
    `evidence_inventory.py` too, so the count is the same at both layers.
    """
    return (
        row["type"],
        str(row["name"]).strip().lower(),
        *(str(row.get(k, "")).strip().lower() for k in _IDENTITY),
    )


def _same_place(entity: Row, row: Row) -> bool:
    """Unscoped types match on identity alone; scoped ones unless both devices are known and differ."""
    if row["type"] not in _SCOPED or not entity.get("device") or not row.get("device"):
        return True
    return str(entity["device"]).lower() == str(row["device"]).lower()


def _merge(rows: Iterable[Row]) -> list[Row]:
    by_identity: dict[tuple[str, ...], list[Row]] = {}
    entities: list[Row] = []
    for row in rows:
        candidates = by_identity.setdefault(_identity(row), [])
        entity = next((e for e in candidates if _same_place(e, row)), None)
        if entity is None:
            entity = {"alert_ids": [], "_devices": set()}
            candidates.append(entity)
            entities.append(entity)
        entity["alert_ids"] = sorted({*entity["alert_ids"], *row["alert_ids"]})
        if row.get("device"):
            entity["_devices"].add(row["device"])
        for name, value in row.items():
            entity.setdefault(name, value)
    for entity in entities:
        seen = sorted(entity.pop("_devices"))
        if len(seen) > 1:  # cited on several devices: it belongs to none of them
            entity.pop("device", None)
            entity["devices"] = seen
    return [{"type": e["type"], "name": e["name"], **e} for e in entities]
