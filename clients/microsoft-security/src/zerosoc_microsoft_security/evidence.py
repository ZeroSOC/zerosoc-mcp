"""The evidence inventory of an incident: every entity its alerts cite, once, joined to its device.

Pure functions over the alert resources of the Microsoft Graph security API. The output rows use the
keys the ZeroSOC skills' `evidence_inventory.py` reads (`type`, `name`, `device`, `alert_ids` and the
identity keys `pid`, `created`, `sha1`, `sha256`, `path`, `key`), so the inventory can be recorded in
a ledger unchanged.

`entityCount` is the length of the de-duplicated list, built with the same identity rule as
`evidence_inventory.py`. It is a reproduction of the portal's count of unique evidence items, which it
matched on one incident checked by hand; the source returns no count of its own. So it is not an
independent check of the extraction: passed to `evidence_inventory.py` as the source's count, it
compares the list with its own length and always finds it complete. A count to check against comes
from the portal, read by a person.

A row carries what the source says of its entity, except for these properties, left out for the reason
given:
- `md5`: a third hash of a file whose SHA-1 and SHA-256 are kept.
- `sha256Ac`: the hash of the file's signature.
- `activeDirectoryObjectGuid` and `rbacGroupId`: identifiers with nothing to reason from. The device
  group's name is kept.
- `vmMetadata.vmId` and `vmMetadata.subscriptionId`: both are part of the `resourceId`, which is kept.
- `createdDateTime` of an evidence item: when the source attached the item to its alert, which is no
  event's time.
- `hostName` and `dnsDomain`: the two parts of `deviceDnsName`. They name a device that has no DNS name.

One entity cited by several alerts is one row. A field keeps the first value an alert gave, and the
alerts and the tags are unioned. Where the alerts say different things of the entity (its verdict,
remediation status and the words for it, detection status, roles or detailed roles), `by_alert` gives
each alert's values of the fields they differ on.

A registry value's data is passed as the source sends it (`value_data`): text, or the bytes written in
hex (`43-00-3A-00-…`). Where its type (`value_type`) makes the data text (a string, an expandable
string or a multi-string) and it came as bytes, `value_text` holds it decoded, a list for a
multi-string.
"""

from __future__ import annotations

import re
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
_PER_ALERT = (
    "verdict",
    "remediation_status",
    "remediation_status_details",
    "detection_status",
    "roles",
    "detailed_roles",
)
"""What an alert says of an entity it cites, which another alert citing it can say differently."""


def inventory(alerts: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """De-duplicated entities of the given alerts, with their counts. `entityCount` reproduces the
    portal's figure and is no independent check of this list (see the module docstring)."""
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
        remediation_status_details=item.get("remediationStatusDetails"),
        detection_status=item.get("detectionStatus"),
        tags=item.get("tags"),
        alert_ids=[alert_id] if alert_id else [],
    )
    row = {k: v for k, v in row.items() if v not in (None, "", [], {})}
    row.setdefault("name", "(unnamed)")
    row.setdefault("alert_ids", [])
    return row


def _file(details: Evidence | None, prefix: str = "") -> Row:
    details = details or {}
    return {
        f"{prefix}name": details.get("fileName"),
        f"{prefix}path": details.get("filePath"),
        f"{prefix}sha1": details.get("sha1"),
        f"{prefix}sha256": details.get("sha256"),
        f"{prefix}size": details.get("fileSize"),
        f"{prefix}publisher": details.get("filePublisher"),
        f"{prefix}signer": details.get("signer"),
        f"{prefix}issuer": details.get("issuer"),
    }


def _account(account: Evidence | None) -> Row:
    account = account or {}
    name, domain = account.get("accountName"), account.get("domainName")
    return {
        "account": f"{domain}\\{name}" if name and domain else name,
        "user_sid": account.get("userSid"),
        "upn": account.get("userPrincipalName"),
        "aad_user_id": account.get("azureAdUserId"),
        "user_display_name": account.get("displayName"),
        "user_tenant_id": account.get("tenantId"),
        "user_resource_access_events": _accesses(account.get("resourceAccessEvents")),
    }


def _accesses(events: Iterable[Evidence] | None) -> list[Row]:
    """Accesses to a resource, by an account or on a device, each with its time in UTC."""
    return [
        {
            k: v
            for k, v in (
                ("time", _utc(e.get("accessDateTime"))),
                ("account_id", e.get("accountId")),
                ("ip", e.get("ipAddress")),
                ("resource", e.get("resourceIdentifier")),
            )
            if v not in (None, "")
        }
        for e in events or []
    ]


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
    return {
        **_file(item.get("imageFile")),
        **_account(item.get("userAccount")),
        "pid": item.get("processId"),
        "parent_pid": item.get("parentProcessId"),
        **_file(item.get("parentProcessImageFile"), "parent_"),
        "created": _utc(item.get("processCreationDateTime")),
        "parent_created": _utc(item.get("parentProcessCreationDateTime")),
        "command_line": command_line,
        **_decoding(command_line),
        "mde_device_id": item.get("mdeDeviceId"),
    }


def _device_name(item: Evidence) -> Any:
    """The device's DNS name, else its host name in its DNS domain, else its id."""
    host = ".".join(p for p in (item.get("hostName"), item.get("dnsDomain")) if p)
    return (
        item.get("deviceDnsName")
        or (host if item.get("hostName") else None)
        or item.get("mdeDeviceId")
        or item.get("azureAdDeviceId")
    )


def _device(item: Evidence) -> Row:
    users = [
        "\\".join(p for p in (u.get("domainName"), u.get("accountName")) if p)
        for u in item.get("loggedOnUsers") or []
    ]
    vm = item.get("vmMetadata") or {}
    return {
        "name": _device_name(item),
        "mde_device_id": item.get("mdeDeviceId"),
        "aad_device_id": item.get("azureAdDeviceId"),
        "os": item.get("osPlatform"),
        "os_version": item.get("version"),
        "os_build": item.get("osBuild"),
        "risk_score": item.get("riskScore"),
        "health_status": item.get("healthStatus"),
        "onboarding_status": item.get("onboardingStatus"),
        "av_status": item.get("defenderAvStatus"),
        "device_group": item.get("rbacGroupName"),
        "nt_domain": item.get("ntDomain"),
        "last_ip": item.get("lastIpAddress"),
        "last_external_ip": item.get("lastExternalIpAddress"),
        "ip_interfaces": item.get("ipInterfaces"),
        "cloud_provider": vm.get("cloudProvider"),
        "cloud_resource_id": vm.get("resourceId"),
        "logged_on_users": users,
        "resource_access_events": _accesses(item.get("resourceAccessEvents")),
        "first_seen": _utc(item.get("firstSeenDateTime")),
    }


def _user(item: Evidence) -> Row:
    account = _account(item.get("userAccount"))
    return {
        "name": account["upn"] or account["account"] or account["user_sid"],
        **account,
        "stream": (item.get("stream") or {}).get("name"),
    }


def _ip(item: Evidence) -> Row:
    place = item.get("location") or {}
    location = {
        k: v
        for k, v in (
            ("city", place.get("city")),
            ("state", place.get("state")),
            ("country_name", place.get("countryName")),
            ("latitude", place.get("latitude")),
            ("longitude", place.get("longitude")),
        )
        if v not in (None, "")
    }
    return {
        "name": item.get("ipAddress"),
        "ip": item.get("ipAddress"),
        "country": item.get("countryLetterCode"),
        "location": location,
        "stream": (item.get("stream") or {}).get("name"),
    }


_HEX_BYTES = re.compile(r"[0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2})+")
_TEXT_TYPES = {"string": False, "regsz": False, "expandstring": False, "regexpandsz": False}
_TEXT_TYPES |= {"multistring": True, "regmultisz": True}
"""The registry value types whose data is text, and whether it is a list of strings."""


def _registry_text(value_type: Any, data: Any) -> str | list[str] | None:
    """The data of a text value the source sent as bytes, decoded as the UTF-16LE Windows stores it.
    None for any other value, and for bytes that are not text."""
    multi = _TEXT_TYPES.get(str(value_type or "").replace("_", "").lower())
    if multi is None or not isinstance(data, str) or not _HEX_BYTES.fullmatch(data.strip()):
        return None
    raw = bytes.fromhex(data.strip().replace("-", ""))
    try:
        text = raw.decode("utf-16-le")
    except UnicodeDecodeError:
        return None
    # a string ends at its first NUL, a multi-string's list at its first empty string
    strings = text.split("\0")
    strings = strings[: strings.index("") if "" in strings else None] if multi else strings[:1]
    if not all(c.isprintable() or c in "\t\r\n" for s in strings for c in s):
        return None
    return strings if multi else strings[0]


def _registry(item: Evidence) -> Row:
    key = "\\".join(p for p in (item.get("registryHive"), item.get("registryKey")) if p)
    value_name = item.get("registryValueName")
    value_type, data = item.get("registryValueType"), item.get("registryValue")
    return {
        "name": f"{key}:{value_name}" if value_name else key,
        "key": key,
        "value_name": value_name,
        "value_type": value_type,
        "value_data": data,
        "value_text": _registry_text(value_type, data),
        "mde_device_id": item.get("mdeDeviceId"),
    }


def _mailbox(item: Evidence) -> Row:
    """A mailbox is named by its own address and UPN. Its account's UPN fills `upn` where the mailbox
    has none, and is kept as `account_upn` where the two differ."""
    address = item.get("primaryAddress") or item.get("upn")
    account = {k: v for k, v in _account(item.get("userAccount")).items() if v}
    upn = item.get("upn")
    if upn and account.get("upn", upn) != upn:
        account["account_upn"] = account.pop("upn")
    return {
        "name": address,
        "address": address,
        "display_name": item.get("displayName"),
        "upn": upn,
        **account,
    }


def _unknown(item: Evidence) -> Row:
    """A type this client does not model is never dropped: the count must still cover it."""
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
    "ip": _ip,
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
                names.setdefault(str(item["mdeDeviceId"]), _device_name(item))
    return names


def _joined(row: Row, alert: Mapping[str, Any], device_names: Mapping[str, str]) -> Row:
    """Attach the device: by the row's device id first, else when the alert cites exactly one."""
    if row["type"] == "device":
        return row
    device = device_names.get(str(row.get("mde_device_id", "")))
    if device is None:
        cited = {
            _device_name(item)
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
            entity = {"alert_ids": [], "_devices": set(), "_said": {}}
            candidates.append(entity)
            entities.append(entity)
        entity["alert_ids"] = sorted({*entity["alert_ids"], *row["alert_ids"]})
        if row.get("device"):
            entity["_devices"].add(row["device"])
        if row.get("tags"):
            entity["tags"] = list(dict.fromkeys([*entity.get("tags", []), *row["tags"]]))
        for alert in row["alert_ids"]:
            said = entity["_said"].setdefault(alert, {})
            for name in _PER_ALERT:
                if name in row:
                    said.setdefault(name, row[name])
        for name, value in row.items():
            entity.setdefault(name, value)
    for entity in entities:
        seen = sorted(entity.pop("_devices"))
        if len(seen) > 1:  # cited on several devices: it belongs to none of them
            entity.pop("device", None)
            entity["devices"] = seen
        by_alert = _by_alert(entity.pop("_said"))
        if by_alert:
            entity["by_alert"] = by_alert
    return [{"type": e["type"], "name": e["name"], **e} for e in entities]


def _by_alert(said: Mapping[str, Row]) -> dict[str, Row]:
    """Each alert's values of the fields the alerts citing one entity give different values for."""

    def same(value: Any) -> Any:
        return tuple(sorted(map(str, value))) if isinstance(value, list) else value

    differ = [n for n in _PER_ALERT if len({same(v[n]) for v in said.values() if n in v}) > 1]
    out = {alert: {n: v[n] for n in differ if n in v} for alert, v in sorted(said.items())}
    return {alert: values for alert, values in out.items() if values}
