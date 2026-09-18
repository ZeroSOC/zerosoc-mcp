from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from zerosoc_defender_xdr.evidence import inventory

KEY = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
FIXTURE = Path(__file__).parent / "fixtures" / "incident_14.json"


def alerts() -> list[dict[str, Any]]:
    return json.loads(FIXTURE.read_text())["alerts"]  # type: ignore[no-any-return]


def entity(result: dict[str, Any], **wanted: Any) -> dict[str, Any]:
    found = [e for e in result["entities"] if all(e.get(k) == v for k, v in wanted.items())]
    assert len(found) == 1, f"{wanted} matched {len(found)} entities"
    return found[0]


def test_every_entity_is_listed_once_with_the_alerts_that_cite_it() -> None:
    result = inventory(alerts())

    assert result["rowCount"] == 17
    assert result["entityCount"] == 13
    assert result["countsByType"] == {
        "device": 2,
        "user": 1,
        "process": 2,
        "ip": 1,
        "url": 1,
        "file": 2,
        "registry": 2,
        "mailbox": 1,
        "quantumteapot": 1,
    }
    assert entity(result, type="ip")["alert_ids"] == ["da-1", "da-3"]
    assert entity(result, type="user")["alert_ids"] == ["da-1", "da-2"]


def test_a_process_row_carries_what_an_analyst_reads_in_the_portal() -> None:
    process = entity(inventory(alerts()), type="process", device="ws01.lab.example")

    assert process["name"] == "powershell.exe"
    assert (process["pid"], process["parent_pid"]) == (4312, 2200)
    assert process["parent_name"] == "winword.exe"
    assert process["created"] == "2026-09-10T10:00:00.5Z"
    assert process["parent_created"] == "2026-09-10T09:59:00Z"
    assert process["command_line"].startswith("powershell.exe -NoP -W Hidden -enc ")
    assert process["decoded_command"].startswith("IEX (New-Object Net.WebClient)")
    assert process["sha256"] == "a" * 64 and process["sha1"] == "b" * 40
    assert process["path"] == "C:\\Windows\\System32\\WindowsPowerShell\\v1.0"
    assert process["user_sid"] == "S-1-5-21-1-2-3-1104"
    assert process["upn"] == "alice@lab.example"
    assert process["mde_device_id"] == "mde-ws01"
    assert process["detailed_roles"] == ["attacker tool"]
    assert (process["verdict"], process["remediation_status"]) == ("malicious", "active")
    assert process["alert_ids"] == ["da-1", "da-2"]


def test_the_same_pid_on_another_device_is_another_process() -> None:
    result = inventory(alerts())
    other = entity(result, type="process", device="ws02.lab.example")
    assert other["pid"] == 4312 and "decoded_command" not in other


def test_rows_are_joined_to_their_device_by_device_id_or_by_the_alert() -> None:
    result = inventory(alerts())
    # by mdeDeviceId
    assert entity(result, type="registry", value_name="Updater")["device"] == "ws01.lab.example"
    assert {e["device"] for e in result["entities"] if e["type"] == "file"} == {
        "ws01.lab.example",
        "ws02.lab.example",
    }
    # no device id on the row: the alert cites exactly one device
    assert entity(result, type="registry", name=KEY)["device"] == "ws01.lab.example"
    assert entity(result, type="url")["device"] == "ws01.lab.example"
    # cited by alerts on two devices: joined to neither, and said so
    address = entity(result, type="ip")
    assert "device" not in address
    assert address["devices"] == ["ws01.lab.example", "ws02.lab.example"]
    assert result["withoutDevice"] == 1


def test_registry_rows_name_the_key_and_the_value() -> None:
    value = entity(inventory(alerts()), type="registry", value_name="Updater")
    assert value["key"] == "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    assert value["value_name"] == "Updater"
    assert value["value_data"].endswith("upd.exe")
    assert value["name"] == f"{value['key']}:Updater"


def test_an_evidence_type_this_client_has_never_seen_is_still_counted() -> None:
    unknown = entity(inventory(alerts()), type="quantumteapot")
    assert unknown["name"] == "teapot-1"
    assert unknown["alert_ids"] == ["da-3"]


def test_an_alert_without_evidence_adds_nothing_and_breaks_nothing() -> None:
    result = inventory([{"id": "da-9", "evidence": None}, {"id": "da-10"}])
    assert (result["alertCount"], result["rowCount"], result["entityCount"]) == (2, 0, 0)


def test_the_rows_feed_the_skills_evidence_inventory_unchanged() -> None:
    """The keys the skills' evidence_inventory.py reads: type, name, device, alert_ids, identity keys."""
    for row in inventory(alerts())["entities"]:
        assert row["type"] and row["name"] and isinstance(row["alert_ids"], list)
        assert set(row) <= {
            "type",
            "name",
            "device",
            "devices",
            "alert_ids",
            "pid",
            "parent_pid",
            "parent_name",
            "created",
            "parent_created",
            "command_line",
            "decoded_command",
            "sha1",
            "sha256",
            "path",
            "size",
            "user_sid",
            "upn",
            "account",
            "aad_user_id",
            "mde_device_id",
            "aad_device_id",
            "os",
            "risk_score",
            "logged_on_users",
            "ip",
            "country",
            "url",
            "key",
            "value_name",
            "value_data",
            "address",
            "roles",
            "detailed_roles",
            "verdict",
            "remediation_status",
            "detection_status",
            "first_seen",
            "attributes",
            "instance",
        }


def test_a_scoped_row_without_a_device_joins_the_entity_that_has_one() -> None:
    file = {
        "@odata.type": "#microsoft.graph.security.fileEvidence",
        "fileDetails": {"fileName": "upd.exe", "sha256": "f" * 64},
    }
    device = {
        "@odata.type": "#microsoft.graph.security.deviceEvidence",
        "deviceDnsName": "ws01",
        "mdeDeviceId": "m1",
    }
    result = inventory(
        [
            {"id": "a1", "evidence": [device, {**file, "mdeDeviceId": "m1"}]},
            {"id": "a2", "evidence": [file]},  # no device on the row, none on the alert
        ]
    )
    files = [e for e in result["entities"] if e["type"] == "file"]
    assert len(files) == 1
    assert files[0]["device"] == "ws01" and files[0]["alert_ids"] == ["a1", "a2"]


T = "#microsoft.graph.security."


# --- the unit of the inventory is the source's own evidence item ------------------------------------
#
# Checked against a test incident of 32 alerts and 143 evidence rows: the portal's evidence list showed
# 37 items (5 devices, 20 processes, 1 user, 5 files, 3 addresses, 3 registry items). Only the strict
# identity below reproduces it, on every type. It is also the identity of the skills' script, so the
# two layers cannot disagree. Two attempts to merge "obviously the same" rows both broke the count.


def _process(image: dict[str, Any] | None, **extra: Any) -> dict[str, Any]:
    return {
        "@odata.type": T + "processEvidence",
        "processId": 640,
        "mdeDeviceId": "m1",
        "processCreationDateTime": "2026-09-13T18:38:51.74649Z",
        "imageFile": image,
        **extra,
    }


DEVICE = {"@odata.type": T + "deviceEvidence", "deviceDnsName": "ws01", "mdeDeviceId": "m1"}


def test_the_source_lists_one_process_twice_when_its_details_differ_and_so_does_the_inventory() -> (
    None
):
    """services.exe, PID 640: one alert gives an NT device path and no hash, the next a drive path
    and a hash. The portal lists two items."""
    bare = _process(
        {"fileName": "services.exe", "filePath": "\\Device\\HarddiskVolume2\\Windows\\System32"}
    )
    full = _process(
        {"fileName": "services.exe", "filePath": "C:\\Windows\\System32", "sha1": "e" * 40}
    )
    result = inventory(
        [{"id": "a1", "evidence": [DEVICE, bare]}, {"id": "a2", "evidence": [DEVICE, full, full]}]
    )
    assert result["countsByType"] == {"device": 1, "process": 2}


def test_rows_of_one_process_are_linked_not_merged_so_no_verdict_is_lost() -> None:
    """PID 3132: a blocked, malicious row without an image file, and a suspicious WmiPrvSE.exe row
    with the same creation time. Two items in the portal; one process."""
    blocked = _process(None, verdict="malicious", remediationStatus="blocked")
    named = _process({"fileName": "WmiPrvSE.exe"}, verdict="suspicious", remediationStatus="active")
    result = inventory(
        [{"id": "a1", "evidence": [DEVICE, blocked]}, {"id": "a2", "evidence": [DEVICE, named]}]
    )

    processes = [e for e in result["entities"] if e["type"] == "process"]
    assert [(p["name"], p["verdict"]) for p in processes] == [
        ("(unnamed)", "malicious"),
        ("WmiPrvSE.exe", "suspicious"),
    ]
    assert (
        processes[0]["instance"]
        == processes[1]["instance"]
        == ("ws01|640|2026-09-13T18:38:51.74649Z")
    )
    assert result["processInstanceCount"] == 1
    assert result["sameProcess"] == [
        {
            "instance": "ws01|640|2026-09-13T18:38:51.74649Z",
            "rows": 2,
            "names": ["WmiPrvSE.exe"],
            "verdicts": ["malicious", "suspicious"],
        }
    ]


def test_a_reused_pid_is_another_process_instance() -> None:
    first = _process({"fileName": "services.exe"})
    later = first | {"processCreationDateTime": "2026-09-14T08:00:00Z"}
    result = inventory([{"id": "a1", "evidence": [DEVICE, first, later]}])
    assert result["processInstanceCount"] == 2 and result["sameProcess"] == []


def test_identity_is_exact_a_missing_hash_is_a_difference() -> None:
    def file(**details: str) -> dict[str, Any]:
        return {
            "@odata.type": T + "fileEvidence",
            "mdeDeviceId": "m1",
            "fileDetails": {"fileName": "l.dmp", **details},
        }

    result = inventory(
        [
            {
                "id": "a1",
                "evidence": [
                    DEVICE,
                    file(sha1="1" * 40),
                    file(sha1="1" * 40, sha256="2" * 64),
                    file(sha1="1" * 40),
                ],
            }
        ]
    )
    assert result["countsByType"] == {"device": 1, "file": 2}


def test_names_compare_without_case() -> None:
    def device(name: str) -> dict[str, Any]:
        return {"@odata.type": T + "deviceEvidence", "deviceDnsName": name}

    assert (
        inventory([{"id": "a1", "evidence": [device("WS01.lab"), device("ws01.lab")]}])[
            "entityCount"
        ]
        == 1
    )


def test_the_same_registry_value_on_two_devices_is_two_entities_for_the_skills_script_too() -> None:
    """Registry rows have the type the skills script scopes by device: `registry`."""

    def alert(i: int) -> dict[str, Any]:
        return {
            "id": f"a{i}",
            "evidence": [
                {
                    "@odata.type": T + "deviceEvidence",
                    "deviceDnsName": f"ws0{i}",
                    "mdeDeviceId": f"m{i}",
                },
                {
                    "@odata.type": T + "registryValueEvidence",
                    "registryHive": "HKLM",
                    "registryKey": "Run",
                    "registryValueName": "Updater",
                    "mdeDeviceId": f"m{i}",
                },
            ],
        }

    result = inventory([alert(1), alert(2)])
    assert result["countsByType"] == {"device": 2, "registry": 2}
