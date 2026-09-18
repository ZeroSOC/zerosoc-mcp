"""Devices and device response actions (Defender for Endpoint API, /machines)."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field

from .errors import InvalidInputError
from .operations import operation
from .surface import Comment, Filter, MachineId, Skip, Surface, top
from .transport import MDE, JsonObject, seg

_READ = ("Machine.Read.All",)
_WRITE = ("Machine.ReadWrite.All",)


class Machines(Surface):
    @operation(tool="defender_get_machines", api="mde", permissions=_READ)
    async def list_machines(
        self,
        filter: Filter = None,
        top: Annotated[int, top("machines", 25, 100)] = 25,
        skip: Skip = 0,
    ) -> JsonObject:
        """List devices onboarded to Defender for Endpoint, with OData filtering, e.g.
        "healthStatus eq 'Active'", "riskScore eq 'High'", "startswith(computerDnsName,'ws')"."""
        return await self._mde_list("/machines", filter, top, skip)

    @operation(tool="defender_get_machine_by_id", api="mde", permissions=_READ)
    async def get_machine(self, machine_id: MachineId) -> JsonObject:
        """Get one device: DNS name, OS, health, risk and exposure level, tags, device value, IPs,
        first and last seen. Accepts the machine ID (the mdeDeviceId of alert evidence)."""
        return await self._mde_get(f"/machines/{seg(machine_id)}")

    @operation(tool="defender_find_machines_by_ip", api="mde", permissions=_READ)
    async def find_machines_by_ip(
        self,
        ip: Annotated[str, Field(description="IP address to search for.")],
        timestamp: Annotated[
            str, Field(description="UTC ISO 8601 time; devices seen with the IP within 15 minutes.")
        ],
        top: Annotated[int, top("machines", 25, 200)] = 25,
    ) -> JsonObject:
        """Find the devices that had an IP address around a given time."""
        return await self._mde_bounded(
            f"/machines/findbyip(ip='{seg(ip)}',timestamp={seg(timestamp)})", top
        )

    @operation(tool="defender_find_machines_by_tag", api="mde", permissions=_READ)
    async def find_machines_by_tag(
        self,
        tag: Annotated[str, Field(description="Machine tag to search for.")],
        starts_with: Annotated[
            bool, Field(description="Match tags that start with the value instead of equal it.")
        ] = False,
        top: Annotated[int, top("machines", 25, 200)] = 25,
    ) -> JsonObject:
        """Find the devices that carry a tag."""
        return await self._mde_bounded(
            "/machines/findbytag", top, params={"tag": tag, "useStartsWithFilter": starts_with}
        )

    @operation(tool="defender_get_machine_logon_users", api="mde", permissions=("User.Read.All",))
    async def get_machine_logon_users(
        self,
        machine_id: MachineId,
        top: Annotated[int, top("users", 25, 200)] = 25,
    ) -> JsonObject:
        """List the users that logged on to a device."""
        return await self._mde_bounded(f"/machines/{seg(machine_id)}/logonusers", top)

    @operation(tool="defender_get_machine_alerts", api="mde", permissions=("Alert.Read.All",))
    async def get_machine_alerts(
        self,
        machine_id: MachineId,
        filter: Filter = None,
        top: Annotated[int, top("alerts", 25, 100)] = 25,
    ) -> JsonObject:
        """List the Defender for Endpoint alerts of one device."""
        return await self._mde_list(f"/machines/{seg(machine_id)}/alerts", filter, top)

    @operation(tool="defender_update_machine", api="mde", kind="write", permissions=_WRITE)
    async def update_machine(
        self,
        machine_id: MachineId,
        machine_tags: Annotated[
            list[str] | None, Field(description="New tag set; replaces the existing one.")
        ] = None,
        device_value: Annotated[
            Literal["Low", "Normal", "High"] | None, Field(description="Device value.")
        ] = None,
    ) -> JsonObject:
        """Update a device's tags or device value (a metadata write)."""
        body = {"machineTags": machine_tags, "deviceValue": device_value}
        body = {k: v for k, v in body.items() if v is not None}
        if not body:
            raise InvalidInputError("nothing to update: pass machine_tags or device_value")
        return await self._api.request(MDE, "PATCH", f"/machines/{seg(machine_id)}", json=body)

    @operation(tool="defender_add_remove_machine_tag", api="mde", kind="write", permissions=_WRITE)
    async def add_remove_machine_tag(
        self,
        machine_id: MachineId,
        value: Annotated[str, Field(description="Tag value.")],
        action: Annotated[Literal["Add", "Remove"], Field(description="Add or Remove.")],
    ) -> JsonObject:
        """Add a tag to a device or remove one (a metadata write)."""
        return await self._mde_post(
            f"/machines/{seg(machine_id)}/tags", {"Value": value, "Action": action}
        )

    # --- response actions: off unless the client is created with allow_actions=True -------------

    @operation(
        tool="defender_isolate_machine", api="mde", kind="action", permissions=("Machine.Isolate",)
    )
    async def isolate_machine(
        self,
        machine_id: MachineId,
        comment: Comment,
        isolation_type: Annotated[
            Literal["Full", "Selective"],
            Field(description="Full cuts every connection; Selective keeps Outlook and Teams."),
        ] = "Full",
    ) -> JsonObject:
        """RESPONSE ACTION. Isolate a device from the network. The device keeps its connection to
        the Defender service, so it can be released with defender_unisolate_machine. Returns the
        machine action to follow with defender_get_machine_action_by_id."""
        return await self._mde_post(
            f"/machines/{seg(machine_id)}/isolate",
            {"Comment": comment, "IsolationType": isolation_type},
        )

    @operation(
        tool="defender_unisolate_machine",
        api="mde",
        kind="action",
        permissions=("Machine.Isolate",),
    )
    async def unisolate_machine(self, machine_id: MachineId, comment: Comment) -> JsonObject:
        """RESPONSE ACTION. Release a device from network isolation: the rollback of
        defender_isolate_machine."""
        return await self._mde_post(f"/machines/{seg(machine_id)}/unisolate", {"Comment": comment})

    @operation(tool="defender_run_av_scan", api="mde", kind="action", permissions=("Machine.Scan",))
    async def run_av_scan(
        self,
        machine_id: MachineId,
        comment: Comment,
        scan_type: Annotated[
            Literal["Quick", "Full"], Field(description="Quick or Full antivirus scan.")
        ] = "Quick",
    ) -> JsonObject:
        """RESPONSE ACTION. Start an antivirus scan on a device."""
        return await self._mde_post(
            f"/machines/{seg(machine_id)}/runAntiVirusScan",
            {"Comment": comment, "ScanType": scan_type},
        )

    @operation(
        tool="defender_restrict_code_execution",
        api="mde",
        kind="action",
        permissions=("Machine.RestrictExecution",),
    )
    async def restrict_code_execution(self, machine_id: MachineId, comment: Comment) -> JsonObject:
        """RESPONSE ACTION. Restrict a device to running Microsoft-signed binaries only."""
        return await self._mde_post(
            f"/machines/{seg(machine_id)}/restrictCodeExecution", {"Comment": comment}
        )

    @operation(
        tool="defender_unrestrict_code_execution",
        api="mde",
        kind="action",
        permissions=("Machine.RestrictExecution",),
    )
    async def unrestrict_code_execution(
        self, machine_id: MachineId, comment: Comment
    ) -> JsonObject:
        """RESPONSE ACTION. Remove the code execution restriction from a device: the rollback of
        defender_restrict_code_execution."""
        return await self._mde_post(
            f"/machines/{seg(machine_id)}/unrestrictCodeExecution", {"Comment": comment}
        )

    @operation(
        tool="defender_stop_and_quarantine_file",
        api="mde",
        kind="action",
        permissions=("Machine.StopAndQuarantine",),
    )
    async def stop_and_quarantine_file(
        self,
        machine_id: MachineId,
        comment: Comment,
        sha1: Annotated[str, Field(description="SHA1 of the file to stop and quarantine.")],
    ) -> JsonObject:
        """RESPONSE ACTION. Stop a running file on a device and quarantine it, by SHA1."""
        return await self._mde_post(
            f"/machines/{seg(machine_id)}/StopAndQuarantineFile",
            {"Comment": comment, "Sha1": sha1},
        )

    @operation(
        tool="defender_collect_investigation_package",
        api="mde",
        kind="action",
        permissions=("Machine.CollectForensics",),
    )
    async def collect_investigation_package(
        self, machine_id: MachineId, comment: Comment
    ) -> JsonObject:
        """RESPONSE ACTION. Collect a forensic investigation package (logs, registry, network state)
        from a device. Fetch it with defender_get_package_sas_uri once the action succeeds."""
        return await self._mde_post(
            f"/machines/{seg(machine_id)}/collectInvestigationPackage", {"Comment": comment}
        )

    @operation(
        tool="defender_offboard_machine",
        api="mde",
        kind="action",
        permissions=("Machine.Offboard",),
    )
    async def offboard_machine(self, machine_id: MachineId, comment: Comment) -> JsonObject:
        """RESPONSE ACTION, NOT REVERSIBLE FROM HERE. Offboard a device from Defender for Endpoint:
        it stops reporting and loses protection."""
        return await self._mde_post(f"/machines/{seg(machine_id)}/offboard", {"Comment": comment})
