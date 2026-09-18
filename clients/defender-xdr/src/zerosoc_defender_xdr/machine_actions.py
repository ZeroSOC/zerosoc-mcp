"""Machine actions, live response, automated investigations (Defender for Endpoint API)."""

from __future__ import annotations

import base64
import binascii
from typing import Annotated, Literal

from pydantic import BaseModel, Field

from .errors import InvalidInputError
from .operations import operation
from .surface import Comment, Filter, MachineId, Skip, Surface, top
from .transport import MDE, JsonObject, seg

ActionId = Annotated[str, Field(description="The machine action ID.")]
_READ = ("Machine.Read.All",)
_LIVE = ("Machine.LiveResponse",)
_LIBRARY = ("Library.Manage",)


class CommandParam(BaseModel):
    key: str
    value: str


class LiveResponseCommand(BaseModel):
    type: Literal["RunScript", "GetFile", "PutFile"]
    params: list[CommandParam] = Field(
        description="RunScript: ScriptName, Args. GetFile: Path. PutFile: FileName."
    )


class MachineActions(Surface):
    @operation(tool="defender_get_machine_actions", api="mde", permissions=_READ)
    async def list_machine_actions(
        self,
        filter: Filter = None,
        top: Annotated[int, top("actions", 25, 100)] = 25,
        skip: Skip = 0,
    ) -> JsonObject:
        """List response actions taken on devices (isolation, release, scans, quarantine, packages,
        live response) with their status, requestor, comment and times, e.g. filter "machineId eq
        '<id>'" or "type eq 'Isolate'". It lists actions taken by anyone, people included, so it is
        how to check whether a containment still stands."""
        return await self._mde_list("/machineactions", filter, top, skip)

    @operation(tool="defender_get_machine_action_by_id", api="mde", permissions=_READ)
    async def get_machine_action(self, action_id: ActionId) -> JsonObject:
        """Get one machine action: type, status (Pending, InProgress, Succeeded, Failed, TimeOut,
        Cancelled), requestor, comment and times. Poll it after a response action."""
        return await self._mde_get(f"/machineactions/{seg(action_id)}")

    @operation(
        tool="defender_get_package_sas_uri", api="mde", permissions=("Machine.CollectForensics",)
    )
    async def get_package_uri(self, action_id: ActionId) -> JsonObject:
        """Get the short-lived download link of a collected investigation package. The link grants
        access to forensic data: hand it to a person, do not store it in a note."""
        return await self._mde_get(f"/machineactions/{seg(action_id)}/getPackageUri")

    @operation(tool="defender_get_live_response_result", api="mde", permissions=_LIVE)
    async def get_live_response_result(
        self,
        action_id: ActionId,
        command_index: Annotated[int, Field(description="Index of the command (0-based).", ge=0)],
    ) -> JsonObject:
        """Get the short-lived download link of the output of one live response command."""
        return await self._mde_get(
            f"/machineactions/{seg(action_id)}/GetLiveResponseResultDownloadLink(index={command_index})"
        )

    @operation(tool="defender_get_investigations", api="mde", permissions=("Alert.Read.All",))
    async def list_investigations(
        self,
        filter: Filter = None,
        top: Annotated[int, top("investigations", 25, 100)] = 25,
        skip: Skip = 0,
    ) -> JsonObject:
        """List automated investigations with their state and the alert that triggered each."""
        return await self._mde_list("/investigations", filter, top, skip)

    @operation(tool="defender_get_investigation_by_id", api="mde", permissions=("Alert.Read.All",))
    async def get_investigation(
        self, investigation_id: Annotated[str, Field(description="The investigation ID.")]
    ) -> JsonObject:
        """Get one automated investigation: state, status details, device and triggering alert."""
        return await self._mde_get(f"/investigations/{seg(investigation_id)}")

    @operation(tool="defender_list_library_files", api="mde", permissions=_LIBRARY)
    async def list_library_files(
        self, top: Annotated[int, top("files", 25, 200)] = 25
    ) -> JsonObject:
        """List the scripts in the live response library."""
        return await self._mde_bounded("/libraryfiles", top)

    # --- response actions ------------------------------------------------------------------------

    @operation(
        tool="defender_cancel_machine_action",
        api="mde",
        kind="action",
        permissions=("Machine.Isolate", "Machine.Scan", "Machine.LiveResponse"),
    )
    async def cancel_machine_action(self, action_id: ActionId, comment: Comment) -> JsonObject:
        """RESPONSE ACTION. Cancel a pending machine action."""
        return await self._mde_post(
            f"/machineactions/{seg(action_id)}/cancel", {"Comment": comment}
        )

    @operation(tool="defender_run_live_response", api="mde", kind="action", permissions=_LIVE)
    async def run_live_response(
        self,
        machine_id: MachineId,
        commands: Annotated[
            list[LiveResponseCommand], Field(description="Commands to run, in order (max 10).")
        ],
        comment: Comment,
    ) -> JsonObject:
        """RESPONSE ACTION. Run live response commands on a device: run a library script, get a file,
        put a library file. This executes code on the device. Returns the machine action to poll;
        read the output with defender_get_live_response_result."""
        if not 0 < len(commands) <= 10:
            raise InvalidInputError("pass between 1 and 10 commands")
        return await self._mde_post(
            f"/machines/{seg(machine_id)}/runliveresponse",
            {"Commands": [c.model_dump() for c in commands], "Comment": comment},
        )

    @operation(
        tool="defender_start_investigation",
        api="mde",
        kind="action",
        permissions=("Alert.ReadWrite.All",),
    )
    async def start_investigation(self, machine_id: MachineId, comment: Comment) -> JsonObject:
        """RESPONSE ACTION. Start an automated investigation on a device. Automated investigations
        can remediate on their own, depending on the device group's automation level."""
        return await self._mde_post(
            f"/machines/{seg(machine_id)}/startInvestigation", {"Comment": comment}
        )

    @operation(tool="defender_upload_library_file", api="mde", kind="action", permissions=_LIBRARY)
    async def upload_library_file(
        self,
        file: Annotated[str, Field(description="Base64 of the file content.")],
        file_name: Annotated[str, Field(description="Name of the file in the library.")],
        description: Annotated[str | None, Field(description="What the script does.")] = None,
        parameters_description: Annotated[
            str | None, Field(description="The parameters the script takes.")
        ] = None,
        has_parameters: Annotated[bool, Field(description="The script takes parameters.")] = False,
        override_if_exists: Annotated[
            bool, Field(description="Replace a library file of the same name.")
        ] = False,
    ) -> JsonObject:
        """RESPONSE ACTION. Upload a script to the live response library, from where it can be run on
        any device. Review the content first: it is code that will run with system privileges."""
        try:
            content = base64.b64decode(file, validate=True)
        except (binascii.Error, ValueError):
            raise InvalidInputError("file must be base64") from None
        form = {
            "Description": description,
            "ParametersDescription": parameters_description,
            "HasParameters": str(has_parameters).lower(),
            "OverrideIfExists": str(override_if_exists).lower(),
        }
        return await self._api.request(
            MDE,
            "POST",
            "/libraryfiles",
            form={k: v for k, v in form.items() if v is not None},
            files={"file": (file_name, content)},
        )

    @operation(tool="defender_delete_library_file", api="mde", kind="action", permissions=_LIBRARY)
    async def delete_library_file(
        self, file_name: Annotated[str, Field(description="Name of the library file.")]
    ) -> JsonObject:
        """RESPONSE ACTION. Delete a script from the live response library."""
        await self._api.request(MDE, "DELETE", f"/libraryfiles/{seg(file_name)}")
        return {"deleted": file_name}
