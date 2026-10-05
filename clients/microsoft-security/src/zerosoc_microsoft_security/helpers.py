"""Deterministic helpers exposed as operations: no API call, the same answer every time."""

from __future__ import annotations

from typing import Annotated

from pydantic import Field

from .decode import ROUNDS, decode_layers, to_utc
from .operations import operation
from .surface import Surface
from .transport import JsonObject


class Helpers(Surface):
    @operation(tool="defender_decode_command", api="local")
    async def decode_command(
        self,
        command_line: Annotated[
            str,
            Field(description="A command line containing -EncodedCommand, or the bare payload."),
        ],
    ) -> JsonObject:
        """Decode a PowerShell -EncodedCommand payload (base64 of UTF-16LE) exactly. Accepts the full
        command line, any spelling of the flag (-e, -enc, -ec, ...), or the bare base64. Use it
        instead of decoding by hand. A decoding that is itself an encoded command is decoded again,
        up to five rounds: `rounds` is how many layers were removed and `capped` says the command was
        still encoded when they ran out. The evidence inventory already carries decoded_command,
        decode_rounds and decode_capped on process rows."""
        layers = decode_layers(command_line, rounds=ROUNDS)
        return {
            "decoded": layers["decoded"],
            "found": layers["decoded"] is not None,
            "rounds": layers["rounds"],
            "layers": layers["layers"],
            "capped": layers["capped"],
        }

    @operation(tool="defender_to_utc", api="local")
    async def timestamp_to_utc(
        self,
        timestamp: Annotated[str, Field(description="An ISO 8601 timestamp.")],
        assume_zone: Annotated[
            str,
            Field(
                description="IANA zone a timestamp without offset is read in, e.g. 'Europe/Rome'."
                " Use the analyst's zone for a time copied from the portal, which shows local time."
            ),
        ] = "UTC",
    ) -> JsonObject:
        """Convert a timestamp to UTC exactly. The APIs return UTC; the Defender portal shows the
        viewer's local time. Convert every time quoted from the portal or by a person before it goes
        into a timeline, so all entries share one reference."""
        return {"utc": to_utc(timestamp, assume_zone=assume_zone)}
