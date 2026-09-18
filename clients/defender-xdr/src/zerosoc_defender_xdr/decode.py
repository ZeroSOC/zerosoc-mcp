"""Deterministic helpers: decode an encoded PowerShell command, normalize a timestamp to UTC.

Both are pure functions. A model that decodes base64 or converts time zones in its head gets them
wrong some of the time; a timeline built on those mistakes is wrong all of the time.
"""

from __future__ import annotations

import base64
import binascii
import re
from datetime import UTC, datetime
from typing import TypedDict
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .errors import InvalidInputError

# PowerShell accepts any prefix of -EncodedCommand ("-e", "-en", "-enc", ...) and the alias "-ec",
# introduced by "-", "/" or a typographic dash. "-ep" and "-ex..." (ExecutionPolicy) are not prefixes.
_DASHES = "-/\u2013\u2014\u2015"
_PREFIXES = "|".join(["ec", *("encodedcommand"[:n] for n in range(len("encodedcommand"), 0, -1))])
_FLAG = re.compile(
    rf"""(?:^|\s)[{_DASHES}](?:{_PREFIXES})\s+["']?([A-Za-z0-9+/=]+)["']?""", re.IGNORECASE
)
_BARE = re.compile(r"^[A-Za-z0-9+/]{8,}={0,2}$")
ROUNDS = 5  # a command still encoded after this many rounds is obfuscation for its own sake: stop


class Decoding(TypedDict):
    """What came out of a command line: the innermost script, the layers removed, and whether more remain."""

    decoded: str | None
    rounds: int
    layers: list[str]
    capped: bool


_FRACTION = re.compile(r"(\.\d{6})\d+")


def decode_encoded_command(command_line: str, *, rounds: int = ROUNDS) -> str | None:
    """The innermost script behind `-EncodedCommand` (base64 of UTF-16LE), or None when there is none.

    Accepts a full command line or the bare payload. A decoding that is itself an encoded command is
    decoded again, up to `rounds` times.
    """
    return decode_layers(command_line, rounds=rounds)["decoded"]


def decode_layers(command_line: str, *, rounds: int = ROUNDS) -> Decoding:
    """Every layer of encoding, innermost decoding first reported as `decoded`.

    `rounds` is the number of decodings attempted. One layer of encoding hides the command from a
    reader; each further layer hides it from the previous decoding and costs another round to remove.
    A command still encoded when the rounds run out is reported with `capped` set: the count is the
    finding, and the remaining layers are not chased.
    """
    layers: list[str] = []
    text, decoded = command_line.strip(), None
    for round_ in range(max(0, rounds)):
        step = _decode_once(text, bare=round_ == 0)
        if step is None:
            break
        layers.append(step)
        text = decoded = step
    return Decoding(
        decoded=decoded,
        rounds=len(layers),
        layers=layers,
        capped=bool(layers) and _decode_once(text, bare=False) is not None,
    )


def _decode_once(command_line: str, *, bare: bool) -> str | None:
    """One layer. A bare payload is accepted only from the caller: a decoding must name the flag
    itself, otherwise any decoded word long enough to look like base64 would be "decoded" again."""
    text = command_line.strip()
    candidates = [match.group(1) for match in _FLAG.finditer(text)]
    if not candidates and bare and _BARE.match(text):
        candidates = [text]
    for payload in candidates:
        decoded = _utf16(payload)
        if decoded is not None:
            return decoded
    return None


def _utf16(payload: str) -> str | None:
    try:
        raw = base64.b64decode(payload + "=" * (-len(payload) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(raw) < 2 or len(raw) % 2:
        return None
    try:
        text = raw.decode("utf-16-le")
    except UnicodeDecodeError:
        return None
    return text if text.isprintable() or any(c in text for c in "\r\n\t") else None


def to_utc(timestamp: str, *, assume_zone: str = "UTC") -> str:
    """An ISO 8601 timestamp as UTC with a `Z` suffix.

    A timestamp that carries an offset is converted. One that carries none is read in `assume_zone`
    (an IANA name): UTC for API values, the analyst's zone for a time copied from a portal, which
    shows local time.
    """
    text = _FRACTION.sub(r"\1", timestamp.strip())
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        raise InvalidInputError(f"not a timestamp: {timestamp!r}") from None
    if parsed.tzinfo is None:
        try:
            parsed = parsed.replace(tzinfo=ZoneInfo(assume_zone))
        except (ZoneInfoNotFoundError, ValueError):
            raise InvalidInputError(f"unknown time zone: {assume_zone!r}") from None
    moment = parsed.astimezone(UTC).replace(tzinfo=None)
    text = moment.isoformat(timespec="microseconds" if moment.microsecond else "seconds")
    return (text.rstrip("0") if moment.microsecond else text) + "Z"
