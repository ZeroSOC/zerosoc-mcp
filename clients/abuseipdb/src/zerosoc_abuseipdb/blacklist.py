"""AbuseIPDB's blacklist, held locally: synced on a schedule, matched with no request.

AbuseIPDB regenerates its blacklist every hour: the addresses with the most reports above a
confidence threshold. A host syncs it into a store it names and looks addresses up there, so an
address on the list costs no query of the plan and tells AbuseIPDB nothing about who asked.

The store is one JSON file written whole: a new copy replaces the old one only once it has been
read and written in full, so a sync that fails keeps the last good copy. It says when it was synced
and when AbuseIPDB generated the list, which is how fresh an answer read from it is.
"""

from __future__ import annotations

import ipaddress
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

FORMAT = "zerosoc-abuseipdb-blacklist"
VERSION = 1


@dataclass(frozen=True)
class BlacklistEntry:
    ip: str
    score: int
    country_code: str | None
    last_reported_at: str | None


@dataclass(frozen=True)
class Synced:
    """What a sync wrote."""

    count: int
    skipped: int
    """Entries the list held that were not addresses, left out rather than failing the sync."""
    generated_at: str | None
    synced_at: int
    """When the store was written, in milliseconds since the epoch."""
    confidence_minimum: int


def _address(value: Any) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


class BlacklistStore:
    """The local copy of the blacklist, in one file the host names."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self._entries: dict[str, BlacklistEntry] = {}
        self.generated_at: str | None = None
        self.synced_at: int | None = None
        self.confidence_minimum: int | None = None
        self._load()

    @property
    def count(self) -> int:
        return len(self._entries)

    def lookup(self, ip: str) -> BlacklistEntry | None:
        """The entry for this address, or None when it is not listed (or is not an address)."""
        key = _address(ip)
        return self._entries.get(key) if key is not None else None

    def _load(self) -> None:
        try:
            held = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return  # absent or unreadable: an empty store, never a trusted one
        if not isinstance(held, dict) or held.get("format") != FORMAT:
            return
        entries: dict[str, BlacklistEntry] = {}
        for ip, (score, country, reported) in (held.get("entries") or {}).items():
            entries[ip] = BlacklistEntry(ip, int(score), country, reported)
        self._entries = entries
        self.generated_at = held.get("generated_at")
        self.synced_at = held.get("synced_at")
        self.confidence_minimum = held.get("confidence_minimum")

    def replace(
        self, data: Any, *, generated_at: str | None, confidence_minimum: int, synced_at: int
    ) -> Synced:
        """Write the list as AbuseIPDB answered it, whole, in place of the current copy."""
        entries: dict[str, BlacklistEntry] = {}
        skipped = 0
        for item in data:
            ip = _address(item.get("ipAddress")) if isinstance(item, dict) else None
            if ip is None:
                skipped += 1
                continue
            entries[ip] = BlacklistEntry(
                ip,
                int(item.get("abuseConfidenceScore") or 0),
                item.get("countryCode") or None,
                item.get("lastReportedAt") or None,
            )
        document = {
            "format": FORMAT,
            "version": VERSION,
            "generated_at": generated_at,
            "synced_at": synced_at,
            "confidence_minimum": confidence_minimum,
            "entries": {
                ip: [e.score, e.country_code, e.last_reported_at] for ip, e in entries.items()
            },
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle, temporary = tempfile.mkstemp(dir=self.path.parent, prefix=".blacklist-")
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as out:
                json.dump(document, out, separators=(",", ":"))
            os.replace(temporary, self.path)
        except BaseException:
            Path(temporary).unlink(missing_ok=True)
            raise
        self._entries = entries
        self.generated_at, self.synced_at = generated_at, synced_at
        self.confidence_minimum = confidence_minimum
        return Synced(len(entries), skipped, generated_at, synced_at, confidence_minimum)
