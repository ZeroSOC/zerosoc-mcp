"""`zerosoc-defender-xdr`: the deterministic entry points, without an agent.

  zerosoc-defender-xdr probe [--out zerosoc.capabilities.json]     probe the tenant, write the binding
  zerosoc-defender-xdr evidence INCIDENT_ID [--out evidence.json]  the evidence rows of an incident
  zerosoc-defender-xdr manifest [--out capabilities.manifest.json] the capabilities manifest (no tenant)

Credentials come from DEFENDER_TENANT_ID, DEFENDER_CLIENT_ID and DEFENDER_CLIENT_SECRET.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

from .auth import CREDENTIAL_VARIABLES, ClientSecretCredential, credential_from
from .client import DefenderClient
from .errors import DefenderApiError
from .manifest import manifest

PAGE = 1000


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="zerosoc-defender-xdr",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("probe", "manifest", "evidence"):
        command = commands.add_parser(name)
        command.add_argument("--out", type=Path, help="write here instead of standard output")
        if name == "evidence":
            command.add_argument("incident_id")
    arguments = parser.parse_args(argv)

    if arguments.command == "manifest":
        return _emit(manifest(), arguments.out)
    credential = credential_from(os.environ)
    if credential is None:
        print(f"set {', '.join(CREDENTIAL_VARIABLES)}", file=sys.stderr)
        return 2
    try:
        return _emit(asyncio.run(_run(arguments, credential)), arguments.out)
    except DefenderApiError as error:
        print(error, file=sys.stderr)
        return 1


async def _run(arguments: argparse.Namespace, credential: ClientSecretCredential) -> Any:
    client = DefenderClient(credential)
    try:
        if arguments.command == "probe":
            return await client.get_capabilities()
        return await _evidence_rows(client, arguments.incident_id)
    finally:
        await client.aclose()


async def _evidence_rows(client: DefenderClient, incident_id: str) -> list[dict[str, Any]]:
    """Every page of the inventory, as the plain list of rows the skills' script takes."""
    rows: list[dict[str, Any]] = []
    while True:
        page = await client.get_incident_evidence(incident_id, top=PAGE, skip=len(rows))
        rows.extend(page["entities"])
        if not page["hasMore"]:
            break
    print(
        f"incident {page['incidentId']}: {page['entityCount']} entities from {page['rowCount']}"
        f" evidence rows in {page['alertCount']} alerts"
        + (" (TRUNCATED: not the whole incident)" if page["alertsTruncated"] else ""),
        file=sys.stderr,
    )
    return rows


def _emit(document: Any, out: Path | None) -> int:
    text = json.dumps(document, indent=2, ensure_ascii=False) + "\n"
    if out is None:
        sys.stdout.write(text)
    else:
        out.write_text(text, encoding="utf-8")
        print(f"wrote {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
