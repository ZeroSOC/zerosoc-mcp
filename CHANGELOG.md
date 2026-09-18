# Changelog

## defender-xdr 0.3.6 (2026-09-18)

First release from the public repository.

**Fixed**
- The server's dependency on the tool client named `0.3.4` while both packages were `0.3.5`, so a
  real install of the server could not resolve. The workspace lockfile pins the client as an
  editable path and never saw the mismatch; `make ci` now regenerates the capabilities manifest and
  fails on any difference, which is the check that was missing.
- The documented `uvx` command built the server subdirectory alone, which then looked for the tool
  client on an index that does not carry it. Both commands now name the client with `--with`, and CI
  runs the exact command the README prints.

## defender-xdr 0.3.5 (2026-09-17)

**Changed**
- An encoded command whose decoding is itself an encoded command is decoded again, up to **five
  rounds**. Process rows carry `decode_rounds` when more than one layer was removed and
  `decode_capped` when the command was still encoded after the fifth, and `defender_decode_command`
  returns `rounds`, `layers` and `capped` beside the decoding. The layers are a fact for the method
  to weigh: one hides the command from a reader, each further one is a deliberate choice, and a
  command still encoded after five rounds is chasing the reader's time rather than hiding anything.
  Checked on a test incident: 3 of its 25 commands are double-encoded.
- A later round accepts only a payload that names the flag. A bare base64 payload is still accepted
  from the caller, but a decoded word that merely looks like base64 is no longer "decoded" again
  into nonsense.

## defender-xdr 0.3.4 (2026-09-17)

Checked on a test tenant with full endpoint telemetry: the probe binds `telemetry.endpoint`,
`telemetry.network` and `siem.search` to the hunting tool and marks the endpoint sources available;
all 30 processes of a test incident's evidence were found in the raw telemetry by PID and UTC
creation time.

**Changed**
- `defender_run_hunting_query` tells the agent that the sensor records no creation event for some
  processes, which then appear only as the initiating process of other events (5 of 30 on the test
  incident), and to match a process by PID together with its creation time.

## defender-xdr 0.3.3 (2026-09-17)

The evidence inventory reconciles with the portal, checked on a test incident of 32 alerts and 143
evidence rows against the portal's evidence list and its process export: 37 items, the same on
every type, the 20 process rows identical one by one.

**Changed**
- A row of the inventory is the source's own evidence item. Identity is exact: every identifying
  field must be equal, and a missing hash is a difference. No looser rule reproduces the portal. It
  is the identity of the ZeroSOC skills' `evidence_inventory.py`, so the count is the same at both
  layers.
- Reverts the merging added in 0.3.0 (rows lacking a hash; users, mailboxes and devices by any shared
  identifier) and in 0.3.1 (processes by device, PID and creation time; paths without their volume).
  Each made the count fall short of the portal, and merging two rows of one process hid one of two
  different verdicts.
- Rows of one process are linked instead: they share `instance`, `sameProcess` groups them with
  their names and verdicts, and `processInstanceCount` is the number of real processes.

## defender-xdr 0.3.2 (2026-09-17)

Found by probing a second test tenant: every permission granted, the endpoint service inactive.

**Changed**
- The probe reports a refusal that no permission would lift as `unlicensed` ("Account mode is
  inactive", "No Tvm license", "doesn't have premium license"), apart from `forbidden`, which now
  means a missing or unconsented permission only. The binding's notes say "is not licensed in this
  tenant".

## defender-xdr 0.3.1 (2026-09-17)

Found by running the evidence inventory against a test tenant.

**Fixed**
- A process is identified by its device, PID and creation time. The source writes the same folder as
  an NT device path (`\Device\HarddiskVolume2\...`) in one alert and as a drive path (`C:\...`) in
  the next, which counted one process twice.
- A process that one alert reports without its image file is merged with its named twin and takes
  its name.
- Files compare their paths without the volume prefix, for the same reason.

## defender-xdr 0.3.0 (2026-09-17)

The Defender XDR integration is now two parts for one technology: a typed **tool client**
(`clients/defender-xdr`, Python) and the **MCP server** (`servers/defender-xdr`) as a thin wrapper over
it. Every MCP tool is one client operation; the server holds no API code.

**Breaking**
- The server is a Python package (`zerosoc-mcp-defender-xdr`, command `mcp-defender-xdr`, run with
  `uvx` or pip) and replaces the Node.js package. Tool names are unchanged.
- Tool parameters are `snake_case` (`incident_id`, `machine_id`, `summary_only`, ...).
- `defender_get_live_response_result` takes `action_id` and `command_index` (the documented call).

**Added**
- `defender_get_incident_evidence`: the full evidence inventory of an incident, one row per entity,
  de-duplicated, joined to its device, with the count to reconcile against the portal.
- `defender_get_capabilities` and `zerosoc-defender-xdr probe`: the capability probe, which writes a
  ZeroSOC capability binding file for what the tenant exposes.
- `defender_resolve_incident`; incident comments and updates follow a merged incident to its master.
- `defender_decode_command` and `defender_to_utc`: deterministic helpers.
- `entra_list_sign_ins` and `entra_list_directory_audits`.
- `capabilities.manifest.json`, generated from the code.
- MCP tool annotations (read-only, destructive); retry on throttling (a write is never sent twice);
  every collection bounded, by the client where the API returns it whole.
- The server probes the tenant as it starts.

**Fixed**
- Identifiers are encoded as URL path segments.
- `defender_find_machines_by_tag`, `defender_upload_library_file`, `defender_get_device_health` and
  `defender_export_antivirus_health` make the documented API calls.
- List tools that had no ceiling now have one.

**Removed**
- Editor configuration that pointed at a local path.
