# Changelog

## Unreleased

**Added**
- `defender_get_disruption_events` reads the `DisruptionAndResponseEvents` hunting table for a time
  window, for one device or one account, newest first and bounded, so what automatic attack
  disruption did is read without anyone writing the query. The table records the outcomes of a
  containment (blocked logons, blocked file and RPC access, disconnected sessions, policy
  applications) and never the containment itself, so an empty answer says that it is not evidence
  that nothing was contained, names the portal's Action center as the record of the action, and
  carries what the deployment declared about the entitlement that writes the table. No API returns
  the disruption actions themselves: the machine-action types are the manual ones, alert evidence
  carries the automated investigation's state, and the incident carries a tag. The check was made
  against the vendor's current reference pages before this was written.
- Each entry of `probe.manual_checks` carries the tool that automates it, the status of the check
  behind it, and `required`: whether the portal must be read by hand regardless. For attack
  disruption that is whenever the table holds no rows and the deployment did not state the feature
  absent, because then nothing readable says whether it acted. The check was previously reported as
  `automated` on a declared entitlement with an empty table, which read as "nothing to do".
- A data source may name the checks it needs all of (`all_of`) beside the ones any of which
  suffice (`any_of`).
- Identity and mailbox containment, the three response actions an incident that reaches an account
  needs and the reads that decide them: `entra_revoke_sign_in_sessions`, `entra_disable_account`
  with `entra_enable_account` as its rollback, and `mailbox_delete_inbox_rule` with
  `mailbox_create_inbox_rule` as its rollback, beside `entra_list_users`, `entra_get_user`,
  `mailbox_list_inbox_rules` and `mailbox_get_inbox_rule`. Each action is reversible or recoverable
  — the sessions come back by signing in, the account by being enabled, the rule by being put back
  from what was read — which is what lets one run under an approval rather than a change window.
  Removal destroys an inbox rule and the service keeps no copy, so the surface reads a rule before
  anything deletes one and restores exactly what it read, minus the fields the service owns.
  All five actions are behind `DEFENDER_MCP_ALLOW_ACTIONS`, the rollbacks included.
- The capability classes `containment.suspend_sessions`, `containment.disable_account` and
  `containment.remove_inbox_rule`, each bound only where the directory answers *and* the tenant
  granted a permission that acts: `User.RevokeSessions.All` or `User.ReadWrite.All`,
  `User.EnableDisableAccount.All` or `User.ReadWrite.All`, `Mail.ReadWrite`. The probe asks the
  directory one bounded question (`api:graph.users`), so a tenant whose app registration reads
  security data and nothing else binds none of them and says which permission is missing.
- `update_incident` writes `severity`, `resolvingComment` and `description` alongside the status,
  classification and determination it already wrote. All three are documented as writable and none
  carried a documented limit; these were measured against a live incident — a ladder of lengths,
  each write read back, so a value stored short is told apart from one stored whole. An executor
  that resolves an incident can now leave the record agreeing with itself in one write: the
  severity it decided, why it classified as it did, and an account a reader sees without leaving
  the incident page.

**Changed**
- The binding names the source profile of this technology under `source_profiles`
  (`zerosoc-defender-xdr/source_profile.json`) and no longer carries `alert_type_map`. The skills
  moved the alert-type rules into the source profile and retired the field, and the name the
  binding now carries is one the skills' loader resolves beside the binding or beside the installed
  skills, so a freshly probed deployment reads its alert-type rules with nothing copied by hand.
  The `alert_type_map` field named a file the probe never emitted.

**Fixed**
- "Threat-intel / reputation enrichment (hash, IP, domain)" was reported unavailable although
  `malware.repository` was bound to `defender_get_file_info`, which answers for a hash. It is now
  available where the endpoint API answers and `File.Read.All` is granted, with a note that it is
  file reputation by hash only and that address and domain reputation are not covered, so a
  consumer neither reports a gap the deployment does not have nor expects a verdict on an address.
- `resolvingComment` past 30,000 characters is refused rather than sent. The API answers 200 and
  keeps the first 30,000, so a caller was told the write succeeded and lost the tail without
  anything saying so. `description` has no bound worth stating — a megabyte is accepted and read
  back whole — and is a whole-value replace over the product's own text, which its description now
  says.

## defender-xdr 0.3.7 (2026-09-21)

**Added**
- `DefenderClient.incident_record(id)`: the **data plane** of an incident — the master after the
  merge chain, with every alert, in one `$expand=alerts` whose own paging is followed once. No
  `top`, no `skip`, no summary: a reader that maps an incident to a record needs all of it, at one
  instant, and is not billed by the token. It is not an MCP tool; the agent's surface is unchanged.

**Fixed**
- The walk of the alert expansion was bounded only by the number of alerts read, which stops it
  only while each page carries some: a page answering with none and still offering a next link was
  followed forever. The walk now stops at `MAX_ALERT_PAGES` as well, and reports it as it reports
  the alert ceiling.

**Changed**
- `defender_get_incident_alerts` and `defender_get_incident_evidence` page and summarize *that*
  record instead of expanding the incident again. A reader that paged a 60-alert incident fifty at
  a time previously paid one complete expansion per page, and two pages could disagree because they
  were two reads of a live incident. One API call is still implemented once: the agent-plane
  operation calls the data-plane method rather than reimplementing it.

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
