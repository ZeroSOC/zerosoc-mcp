# Microsoft Defender XDR MCP Server

A **Model Context Protocol (MCP) server** for Microsoft Defender XDR. It lets AI agents investigate incidents, read the full evidence of an incident as one table, hunt across all Defender workloads, read Entra ID sign-in and audit logs, manage devices and query vulnerabilities, directly against the source of truth, with no telemetry duplication.

It runs on its own in any MCP host (Claude Desktop, Claude Code, VS Code, your own agent). It is a thin wrapper over the typed tool client in [`clients/defender-xdr`](../../clients/defender-xdr/): every tool is one operation of that client, so an agent and a program that calls the client directly get the same behaviour.

## Run it

Python 3.11 or later. With [uv](https://docs.astral.sh/uv/) there is nothing to install first:

```bash
# from a release tag of this repository
uvx --from "git+https://github.com/ZeroSOC/zerosoc-mcp@defender-xdr-v0.3.6#subdirectory=servers/defender-xdr" \
    --with "git+https://github.com/ZeroSOC/zerosoc-mcp@defender-xdr-v0.3.6#subdirectory=clients/defender-xdr" \
    mcp-defender-xdr

# or from a clone
uvx --from ./servers/defender-xdr mcp-defender-xdr
```

With pip, from a clone: `pip install ./clients/defender-xdr ./servers/defender-xdr` (the client first — the server depends on it), then run `mcp-defender-xdr`.

The server speaks MCP over stdio and is configured by environment variables only (see [.env.example](.env.example)).

### MCP host configuration

```json
{
  "mcpServers": {
    "defender-xdr": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/ZeroSOC/zerosoc-mcp@defender-xdr-v0.3.6#subdirectory=servers/defender-xdr",
        "--with",
        "git+https://github.com/ZeroSOC/zerosoc-mcp@defender-xdr-v0.3.6#subdirectory=clients/defender-xdr",
        "mcp-defender-xdr"
      ],
      "env": {
        "DEFENDER_TENANT_ID": "your-tenant-id",
        "DEFENDER_CLIENT_ID": "your-client-id",
        "DEFENDER_CLIENT_SECRET": "your-client-secret"
      }
    }
  }
}
```

Add `"DEFENDER_MCP_ALLOW_ACTIONS": "true"` to the `env` block to enable response actions for that host. Without credentials the server still starts and lists its tools; every call then says which variables to set.

## API surfaces

The server is **Graph-first**: XDR-level operations use the [Microsoft Graph security API](https://learn.microsoft.com/graph/api/resources/security-api-overview); endpoint-level operations use the Defender for Endpoint API, which has no Graph equivalent yet.

| API | Base | Used for |
|---|---|---|
| Microsoft Graph security API | `graph.microsoft.com/v1.0/security` | Incidents, alerts (alerts_v2, all workloads), advanced hunting (`runHuntingQuery`) |
| Microsoft Graph reporting API | `graph.microsoft.com/v1.0/auditLogs` | Entra ID sign-in log and directory audit log |
| Defender for Endpoint API | `api.securitycenter.microsoft.com/api` | Devices, response actions, live response, indicators, vulnerability management, scores, entity enrichment |

## Tools

| Group | Read | Triage writes | Response actions (gated) | Notes |
|---|---|---|---|---|
| Incidents | 5 | 2 | | list, get, resolve merges, alerts, **evidence inventory**, update, comment |
| Alerts | 2 | 2 | | alerts_v2: Endpoint, Office 365, Identity, Cloud Apps, Entra ID Protection |
| Advanced hunting | 1 | | | cross-workload KQL |
| Entra ID logs | 2 | | | sign-ins, directory audits |
| Devices | 6 | 2 | 8 | isolate, release, scan, restrict, quarantine, package, offboard |
| Machine actions | 7 | | 5 | action history, live response, investigations, library |
| Indicators | 1 | | 4 | allow, audit, warn and block lists |
| Entities | 11 | | | file, domain, IP and user enrichment |
| Vulnerabilities | 17 | | | CVEs, software inventory, recommendations, remediation |
| Scoring | 5 | | | exposure score, secure score, antivirus health |
| Helpers | 2 | | | decode `-EncodedCommand`, convert a timestamp to UTC |
| Capabilities | 1 | | | the capability probe |

Every tool that returns a collection is bounded: a conservative default and a hard ceiling. Tool parameters are `snake_case`.

### What an investigation needs first

- **`defender_get_capabilities`** answers from a probe the server runs as it starts (and again on `refresh`): which hunting tables hold data (`available`), which are exposed but `empty`, which the licence does `not_exposed`, which APIs answer, which refuse because the service is `unlicensed` or inactive in the tenant, which refuse because a permission is missing (`forbidden`), and which application permissions are granted. An empty query result can then be read for what it is: a visibility gap, a missing licence or a missing permission. The result is a ZeroSOC capability binding (see below).
- **`defender_get_incident_evidence`** returns the evidence of an incident the way the portal shows it: it pages through every alert, flattens the evidence into one row per evidence item, joins each row to its device, decodes encoded commands, gives every time in UTC, and returns `entityCount` to reconcile with the portal's evidence list (checked on a test incident: same count on every type). Where the source lists one process twice because two alerts describe it differently, the rows are linked (`instance`, `sameProcess`) and not merged, so no verdict is lost. An incident too large to read whole says so (`alertsTruncated`).
- **Writes follow merges.** A comment or an update sent to an incident that was merged into another lands on the master incident, and the result says so in `redirectedFrom`.

### Known gap: attack disruption

Automatic attack disruption actions (for example "1 account contained") are not returned by the incident, alert or machine-action APIs. Where the tenant's `DisruptionAndResponseEvents` hunting table holds data, query it; otherwise check the incident's Action center in the portal by hand and record what it shows. The probe reports which of the two applies under `probe.manual_checks`.

### Telling an entitlement from an empty table

Most hunting tables are written by ordinary traffic, so an empty answer from one means that traffic did not occur. A few are written only by a licensed feature, and for those an empty answer says nothing on its own: **the table's schema resolves at every licensing tier and the query succeeds either way**, so a tenant that lacks the feature and a tenant where the feature has not acted are indistinguishable from this API. `DisruptionAndResponseEvents` is the clearest case — it is written only when automatic attack disruption acts, which on an entitled tenant is most days not at all.

Nor can the entitlement be looked up. Where the capability arrives as a Microsoft 365 licence, `subscribedSkus` names it; where the same capability arrives as Defender for Cloud's Defender for Servers plan, it is billed per Azure resource and appears in no SKU list, so reading it would mean a different API, a different credential and a different scope.

So the deployment declares it:

```
DEFENDER_MCP_ENTITLEMENTS=endpoint_p2
```

Setting the variable states the **complete** set: an entitlement left out is stated to be absent. Leaving it unset states nothing, and the probe then reports such a source as `undeclared` — neither present nor absent — so a caller records a visibility gap and reads the portal, instead of concluding from an empty result that nothing happened. The three outcomes appear in `probe.checks` as `entitled_no_rows`, `unlicensed` and `undeclared`.

## Safe by default: response-action gating

Response actions (device isolation and release, code-execution restriction, antivirus scans, stop-and-quarantine, investigation packages, offboarding, live response, starting automated investigations, live-response library writes, and indicator create, import and delete) are **not registered** unless the deployment explicitly sets:

```
DEFENDER_MCP_ALLOW_ACTIONS=true
```

Triage writes (incident and alert status, classification, assignment, comments, device tags) stay on: they are how an agent records its work. Every tool carries MCP annotations (`readOnlyHint`, `destructiveHint`) so a host can ask for confirmation.

## Capabilities manifest and the capability probe

[capabilities.manifest.json](capabilities.manifest.json) is generated from the code. It lists the ZeroSOC capability classes this server satisfies, each with its MCP tool, the tool-client operation behind it, the permissions and the probe checks it requires; the framework data sources it can provide; and every tool with its kind and permissions.

The probe combines the manifest with what one tenant exposes and writes a binding file, `zerosoc.capabilities.json`:

```bash
export DEFENDER_TENANT_ID=... DEFENDER_CLIENT_ID=... DEFENDER_CLIENT_SECRET=...
uvx --from ./clients/defender-xdr zerosoc-defender-xdr probe --out zerosoc.capabilities.json
```

The probe only reads: one row from each hunting table and one item from each API. On a Defender for Business tenant the binding marks the hunting-backed sources unavailable, each with the reason, keeps the alert-backed sources available, and binds `telemetry.endpoint` to the evidence inventory with the note "alert evidence only". Bind the classes this technology does not satisfy (a knowledge base, a reputation service) before using the file.

## Prerequisites

A **Microsoft Entra ID app registration** with **Application** permissions (admin consent required). Grant only what the tools you use need; a read-only deployment needs none of the action permissions.

**Microsoft Graph:**
- `SecurityIncident.ReadWrite.All` (or `.Read.All` for read-only deployments)
- `SecurityAlert.ReadWrite.All` (or `.Read.All`)
- `ThreatHunting.Read.All`
- `AuditLog.Read.All` and `Directory.Read.All` for the Entra ID logs (the sign-in log needs an Entra ID P1 or P2 licence in the tenant)

**WindowsDefenderATP:**
- `Machine.Read.All`, `Machine.ReadWrite.All`
- `Machine.Isolate`, `Machine.Scan`, `Machine.RestrictExecution`, `Machine.StopAndQuarantine`, `Machine.Offboard`, `Machine.CollectForensics`, `Machine.LiveResponse`, `Library.Manage` (only if response actions are enabled)
- `Ti.Read.All` (+ `Ti.ReadWrite.All` if indicator writes are enabled)
- `Vulnerability.Read.All`, `Software.Read.All`, `RemediationTasks.Read.All`
- `Score.Read.All`, `SecurityRecommendation.Read.All`
- `Alert.Read.All`, `File.Read.All`, `Ip.Read.All`, `Url.Read.All`, `User.Read.All` (entity enrichment)

The exact permissions of each tool are in the manifest.

## Architecture

```
servers/defender-xdr/src/zerosoc_mcp_defender_xdr/
  server.py      registers one MCP tool per client operation; action gating; error translation
  __main__.py    stdio entry point, configured from the environment

clients/defender-xdr/src/zerosoc_defender_xdr/
  client.py      DefenderClient, composed of the operation groups
  operations.py  @operation: the registry the server and the manifest are built from
  transport.py   tokens per API, paging, bounded lists, retry on throttling, actionable errors
  ...            one module per API surface; evidence, decode, probe, capabilities
```

A test fails if the server imports an HTTP library or mentions an API host or path: it cannot duplicate a call.

## Development

See [CONTRIBUTING](../../CONTRIBUTING.md). Smoke-test against a non-production tenant only, with response actions disabled.

## License

Apache 2.0 (see repository [LICENSE](../../LICENSE)). The tool surface derives in part from the MIT-licensed [Defender-MCP](https://github.com/MenkW/Defender-MCP); see [NOTICE](../../NOTICE).
