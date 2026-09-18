# Microsoft Defender XDR tool client

A typed, asynchronous Python client for Microsoft Defender XDR: the Microsoft Graph security API, the Defender for Endpoint API and the Entra ID sign-in and audit logs. It is the single implementation of every API call in this integration. The [MCP server](../../servers/defender-xdr/) wraps it for agents; programs call it directly for the paths that must be deterministic: polling, write-back, containment and its rollback, the capability probe, bulk data pulls.

```python
from zerosoc_defender_xdr.auth import ClientSecretCredential
from zerosoc_defender_xdr.client import DefenderClient

client = DefenderClient(ClientSecretCredential(tenant_id, client_id, client_secret))

page = await client.list_incidents(filter="lastUpdateDateTime gt 2026-09-01T00:00:00Z", top=50)
evidence = await client.get_incident_evidence("14")  # every entity, once, joined to its device
await client.add_incident_comment("17", "Triage note ...")  # lands on the master if 17 was merged
binding = await client.get_capabilities()  # what this tenant exposes
```

- **Credentials.** Any object with `async get_token(*scopes)` returning `.token` and `.expires_on` works, which is the shape of the asynchronous credentials of the Azure identity library: a managed identity, a certificate credential or your own token service can be passed in unchanged. `ClientSecretCredential` is the dependency-free default.
- **Safe by default.** Response actions raise `ActionsDisabledError` unless the client is created with `allow_actions=True`.
- **Bounded.** Every operation that returns a collection has a default and a ceiling; where the API returns a collection whole, the client cuts it and reports `total` and `hasMore`. Throttling (429) is retried with the delay the service asks for; a 503 is retried for reads only, so a write or an action is never sent twice. A next link is followed only on the API's own host, so a bearer token goes nowhere else.
- **Actionable errors.** Bad arguments raise `InvalidInputError`. `DefenderApiError` carries the status, the API, the call, the service's message and, for 401 and 403, the permission likely missing.
- **Pure parts are importable on their own:** `evidence.inventory(alerts)`, `decode.decode_encoded_command(line)`, `decode.to_utc(timestamp)`, `manifest.manifest()`.

## Command line

```bash
zerosoc-defender-xdr probe --out zerosoc.capabilities.json   # probe the tenant, write the binding
zerosoc-defender-xdr evidence 14 --out evidence.json         # every row, as the list the skills' evidence_inventory.py takes
zerosoc-defender-xdr manifest                                # the capabilities manifest, no tenant needed
```

Credentials come from `DEFENDER_TENANT_ID`, `DEFENDER_CLIENT_ID` and `DEFENDER_CLIENT_SECRET`.

## Adding an operation

Add a method to the matching group and decorate it with `@operation(tool=..., api=..., kind=..., permissions=...)`. The docstring is the MCP tool description: write it for an agent. Add its row to `tests/test_operations.py`; the suite fails until you do. The server picks it up with no change.
