# zerosoc-abuseipdb

A typed Python client for [AbuseIPDB](https://www.abuseipdb.com), for programs whose path must be
deterministic: an address's reputation, with a cache and the plan's quota, and the blacklist synced
to a local store and matched with no request.

Agents should use AbuseIPDB's own MCP server, [`mcp-server-abuseipdb`](https://github.com/AbuseIPDB/AbuseIPDB-MCP).
This repository adopts it rather than building another (see the coverage registry in the root
README). This client is for hosts that call AbuseIPDB from code.

## What it does, and never does

- **`check(ip, max_age_in_days=90)`** answers what AbuseIPDB knows of one address:
  - the abuse confidence score (0–100: one source's reading, not a count of engines);
  - total reports and distinct reporters in the window;
  - report counts per AbuseIPDB category ("Brute-Force", "SSH", …);
  - country, network operator, domain, usage type and host names;
  - whether it is a Tor exit or on AbuseIPDB's allowlist.
- **Only one bare public address is ever sent.** A private, shared, reserved or multicast address, a
  range, a URL, a host name or an address with a port is refused before any request.
- **No report comment is returned.** Anyone can write one, so it can say anything, including
  instructions for whoever reads it. The kinds of abuse are counted from the reports' categories
  instead.
- **No service text is passed on.** A failure is an `AbuseIPDBError` with a code (`unauthorized`,
  `plan`, `quota`, `unavailable`, `timeout`, …) and the client's own sentence.
- **Answers are cached** for an hour per address and window, since each check spends one of the
  plan's daily checks. `client.quota` holds the limit, the remaining checks and the reset time as
  the last answer stated them.
- **`sync_blacklist(store, confidence_minimum=75, limit=10_000)`** downloads the blacklist into a
  `BlacklistStore`. That is one JSON file the host names, written whole, so a failed sync keeps the
  last good copy. `store.lookup(ip)` answers from the file with no network call. AbuseIPDB
  regenerates the list hourly and a plan allows a number of downloads a day, so a daily sync is the
  usual schedule.

```python
from zerosoc_abuseipdb import AbuseIPDBClient, BlacklistStore

# base_url= points it at any endpoint that answers in AbuseIPDB's shape
client = AbuseIPDBClient(key)
store = BlacklistStore("/var/lib/host/abuseipdb-blacklist.json")
if (listed := store.lookup("203.0.113.9")) is None:
    result = await client.check("203.0.113.9")
```

The key is the caller's. Keep it out of code and logs. The free plan is for non-commercial use; see
AbuseIPDB's terms for the plan behind your key.

## Development

Part of the [ZeroSOC MCP workspace](../../README.md): `make sync`, `make check`, `make test` at the
root. The tests use a scripted HTTP transport and need no key and no network.
