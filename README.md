# ZeroSOC MCP Servers

**Model Context Protocol (MCP) servers, and the typed tool clients they wrap, for security operations.**

MCP servers are the integration layer that lets AI agents query security platforms directly — the source of truth — instead of copying telemetry into yet another data lake. This repository is the [ZeroSOC Framework](https://github.com/ZeroSOC/zerosoc-framework) community's home for MCP servers covering major security technologies that lack an official or complete one.

## Operating model

For each security technology we pick exactly one engagement mode:

| Mode | When | What we do |
|---|---|---|
| **Adopt** | An official vendor (or healthy third-party) MCP server exists and is adequate | Reference it via its package manager distribution. We never fork-and-diverge. |
| **Contribute** | A server exists but is partial | Contribute enhancements upstream, under the upstream project's license and governance. |
| **Build** | No usable server exists | Build and maintain it here — vendor-neutral, permissively licensed, production-quality. |

**Sunset policy:** when a vendor ships an official server for a technology we Build, we converge — we contribute our learnings and tests upstream, put our server in maintenance mode with a migration note, and offer to donate the codebase to the vendor. The goal is ecosystem health, not ownership.

## Coverage registry

| Technology | Mode | Status | Server / upstream |
|---|---|---|---|
| Microsoft Defender XDR | **Build** | Active | [`servers/defender-xdr`](servers/defender-xdr/) |
| Google SecOps (Chronicle) | Contribute | Planned | Official server exists but is partial; upstream contributions being scoped |
| CrowdStrike Falcon | Adopt | Evaluating | Official/third-party options under evaluation |
| Microsoft Sentinel | — | Candidate | Not yet scoped |

Want a technology covered? [Open an issue](../../issues) with the vendor, the API surface, and links to any existing MCP servers.

## One technology, two parts

Every integration built here ships as a **tool client** (`clients/<technology>/`, a typed Python library) and an **MCP server** (`servers/<technology>/`) that is a thin wrapper over it. Agents use the server from any MCP host; programs call the client directly where the path must be deterministic. Each API call is implemented once, so both see the same behaviour. Each server also ships a **capabilities manifest** and, where the technology allows it, a **capability probe** that writes a ZeroSOC capability binding file for what a given tenant exposes.

Servers run standalone. The server and its tool client are two packages in this repository, so both are named on the command line:

```bash
uvx --from "git+https://github.com/ZeroSOC/zerosoc-mcp@<tag>#subdirectory=servers/<technology>" \
    --with "git+https://github.com/ZeroSOC/zerosoc-mcp@<tag>#subdirectory=clients/<technology>" \
    <command>
```

## Quality bar

Every server built here meets the same bar:

- **Safe by default** — read tools and response/write tools are separated; destructive response actions are disabled unless explicitly enabled per deployment via an environment flag.
- **Context-friendly** — every list tool paginates with sane caps; no unbounded dumps into an agent's context window.
- **Actionable errors** — API failures surface the status and a remediation hint (e.g. the exact missing permission).
- **No secrets** — configuration via environment variables only, documented in each server's `.env.example`; required API permissions are documented per tool group.

## Servers

### [`servers/defender-xdr`](servers/defender-xdr/) — Microsoft Defender XDR

Incidents with their full evidence inventory, alerts, cross-workload advanced hunting and Entra ID logs via **Microsoft Graph**, a capability probe, plus device response actions, threat indicators, and vulnerability management via the Microsoft Defender for Endpoint API. See its [README](servers/defender-xdr/README.md) for setup, and [`clients/defender-xdr`](clients/defender-xdr/) for the tool client.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Contributions are accepted under Apache 2.0 with [DCO](https://developercertificate.org/) sign-off (`git commit -s`); there is no CLA. Taking part means keeping to the [Code of Conduct](CODE_OF_CONDUCT.md).

Please do not put real tenant data in an issue or a pull request — no device or user names, tenant identifiers, hashes or incident exports.

## Security

Found a vulnerability? **Do not open a public issue.** See [SECURITY.md](SECURITY.md) for private reporting and what is in scope.

## License

[Apache 2.0](LICENSE). Portions derived from MIT-licensed prior work — see [NOTICE](NOTICE).
