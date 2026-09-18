# Contributing

Thanks for helping build MCP servers for security operations.

Found a security problem? **Do not open an issue** — see [SECURITY.md](SECURITY.md).
By taking part you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## Ground rules

- **License & DCO** — contributions are accepted under [Apache 2.0](LICENSE) with [Developer Certificate of Origin](https://developercertificate.org/) sign-off. Add `Signed-off-by` with `git commit -s`. No CLA.
- **Conventional Commits** — `feat:`, `fix:`, `docs:`, `chore:` etc., scoped to the server when relevant (e.g. `feat(defender-xdr): add incident comments tool`).
- **One technology, two packages** — the tool client lives under `clients/<technology>/`, the MCP server that wraps it under `servers/<technology>/`; they are versioned together (semver) and released under a `<technology>-v<version>` tag.
- **Check the operating model first** — before proposing a new server, check the [coverage registry](README.md#coverage-registry). If an official vendor server exists (Adopt) or a partial one exists (Contribute), we work upstream instead of building here.

## Quality bar (enforced in review)

1. **Safe by default.** Destructive response actions (device isolation, quarantine, offboarding, indicator writes, …) must be behind an opt-in environment flag and not registered when the flag is off. Metadata writes used in routine triage (e.g. updating an incident's classification) may stay always-on, but must be clearly described as writes in the tool description.
2. **Pagination everywhere.** Every list tool takes a result cap with a conservative default. Never return unbounded result sets.
3. **Actionable errors.** Surface the HTTP status, the API's error message, and — for 401/403 — the permission likely missing.
4. **No secrets.** Configuration comes from environment variables, documented in the server's `.env.example` and README (including the exact API permissions required per tool group). Never commit `.env`, tokens, tenant IDs, or real hostnames.
   This holds for issues and pull requests too: no incident exports, device or user
   names, or hashes from a real estate. Tests use the synthetic fixtures under
   `clients/*/tests/fixtures/`.
5. **Tool descriptions are for agents.** Write them so an LLM can pick the right tool without trial and error: state what the tool returns, its scope, and when to prefer a sibling tool.

## Development

The repository is a [uv](https://docs.astral.sh/uv/) workspace: tool clients under `clients/<technology>/`, MCP servers under `servers/<technology>/`. A server imports its client and holds no API code of its own, so an agent and a program get the same behaviour from one implementation.

```bash
make sync     # uv sync
make check    # format check, lint, types, security lint
make test     # the whole suite, no network and no tenant needed
make manifest # regenerate the capabilities manifest after changing the tool surface
make ci       # what CI runs, including the manifest check
uv run mcp-defender-xdr   # run a server from source
```

Tests come first and run against a scripted HTTP transport; nothing in the suite reaches a tenant. Smoke-test against a **non-production tenant only**, with response actions disabled.


## Releasing

Both packages of a technology carry the same version. A release bumps the version
in `clients/<technology>/pyproject.toml` and `servers/<technology>/pyproject.toml`,
**and the server's dependency pin on its client**, re-runs `uv lock` and
`make manifest`, adds a `CHANGELOG.md` entry, and is tagged
`<technology>-v<version>`. `make ci` fails if the manifest was not regenerated, and
the `documented-install` job fails if the command the README prints does not resolve.
