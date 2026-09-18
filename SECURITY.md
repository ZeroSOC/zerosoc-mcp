# Security Policy

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Report it through GitHub's private vulnerability reporting on this repository:
**Security → Report a vulnerability**. That channel is private to the maintainers
until a fix is published.

Please include the affected server or tool client and version, what an attacker
can do, and the smallest reproduction you have. If a proof of concept touches a
tenant, describe it rather than attaching real telemetry — see *Do not send us
tenant data* below.

We aim to acknowledge a report within 5 working days, and to agree a disclosure
timeline with you before anything is published. Credit is given unless you ask
otherwise.

## What is in scope

These servers hold Microsoft Entra ID application credentials and, when a
deployment enables it, can take destructive response actions on devices. In
scope:

- Credential handling: a client secret reaching a log, an error, a tool result,
  a crash dump or a cached artefact.
- **Response-action gating**: any way to reach a gated response action without
  `DEFENDER_MCP_ALLOW_ACTIONS=true`, or any action registered that the tool
  annotations declare read-only. See the gating section of the
  [server README](servers/defender-xdr/README.md).
- Privilege or tenant confusion: a call that reads or writes outside the tenant
  the credentials belong to.
- Prompt-injection paths where content fetched from a tenant can drive the
  server into an unintended write.
- Dependency or supply-chain problems in the published packages.

Out of scope: vulnerabilities in Microsoft's APIs themselves (report those to
Microsoft), and findings that require an attacker who already holds the
deployment's client secret.

## Do not send us tenant data

Never attach real incident exports, evidence tables, hunting results, device
names, user principal names or tenant identifiers to a report, an issue or a
pull request. Describe the shape of the data instead, or reduce it to the
synthetic fixtures under `clients/*/tests/fixtures/`.
