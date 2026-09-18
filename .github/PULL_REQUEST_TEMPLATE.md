## What this changes

<!-- The behaviour that differs, in one or two sentences. -->

## Why

<!-- The problem. Link the issue if there is one. -->

## How it was checked

<!-- `make ci` is the floor. If you smoke-tested against a tenant, say which
     kind (non-production, actions disabled) — not which tenant. -->

## Checklist

- [ ] `make ci` passes
- [ ] Commits are signed off (`git commit -s`) — see [CONTRIBUTING.md](../CONTRIBUTING.md)
- [ ] Conventional Commits subject, scoped to the server or client
- [ ] No real tenant data: no device or user names, tenant or subscription
      identifiers, hashes or incident exports, in code, tests or this description
- [ ] A new write or destructive action is gated behind the deployment's
      action flag and carries the right MCP annotation
- [ ] New collection-returning tools are bounded (default and hard ceiling)
- [ ] `CHANGELOG.md` updated, and the version bumped in both packages if this is a release
- [ ] `make manifest` re-run if the tool surface changed
