.PHONY: sync format lint typecheck security audit test manifest manifest-check check ci

sync:
	uv sync --locked

format:
	uv run ruff format .

lint:
	uv run ruff format --check .
	uv run ruff check .

typecheck:
	uv run mypy

security:
	uv run bandit -q -r clients/defender-xdr/src servers/defender-xdr/src

audit:
	uv export --locked --no-dev --no-emit-workspace -o requirements-audit.txt -q
	uv run pip-audit -r requirements-audit.txt --disable-pip --require-hashes

manifest:
	uv run zerosoc-defender-xdr manifest --out servers/defender-xdr/capabilities.manifest.json

# The manifest in the tree is generated from the code; a release that forgets to
# regenerate it must fail here rather than in a test nobody reads. Compares the
# file, not the git index, so it behaves the same in a dirty tree and in CI.
manifest-check:
	@tmp=$$(mktemp -t capabilities.manifest.XXXXXX.json); \
	trap 'rm -f "$$tmp"' EXIT; \
	uv run zerosoc-defender-xdr manifest --out "$$tmp" >/dev/null; \
	diff -u servers/defender-xdr/capabilities.manifest.json "$$tmp" \
	  || { echo "capabilities.manifest.json is stale: run 'make manifest'"; exit 1; }

test:
	uv run pytest

check: lint typecheck security

ci: check manifest-check test
