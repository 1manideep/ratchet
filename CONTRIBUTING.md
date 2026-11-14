# Contributing to Ratchet

Thanks for considering a contribution. This is a young project (v0.1) with
a security-sensitive core, so a few ground rules keep it trustworthy.

## Development setup

```bash
git clone <this-repo>
cd ratchet
uv sync --group dev
```

## Before opening a PR

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run --package ratchet-authz-core pytest packages/ratchet-core/tests/ -v
```

All four must pass. CI runs the same checks on every PR.

## Where things live

- **`packages/ratchet-core/`** — the security-critical core (identity,
  tokens, broker/PEP, audit, revocation). Changes here need the most
  scrutiny: new caveat types, changes to the signature-chaining scheme, or
  changes to the narrowing rules in `caveats.check_narrowing()` should come
  with new test cases in `tests/test_attacks.py` or `tests/test_tokens.py`,
  not just a passing existing suite.
- **`packages/ratchet-{langgraph,crewai,autogen,mcp}/`** — thin adapters.
  No authorization logic should live here; they only translate a
  framework's native call shape into `ratchet_core.ProposedToolCall` and
  translate the `Decision` back into that framework's idiom. If you find
  yourself adding a caveat check or a narrowing rule inside an adapter,
  it belongs in `ratchet-core` instead.
- **`examples/`** — one runnable script per framework. If you change an
  adapter's public API, update the matching example and re-run it.
- **`benchmarks/reproduce_paper_numbers.py`** — not a CI gate (numbers are
  machine-dependent); if you touch anything in the authorization hot path
  (`Broker.authorize`, `Broker.exchange`, signature verification), run it
  manually and mention the before/after numbers in your PR description.

## Adding a new caveat type or changing narrowing rules

This is the part of the codebase where a subtle bug is a security bug.
Any change to `ratchet_core.caveats` should:

1. Add or update a factory function (`*_caveat(...)`) and, if it's an
   action caveat, a case in `evaluate_caveat()`.
2. Add a narrowing rule to `check_narrowing()` — default to rejecting
   anything you haven't explicitly reasoned about (fail closed).
3. Add at least one test proving the narrowing rule actually rejects a
   widening attempt, not just that it accepts a narrowing one.

## Reporting a security issue

Please do **not** open a public GitHub issue for a suspected vulnerability
in the broker itself (a way to bypass `authorize()`, forge a token, or
escalate scope). Instead, open a private security advisory on GitHub
(Security tab → "Report a vulnerability") so it can be fixed before
disclosure.

## Code style

Enforced by `ruff format` / `ruff check` / `mypy` in CI — see
[README.md](README.md) for the broader design conventions (type hints on
every function, fail-closed error handling, no bare `except:`).
