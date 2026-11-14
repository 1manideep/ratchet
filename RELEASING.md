# Releasing

Releases are built and uploaded from a maintainer's machine. Work happens on `dev`; a release is `dev` merged
into `main`, tagged and published.

1. On `dev`, set the new version in every `packages/*/pyproject.toml` (they release together), add it to
   `CHANGELOG.md`, and run the checks CI runs:

   ```bash
   uv sync --group dev
   uv run ruff check . && uv run ruff format --check . && uv run mypy
   uv run --package ratchet-authz-core pytest packages/ratchet-core/tests/ -q
   for e in langgraph crewai autogen mcp; do uv run python examples/${e}_example.py; done
   ```

2. Merge `dev` into `main` (a pull request), and check out `main`.

3. Build and upload all five packages:

   ```bash
   rm -rf dist && uv build --all-packages --out-dir dist
   uv publish dist/*        # a PyPI API token in UV_PUBLISH_TOKEN
   ```

   Keep the token out of the shell history and out of files: put it in the macOS Keychain once
   (`security add-generic-password -U -s pypi-ratchet -a "$USER" -w`) and read it for the upload:
   `UV_PUBLISH_TOKEN="$(security find-generic-password -s pypi-ratchet -a "$USER" -w)" uv publish dist/*`.

4. On GitHub: Releases, then Draft a new release. Tag `vX.Y.Z` on `main`, the version's `CHANGELOG.md`
   section as the notes, then Publish.
