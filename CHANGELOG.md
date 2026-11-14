# Changelog

Notable changes to the `ratchet-authz-*` packages. Versions follow [Semantic Versioning](https://semver.org/).

## 0.1.0 (unreleased)

The first public release.

- `ratchet-authz-core`: macaroon-style capability tokens whose caveats can only narrow at each delegation hop;
  sender-constrained, workload-bound tokens (Ed25519 workload identity); a model-independent policy enforcement
  point (`Broker.authorize()`); a hash-chained audit log; revocation that cascades to descendant tokens; and a
  `max_depth` caveat bounding delegation chains.
- A token is accepted only in the one string `serialize_token()` writes for it: other JSON spellings of
  the same token (spacing, key order, a float written differently) are refused, like non-canonical base64.
- Adapters: `ratchet-authz-langgraph`, `ratchet-authz-crewai`, `ratchet-authz-autogen` and `ratchet-authz-mcp`.
- Published as `ratchet-authz-*` because `ratchet-core` on PyPI is an unrelated project. The import names are
  unchanged (`import ratchet_core`, and so on), and every adapter pins `ratchet-authz-core>=0.1,<0.2`.
