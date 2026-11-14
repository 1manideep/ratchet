# Security policy

Ratchet is an authorization broker, so a way around its guarantees is a security bug. Please report it
privately, not in a public issue.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting: this repository's **Security** tab, then **Report a
vulnerability**. Include the package and version, what you did, and what Ratchet allowed that it should not
have. A minimal script that shows it is ideal.

Fixes ship as a patch release with a GitHub security advisory, crediting you unless you prefer otherwise.

## In scope

Anything that breaks the invariant that a delegated token can only narrow, in any `ratchet-authz-*` package:

- a token widened through `attenuate()` or `exchange()`, or a caveat stripped
- a forged or mutated token accepted, or signature verification bypassed
- a revoked, expired or replayed token accepted, or one used off the workload it is bound to
- the delegation depth limit bypassed
- the audit log altered without the hash chain showing it

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |
