# Security Policy

## Reporting a vulnerability

Do **not** open a public issue for a security vulnerability.

Report through GitHub's private vulnerability reporting on this repository
(**Security → Report a vulnerability**), or contact the maintainers directly.
Include: affected component (crate + module), reproduction steps, expected
vs actual behavior, and any proof-of-concept.

## Scope

In scope:

- The DSL parser (`quarry-dsl`) — parsing untrusted rule text
- The engine (`quarry-engine`) — scanning untrusted conversations, limits,
  budgets, witness evidence
- The trace provenance chain — tamper evidence, chain verification
- The override nonce law — single-use, scope, expiry semantics
- The CLI (`quarry-cli`) — exit codes, input handling

Out of scope for this repository (see the estate layer instead):

- Model adapter implementations (host responsibility)
- Network transport (Maddie/Iroh perimeter)
- Key management and custody infrastructure

## What we promise

- Acknowledgment within 5 business days
- No public disclosure until a fix or mitigation ships
- Credit to reporters in the fix notes (unless they prefer otherwise)

## Supported versions

The `main` branch is the only supported line during alpha. Pin the
compiler version (`compiler-7` at port time) and revalidate on every pull —
upstream's DSL may change before v1.0.0.
