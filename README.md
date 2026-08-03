# Vauxl Matrix Server (MVP)

This repository hosts the Matrix-first server strategy for Vauxl.

## MVP Goals
- Deploy a compliant Matrix homeserver baseline (fork or implementation path).
- Provide authentication, room state, federation basics, and media service compatibility.
- Keep all Vauxl features as additive, namespaced, and documented extensions.

## Non-Goals (MVP)
- Breaking Matrix client interoperability.
- Undocumented proprietary event formats.

## Structure
- `crates/` Cargo workspace with the server binary, Matrix client API, and cryptographic primitives
- `migrations/` PostgreSQL schema and committed SQLx metadata for offline builds
- `config/` runtime configuration defaults
- `docker/` dev compose stack and Dockerfiles
- `scripts/` local development and quality checks
- `docs/` extension and operations docs

## Extension Policy
All custom events/capabilities use the `org.vauxl.*` namespace and include discovery/fallback behavior.
