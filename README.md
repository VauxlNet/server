# Vauxl Matrix Server (MVP)

This repository hosts the Matrix-first server strategy for Vauxl.

See [federation security and supported behavior](docs/FEDERATION_SECURITY.md) for
the implemented checks, validation commands, and current interoperability and
existing-data limitations.

## MVP Goals
- Deploy a compliant Matrix homeserver baseline (fork or implementation path).
- Provide authentication, room state, federation basics, and media service compatibility.
- Keep all Vauxl features as additive, namespaced, and documented extensions.

## Non-Goals (MVP)
- Breaking Matrix client interoperability.
- Undocumented proprietary event formats.

## Structure
- `crates/` Cargo workspace: `vauxl-server` (binary), `vauxl-matrix` (Matrix APIs), `vauxl-federation` (transport and key verification), `vauxl-crypto`, plus stubs for identity, media, admin, push
- `migrations/` PostgreSQL schema (regenerate `.sqlx/` with `cargo sqlx prepare --workspace` after changing queries)
- `config/` runtime configuration defaults
- `docker/` dev compose stack and Dockerfiles
- `scripts/` local dev helpers
- `docs/` extension and operations docs

## Extension Policy
All custom events/capabilities use the `org.vauxl.*` namespace and include discovery/fallback behavior.
