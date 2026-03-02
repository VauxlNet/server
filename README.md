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
- `src/` implementation or fork integration
- `tests/` conformance and integration tests
- `docs/` extension and operations docs

## Extension Policy
All custom events/capabilities use the `org.vauxl.*` namespace and include discovery/fallback behavior.
