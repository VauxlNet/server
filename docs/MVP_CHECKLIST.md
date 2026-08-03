# Server MVP Checklist

## Matrix Baseline
- [ ] User registration/authentication
- [ ] Room creation/join/leave/state
- [ ] Event persistence and sync endpoints
- [ ] Media repository endpoints
- [ ] Federation baseline support

## Operations
- [ ] Configured observability (logs/metrics)
- [ ] Backup and restore procedure
- [ ] Security baseline hardening checklist

## Extensions
- [ ] Capability discovery endpoint/event documented
- [ ] `org.vauxl.*` extension contracts versioned
- [ ] Client fallback behavior documented

## Deferred Decisions (2026-07-06)
- Workspace lints (`clippy pedantic`, `unsafe_code = "forbid"`) are declared in the root `Cargo.toml` but no crate sets `[lints] workspace = true`. The quality gate denies warnings and unsafe code directly.
- `AuthenticatedUser` gates protected client endpoints. New protected routes must use the same extractor.
- Redis stores sync counters, presence, and typing state. The server requires it at runtime.
- After changing a SQLx query, regenerate the workspace offline cache against a migrated database and commit `.sqlx/`.
