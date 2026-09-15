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

Implemented security checks and remaining federation limitations are described in
[Federation security](FEDERATION_SECURITY.md). Passing regression tests does not
complete the federation baseline item above.

## Extensions
- [ ] Capability discovery endpoint/event documented
- [ ] `org.vauxl.*` extension contracts versioned
- [ ] Client fallback behavior documented

## Deferred Decisions (2026-07-06)
- Workspace lints (`clippy pedantic`, `unsafe_code = "forbid"`) are declared in the root `Cargo.toml` but no crate sets `[lints] workspace = true`, so they are not enforced. CI runs with `RUSTFLAGS="-D warnings"`, so wiring them up requires fixing the pedantic fallout in the same change.
- Protected client routes use `AuthenticatedUser`; room mutations additionally authorize against locked room state.
- Redis is used for ephemeral state, sync bookkeeping, and validated federation key caching.
- After changing any sqlx query, regenerate the offline cache with `cargo sqlx prepare --workspace` against a migrated database and commit `.sqlx/`.
