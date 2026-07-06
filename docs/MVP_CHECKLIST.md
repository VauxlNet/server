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
- Workspace lints (`clippy pedantic`, `unsafe_code = "forbid"`) are declared in the root `Cargo.toml` but no crate sets `[lints] workspace = true`, so they are not enforced. CI runs with `RUSTFLAGS="-D warnings"`, so wiring them up requires fixing the pedantic fallout in the same change.
- The `AuthenticatedUser` extractor in `vauxl-matrix` exists but no route uses it yet; gate endpoints with it as soon as the first protected route lands.
- Redis is required by config and started by the dev compose stack but no crate uses it yet. Either wire it up or drop it from required config.
- After changing any sqlx query, regenerate the offline cache with `cargo sqlx prepare --workspace` against a migrated database and commit `.sqlx/`.
