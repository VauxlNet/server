# SQLx offline query cache

This directory contains generated query metadata for offline builds.

Use the online mode of `scripts/check.sh` after changing a SQLx query. The
script applies every migration to a disposable PostgreSQL database and checks
the committed cache against that schema.
