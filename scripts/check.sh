#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

fast=false
fix=false
ci=false
online=false

usage() {
    cat <<'EOF'
Usage: scripts/check.sh [--fast] [--fix] [--ci] [--online]

  --fast    Run whitespace, formatting, shell, and Clippy checks only
  --fix     Apply Rust formatting and safe Clippy fixes before checking
  --ci      Keep the Rust quality gate read-only for CI compatibility
  --online  Also verify SQLx metadata against a disposable PostgreSQL container
  --help    Show this help
EOF
}

for arg in "$@"; do
    case "$arg" in
        --fast) fast=true ;;
        --fix) fix=true ;;
        --ci) ci=true ;;
        --online) online=true ;;
        --help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $arg" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if $ci && $fix; then
    echo "--ci and --fix cannot be combined" >&2
    exit 2
fi
if $fast && $online; then
    echo "--fast and --online cannot be combined" >&2
    exit 2
fi

need() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "Required tool not found: $1" >&2
        exit 127
    }
}

for tool in bash cargo cargo-clippy git rustc rustfmt; do
    need "$tool"
done
if ! $fast; then
    need cargo-deny
    need rustdoc
fi
if $online; then
    need cargo-sqlx
    need docker
fi

export SQLX_OFFLINE=true
export RUSTFLAGS="-Dwarnings -Funsafe_code"

if $fix; then
    cargo fmt --all
    cargo clippy --fix --allow-dirty --allow-staged --locked --workspace --all-targets --all-features
fi

git diff --check HEAD
if git grep -I -n -E '[[:blank:]]+$' -- .; then
    echo "Tracked files contain trailing whitespace" >&2
    exit 1
fi
cargo fmt --all -- --check
while IFS= read -r -d '' script; do
    bash -n "$script"
done < <(git ls-files -z '*.sh')
cargo clippy --locked --workspace --all-targets --all-features

if $fast; then
    exit 0
fi

cargo test --locked --workspace --all-targets --all-features
cargo test --locked --workspace --all-features --doc
RUSTDOCFLAGS="-Dwarnings" cargo doc --locked --workspace --all-features --no-deps --document-private-items
cargo build --locked --workspace --all-targets --all-features --release
cargo deny --locked --all-features check advisories licenses bans sources
cargo deny --manifest-path crates/vauxl-crypto/fuzz/Cargo.toml --locked --all-features check advisories licenses bans sources

if $online; then
    db_container="vauxl-sqlx-check-$$"
    db_container_id=""
    cleanup() {
        if [[ -n "$db_container_id" ]]; then
            docker rm -f "$db_container_id" >/dev/null 2>&1 || true
        fi
    }

    db_container_id=$(docker run --detach --rm --name "$db_container" \
        --env POSTGRES_USER=vauxl \
        --env POSTGRES_PASSWORD=vauxl_check \
        --env POSTGRES_DB=vauxl_check \
        --publish 127.0.0.1::5432 \
        postgres:16-alpine)
    trap cleanup EXIT

    for _ in {1..30}; do
        docker exec "$db_container_id" pg_isready -U vauxl -d vauxl_check >/dev/null 2>&1 && break
        sleep 1
    done
    docker exec "$db_container_id" pg_isready -U vauxl -d vauxl_check >/dev/null

    db_port=$(docker port "$db_container_id" 5432/tcp | sed -n 's/.*://p' | tail -n 1)
    database_url="postgres://vauxl:vauxl_check@127.0.0.1:${db_port}/vauxl_check?sslmode=disable"
    DATABASE_URL="$database_url" cargo sqlx migrate run --source migrations
    DATABASE_URL="$database_url" cargo test --locked -p vauxl-matrix \
        concurrent_message_transaction_creates_one_event -- --ignored
    (
        unset SQLX_OFFLINE
        DATABASE_URL="$database_url" cargo sqlx prepare --workspace --check -- --locked --all-targets --all-features
    )
fi
