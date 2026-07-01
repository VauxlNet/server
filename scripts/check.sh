#!/usr/bin/env bash
# =============================================================================
# check.sh — Vauxl development quality gate
#
# Usage:
#   ./scripts/check.sh           — run all checks, fix what can be auto-fixed
#   ./scripts/check.sh --ci      — same flags as CI, no auto-fix (read-only)
#   ./scripts/check.sh --fix     — auto-fix fmt + clippy, then run all checks
#   ./scripts/check.sh --fast    — fmt + clippy only, skip tests and audit
#
# Place this file at: scripts/check.sh
# Make executable:    chmod +x scripts/check.sh
# =============================================================================

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'
RESET='\033[0m'

# ── State ────────────────────────────────────────────────────────────────────
FAILED=()
PASSED=()
SKIPPED=()
START_TIME=$(date +%s)

# ── Flags ────────────────────────────────────────────────────────────────────
CI_MODE=false
FIX_MODE=false
FAST_MODE=false

for arg in "$@"; do
  case "$arg" in
    --ci)   CI_MODE=true  ;;
    --fix)  FIX_MODE=true ;;
    --fast) FAST_MODE=true ;;
    --help)
      echo "Usage: $0 [--ci] [--fix] [--fast]"
      echo "  --ci    Read-only mode, same flags as GitHub Actions"
      echo "  --fix   Auto-fix fmt + clippy before checking"
      echo "  --fast  Only fmt + clippy (skip tests, audit, deny)"
      exit 0
      ;;
  esac
done

# ── Helpers ───────────────────────────────────────────────────────────────────
header() {
  echo ""
  echo -e "${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  echo -e "${BOLD}${BLUE}  $1${RESET}"
  echo -e "${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
}

step() {
  echo -e "\n${CYAN}▶ $1${RESET}"
}

ok() {
  echo -e "${GREEN}  ✓ $1${RESET}"
  PASSED+=("$1")
}

fail() {
  echo -e "${RED}  ✗ $1${RESET}"
  FAILED+=("$1")
}

skip() {
  echo -e "${DIM}  ○ $1 (skipped)${RESET}"
  SKIPPED+=("$1")
}

warn() {
  echo -e "${YELLOW}  ⚠ $1${RESET}"
}

# Run a command, capture result, never exit early (we collect all failures)
run_check() {
  local name="$1"
  shift
  if "$@" 2>&1; then
    ok "$name"
    return 0
  else
    fail "$name"
    return 1
  fi
}

# ── Check that we're in the workspace root ────────────────────────────────────
if [[ ! -f "Cargo.toml" ]] || ! grep -q "\[workspace\]" Cargo.toml 2>/dev/null; then
  echo -e "${RED}Error: run this from the workspace root (where Cargo.toml is)${RESET}"
  exit 1
fi

# ── Banner ────────────────────────────────────────────────────────────────────
header "Vauxl check.sh"
echo -e "  Mode: ${BOLD}$([ "$CI_MODE" = true ] && echo "CI (read-only)" || ([ "$FIX_MODE" = true ] && echo "Fix + check" || ([ "$FAST_MODE" = true ] && echo "Fast (fmt + clippy)" || echo "Standard")))${RESET}"
echo -e "  ${DIM}$(date '+%Y-%m-%d %H:%M:%S')${RESET}"

# =============================================================================
# STEP 1 — rustfmt
# =============================================================================
header "1 / 5  Formatting (rustfmt)"

if [ "$FIX_MODE" = true ] && [ "$CI_MODE" = false ]; then
  step "Auto-fixing formatting..."
  if cargo fmt --all; then
    ok "cargo fmt --all (auto-fixed)"
  else
    fail "cargo fmt --all"
  fi
else
  step "Checking formatting (read-only)..."
  if cargo fmt --all -- --check; then
    ok "cargo fmt --check"
  else
    fail "cargo fmt --check"
    if [ "$CI_MODE" = false ]; then
      echo ""
      echo -e "${YELLOW}  → Run ${BOLD}./scripts/check.sh --fix${RESET}${YELLOW} to auto-fix formatting${RESET}"
      echo -e "${YELLOW}  → Or run ${BOLD}cargo fmt --all${RESET}${YELLOW} directly${RESET}"
    fi
  fi
fi

# =============================================================================
# STEP 2 — Clippy
# =============================================================================
header "2 / 5  Linting (clippy)"

CLIPPY_FLAGS="--all-targets --all-features"
RUSTFLAGS_VAL="-D warnings"

if [ "$FIX_MODE" = true ] && [ "$CI_MODE" = false ]; then
  step "Auto-fixing clippy warnings..."
  # --fix applies safe automatic fixes; -- -D warnings still shows what couldn't be fixed
  if RUSTFLAGS="$RUSTFLAGS_VAL" cargo clippy --fix --allow-dirty --allow-staged $CLIPPY_FLAGS 2>&1; then
    ok "cargo clippy --fix"
  else
    warn "Some clippy warnings need manual fixing (see above)"
    fail "cargo clippy --fix (manual fixes required)"
  fi
  # Now run a clean check to show what's left
  step "Checking remaining warnings..."
  if RUSTFLAGS="$RUSTFLAGS_VAL" cargo clippy $CLIPPY_FLAGS 2>&1; then
    ok "cargo clippy (clean after fix)"
  else
    fail "cargo clippy (warnings remain — fix manually)"
  fi
else
  step "Running clippy..."
  if RUSTFLAGS="$RUSTFLAGS_VAL" cargo clippy $CLIPPY_FLAGS 2>&1; then
    ok "cargo clippy"
  else
    fail "cargo clippy"
    if [ "$CI_MODE" = false ]; then
      echo ""
      echo -e "${YELLOW}  → Run ${BOLD}./scripts/check.sh --fix${RESET}${YELLOW} to auto-fix what clippy can${RESET}"
      echo -e "${YELLOW}  → Manual fixes needed for the rest (see output above)${RESET}"
    fi
  fi
fi

# =============================================================================
# STEP 3 — Tests  (skipped in --fast mode)
# =============================================================================
if [ "$FAST_MODE" = true ]; then
  skip "Tests (--fast mode)"
else
  header "3 / 5  Tests"
  step "Running cargo test --all..."
  if cargo test --all 2>&1; then
    ok "cargo test --all"
  else
    fail "cargo test --all"
  fi
fi

# =============================================================================
# STEP 4 — cargo-deny  (skipped in --fast mode)
# =============================================================================
if [ "$FAST_MODE" = true ]; then
  skip "cargo deny (--fast mode)"
elif ! command -v cargo-deny &>/dev/null; then
  warn "cargo-deny not installed — skipping"
  skip "cargo deny (not installed)"
  echo -e "${DIM}  Install: cargo install cargo-deny${RESET}"
else
  header "4 / 5  Security & Licenses (cargo-deny)"
  step "Running cargo deny check..."
  if cargo deny check 2>&1; then
    ok "cargo deny check"
  else
    fail "cargo deny check"
    echo ""
    echo -e "${YELLOW}  → Check deny.toml to add ignores for known advisories${RESET}"
  fi
fi

# =============================================================================
# STEP 5 — Uncommitted changes warning  (skipped in --fast and --ci mode)
# =============================================================================
if [ "$FAST_MODE" = false ] && [ "$CI_MODE" = false ]; then
  header "5 / 5  Git status"
  step "Checking for uncommitted changes..."

  UNTRACKED=$(git ls-files --others --exclude-standard | wc -l)
  MODIFIED=$(git diff --name-only | wc -l)
  STAGED=$(git diff --cached --name-only | wc -l)

  if [ "$MODIFIED" -gt 0 ]; then
    warn "Modified files not staged:"
    git diff --name-only | while read -r f; do
      echo -e "    ${YELLOW}M  $f${RESET}"
    done
  fi

  if [ "$STAGED" -gt 0 ]; then
    echo -e "  ${GREEN}Staged files ready to commit:${RESET}"
    git diff --cached --name-only | while read -r f; do
      echo -e "    ${GREEN}S  $f${RESET}"
    done
  fi

  if [ "$UNTRACKED" -gt 0 ]; then
    warn "$UNTRACKED untracked file(s) — add to .gitignore or stage them"
  fi

  if [ "$MODIFIED" -eq 0 ] && [ "$STAGED" -eq 0 ] && [ "$UNTRACKED" -eq 0 ]; then
    ok "Working tree clean"
  fi
fi

# =============================================================================
# SUMMARY
# =============================================================================
END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

echo ""
echo -e "${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}  Summary  (${ELAPSED}s)${RESET}"
echo -e "${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

for p in "${PASSED[@]+"${PASSED[@]}"}"; do
  echo -e "  ${GREEN}✓${RESET}  $p"
done
for s in "${SKIPPED[@]+"${SKIPPED[@]}"}"; do
  echo -e "  ${DIM}○${RESET}  $s"
done
for f in "${FAILED[@]+"${FAILED[@]}"}"; do
  echo -e "  ${RED}✗${RESET}  $f"
done

echo ""
PASS_COUNT=${#PASSED[@]}
FAIL_COUNT=${#FAILED[@]}
SKIP_COUNT=${#SKIPPED[@]}

if [ "$FAIL_COUNT" -eq 0 ]; then
  echo -e "  ${GREEN}${BOLD}All checks passed${RESET}  ${DIM}(${PASS_COUNT} passed, ${SKIP_COUNT} skipped)${RESET}"
  echo ""
  if [ "$CI_MODE" = false ] && [ "$FAST_MODE" = false ]; then
    echo -e "  ${DIM}Ready to commit. Suggested message format:${RESET}"
    echo -e "  ${DIM}  git commit -m \"type(scope): description\"${RESET}"
    echo -e "  ${DIM}  types: feat fix chore docs test refactor security perf ci${RESET}"
  fi
  exit 0
else
  echo -e "  ${RED}${BOLD}${FAIL_COUNT} check(s) failed${RESET}  ${DIM}(${PASS_COUNT} passed, ${SKIP_COUNT} skipped)${RESET}"
  echo ""
  if [ "$CI_MODE" = false ]; then
    echo -e "  ${YELLOW}Tip: run ${BOLD}./scripts/check.sh --fix${RESET}${YELLOW} to auto-fix fmt + clippy${RESET}"
  fi
  exit 1
fi
