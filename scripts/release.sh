#!/usr/bin/env bash
#
# Pre-release checks and packaging for vantage.
#
#   ./scripts/release.sh            # run the checks, build, and write ../vantage.zip
#   ./scripts/release.sh --no-zip   # checks and build only
#
# Hard gates (a failure stops the release): clean working tree, tests, and
# cargo audit against the RustSec advisory database. Audit is the one check that
# goes stale on its own, since new advisories land against code that has not
# changed, so it runs every time rather than once.
#
# Advisory only (reported, does not stop the release): rustfmt and clippy.

set -uo pipefail

cd "$(dirname "$0")/.." || exit 1
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"

ZIP=1
[ "${1:-}" = "--no-zip" ] && ZIP=0

fail=0
step()  { printf '\n== %s\n' "$1"; }
ok()    { printf '   ok: %s\n' "$1"; }
bad()   { printf '   FAIL: %s\n' "$1"; fail=1; }
warn()  { printf '   warn: %s\n' "$1"; }

VERSION=$(grep -m1 '^version = ' Cargo.toml | cut -d'"' -f2)
printf 'vantage %s\n' "$VERSION"

step "working tree"
if [ -n "$(git status --porcelain)" ]; then
    bad "uncommitted changes; a release must be built from a committed tree"
    git status --short | sed 's/^/        /'
else
    ok "clean, at $(git rev-parse --short HEAD)"
fi

step "tests"
if cargo test --locked --quiet >/tmp/vantage-test.log 2>&1; then
    ok "cargo test"
else
    bad "cargo test"
    tail -20 /tmp/vantage-test.log | sed 's/^/        /'
fi

step "dependency audit"
if ! command -v cargo-audit >/dev/null 2>&1; then
    bad "cargo-audit is not installed. Install it with: cargo install cargo-audit --locked"
else
    # cargo audit exits non-zero when it finds a vulnerability or a warning
    # (unmaintained, unsound, or yanked crate).
    if cargo audit --deny warnings >/tmp/vantage-audit.log 2>&1; then
        ok "no advisories against $(grep -c '^\[\[package\]\]' Cargo.lock) crates"
    else
        bad "cargo audit reported findings"
        sed 's/^/        /' /tmp/vantage-audit.log
    fi
fi

step "style (advisory)"
cargo fmt --check >/dev/null 2>&1 && ok "rustfmt" || warn "rustfmt would reformat; run: cargo fmt"
cargo clippy --all-targets >/dev/null 2>&1 && ok "clippy" || warn "clippy has lints; run: cargo clippy --all-targets"

step "release build"
if cargo build --locked --release --quiet >/tmp/vantage-build.log 2>&1; then
    ok "target/release/vantage"
else
    bad "release build"
    tail -20 /tmp/vantage-build.log | sed 's/^/        /'
fi

if [ "$fail" -ne 0 ]; then
    printf '\nrelease blocked, fix the failures above\n'
    exit 1
fi

if [ "$ZIP" -eq 1 ]; then
    step "package"
    OUT=../vantage.zip
    rm -f "$OUT"
    # Archive from HEAD, so the zip can only ever contain committed code.
    if git archive --format=zip --prefix=vantage/ -o "$OUT" HEAD; then
        ok "$(cd .. && pwd)/vantage.zip ($(du -h "$OUT" | cut -f1))"
    else
        bad "git archive"
        exit 1
    fi
fi

printf '\nvantage %s is ready to release\n' "$VERSION"
