#!/usr/bin/env bash
# The same client checks used by Linux CI; no provider or cloud credentials.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."

for program in cargo rustc python3 bash zsh fish; do
    if ! command -v "$program" >/dev/null; then
        printf 'Missing required program: %s\n' "$program" >&2
        exit 1
    fi
done
python3 -c 'import sys; assert sys.version_info >= (3, 11), "Python 3.11 or newer is required"'

cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy -p gent-protocol -p gent-crypto --lib --all-features \
    --target wasm32-unknown-unknown --locked -- -D warnings
# Cryptographic integration tests are expensive without optimization. Keep
# development assertions and checked arithmetic in this faster test build.
CARGO_PROFILE_TEST_OPT_LEVEL=1 \
    CARGO_PROFILE_TEST_DEBUG_ASSERTIONS=true \
    CARGO_PROFILE_TEST_OVERFLOW_CHECKS=true \
    RUST_TEST_THREADS="${RUST_TEST_THREADS:-2}" \
    cargo test --workspace --locked
cargo build -p gent-link --bin gent --locked

# Respect Cargo's selected target directory, including absolute overrides.
target_dir="$(cargo metadata --no-deps --format-version 1 --locked |
    python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')"
binary="$target_dir/debug/gent"
python3 scripts/smoke_cli.py "$binary"
python3 scripts/smoke_mcp.py "$binary"
python3 scripts/smoke_host_bindings.py "$binary"
python3 scripts/prove_chat_names.py --gent "$binary"
python3 scripts/smoke_config_edit.py "$binary"
python3 scripts/smoke_hooks.py --binary "$binary" \
    --bash "$(command -v bash)" --zsh "$(command -v zsh)" --fish "$(command -v fish)"
