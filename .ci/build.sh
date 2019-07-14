#!/usr/bin/env bash

: ${TRAVIS_OS_NAME:=osx}
: ${OTPCLI_ALL_FEATURES:=false}

CARGO_ARGS=()

function set_cargo_args() {

    if [ "$TRAVIS_OS_NAME" = "linux" -a "$OTPCLI_ALL_FEATURES" != "true" ]; then
        CARGO_ARGS+=(--no-default-features)
    fi
}

set_cargo_args

set -x

cargo fmt --all -- --check
cargo clippy --all-targets "${CARGO_ARGS[@]}"
cargo build "${CARGO_ARGS[@]}"
cargo test  "${CARGO_ARGS[@]}"
