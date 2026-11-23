#!/usr/bin/env bash
# Testes sem root (MemoryNic).
set -euo pipefail
cd "$(dirname "$0")/.."
cargo test "$@"
