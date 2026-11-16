#!/bin/sh
# quarry-rs verification gate — rungs 0–2 of the ladder, in one command.
# The green law wall: nothing lands without this being green.
set -e
cd "$(dirname "$0")"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/qrs-target}"

echo "== 1. workspace tests (unit + conformance + fuzz + latency) =="
cargo test --workspace --quiet

echo "== 2. all corpus rules parse =="
cargo run -q -p quarry-cli -- parse conformance/examples/rules/*.rule > /dev/null
cargo run -q -p quarry-cli -- parse conformance/language-examples/*.rule > /dev/null
echo "   corpus parse: ok"

echo "== 3. upstream drift check (spec-diff) =="
if [ -d "${QUARRY_UPSTREAM:-$HOME/Projects/project-quarry}" ]; then
    ./scripts/spec-diff.sh "${QUARRY_UPSTREAM:-$HOME/Projects/project-quarry/quarry/language/spec.json}"
else
    echo "   (upstream clone not found — set QUARRY_UPSTREAM to run the drift check)"
fi

echo "== GATE GREEN =="
