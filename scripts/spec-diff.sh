#!/bin/sh
# spec-diff — rung 1 of the verification ladder: upstream drift detection.
# Compares upstream's machine-readable spec.json against our vendored copy.
# Usage: scripts/spec-diff.sh [path/to/upstream/spec.json]
set -e
OURS="$(dirname "$0")/../conformance/spec.json"
THEIRS="${1:-$HOME/Projects/project-quarry/quarry/language/spec.json}"

python3 - "$OURS" "$THEIRS" <<'EOF'
import json, sys

ours = json.load(open(sys.argv[1]))
theirs = json.load(open(sys.argv[2]))

drift = []

if ours.get("compiler_version") != theirs.get("compiler_version"):
    drift.append(
        f"compiler_version: ours={ours.get('compiler_version')} upstream={theirs.get('compiler_version')}"
    )

def summary(spec):
    ex = spec.get("examples", [])
    items = set()
    for e in ex:
        items.update(e.get("covered_item_ids", []))
    return len(ex), items

n_ours, items_ours = summary(ours)
n_theirs, items_theirs = summary(theirs)

if n_ours != n_theirs:
    drift.append(f"example count: ours={n_ours} upstream={n_theirs}")

added = items_theirs - items_ours
removed = items_ours - items_theirs
if added:
    drift.append(f"constructs added upstream: {sorted(added)}")
if removed:
    drift.append(f"constructs removed upstream: {sorted(removed)}")

if drift:
    print("UPSTREAM DRIFT DETECTED — revalidation required before pull:")
    for d in drift:
        print("  -", d)
    sys.exit(1)
print(f"no drift: compiler {theirs.get('compiler_version')}, {n_theirs} examples, {len(items_theirs)} constructs")
EOF
