#!/usr/bin/env bash
# Run the upstream OCI runtime-tools validation suite against a runz binary.
#
# Required env (exported by `nix develop`):
#   OCI_VALIDATION_DIR  directory containing validation/*.t binaries
#   OCI_RUNTIMETEST     path to the runtimetest binary that gets injected
#                       into each test bundle
#
# Optional env:
#   RUNTIME             path to runtime under test (default: zig-out/bin/runz)
#   OCI_VALIDATION_FILTER  shell glob; only tests whose name matches run
#
# Skips with exit 0 when prerequisites are missing (not in nix devShell, or
# not root). Use this in local dev; CI should assert prerequisites separately.

set -euo pipefail

RUNTIME="${RUNTIME:-$PWD/zig-out/bin/runz}"
FILTER="${OCI_VALIDATION_FILTER:-*}"

skip() {
    echo "test-oci-validation: SKIPPED — $*" >&2
    exit 0
}

[ -n "${OCI_VALIDATION_DIR:-}" ] || skip "OCI_VALIDATION_DIR unset (enter \`nix develop\`)"
[ -n "${OCI_RUNTIMETEST:-}" ]    || skip "OCI_RUNTIMETEST unset (enter \`nix develop\`)"
[ -d "$OCI_VALIDATION_DIR" ]     || skip "OCI_VALIDATION_DIR ($OCI_VALIDATION_DIR) is not a directory"
[ -x "$OCI_RUNTIMETEST" ]        || skip "OCI_RUNTIMETEST ($OCI_RUNTIMETEST) is not executable"
[ "$(id -u)" -eq 0 ]             || skip "must run as root for namespace setup"
[ -x "$RUNTIME" ]                || { echo "test-oci-validation: runtime not found at $RUNTIME" >&2; exit 1; }

# Each validation .t binary copies "./runtimetest" into its bundle, so we have
# to chdir into a directory containing that file before invoking it.
workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT
cp "$OCI_RUNTIMETEST" "$workdir/runtimetest"
cd "$workdir"

export RUNTIME
export PATH="$(dirname "$RUNTIME"):$PATH"

total=0
fail=0
failed_tests=()
for t in "$OCI_VALIDATION_DIR"/$FILTER.t; do
    [ -e "$t" ] || continue
    name=$(basename "$t" .t)
    total=$((total + 1))
    echo "==> $name"
    if "$t"; then :; else
        fail=$((fail + 1))
        failed_tests+=("$name")
    fi
done

echo
if [ $fail -eq 0 ]; then
    echo "test-oci-validation: $total/$total passed"
else
    echo "test-oci-validation: $((total - fail))/$total passed; failed:" >&2
    for n in "${failed_tests[@]}"; do echo "  - $n" >&2; done
    exit 1
fi
