#!/bin/sh
set -eu

if [ "$#" -lt 1 ]; then
    echo "usage: C2PATOOL_BIN=/path/to/c2patool BANKSY_C2PA_BIN=/path/to/banksy-c2pa $0 IMAGE..." >&2
    exit 2
fi

BANKSY_C2PA_BIN="${BANKSY_C2PA_BIN:-./banksy-c2pa}"
C2PATOOL_BIN="${C2PATOOL_BIN:-c2patool}"

test -x "$BANKSY_C2PA_BIN"
"$C2PATOOL_BIN" --version

for image in "$@"; do
    "$BANKSY_C2PA_BIN" audit "$image"
    "$C2PATOOL_BIN" "$image" >/dev/null
    printf 'independent validation passed: %s\n' "$image"
done
