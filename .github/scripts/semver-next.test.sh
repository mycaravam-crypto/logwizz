#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
check() { local got; got=$(bash semver-next.sh "$1" "$2" "$3") || got=ERROR; [[ "$got" == "$4" ]] || { echo "FAIL: $1 $2 expected $4 got $got"; exit 1; }; }
check "" "" "0.1.0" "0.1.0"
check v0.1.0 "" "0.1.0" "0.1.1"
check v0.1.1 "release:patch" "0.1.0" "0.1.2"
check v0.1.1 "release:minor" "0.1.0" "0.2.0"
check v0.1.1 "release:major" "0.1.0" "1.0.0"
check v0.1.1 "release:none" "0.1.0" ""
check v0.1.1 "release:major,release:minor" "0.1.0" "ERROR"
check badtag "" "0.1.0" "ERROR"
check v0.1.1 "release:minor-ish" "0.1.0" "0.1.2"
echo "Release version tests passed"
