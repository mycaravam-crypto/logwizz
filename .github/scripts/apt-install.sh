#!/usr/bin/env bash
# Usage: apt-install.sh <package>...
# The runner's package mirror sometimes stalls for half an hour. Downloading is bounded and retried (killing it
# leaves nothing half-installed); installing from the downloaded packages is then local. Callers also set a step
# timeout-minutes, which bounds this script's worst case of three 3-minute attempts.
set -euo pipefail
(( $# > 0 )) || { echo "usage: apt-install.sh <package>..." >&2; exit 2; }
opts=(-qq -o Acquire::Retries=3 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30)
for try in 1 2 3; do
  sudo timeout 90 apt-get "${opts[@]}" update &&
    sudo timeout 90 apt-get "${opts[@]}" install -y --download-only "$@" && break
  (( try < 3 )) || exit 1
  echo "::warning::package download attempt $try failed or timed out; retrying"
done
sudo apt-get -qq install -y "$@"
