#!/usr/bin/env bash
# Usage: semver-next.sh <latest vX.Y.Z tag or empty> <PR labels> [initial version]
# PR labels are comma-separated; the label sets of several PRs are separated by ';'. Each PR picks its bump
# (release:patch|minor|major|none, patch by default) and the largest wins, so one run releases every PR merged
# since the latest tag even when the release runs of earlier merges were replaced in the concurrency queue.
set -euo pipefail
latest=${1:-}; initial=${3:-0.1.0}
[[ $initial =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "invalid initial version" >&2; exit 1; }
rank() { case $1 in none) echo 0 ;; patch) echo 1 ;; minor) echo 2 ;; major) echo 3 ;; esac; }
bump=none
IFS=";" read -r -a sets <<< "${2:-};"  # the extra ";" keeps a trailing empty set
for set in "${sets[@]}"; do
  labels=",$set,"; count=0; pr=patch
  for level in patch minor major none; do
    if [[ $labels == *",release:$level,"* ]]; then
      pr=$level
      count=$((count+1))
    fi
  done
  ((count <= 1)) || { echo "conflicting release labels" >&2; exit 1; }
  (($(rank "$pr") > $(rank "$bump"))) && bump=$pr
done
[[ $bump == none ]] && exit 0
if [[ -z $latest ]]; then echo "$initial"; exit 0; fi
[[ $latest =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || { echo "invalid release tag: $latest" >&2; exit 1; }
major=${BASH_REMATCH[1]}; minor=${BASH_REMATCH[2]}; patch=${BASH_REMATCH[3]}
case $bump in
  major) echo "$((major+1)).0.0" ;;
  minor) echo "$major.$((minor+1)).0" ;;
  patch) echo "$major.$minor.$((patch+1))" ;;
esac
