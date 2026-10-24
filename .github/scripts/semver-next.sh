#!/usr/bin/env bash
# Usage: semver-next.sh <latest vX.Y.Z tag or empty> <comma-separated PR labels> [initial version]
set -euo pipefail
latest=${1:-}; labels=",${2:-},"; initial=${3:-0.1.0}
[[ $initial =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "invalid initial version" >&2; exit 1; }
count=0; bump=patch
for level in patch minor major none; do
  if [[ $labels == *",release:$level,"* ]]; then
    bump=$level
    count=$((count+1))
  fi
done
((count <= 1)) || { echo "conflicting release labels" >&2; exit 1; }
[[ $bump == none ]] && exit 0
if [[ -z $latest ]]; then echo "$initial"; exit 0; fi
[[ $latest =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || { echo "invalid release tag: $latest" >&2; exit 1; }
major=${BASH_REMATCH[1]}; minor=${BASH_REMATCH[2]}; patch=${BASH_REMATCH[3]}
case $bump in
  major) echo "$((major+1)).0.0" ;;
  minor) echo "$major.$((minor+1)).0" ;;
  patch) echo "$major.$minor.$((patch+1))" ;;
esac
