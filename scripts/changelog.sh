#!/usr/bin/env bash
# Print the entries CHANGELOG.md lists for one version, without the heading.
#
#   scripts/changelog.sh 0.1.0
#   scripts/changelog.sh Unreleased
#
# Fails if the version has no section or the section is empty.
set -euo pipefail

version=${1:?usage: scripts/changelog.sh <version>}
changelog=$(dirname "${BASH_SOURCE[0]}")/../CHANGELOG.md

notes=$(awk -v heading="## [$version]" '
	/^## \[/ { if (found) exit; found = index($0, heading) == 1; next }
	found
' "$changelog" | sed '/./,$!d')

if [[ ! $notes =~ [^[:space:]] ]]; then
	echo "CHANGELOG.md has no entries for $version" >&2
	exit 1
fi
printf '%s\n' "$notes"
