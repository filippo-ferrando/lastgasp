#!/bin/sh
# Prints the section of an upgrade notes file for a tag, or the "Unreleased" one when the tag has none.
# Relative links to .md files get the base URL, so they work on the release page.
# Usage: upgrade-notes.sh TAG FILE BASE_URL
set -eu
tag=${1:?tag} file=${2:?file} base=${3:?base url}

awk -v tag="$tag" '
	/^## / { cur = substr($0, 4); seen[cur] = 1; next }
	cur != "" { sec[cur] = sec[cur] $0 "\n" }
	END {
		name = (tag in seen) ? tag : "Unreleased"
		printf "%s", sec[name]
	}' "$file" |
	sed -e "s|](\([A-Za-z0-9_-]*\.md\)|]($base/\1|g" |
	# Drop blank lines at the start and the end.
	awk 'NF { for (; blank > 0; blank--) print ""; print; started = 1; next } started { blank++ }'
