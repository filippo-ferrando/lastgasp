#!/bin/sh
# Prints the CHANGELOG.md section of a tag (v1.2.0 or 1.2.0), or "Unreleased" when the tag has none.
# Relative links to .md files get the base URL, so they work on the release page.
# Usage: changelog.sh TAG FILE BASE_URL
set -eu
tag=${1:?tag} file=${2:?file} base=${3:?base url}

awk -v ver="${tag#v}" '
	/^## \[/ { cur = substr($0, 5); sub(/\].*/, "", cur); sub(/^v/, "", cur); seen[cur] = 1; next }
	/^\[[^]]+\]: / { cur = ""; next }
	cur != "" { sec[cur] = sec[cur] $0 "\n" }
	END {
		name = (ver in seen) ? ver : "Unreleased"
		printf "%s", sec[name]
	}' "$file" |
	sed -e "s|](\([A-Za-z0-9_.][A-Za-z0-9_./-]*\.md\)|]($base/\1|g" |
	# Drop blank lines at the start and the end.
	awk 'NF { for (; blank > 0; blank--) print ""; print; started = 1; next } started { blank++ }'
