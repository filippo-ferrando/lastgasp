#!/bin/sh
# Checks deploy/upgrade-notes.sh. Run from the repository root.
set -eu
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
fails=0
fail() { echo "FAIL upgrade-notes: $*" >&2; fails=$((fails + 1)); }

cat > "$TMP/notes.md" <<'MD'
# Upgrade notes

Intro text.

## Unreleased

Next one, see [the design](design.md) and [a site](https://example.net/x.md).

- item

## v1.0.0

Old notes.
MD

out=$(sh deploy/upgrade-notes.sh v2.0.0 "$TMP/notes.md" https://git.example/r/src/tag/v2.0.0/docs)
want='Next one, see [the design](https://git.example/r/src/tag/v2.0.0/docs/design.md) and [a site](https://example.net/x.md).

- item'
[ "$out" = "$want" ] || fail "unreleased section: got
$out"

out=$(sh deploy/upgrade-notes.sh v1.0.0 "$TMP/notes.md" https://b)
[ "$out" = "Old notes." ] || fail "tagged section: got $out"

printf '# Upgrade notes\n\n## v1.0.0\n\nOld.\n' > "$TMP/none.md"
out=$(sh deploy/upgrade-notes.sh v2.0.0 "$TMP/none.md" https://b)
[ -z "$out" ] || fail "no section should print nothing, got $out"

# The real file must have a section for the next release.
[ -n "$(sh deploy/upgrade-notes.sh v0.0.0-next docs/upgrade-notes.md https://b)" ] || fail "docs/upgrade-notes.md has no Unreleased section"

[ "$fails" -eq 0 ] || exit 1
echo "ok  	deploy/upgrade-notes.sh"
