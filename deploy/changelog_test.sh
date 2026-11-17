#!/bin/sh
# Checks deploy/changelog.sh. Run from the repository root.
set -eu
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
fails=0
fail() { echo "FAIL changelog: $*" >&2; fails=$((fails + 1)); }

cat > "$TMP/CHANGELOG.md" <<'MD'
# Changelog

Intro text.

## [Unreleased]

### Added

- Next one, see [the design](docs/design.md#keys) and [a site](https://example.net/x.md).

## [1.0.0] - 2026-01-02

Old notes.

[Unreleased]: https://git.example/r/compare/v1.0.0...HEAD
[1.0.0]: https://git.example/r/releases/tag/v1.0.0
MD

out=$(sh deploy/changelog.sh v2.0.0 "$TMP/CHANGELOG.md" https://git.example/r/src/tag/v2.0.0)
want='### Added

- Next one, see [the design](https://git.example/r/src/tag/v2.0.0/docs/design.md#keys) and [a site](https://example.net/x.md).'
[ "$out" = "$want" ] || fail "unreleased section: got
$out"

out=$(sh deploy/changelog.sh v1.0.0 "$TMP/CHANGELOG.md" https://b)
[ "$out" = "Old notes." ] || fail "tagged section, link lines must be left out: got $out"

out=$(sh deploy/changelog.sh 1.0.0 "$TMP/CHANGELOG.md" https://b)
[ "$out" = "Old notes." ] || fail "tag without v: got $out"

printf '# Changelog\n\n## [1.0.0]\n\nOld.\n' > "$TMP/none.md"
out=$(sh deploy/changelog.sh v2.0.0 "$TMP/none.md" https://b)
[ -z "$out" ] || fail "no section should print nothing, got $out"

# The real file must have a section for the next release.
[ -n "$(sh deploy/changelog.sh v0.0.0-next CHANGELOG.md https://b)" ] || fail "CHANGELOG.md has no Unreleased section"

[ "$fails" -eq 0 ] || exit 1
echo "ok  	deploy/changelog.sh"
