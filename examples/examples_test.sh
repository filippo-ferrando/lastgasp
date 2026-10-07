#!/bin/sh
# Checks the example compose files: every server flag must exist, and docker compose must accept
# each file when docker is installed. Run from the repository root.
set -eu

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
fail() { echo "FAIL examples: $*" >&2; exit 1; }

CGO_ENABLED=0 go build -o "$TMP/server" ./cmd/lastgasp-server
"$TMP/server" -h 2>"$TMP/help" || true

for f in examples/*/compose.yaml; do
	# Flags are list items like "- -retain=720h". Commented lines are checked too, so examples stay valid.
	for flag in $(sed -n 's/^[[:space:]#]*- -\([a-z][a-z-]*\).*/\1/p' "$f" | sort -u); do
		grep -Eq "^  -$flag( |$)" "$TMP/help" || fail "$f: unknown server flag -$flag"
	done
done

if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
	for f in examples/*/compose.yaml; do
		d=$(dirname "$f")
		POSTGRES_PASSWORD=x TELEGRAM_CHAT=1 LASTGASP_DOMAIN=lastgasp.example LASTGASP_AGENT_ADDRESS=10.0.0.5:5140 \
			docker compose --project-directory "$d" -f "$f" config -q >"$TMP/out" 2>&1 || fail "$f: $(cat "$TMP/out")"
	done
else
	echo "examples: docker compose not found, only flags checked"
fi
echo "ok  	examples"
