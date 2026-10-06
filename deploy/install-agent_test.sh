#!/bin/sh
# Tests install-agent.sh against a temporary directory tree with a fake agent binary.
set -eu

DIR=$(cd "$(dirname "$0")" && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
export ROOT="$TMP/root"
fails=0

fail() { echo "FAIL: $*" >&2; fails=$((fails + 1)); }
check() { grep -q -- "$2" "$1" || fail "$1 does not contain '$2'"; }

printf '#!/bin/sh\nexit 0\n' > "$TMP/agent"
chmod +x "$TMP/agent"
install() { sh "$DIR/install-agent.sh" -b "$TMP/agent" "$@" > "$TMP/out" 2>&1; }

# A first install creates a key and prints the server key line.
install -s logs.example.net:5140,10.0.0.2:5140 -n db-01 -a "-buffer 32768" || fail "install: $(cat "$TMP/out")"
key=$(cat "$ROOT/etc/lastgasp/agent.key")
[ ${#key} -eq 64 ] || fail "generated key has length ${#key}"
check "$TMP/out" "db-01 $key"
[ -x "$ROOT/usr/local/sbin/lastgasp-agent" ] || fail "binary not installed"
[ -f "$ROOT/etc/systemd/system/lastgasp-agent.service" ] || fail "unit not installed"
dropin="$ROOT/etc/systemd/system/lastgasp-agent.service.d/10-install.conf"
check "$dropin" "^ExecStart=$"
check "$dropin" "-server logs.example.net:5140,10.0.0.2:5140 -key-file /etc/lastgasp/agent.key -hostname db-01 -buffer 32768"
[ "$(stat -c %a "$ROOT/etc/lastgasp/agent.key")" = 600 ] || fail "key file is not mode 600"
[ "$(stat -c %a "$ROOT/etc/lastgasp")" = 700 ] || fail "config dir is not mode 700"

# Characters systemd would expand are escaped.
install -s a:1 -a '-x 50% -y $HOME -z a\b' || fail "install with args: $(cat "$TMP/out")"
check "$dropin" '-x 50%% -y \$\$HOME -z a\\\\b'

# Running again keeps the existing key.
install -s logs.example.net:5140 || fail "reinstall: $(cat "$TMP/out")"
[ "$(cat "$ROOT/etc/lastgasp/agent.key")" = "$key" ] || fail "key changed on reinstall"
grep -q "server key file" "$TMP/out" && fail "key line printed again"

# A given key replaces the stored one.
install -s a:1 -k 00112233445566778899aabbccddeeff || fail "install with key: $(cat "$TMP/out")"
[ "$(cat "$ROOT/etc/lastgasp/agent.key")" = 00112233445566778899aabbccddeeff ] || fail "given key not stored"

# Bad input is refused.
install && fail "missing --server accepted"
install -s nohost || true; check "$TMP/out" "must be host:port"
install -s a:1 -k abcd && fail "short key accepted"
install -s a:1 -k zz112233445566778899aabbccddeeff && fail "non hex key accepted"
install -s a:1 -n 'bad name' && fail "hostname with space accepted"
install -s a:1 -b "$TMP/missing" && fail "missing binary accepted"

# Uninstall keeps the key unless --purge is given.
install --uninstall || fail "uninstall: $(cat "$TMP/out")"
[ -e "$ROOT/usr/local/sbin/lastgasp-agent" ] && fail "binary left after uninstall"
[ -e "$dropin" ] && fail "drop-in left after uninstall"
[ -f "$ROOT/etc/lastgasp/agent.key" ] || fail "key removed without --purge"
install --uninstall --purge || fail "purge: $(cat "$TMP/out")"
[ -e "$ROOT/etc/lastgasp" ] && fail "config left after purge"

if [ "$fails" -gt 0 ]; then
	echo "install-agent_test: $fails failures" >&2
	exit 1
fi
echo "ok  	deploy/install-agent.sh"
