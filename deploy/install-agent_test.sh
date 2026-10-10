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
LASTGASP_KEY=ffeeddccbbaa99887766554433221100 install -s a:1 || fail "install with env key: $(cat "$TMP/out")"
[ "$(cat "$ROOT/etc/lastgasp/agent.key")" = ffeeddccbbaa99887766554433221100 ] || fail "env key not stored"

# Bad input is refused.
install && fail "missing --server accepted"
install -s nohost || true; check "$TMP/out" "must be host:port"
install -s a:1 -k abcd && fail "short key accepted"
install -s a:1 -k zz112233445566778899aabbccddeeff && fail "non hex key accepted"
install -s a:1 -n 'bad name' && fail "hostname with space accepted"
install -s a:1 -b "$TMP/missing" && fail "missing binary accepted"

# Uninstall keeps the key unless --purge is given.
mkdir -p "$ROOT/run/lastgasp" && : > "$ROOT/run/lastgasp/agent.stash"
install --uninstall || fail "uninstall: $(cat "$TMP/out")"
[ -e "$ROOT/run/lastgasp" ] && fail "stash left after uninstall"
[ -e "$ROOT/usr/local/sbin/lastgasp-agent" ] && fail "binary left after uninstall"
[ -e "$dropin" ] && fail "drop-in left after uninstall"
[ -f "$ROOT/etc/lastgasp/agent.key" ] || fail "key removed without --purge"
install --uninstall --purge || fail "purge: $(cat "$TMP/out")"
[ -e "$ROOT/etc/lastgasp" ] && fail "config left after purge"

# Download from a release, verify it, and enroll with a token. A local web server plays the Forgejo instance.
if command -v python3 >/dev/null 2>&1 && command -v curl >/dev/null 2>&1; then
	rel="$TMP/www/me/lastgasp/releases/download/v9.9.9"
	mkdir -p "$rel" "$TMP/www/api/v1/repos/me/lastgasp/releases"
	# The fake agent writes a key when asked to enroll, like the real one.
	cat > "$TMP/fake-agent" <<'AGENT'
#!/bin/sh
if [ "${1:-}" = enroll ]; then
	while [ $# -gt 0 ]; do [ "$1" = -key-file ] && echo cafe0000cafe0000cafe0000cafe0000 > "$2"; [ "${LASTGASP_TOKEN:-}" = bad ] && exit 1; shift; done
	exit 0
fi
exit 0
AGENT
	case $(uname -m) in x86_64) arch=amd64 ;; aarch64) arch=arm64 ;; *) arch=arm ;; esac
	cp "$TMP/fake-agent" "$rel/lastgasp-agent-linux-$arch"
	cp "$DIR/lastgasp-agent.service" "$rel/"
	(cd "$rel" && sha256sum "lastgasp-agent-linux-$arch" lastgasp-agent.service > SHA256SUMS)
	echo '{"id":1,"tag_name":"v9.9.9","name":"v9.9.9"}' > "$TMP/www/api/v1/repos/me/lastgasp/releases/latest"
	port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
	python3 -m http.server -b 127.0.0.1 -d "$TMP/www" "$port" >/dev/null 2>&1 &
	web=$!
	for _ in 1 2 3 4 5 6 7 8 9 10; do curl -fs "http://127.0.0.1:$port/" >/dev/null 2>&1 && break; sleep 0.2; done
	repo="http://127.0.0.1:$port/me/lastgasp"
	# Piped like the one line install, so there is no local binary or unit next to the script.
	piped() { (cd "$TMP" && sh -s -- "$@" < "$DIR/install-agent.sh" > "$TMP/out" 2>&1); }
	rm -rf "$ROOT"
	piped --repo "$repo" -s logs:5140 -t lgj_abc || fail "download install: $(cat "$TMP/out")"
	check "$TMP/out" "downloading lastgasp-agent v9.9.9"
	cmp -s "$ROOT/usr/local/sbin/lastgasp-agent" "$TMP/fake-agent" || fail "downloaded binary not installed"
	[ "$(cat "$ROOT/etc/lastgasp/agent.key")" = cafe0000cafe0000cafe0000cafe0000 ] || fail "enrolled key not stored"
	grep -q "server key file" "$TMP/out" && fail "key line printed after enrollment"
	piped --repo "$repo" -V v9.9.9 -s logs:5140 -t bad && fail "failed enrollment accepted"
	piped --repo "$repo" -s logs:5140 -t lgj_abc -k 00112233445566778899aabbccddeeff && fail "--token with --key accepted"
	# The token can come from the environment, so it stays out of ps.
	rm -rf "$ROOT"
	(export LASTGASP_TOKEN=lgj_abc; piped --repo "$repo" -s logs:5140) || fail "token from env: $(cat "$TMP/out")"
	[ "$(cat "$ROOT/etc/lastgasp/agent.key")" = cafe0000cafe0000cafe0000cafe0000 ] || fail "env token did not enroll"
	(export LASTGASP_TOKEN=bad; piped --repo "$repo" -s logs:5140) && fail "bad env token accepted"
	# Without any checksum tool the download is refused, not installed unchecked.
	mkdir "$TMP/path"
	for c in /usr/bin/* /bin/*; do
		case ${c##*/} in sha256sum|shasum|openssl) continue ;; esac
		[ -e "$TMP/path/${c##*/}" ] || ln -s "$c" "$TMP/path/${c##*/}"
	done
	(PATH="$TMP/path"; piped --repo "$repo" -V v9.9.9 -s logs:5140) && fail "download accepted without a checksum tool"
	check "$TMP/out" "sha256sum, shasum or openssl is needed"
	if command -v openssl >/dev/null 2>&1; then
		ln -s "$(command -v openssl)" "$TMP/path/openssl"
		(PATH="$TMP/path"; piped --repo "$repo" -V v9.9.9 -s logs:5140) || fail "openssl fallback: $(cat "$TMP/out")"
	fi
	# A changed download is refused.
	echo tampered >> "$rel/lastgasp-agent-linux-$arch"
	piped --repo "$repo" -V v9.9.9 -s logs:5140 && fail "tampered binary accepted"
	check "$TMP/out" "checksum mismatch"
	piped --repo "$repo" -V v0.0.1 -s logs:5140 && fail "missing release accepted"
	kill "$web"
else
	echo "install-agent_test: python3 or curl not found, download not tested"
fi

if [ "$fails" -gt 0 ]; then
	echo "install-agent_test: $fails failures" >&2
	exit 1
fi
echo "ok  	deploy/install-agent.sh"
