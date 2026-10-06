#!/bin/sh
# Installs lastgasp-agent as a systemd service on this machine. Run as root.
# Set ROOT to install into another directory tree (used by tests, skips systemctl).
set -eu

ROOT=${ROOT:-}
BIN_DIR=/usr/local/sbin
CONF_DIR=/etc/lastgasp
UNIT_DIR=/etc/systemd/system
UNIT=lastgasp-agent.service
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

usage() {
	cat <<EOF
Usage:
  $0 --server HOST:PORT[,HOST:PORT...] [options]
  $0 --uninstall [--purge]

Options:
  -s, --server LIST    servers the agent sends to (required to install)
  -k, --key HEX        agent key in hex (at least 32 characters)
      --key-file PATH  read the agent key from a file
  -n, --hostname NAME  name sent to the server (default: kernel hostname)
  -b, --binary PATH    agent binary (default: bin/lastgasp-agent or ./lastgasp-agent)
  -a, --args "FLAGS"   extra agent flags, for example "-dns 10.0.0.53:53 -buffer 32768"
      --no-start       install and enable, but do not start or restart now
      --no-systemd     only copy files, do not call systemctl
      --uninstall      stop the service and remove the binary and unit
      --purge          with --uninstall, also remove $CONF_DIR (the key)
  -h, --help           show this help

Without --key or --key-file, an existing key is kept, or a new one is created.
EOF
}

die() { echo "install-agent: $*" >&2; exit 1; }
log() { echo "install-agent: $*"; }

servers="" key="" key_file="" host="" binary="" extra=""
start=1 systemd=1 uninstall=0 purge=0
while [ $# -gt 0 ]; do
	case $1 in
	-s|--server) servers=${2:?}; shift ;;
	-k|--key) key=${2:?}; shift ;;
	--key-file) key_file=${2:?}; shift ;;
	-n|--hostname) host=${2:?}; shift ;;
	-b|--binary) binary=${2:?}; shift ;;
	-a|--args) extra=${2?}; shift ;;
	--no-start) start=0 ;;
	--no-systemd) systemd=0 ;;
	--uninstall) uninstall=1 ;;
	--purge) purge=1 ;;
	-h|--help) usage; exit 0 ;;
	*) usage >&2; die "unknown option: $1" ;;
	esac
	shift
done

[ -n "$ROOT" ] && systemd=0
if [ -z "$ROOT" ] && [ "$(id -u)" -ne 0 ]; then
	die "must run as root"
fi
if [ "$systemd" = 1 ] && ! command -v systemctl >/dev/null 2>&1; then
	die "systemctl not found, use --no-systemd and start the agent another way"
fi

if [ "$uninstall" = 1 ]; then
	if [ "$systemd" = 1 ]; then
		systemctl disable --now "$UNIT" 2>/dev/null || true
	fi
	rm -f "$ROOT$UNIT_DIR/$UNIT" "$ROOT$BIN_DIR/lastgasp-agent"
	rm -rf "$ROOT$UNIT_DIR/$UNIT.d"
	[ "$purge" = 1 ] && rm -rf "$ROOT$CONF_DIR"
	[ "$systemd" = 1 ] && systemctl daemon-reload
	log "removed"
	exit 0
fi

# Check the input before touching the system.
[ -n "$servers" ] || { usage >&2; die "--server is required"; }
for s in $(echo "$servers" | tr ',' ' '); do
	case $s in
	*:[0-9]*) ;;
	*) die "server '$s' must be host:port" ;;
	esac
done
case $servers in *[!A-Za-z0-9.:,_\[\]-]*) die "server list has invalid characters" ;; esac
if [ -n "$host" ]; then
	case $host in *[!A-Za-z0-9._-]*) die "hostname may only use letters, digits, '.', '_' and '-'" ;; esac
	[ ${#host} -le 255 ] || die "hostname longer than 255 characters"
fi

if [ -z "$binary" ]; then
	for b in "$SCRIPT_DIR/../bin/lastgasp-agent" "$SCRIPT_DIR/lastgasp-agent" ./lastgasp-agent; do
		[ -f "$b" ] && { binary=$b; break; }
	done
fi
[ -n "$binary" ] && [ -f "$binary" ] || die "agent binary not found, run 'make agent' or use --binary"
# A binary for the wrong CPU fails here instead of in the service.
"$binary" -h >/dev/null 2>&1 || die "$binary does not run on this machine"
[ -e /dev/kmsg ] || log "warning: /dev/kmsg not found, the agent will keep retrying"

if [ -n "$key_file" ]; then
	key=$(cat "$key_file") || die "cannot read $key_file"
fi
key=$(echo "$key" | tr -d ' \n\r\t')
if [ -n "$key" ]; then
	case $key in *[!0-9a-fA-F]*) die "key is not hex" ;; esac
	[ ${#key} -ge 32 ] && [ $((${#key} % 2)) -eq 0 ] || die "key must be at least 16 bytes (32 hex characters)"
fi

umask 077
mkdir -p "$ROOT$CONF_DIR" "$ROOT$BIN_DIR" "$ROOT$UNIT_DIR/$UNIT.d"
chmod 700 "$ROOT$CONF_DIR"
new_key=0
if [ -n "$key" ]; then
	echo "$key" > "$ROOT$CONF_DIR/agent.key"
elif [ ! -s "$ROOT$CONF_DIR/agent.key" ]; then
	od -An -tx1 -N32 /dev/urandom | tr -d ' \n' > "$ROOT$CONF_DIR/agent.key"
	echo >> "$ROOT$CONF_DIR/agent.key"
	new_key=1
fi
chmod 600 "$ROOT$CONF_DIR/agent.key"

# Copy then rename, so a running agent never sees a half written binary.
umask 022
cp "$binary" "$ROOT$BIN_DIR/.lastgasp-agent.new"
chmod 755 "$ROOT$BIN_DIR/.lastgasp-agent.new"
mv -f "$ROOT$BIN_DIR/.lastgasp-agent.new" "$ROOT$BIN_DIR/lastgasp-agent"
cp "$SCRIPT_DIR/$UNIT" "$ROOT$UNIT_DIR/$UNIT"
chmod 644 "$ROOT$UNIT_DIR/$UNIT"

# The flags live in a drop-in, not an EnvironmentFile: systemd keeps it in memory,
# so a restart does not need to read config from a failing disk.
cmd="$BIN_DIR/lastgasp-agent -server $servers -key-file $CONF_DIR/agent.key"
[ -n "$host" ] && cmd="$cmd -hostname $host"
[ -n "$extra" ] && cmd="$cmd $extra"
# systemd expands %, $ and \ in ExecStart, so they are escaped to reach the agent as typed.
cmd=$(printf '%s\n' "$cmd" | sed -e 's/\\/\\\\/g' -e 's/\$/$$/g' -e 's/%/%%/g')
cat > "$ROOT$UNIT_DIR/$UNIT.d/10-install.conf" <<EOF
# Written by install-agent.sh, run it again to change these flags.
[Service]
ExecStart=
ExecStart=$cmd
EOF
chmod 644 "$ROOT$UNIT_DIR/$UNIT.d/10-install.conf"
log "installed $BIN_DIR/lastgasp-agent and $UNIT_DIR/$UNIT"

if [ "$systemd" = 1 ]; then
	systemctl daemon-reload
	systemctl enable "$UNIT" >/dev/null
	if [ "$start" = 1 ]; then
		systemctl restart "$UNIT"
		sleep 1
		systemctl is-active --quiet "$UNIT" || die "service did not start, see: journalctl -u $UNIT"
		log "service is running"
	fi
fi

if [ "$new_key" = 1 ]; then
	name=${host:-$(cat /proc/sys/kernel/hostname 2>/dev/null || hostname)}
	log "created a new key. Add this line to the server key file:"
	echo "$name $(cat "$ROOT$CONF_DIR/agent.key")"
fi
