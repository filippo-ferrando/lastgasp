#!/bin/sh
# Checks the Helm chart: lint, rendered objects for several value sets, and that every flag passed
# to the server and the agent exists. Skips itself when helm is missing. Run from the repository root.
# HELM may hold another helm command, like "docker run --rm -v $PWD:$PWD -w $PWD alpine/helm".
set -eu

CHART=deploy/helm/lastgasp
HELM=${HELM:-helm}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
fails=0

fail() { echo "FAIL chart: $*" >&2; fails=$((fails + 1)); }
has() { grep -qF -- "$2" "$1" || fail "$1: missing '$2'"; }
hasnot() { ! grep -qF -- "$2" "$1" || fail "$1: unexpected '$2'"; }
render() { out=$1; shift; $HELM template lg "$CHART" -n mon "$@" > "$TMP/$out" 2>&1 || fail "render $out: $(cat "$TMP/$out")"; }
refuse() { msg=$1; shift; if $HELM template lg "$CHART" "$@" > "$TMP/err" 2>&1; then fail "rendered with $*"; else has "$TMP/err" "$msg"; fi; }

if ! $HELM version >/dev/null 2>&1; then
	echo "chart: helm not found, skipped"
	exit 0
fi

$HELM lint "$CHART" > "$TMP/lint" 2>&1 || fail "lint: $(cat "$TMP/lint")"

# Defaults: agent on every node with access to the kernel log, one server with SQLite and a shared key.
render default
d="$TMP/default"
for s in "kind: DaemonSet" "kind: Deployment" "kind: PersistentVolumeClaim" "name: lg-lastgasp-udp" "name: lg-lastgasp-http" \
	"privileged: true" "path: /dev/kmsg" "type: CharDevice" "path: /sys/fs/pstore" "path: /var/lib/systemd/pstore" "path: /run/lastgasp" \
	"- -hostname=\$(NODE_NAME)" "fieldPath: spec.nodeName" "- -server=lg-lastgasp-udp.mon.svc.cluster.local.:5140" \
	"- operator: Exists" "priorityClassName: system-node-critical" "replicas: 1" "type: Recreate" \
	"- -db=/var/lib/lastgasp/lastgasp.db" "- -key-file=/etc/lastgasp/key/keys" "protocol: UDP"; do
	has "$d" "$s"
done
hasnot "$d" "kind: ServiceMonitor"
hasnot "$d" "forward-secrecy"
hasnot "$d" "prometheus.io/scrape"
key=$(sed -n 's/^  agent\.key: //p' "$d" | base64 -d)
echo "$key" | grep -Eq '^[0-9a-f]{64}$' || fail "generated key is not 64 hex characters: $key"
sed -n 's/^  keys: //p' "$d" | base64 -d | grep -q "^\*  $key$" || fail "server key file has no '*' line for the agent key"

# Metrics are off by default, and each part turns on with its value.
render metrics --set metrics.enabled=true
has "$TMP/metrics" "kind: ServiceMonitor"
hasnot "$TMP/metrics" "kind: PrometheusRule"
render rules --set metrics.enabled=true --set metrics.prometheusRule.enabled=true --set metrics.annotations=true \
	--set metrics.serviceMonitor.enabled=false
has "$TMP/rules" "kind: PrometheusRule"
has "$TMP/rules" 'summary: "{{ $labels.host }} sent nothing for 5 minutes"'
has "$TMP/rules" 'up{job="lastgasp"}'
has "$TMP/rules" 'reason="replay"'
has "$TMP/rules" 'prometheus.io/scrape: "true"'
hasnot "$TMP/rules" "kind: ServiceMonitor"

# A size limit is passed only when set.
hasnot "$d" "retain-bytes"
render size --set server.retainBytes=4GiB
has "$TMP/size" "- -retain-bytes=4GiB"

# New features are off by default, apart from the incident flags.
for s in "netconsole" "journal" "path: /dev/pmsg0"; do hasnot "$d" "$s"; done
has "$d" "- -pmsg="
has "$d" "- -flap-count=3"
has "$d" "- -group-min-hosts=3"

# Netconsole: a UDP service that keeps source addresses, and the hosts file.
render nc --set server.netconsole.enabled=true --set server.netconsole.from=192.168.10.0/24 \
	--set-string 'server.netconsole.hosts=192.168.10.100 magi'
for s in "name: lg-lastgasp-netconsole" "externalTrafficPolicy: Local" "type: NodePort" "- -netconsole-listen=:6666" \
	"- -netconsole-from=192.168.10.0/24" "- -netconsole-hosts=/etc/lastgasp/netconsole/hosts" "192.168.10.100 magi" \
	"containerPort: 6666"; do
	has "$TMP/nc" "$s"
done
refuse "server.netconsole needs from and hosts" --set server.netconsole.enabled=true

# pmsg and journal: the device, the journal image and the node journal.
render jr --set agent.pmsg=true --set agent.journal.enabled=true --set agent.journal.priority=err --set agent.journal.persistent=false \
	--set agent.enroll.tokenSecret.name=join
for s in "- -pmsg=/dev/pmsg0" "path: /dev/pmsg0" "type: CharDevice" "lastgasp-agent-journal:" "- -journal" \
	"- -journal-priority=err" "path: /etc/machine-id" "path: /run/log/journal"; do
	has "$TMP/jr" "$s"
done
hasnot "$TMP/jr" "path: /var/log/journal"
# The enroll init container keeps the plain agent image.
sed -n '/name: enroll/,/args:/p' "$TMP/jr" | grep -q "lastgasp-agent:" || fail "enroll container must use the agent image"
refuse "agent.journal.priority must be one of" --set agent.journal.enabled=true --set agent.journal.priority=loud

# PostgreSQL: no volume claim, password from a secret.
render pg --set server.database.url='postgres://lastgasp@db:5432/lastgasp' --set server.database.passwordSecret.name=pg
has "$TMP/pg" "- -db=postgres://lastgasp@db:5432/lastgasp"
has "$TMP/pg" "name: PGPASSWORD"
hasnot "$TMP/pg" "kind: PersistentVolumeClaim"

# An existing key secret replaces the generated one.
render existing --set key.existingSecret=mykey
hasnot "$TMP/existing" "kind: Secret"
has "$TMP/existing" "secretName: mykey"

# Agents only, sending to a server outside the cluster.
render agentonly --set server.enabled=false --set agent.server=logs.example.net:5140 --set agent.hostNetwork=true
has "$TMP/agentonly" "- -server=logs.example.net:5140"
has "$TMP/agentonly" "dnsPolicy: ClusterFirstWithHostNet"
hasnot "$TMP/agentonly" "kind: Deployment"

# Enrollment: each agent gets its own key in an init container, and the server key file has no "*" line.
render enroll --set agent.enroll.tokenSecret.name=join --set key.extraLines='other  '"$(printf '%064d' 0)"
e="$TMP/enroll"
for s in "initContainers:" "- enroll" "- -token-file=/etc/lastgasp-join/token" "- -if-missing" "secretName: join" \
	"path: /var/lib/lastgasp" "- -key-file=/var/lib/lastgasp/agent.key"; do
	has "$e" "$s"
done
hasnot "$e" "- -key-file=/etc/lastgasp/agent.key"
sed -n 's/^  keys: //p' "$e" | base64 -d | grep -q '^\*' && fail "enroll: server key file still has a '*' line"
hasnot "$d" "initContainers:"

# Enrollment without other keys: no key secret, and the server runs without a key file.
render enrollonly --set agent.enroll.tokenSecret.name=join
hasnot "$TMP/enrollonly" "kind: Secret"
hasnot "$TMP/enrollonly" "-key-file=/etc/lastgasp/key/keys"
hasnot "$TMP/enrollonly" "mountPath: /etc/lastgasp/key"
has "$TMP/enrollonly" "- -key-file=/var/lib/lastgasp/agent.key"
render enrollexisting --set agent.enroll.tokenSecret.name=join --set key.existingSecret=mykey
has "$TMP/enrollexisting" "- -key-file=/etc/lastgasp/key/keys"

# A device plugin gives /dev/kmsg, so the host path is left out.
render nokmsg --set agent.kmsgHostPath=false --set agent.podSecurityContext.seLinuxOptions.type=spc_t
hasnot "$TMP/nokmsg" "path: /dev/kmsg"
has "$TMP/nokmsg" "type: spc_t"
has "$d" "readOnly: true"
has "$d" "automountServiceAccountToken: false"

refuse "server.replicas must be 0 or 1" --set server.replicas=2
refuse "agent.server is required" --set server.enabled=false
refuse "metrics.requireAuth needs server.auth.existingSecret" --set metrics.enabled=true --set metrics.requireAuth=true

# Every flag the chart can pass must exist in the binaries.
CGO_ENABLED=0 go build -o "$TMP/server" ./cmd/lastgasp-server
CGO_ENABLED=0 go build -o "$TMP/agent" ./cmd/lastgasp-agent
"$TMP/server" -h 2>"$TMP/server.help" || true
"$TMP/agent" -h 2>"$TMP/agent.help" || true
all="--set server.publicURL=https://lg.example --set server.agentAddress=10.0.0.5:5140 --set server.auth.existingSecret=auth
	--set server.rules=x --set metrics.enabled=true --set metrics.requireAuth=true --set metrics.tokenSecret.name=tok
	--set agent.pstore=false --set agent.stash=false --set agent.forwardSecrecy=false --set server.requireForwardSecrecy=true
	--set server.netconsole.enabled=true --set server.netconsole.from=10.0.0.0/8 --set server.netconsole.hosts=x
	--set agent.pmsg=true --set agent.journal.enabled=true --set server.retainBytes=1G"
for part in server agent; do
	# shellcheck disable=SC2086
	render "$part.yaml" --show-only "templates/$part-$([ $part = server ] && echo deployment || echo daemonset).yaml" $all
	for flag in $(sed -n 's/^[[:space:]]*- -\([a-z][a-z-]*\).*/\1/p' "$TMP/$part.yaml" | sort -u); do
		grep -Eq "^  -$flag( |$)" "$TMP/$part.help" || fail "unknown $part flag -$flag"
	done
done
# The flags of the enroll init container must exist in "lastgasp-agent enroll".
"$TMP/agent" enroll -h 2>"$TMP/enroll.help" || true
for flag in $(sed -n '/name: enroll/,/env:/s/^[[:space:]]*- -\([a-z][a-z-]*\).*/\1/p' "$e" | sort -u); do
	grep -Eq "^  -$flag( |$)" "$TMP/enroll.help" || fail "unknown enroll flag -$flag"
done
has "$TMP/server.yaml" "- -auth-metrics"
has "$TMP/server.yaml" "- -rules=/etc/lastgasp/rules/rules"
has "$TMP/server.yaml" "- -require-forward-secrecy"
has "$TMP/agent.yaml" "- -forward-secrecy=false"
has "$TMP/agent.yaml" "- -pstore="
hasnot "$TMP/agent.yaml" "path: /sys/fs/pstore"
hasnot "$TMP/agent.yaml" "path: /var/lib/systemd/pstore"

[ "$fails" -eq 0 ] || exit 1
echo "ok  	chart"
