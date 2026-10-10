# Kubernetes

The Helm chart in `deploy/helm/lastgasp` runs the agent as a DaemonSet on every node and the server (web UI, API, UDP ingest) as a Deployment with one replica. Each release pushes the chart, the server image and the agent image to the container registry.

## Install

```sh
helm install lastgasp oci://git.fferrando.cc/rdfilippo/lastgasp --version 1.2.0 -n lastgasp --create-namespace
kubectl -n lastgasp port-forward svc/lastgasp-http 8080:8080
```

Open `http://127.0.0.1:8080`: every node shows up under its node name with its boot log. From a checkout, use `helm install lastgasp deploy/helm/lastgasp` instead.

## What gets installed

| Object | Does |
| --- | --- |
| DaemonSet `<release>-agent` | one agent per node, control plane and tainted nodes included |
| Deployment `<release>-server` | the server, 0 or 1 replica, `Recreate` updates |
| Service `<release>-udp` | agent packets, UDP 5140 |
| Service `<release>-http` | web UI, API and `/metrics`, TCP 8080 |
| Secret `<release>-key` | the shared agent key and the server key file. Left out when agents enroll and `key.extraLines` is empty: the server then runs without a key file |
| PersistentVolumeClaim `<release>-data` | the SQLite database. Kept on `helm uninstall` |
| Ingress, ServiceMonitor, PrometheusRule, ConfigMap | only when turned on |

## Keys

The chart makes one random key, mounts it into every agent and adds a `*` line with it to the server key file. The key is kept on `helm upgrade`. No join token is needed.

To bring your own key, create a secret with two entries and set `key.existingSecret`:

```sh
key=$(openssl rand -hex 32)
kubectl -n lastgasp create secret generic lastgasp-key --from-literal=agent.key=$key --from-literal=keys="*  $key"
```

With one shared key, any node can send records as any other node. To give each node its own key, make a join token in the web UI (Agents, set a long expiry and no use limit, as new nodes use it too), store it in a secret and set `agent.enroll.tokenSecret.name`:

```sh
kubectl -n lastgasp create secret generic lastgasp-join --from-literal=token=lgj_...
helm upgrade lastgasp oci://git.fferrando.cc/rdfilippo/lastgasp -n lastgasp --reuse-values --set agent.enroll.tokenSecret.name=lastgasp-join
```

An init container then enrolls each node once and keeps its key in `agent.enroll.keyDir` (`/var/lib/lastgasp`) on the node, and the server key file loses its `*` line. Without `key.extraLines` and `key.existingSecret`, no key secret is made at all. A node holding the token can only enroll names that are not enrolled yet, so it cannot take over another node. After a node is reinstalled, its old key is gone: revoke the node in the web UI, and the agent pod enrolls again on its next restart.

Machines outside the cluster can use their own keys: add `host hexkey` lines with `key.extraLines`, or enroll them with a join token from the UI as usual. For that, expose the UDP service (`server.service.udp.type: LoadBalancer` or `NodePort`) and set `server.agentAddress` to the address they reach.

## The agent pod

| Setting | Why |
| --- | --- |
| `privileged: true` | the container runtime allows `/dev/kmsg` only to privileged containers. It also gives `CAP_SYSLOG` and `CAP_IPC_LOCK` for reading the log and locking memory |
| hostPath `/dev/kmsg`, read only | the kernel log of the node. Left out with `agent.kmsgHostPath: false` |
| hostPath `/sys/fs/pstore`, read only | crash logs from the previous boot. Turn off with `agent.pstore: false` on nodes without pstore, or the pod does not start |
| hostPath `/run/lastgasp` | the stash. `/run` on the node is tmpfs, so unconfirmed records survive an agent restart or upgrade but not a reboot |
| `-hostname=$(NODE_NAME)` | logs are grouped by node name, not by pod name |
| `priorityClassName: system-node-critical` | the agent is scheduled first and is the last one the OOM killer picks. It also sets its own `oom_score_adj` to -1000 |
| tolerations `operator: Exists` | runs on every node, whatever its taints |

### Without a privileged container

A privileged agent is root on every node. A device plugin can give the container `/dev/kmsg` instead, like [generic-device-plugin](https://github.com/squat/generic-device-plugin) started with `--device '{"name": "kmsg", "groups": [{"paths": [{"path": "/dev/kmsg"}]}]}'`, which adds the `devic.es/kmsg` resource (the name follows its `--domain` flag). The agent then needs only three capabilities: `SYSLOG` to read the log, `IPC_LOCK` to lock its memory and `SYS_RESOURCE` for its memory lock limit and OOM score.

```yaml
agent:
  kmsgHostPath: false
  # Needed on SELinux nodes (like RHEL, Alma, Rocky, Fedora), where container_t may not read
  # /dev/kmsg and pstore or write the host paths. Ignored on nodes without SELinux.
  podSecurityContext:
    seLinuxOptions:
      type: spc_t
  securityContext:
    privileged: false
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
    runAsUser: 0
    capabilities:
      drop: [ALL]
      add: [SYSLOG, IPC_LOCK, SYS_RESOURCE]
    seccompProfile:
      type: RuntimeDefault
  resources:
    requests:
      cpu: 10m
      memory: 96Mi
    limits:
      memory: 128Mi
      devic.es/kmsg: 1
```

On nodes without SELinux, leave `podSecurityContext` out or keep it: the runtime ignores the SELinux type there, so one set of values fits a mixed cluster. `spc_t` turns off SELinux checks for the agent only. The capability, seccomp and device limits still apply. A policy module made with udica can replace it when stricter rules are needed.

The agent sends to `<release>-udp.<namespace>.svc.cluster.local.:5140`. It looks the address up once and keeps it when DNS fails later, so a broken cluster DNS does not stop it.

`agent.hostNetwork: true` sends from the node network instead of the pod network, so a broken CNI on a dying node does not cut the agent off. The service address still needs kube-proxy, so pair it with `agent.server` set to an address the node reaches directly, like a LoadBalancer IP.

Agents send version 5 packets with forward secrecy (`agent.forwardSecrecy: true`, see [forward-secrecy.md](forward-secrecy.md)). The chart installs agent and server of the same release, so this only needs turning off when the agents send to an older server outside the cluster.

If `systemd-pstore` runs on the nodes, it moves crash files out of `/sys/fs/pstore` at boot, often before the agent starts. Disable it on the nodes (`systemctl mask systemd-pstore`) to get crash logs.

## Server

| Value | Default | Meaning |
| --- | --- | --- |
| `server.replicas` | 1 | 0 or 1. The server keeps per-host state in memory, so a second replica would see half of the packets of each host and report false gaps and silent hosts |
| `server.retain` | 720h | `-retain` |
| `server.database.url` | | a `postgres://` URL. Empty: SQLite on the volume |
| `server.database.passwordSecret` | | secret and key passed as `PGPASSWORD` |
| `server.persistence.*` | 5Gi, ReadWriteOnce | the SQLite volume |
| `server.auth.existingSecret` | | secret with an `auth` entry (the auth file). Set it before exposing the UI |
| `server.rules` | | incident rules file content |
| `server.publicURL` | | `-public-url`, for links in alerts |
| `server.requireForwardSecrecy` | false | `-require-forward-secrecy`: refuse packets before version 5. Turn on once every agent, in and outside the cluster, sends version 5 |
| `server.extraArgs` | | more server flags, like `-alert-webhook=...` |
| `server.ingress.*` | off | an Ingress to the web UI. Set `-auth-proxy-header` and `-auth-trusted-proxies` in `extraArgs` for real client addresses |

The auth file, made with `lastgasp-server user` (see [web-ui-and-api.md](web-ui-and-api.md#login)):

```sh
docker run --rm -i git.fferrando.cc/rdfilippo/lastgasp-server user alice admin < password.txt > auth
kubectl -n lastgasp create secret generic lastgasp-auth --from-file=auth
```

## Prometheus

Off by default. `metrics.enabled: true` turns on:

| Value | Default | Adds |
| --- | --- | --- |
| `metrics.serviceMonitor.enabled` | true | a ServiceMonitor for the Prometheus Operator. Add the labels your Prometheus selects with `metrics.serviceMonitor.labels` |
| `metrics.annotations` | false | `prometheus.io/scrape` annotations on the HTTP service, for Prometheus setups without the operator |
| `metrics.prometheusRule.enabled` | false | the alert rules from [operations.md](operations.md#monitoring) as a PrometheusRule |
| `metrics.requireAuth` | false | `-auth-metrics`. Needs `server.auth.existingSecret` and `metrics.tokenSecret` with a viewer API token |

```sh
helm upgrade lastgasp oci://git.fferrando.cc/rdfilippo/lastgasp -n lastgasp --reuse-values \
  --set metrics.enabled=true --set metrics.prometheusRule.enabled=true \
  --set metrics.serviceMonitor.labels.release=kube-prometheus-stack
```

## Agents only

To send the nodes of a cluster to a server that runs elsewhere:

```sh
helm install lastgasp oci://git.fferrando.cc/rdfilippo/lastgasp -n lastgasp --create-namespace \
  --set server.enabled=false --set agent.server=logs.example.net:5140 --set key.existingSecret=lastgasp-key
```

The secret needs `agent.key` only, and the server needs a matching `*` line (or one line per node name) in its key file.

## Upgrades

`helm upgrade` updates the server and the agents together. Agents hold records while the server restarts, and the DaemonSet replaces them one node at a time. The old agent pod stops before the new one starts, so the new one sends the records still in the stash.
