<p align="center">
  <img src="docs/assets/header.jpg" alt="lastgasp" width="800">
</p>

<p align="center">
  <strong>A kernel log shipper for machines that are about to die.</strong><br>
  The last words of a crashing, freezing or failing Linux machine, saved somewhere else.
</p>

<p align="center">
  A small agent reads the kernel log from <code>/dev/kmsg</code> and pstore and sends every line
  over encrypted UDP to a server. The server stores the logs, notices missing packets, turns
  crashes, reboots and kernel errors into incidents and sends alerts.
</p>

<p align="center">
  <a href="https://git.fferrando.cc/rdfilippo/lastgasp/actions?workflow=ci.yaml"><img alt="CI" src="https://git.fferrando.cc/rdfilippo/lastgasp/actions/workflows/ci.yaml/badge.svg?label=ci"></a>
  <a href="https://git.fferrando.cc/rdfilippo/lastgasp/releases"><img alt="Release" src="https://img.shields.io/gitea/v/release/rdfilippo/lastgasp?gitea_url=https%3A%2F%2Fgit.fferrando.cc&label=release&color=2ea043"></a>
  <a href="go.mod"><img alt="Go" src="https://img.shields.io/badge/go-1.27-00ADD8?logo=go&logoColor=white"></a>
  <img alt="Platforms" src="https://img.shields.io/badge/agent-linux%20amd64%20%7C%20arm64%20%7C%20arm-1d2840">
  <a href="LICENSE.txt"><img alt="License: GPL-3.0" src="https://img.shields.io/badge/license-GPL--3.0-blue"></a>
</p>

<p align="center">
  <a href="#why-lastgasp">Why</a> ·
  <a href="#features">Features</a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="#how-it-works">How it works</a> ·
  <a href="#documentation">Documentation</a> ·
  <a href="#limits">Limits</a> ·
  <a href="CONTRIBUTING.md">Contributing</a> ·
  <a href="#license">License</a>
</p>

---

## Why lastgasp?

A server freezes, reboots and comes back with nothing useful in the logs. The kernel probably
printed something right before it went down, but journald was writing to the same disk that was
failing, or the box locked up before anything got flushed.

lastgasp sends the last words of a machine somewhere else, every time. The agent assumes the
worst: dead disk, broken DNS, no memory, kernel panic. It is a static binary that reads its
config once at start, locks itself in RAM, never touches the disk again and keeps going.

|                        | journald / syslog on disk          | lastgasp                                              |
| ---------------------- | ---------------------------------- | ----------------------------------------------------- |
| Disk dies              | last lines lost with the disk      | lines already on the server                           |
| Kernel panic           | nothing flushed                    | panic text from pstore after reboot, or live with netconsole |
| Lost network packets   | not noticed                        | sequence numbers, acks and resends; gaps are counted  |
| Someone sniffs traffic | plain text with remote syslog      | encrypted, with keys that change every 2 minutes      |
| Crash noticed          | when someone looks                 | incident and alert (webhook, Telegram, email)         |

## Features

### Agent (`lastgasp-agent`)

- **Kernel log and pstore.** Reads `/dev/kmsg` and, after a crash, the logs the kernel saved in
  pstore, also when `systemd-pstore` already moved them.
- **Encrypted UDP.** One line per packet, with keys from a Noise handshake that change every
  2 minutes, so a key stolen later cannot open old traffic.
- **Nothing lost on the way.** Lines are held in memory until a server answers, kept until a
  server confirms them, and sent again when lost.
- **Survives restarts and reboots.** Unconfirmed lines go to a RAM-only stash under `/run` for
  agent restarts and upgrades, and to pmsg (ramoops) for warm reboots.
- **Userspace logs too.** Optional journald lines, on their own queue so they never hold back
  kernel lines.
- **Hard to kill.** Survives dead disks, DNS outages, OOM, journald hangs and its own bugs.
- **One line install.** From the release page, with a join token: the agent gets its own key, no
  key copying.

### Server (`lastgasp-server`)

- **Storage.** SQLite or PostgreSQL, with deduplication and retention by age, by level or by
  record count.
- **Gap tracking.** Missing, late and duplicate packets counted per machine, so it is clear when
  something is not seen.
- **Incidents.** Crashes, reboots, silent hosts and kernel errors (panics, oopses, lockups, OOM
  kills, I/O errors) become incidents. Hosts that keep rebooting are noticed, and many hosts
  going down at once send one alert.
- **Netconsole.** Takes the kernel netconsole too, so a panic arrives while it happens, even
  without pstore.
- **Watches itself.** Opens incidents when its database, queue, alerts or keys have problems.
- **Alerts.** Webhooks (Slack, Mattermost, Alertmanager, or plain JSON with an HMAC signature),
  Telegram and email. Acknowledge or resolve with a note, silence for maintenance windows.
- **Web UI and API.** Live logs, a JSON API, Prometheus metrics, health checks, and login with
  sessions, users and API tokens.
- **Kubernetes.** A Helm chart with the agent on every node.

## Quick start

Start the server. Docker is shown here; release binaries and compose setups are in
[Getting started](docs/getting-started.md). `-agent-address` is where the machines reach it:

```sh
docker run -d --name lastgasp -p 5140:5140/udp -p 127.0.0.1:8080:8080 -v lastgasp:/var/lib/lastgasp \
  git.fferrando.cc/rdfilippo/lastgasp-server:latest \
  -listen :5140 -http :8080 -db /var/lib/lastgasp/lastgasp.db -agent-address 10.0.0.5:5140
```

Open `http://127.0.0.1:8080`, click **Add agents** in the Agents section, and run the command it
gives on the machine to watch (Linux, root):

```sh
curl -fsSL https://git.fferrando.cc/rdfilippo/lastgasp/releases/download/v1.0.0/install-agent.sh | sudo sh -s -- --server 10.0.0.5:5140 --token lgj_...
```

The host shows up with its whole boot log. To check that it is live, run
`echo hello > /dev/kmsg` on the agent machine and watch it show up.

To see an incident, on a **test** machine:

```sh
echo "<3>BUG: just testing" > /dev/kmsg                            # kernel error incident
echo 1 > /proc/sys/kernel/sysrq; echo c > /proc/sysrq-trigger     # real kernel panic, crash incident
```

> **Note:** key files still work for setups that prefer copying keys by hand, see
> [Keys and enrollment](docs/server.md#keys-and-enrollment). On Kubernetes, use the
> [Helm chart](docs/kubernetes.md).

## How it works

```text
 /dev/kmsg, pstore ──► agent ── encrypted UDP ──► server ──► SQLite / PostgreSQL
                         ▲                          │
                         └──────── acks ────────────┤──► incidents ──► webhooks, email
                                                    └──► web UI, API, /metrics
```

Every packet has a sequence number, so the server knows exactly what it missed. The server
answers heartbeats with acks that say what arrived, the agent sends again what got lost, and it
only sends logs while a server is answering. When a machine reboots, the server waits a bit for
the crash logs from pstore, then decides whether it was a clean reboot or a crash.

The packet format and the rest of the design are in [How it works](docs/how-it-works.md).

## Documentation

| Guide                                                 | What's inside                                                         |
| ----------------------------------------------------- | --------------------------------------------------------------------- |
| [Getting started](docs/getting-started.md)            | First server, first agent in one line, check that logs arrive         |
| [Agent](docs/agent.md)                                | Install script, enrollment, flags, stash, sizing, troubleshooting     |
| [Server](docs/server.md)                              | Keys, systemd, Docker, PostgreSQL, retention, netconsole, reverse proxy |
| [Kubernetes](docs/kubernetes.md)                      | Helm chart: agent DaemonSet, server, keys, Prometheus                 |
| [Incidents and alerts](docs/incidents-and-alerts.md)  | Incident kinds, rules, webhooks, email, testing incidents             |
| [Web UI and API](docs/web-ui-and-api.md)              | Login, roles, JSON API with examples, metrics                         |
| [Operations](docs/operations.md)                      | Production checklist, Prometheus rules, backups, upgrades, limits     |
| [How it works](docs/how-it-works.md)                  | Design, packets, acks, missing packets, deduplication                 |
| [Forward secrecy](docs/forward-secrecy.md)            | The Noise handshake of version 5 packets                              |

Ready to use Docker Compose setups (SQLite, PostgreSQL, Telegram, Alertmanager, HTTPS) are in
[`examples/`](examples/README.md). The full index is in [docs/](docs/README.md).

## Limits

- Lost lines are sent again only while they are still in the agent buffer (or its stash, after a
  restart). A long outage at full rate can still lose some; they show up as missing.
- A kernel panic stops everything at once, the agent included. The panic message only arrives
  through pstore or netconsole, so set up a pstore backend (EFI or ramoops) on machines that
  matter.
- On PostgreSQL, the size limit counts record rows only, not indexes or space waiting for vacuum.
- Userspace logs come from journald only (`-journal`), not from plain syslog.
- The web UI needs HTTPS in front of it (a reverse proxy) when used over the network.

More in [Known limits](docs/operations.md#known-limits) and [Open work](docs/open-work.md).

## Contributing

Bug reports and pull requests are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) for the
development setup, the tests and the code layout. Notable changes, and the actions
needed on upgrade, are listed in [CHANGELOG.md](CHANGELOG.md).

```sh
make            # bin/lastgasp-agent and bin/lastgasp-server
make test       # Go tests with the race detector, plus script, examples and Helm chart tests
```

## License

lastgasp is free software, released under the [GNU General Public License v3.0](LICENSE.txt).
