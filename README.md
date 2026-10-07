<div align="center">
  <img src="docs/logo.png" width="600" alt="lastgasp logo">
</div>

# Lastgasp

A kernel log shipper for machines that are about to die.

## Why I built this

If you've ever had a server freeze, reboot, and come back with nothing useful in the logs, you know the feeling. The kernel probably screamed something right before it went down, but journald was writing to the same disk that was failing, or the box locked up before anything got flushed. You end up guessing.

I wanted the last words of a machine to land somewhere else, every time. So I wrote `lastgasp`. It's a small agent that reads the kernel log straight from `/dev/kmsg` and fires every line over encrypted UDP to a server, and a server that stores everything, notices when something goes wrong and tells you about it.

The agent assumes the worst: dead disk, broken DNS, no memory, kernel panic. It's a static binary that reads its config once at start, locks itself in RAM, never touches the disk again, and keeps going no matter what.

## What it does

**Agent** (`lastgasp-agent`)

- reads `/dev/kmsg` and, after a crash, the logs the kernel saved in pstore
- encrypts every line with AES-256-GCM and sends it over UDP, one line per packet
- holds lines in memory until a server actually answers, so starting the agent before the server (or before you add its key) loses nothing
- keeps each line until a server confirms it got it, and sends lost lines again
- keeps unconfirmed lines in a RAM-only stash under `/run`, so an agent restart or upgrade does not lose them
- survives dead disks, DNS outages, OOM, journald hangs and its own bugs
- installs in one line from the release page, and gets its own key with a join token (no key copying)

**Server** (`lastgasp-server`)

- stores logs in SQLite or PostgreSQL, removes duplicates, and deletes old data by age, by level or by record count
- counts missing, late and duplicate packets per machine, so you know when you're not seeing everything
- turns crashes, reboots, silent hosts and kernel errors (panics, oopses, lockups, OOM kills, I/O errors...) into incidents
- watches itself and opens incidents when its database, queue, alerts or keys have problems
- sends alerts to webhooks (Slack, Mattermost, Alertmanager, or plain JSON with an HMAC signature), Telegram and email
- incident workflow: acknowledge or resolve with a note, and silences for maintenance windows
- web UI with live logs, a JSON API, Prometheus metrics, health checks, and login with sessions, users and API tokens

## Quick start

Start the server (Docker here, release binaries and compose setups in [docs/getting-started.md](docs/getting-started.md)). `-agent-address` is where your machines reach it:

```sh
docker run -d --name lastgasp -p 5140:5140/udp -p 127.0.0.1:8080:8080 -v lastgasp:/var/lib/lastgasp \
  git.fferrando.cc/rdfilippo/lastgasp-server:latest \
  -listen :5140 -http :8080 -db /var/lib/lastgasp/lastgasp.db -agent-address 10.0.0.5:5140
```

Open `http://127.0.0.1:8080`, click "add agents" in the Agents section, and run the command it gives you on the machine you want to watch (Linux, root):

```sh
curl -fsSL https://git.fferrando.cc/rdfilippo/lastgasp/releases/download/v1.0.0/install-agent.sh | sudo sh -s -- --server 10.0.0.5:5140 --token lgj_...
```

The host shows up with its whole boot log. To check that it's live, run `echo hello > /dev/kmsg` on the agent machine and watch it show up.

Want to see an incident? On a **test** machine:

```sh
echo "<3>BUG: just testing" > /dev/kmsg                            # kernel error incident
echo 1 > /proc/sys/kernel/sysrq; echo c > /proc/sysrq-trigger     # real kernel panic, crash incident
```

## How it works, in short

```text
 /dev/kmsg, pstore ──► agent ── encrypted UDP ──► server ──► SQLite / PostgreSQL
                         ▲                          │
                         └──────── acks ────────────┤──► incidents ──► webhooks, email
                                                    └──► web UI, API, /metrics
```

Every packet has a sequence number, so the server knows exactly what it missed. The server answers heartbeats with acks that say what arrived, the agent sends again what got lost, and it only sends logs while a server is answering. When a machine reboots, the server waits a bit for the crash logs from pstore, then decides whether it was a clean reboot or a crash.

The longer version, with the packet format and all the details, is in [docs/how-it-works.md](docs/how-it-works.md).

Prefer copying keys around yourself? Key files still work, see [docs/server.md](docs/server.md#keys-and-enrollment).

## Docs

Everything is in [`docs/`](docs/README.md):

- [Getting started](docs/getting-started.md): from zero to logs in the UI
- [How it works](docs/how-it-works.md): design, packets, acks, deduplication
- [Agent](docs/agent.md): install script, flags, sizing, troubleshooting
- [Server](docs/server.md): systemd, Docker, PostgreSQL, retention, reverse proxy
- [Incidents and alerts](docs/incidents-and-alerts.md): rules, webhooks, email, how to trigger test incidents
- [Web UI and API](docs/web-ui-and-api.md): login, API examples, metrics
- [Operations](docs/operations.md): production checklist, Prometheus rules, backups, upgrades
- [Releasing](docs/releasing.md): CI, release files, server image

Ready to use Docker Compose setups (SQLite, PostgreSQL, Telegram, Alertmanager, HTTPS) are in [`examples/`](examples/README.md).

## Development

```sh
make             # bin/lastgasp-agent and bin/lastgasp-server, needs Go 1.27+
make test        # all Go tests with the race detector, plus the install script and examples tests
make dist VERSION=v1.2.0   # the release files in dist/
make image       # server Docker image
```

The PostgreSQL tests run when you point them at a database:

```sh
docker run -d --rm --name pg -e POSTGRES_PASSWORD=test -p 127.0.0.1:55432:5432 postgres:17-alpine
LASTGASP_TEST_PG='postgres://postgres:test@127.0.0.1:55432/postgres?sslmode=disable' go test ./internal/store/
```

Code layout:

```text
cmd/lastgasp-agent     agent binary
cmd/lastgasp-server    server binary, plus the "user" and "token" helper commands
internal/wire          packet format and encryption
internal/agent         kmsg and pstore readers, buffers, DNS cache, sender, hardening
internal/server        ingest, enrollment, gap tracking, retention, login sessions, HTTP API, metrics, web UI
internal/incident      incident rules and detection, webhook and email alerts
internal/store         SQLite and PostgreSQL storage and schema upgrades
internal/version       build version
deploy/                systemd units and the agent install script
.forgejo/              CI and release workflows
examples/              Docker Compose setups of the server
docs/                  documentation
```

## Limits

I try to be honest about what it doesn't do (yet):

- Lost lines are sent again only while they are still in the agent buffer (or its stash, after a restart). A long outage at full rate can still lose some (they show up as missing, at least).
- A kernel panic stops everything instantly, the agent included. The panic message itself only reaches you through pstore, so set up a pstore backend (EFI or ramoops) on machines you care about.
- Retention limits count records, not bytes.
- Only kernel logs, no journald or syslog lines (yet).
- The web UI needs HTTPS in front of it (a reverse proxy) when used over the network.

More in [docs/operations.md](docs/operations.md#known-limits) and [docs/open-work.md](docs/open-work.md). Issues and PRs are welcome!
