<div align="center">
  <img src="docs/logo.png" width="200" alt="lastgasp logo">
</div>

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
- survives dead disks, DNS outages, OOM, journald hangs and its own bugs

**Server** (`lastgasp-server`)

- stores logs in SQLite or PostgreSQL and removes duplicates
- counts missing, late and duplicate packets per machine, so you know when you're not seeing everything
- turns crashes, reboots, silent hosts and kernel errors (panics, oopses, lockups, OOM kills, I/O errors...) into incidents
- sends alerts to webhooks (Slack, Mattermost, or plain JSON with an HMAC signature) and email
- web UI with live logs, a JSON API, Prometheus metrics, and login with users and API tokens

## Quick start

You need Go 1.27+ to build. The agent needs Linux and root.

```sh
make                                     # builds bin/lastgasp-agent and bin/lastgasp-server
openssl rand -hex 32 > agent.key
echo "*  $(cat agent.key)" > keys        # the server key file, "*" means any host

# server (or use docker compose, see docs/server.md)
./bin/lastgasp-server -key-file keys -db lastgasp.db -http 127.0.0.1:8080

# agent, on the machine you want to watch
scp bin/lastgasp-agent deploy/install-agent.sh deploy/lastgasp-agent.service root@db-01:/tmp/
ssh root@db-01 /tmp/install-agent.sh -s my-server:5140 -k "$(cat agent.key)"
```

Open `http://127.0.0.1:8080` and you should see the host with its whole boot log. To check that it's live, run `echo hello > /dev/kmsg` on the agent machine and watch it show up.

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

Every packet has a sequence number, so the server knows exactly what it missed. The server answers heartbeats with acks, and the agent only sends logs while a server is answering. When a machine reboots, the server waits a bit for the crash logs from pstore, then decides whether it was a clean reboot or a crash.

The longer version, with the packet format and all the details, is in [docs/how-it-works.md](docs/how-it-works.md).

## Docs

Everything is in [`docs/`](docs/README.md):

- [Getting started](docs/getting-started.md): from zero to logs in the UI
- [How it works](docs/how-it-works.md): design, packets, acks, deduplication
- [Agent](docs/agent.md): install script, flags, sizing, troubleshooting
- [Server](docs/server.md): systemd, Docker, PostgreSQL, retention, reverse proxy
- [Incidents and alerts](docs/incidents-and-alerts.md): rules, webhooks, email, how to trigger test incidents
- [Web UI and API](docs/web-ui-and-api.md): login, API examples, metrics
- [Operations](docs/operations.md): production checklist, Prometheus rules, backups, upgrades

## Development

```sh
make test        # all Go tests with the race detector, plus the install script test
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
internal/server        ingest, gap tracking, retention, login, HTTP API, metrics, web UI
internal/incident      incident rules and detection, webhook and email alerts
internal/store         SQLite and PostgreSQL storage and schema upgrades
deploy/                systemd units and the agent install script
docs/                  documentation
```

## Limits

I try to be honest about what it doesn't do (yet):

- UDP has no receipts. Acks tell the agent a server is listening, but if the server dies, the agent needs about 15 seconds to notice, and what it sent in between is gone (it shows up as missing, at least).
- A kernel panic stops everything instantly, the agent included. The panic message itself only reaches you through pstore, so set up a pstore backend (EFI or ramoops) on machines you care about.
- Retention is by age only.
- Basic auth has no logout button. Put HTTPS in front of the UI.

More in [docs/operations.md](docs/operations.md#known-limits) and [docs/open-work.md](docs/open-work.md). Issues and PRs are welcome!
