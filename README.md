# lastgasp

A kernel log shipper for machines that are about to die.

`lastgasp-agent` reads kernel logs straight from the kernel and sends them as encrypted UDP datagrams to `lastgasp-server`. The agent assumes the machine it runs on can fail in every possible way: a dead disk, a broken network stack, memory pressure, a crash and reboot. Its job is to get the last words out.

The server stores logs per machine, removes duplicates, finds missing packets, turns crashes and kernel errors into incidents, sends alerts to webhooks and email, and shows everything in a web UI with login and as Prometheus metrics.

## How the agent survives failures

| Failure | What the agent does |
| --- | --- |
| Disk fails | Static binary with no libc. Config, key, hostname and boot ID are read once at start. Memory is locked with `mlockall`, so no page is ever read back from disk. Logs go to stderr through a non-blocking writer and never to files. |
| DNS or `/etc/resolv.conf` gone | Addresses are cached. A failed lookup never removes a known address. `-dns ip:port` skips `resolv.conf`, and plain IPs skip DNS. |
| Network down | Records wait in a fixed size memory ring buffer (`-buffer`) and are retried. A record leaves the buffer only after a server accepted it. When the buffer is full, the oldest records are dropped and counted. |
| Kernel overwrites its buffer | `EPIPE` from `/dev/kmsg` is counted and reading continues. |
| Out of memory | `oom_score_adj` is set to -1000 and a Go memory limit is applied. |
| journald dies or hangs | `SIGPIPE` is ignored and log lines are dropped instead of blocking. |
| Internal bug | Each worker restarts after a panic. systemd restarts the process. |
| Crash and reboot | On start, the agent reads `/sys/fs/pstore` (logs the kernel saved before the crash) and sends them first, from a queue of their own sized to hold every line, so a full buffer never drops them. It also replays the whole kernel buffer. The server removes what it already has. |
| One server down | Several servers can be given with `-server a:5140,b:5140`. Every packet goes to all of them. |
| No server listening yet | The server answers each heartbeat with an encrypted ack. Until a server answers, the agent keeps its records in the buffer and only sends a probe every second. Records go out once a server answers, so a server that starts later or gets the host key later still receives the boot log and the pstore lines. When no ack comes for three heartbeats, the agent holds records again. |

## How the server handles bad input

- Zero bytes and invalid UTF-8 in messages (common in garbled pstore files) are escaped as `\xNN`, like the kernel does, so one bad line never fails a database write.
- Host names must be valid UTF-8 with no spaces or control characters, at most 255 bytes. Other packets are rejected and counted as `bad_host`. A bad metric label is skipped instead of failing the scrape.
- Packets that fail decryption, come from a host without a key, or use an old format are counted by reason and dropped.

## Packets

Each datagram holds one log record or one heartbeat, stays under 1400 bytes (no IP fragmentation), and is encrypted with AES-256-GCM. Long messages are split into parts.

Only the host name, boot ID, agent instance ID and a nonce counter are sent in clear text, because the server needs them to pick the key. The key of each agent run is derived from the shared key with HKDF-SHA256 over the boot ID and the random instance ID, and every packet uses a new nonce from a counter. A nonce is never used twice with the same derived key, even when a send fails and the sequence number is reused. The clear header is authenticated, so a changed host, boot or instance makes the packet fail.

This is wire version 2. Version 1 packets (HMAC only, no encryption) are rejected and counted as `version`, so agents and server must be upgraded together.

Every packet has a sequence number that starts at 1 for each agent run (host, boot ID, random instance ID). The sequence number is only used when a send succeeds, so local network errors do not look like losses. A heartbeat every 5 seconds carries the agent's counters and also reveals losses at the end of a burst.

The server answers every heartbeat with an ack, sent from the listen port back to the address the heartbeat came from. Acks use a key derived with a different HKDF label, so server and agent nonces never meet. A probe is a heartbeat with sequence number 0: it gets an ack but is not counted, so probes sent while no server listens do not show up as missing. Firewalls must let these UDP replies back to the agent (stateful firewalls do by default). Agents started with `-wait-ack=false` do not wait for acks and send right away.

## Missing packets

For each agent run the server tracks the highest sequence number and the missing ranges.

- **Missing**: packets that never arrived.
- **Late**: missing packets that arrived later, out of order.
- **Duplicates**: packets received more than once.
- **Agent drops**: records the agent dropped because its buffer was full. These never got a sequence number, so they are reported by the agent heartbeat.

Gap state is saved to the database, so a server restart does not lose it, and packets sent while the server was down show up as missing.

## Deduplication

| Case | Key |
| --- | --- |
| Agent restarts and replays the kernel buffer | host, boot ID, kmsg sequence number, part |
| pstore line that also arrived through kmsg before the crash | host, previous boot ID, timestamp, message, part |
| Same pstore file sent again after later reboots | host, file content hash, line number, part |

A pstore file is assigned to the boot seen just before the boot that sent it, and keeps that assignment. Boots that first show up in the same batch keep the order their packets arrived in.

## Build

```sh
make            # builds bin/lastgasp-agent and bin/lastgasp-server
make test       # runs all tests with the race detector, and the install script test
make image      # builds the lastgasp-server Docker image
```

The PostgreSQL store tests run when `LASTGASP_TEST_PG` is set:

```sh
docker run -d --rm --name pg -e POSTGRES_PASSWORD=test -p 127.0.0.1:55432:5432 postgres:17-alpine
LASTGASP_TEST_PG='postgres://postgres:test@127.0.0.1:55432/postgres?sslmode=disable' go test ./internal/store/
```

## Run the server

Create a key (at least 16 bytes, hex encoded):

```sh
openssl rand -hex 32 > agent.key
```

Server key file, one `host hexkey` per line. `*` matches any host:

```text
# /etc/lastgasp/keys
db-01  4f1c...e9
*      9a02...7b
```

```sh
lastgasp-server -listen :5140 -http :8080 -db /var/lib/lastgasp/lastgasp.db -key-file /etc/lastgasp/keys
lastgasp-server -db 'postgres://user:pass@db/lastgasp' -key-file /etc/lastgasp/keys -retain 720h \
  -auth-file /etc/lastgasp/auth -public-url https://lastgasp.example.net \
  -alert-webhook 'name=chat,format=slack,url=https://hooks.slack.com/services/...' \
  -alert-webhook 'name=pager,min=critical,key-file=/etc/lastgasp/alert.key,url=https://pager.example.net/hook' \
  -alert-email 'name=ops,min=critical,to=ops@example.net,smtp=mail.example.net:587,user=lastgasp,password-file=/etc/lastgasp/smtp.pw'
```

`SIGHUP` reloads the key file, the rules file and the auth file (`systemctl reload lastgasp-server`, or `docker compose kill -s HUP server`). If a file is broken, the old keys, rules or users stay in use and the error is logged.

The database schema has a version and is upgraded on start, for SQLite and PostgreSQL.

### Server flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `-listen` | :5140 | UDP address for agent packets |
| `-http` | :8080 | web UI, API and `/metrics` |
| `-db` | lastgasp.db | SQLite file, or a `postgres://` URL |
| `-key-file` | | `host hexkey` lines (required) |
| `-rcvbuf` | 8 MiB | UDP receive buffer |
| `-stale-after` | 30s | time without packets before a host is shown as down |
| `-retain` | 0 | delete records, closed incidents, old boots and agent runs older than this. 0 keeps everything |
| `-rules` | | extra incident rules, see Incidents |
| `-silent-after` | 2m | time without packets before a `silent` incident, 0 to disable |
| `-crash-wait` | 2m | time after a reboot to wait for pstore lines before deciding crash or reboot |
| `-resolve-after` | 30m | close a kernel error incident as resolved after this long without a new matching line, 0 never |
| `-incident-context` | 200 | log lines shown with an incident |
| `-alert-webhook` | | webhook alert target, repeatable, see Alerts |
| `-alert-email` | | email alert target, repeatable, see Alerts |
| `-alert-format` | json | default format: `json`, or `slack` for Slack and Mattermost |
| `-alert-key-file` | | default hex key that signs alerts |
| `-alert-min-severity` | warning | default lowest severity: `info`, `warning` or `critical` |
| `-alert-rate-limit` | 10m | default limit of one alert per host and incident kind in this time |
| `-public-url` | | UI address used for links in alerts |
| `-auth-file` | | users and API tokens, see Login. Without it there is no login |
| `-auth-metrics` | false | also require a login for `/metrics` |
| `-auth-proxy-header` | | header with the client address set by a reverse proxy, like `X-Forwarded-For`, for the login failure limit |

Retention runs a minute after start and then every hour. The newest boot of each host is always kept, so crash logs of the next boot still find their boot. SQLite does not give the space back to the file system, it reuses it for new records.

Without `-auth-file`, the server logs a warning when `-http` is not a localhost address.

### Server with Docker

`compose.yaml` runs the server with PostgreSQL and keeps 30 days of data (`LASTGASP_RETAIN`). The web UI listens on `127.0.0.1:8080` unless `LASTGASP_HTTP_BIND` is set. Before opening it to the network, create an `auth` file (see Login) and enable the `-auth-file` lines in `compose.yaml`.

```sh
cp .env.example .env          # set POSTGRES_PASSWORD
echo "*  $(openssl rand -hex 32)" > keys
chmod 644 keys                # the server runs as uid 65532
docker compose up -d --build
```

The image alone uses SQLite in the `/var/lib/lastgasp` volume:

```sh
make image
docker run -d -p 5140:5140/udp -p 127.0.0.1:8080:8080 -v ./keys:/etc/lastgasp/keys:ro -v lastgasp:/var/lib/lastgasp lastgasp-server
```

## Run the agent

The agent must run as root (or with `CAP_SYSLOG` and `CAP_IPC_LOCK`):

```sh
lastgasp-agent -server logs.example.net:5140 -key-file /etc/lastgasp/agent.key
```

systemd units are in `deploy/`. The agent unit starts early in boot and restarts forever.

### Install the agent

`deploy/install-agent.sh` copies the binary to `/usr/local/sbin`, writes the key to `/etc/lastgasp/agent.key`, installs the unit with a drop-in holding the flags, and starts it. Without `-k` or `--key-file` it keeps the existing key or creates one, and prints the line to add to the server key file.

```sh
make agent
ssh root@db-01 mkdir -p /tmp/lg
scp bin/lastgasp-agent deploy/install-agent.sh deploy/lastgasp-agent.service root@db-01:/tmp/lg/
ssh root@db-01 /tmp/lg/install-agent.sh -s logs.example.net:5140 -n db-01
ssh root@db-01 /tmp/lg/install-agent.sh --uninstall --purge
```

The flags are kept in a systemd drop-in instead of an environment file. systemd holds it in memory, so a restart does not read config from a failing disk.

### Agent flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `-server` | | comma separated `host:port` list (required) |
| `-key-file` | | hex key file, or `LASTGASP_KEY` env var |
| `-hostname` | kernel hostname | name sent to the server: UTF-8, no spaces or control characters, at most 255 bytes |
| `-dns` | | DNS server `ip:port`, skips `/etc/resolv.conf` |
| `-buffer` | 16384 | records kept in memory. pstore lines have their own queue on top of this |
| `-rate` | 2000 | max packets per second |
| `-heartbeat` | 5s | heartbeat interval |
| `-wait-ack` | true | hold records until a server answers a heartbeat. Needs `-heartbeat` above 0. Set to false when server replies cannot reach the agent |
| `-resolve-every` | 1m | DNS refresh interval |
| `-pstore` | /sys/fs/pstore | empty to disable |
| `-mlock` | true | lock memory |
| `-memory-limit` | 64 MiB | soft Go memory limit |

## Incidents

The server turns the moments that matter into incidents, one per host and boot:

| Kind | When | Severity |
| --- | --- | --- |
| `kernel_error` | a kernel line matches a rule. Lines of the same rule and boot are grouped and counted. Resolved after `-resolve-after` without a new line, or by a clean reboot. | from the rule |
| `silent` | no packet for `-silent-after`. Resolved when the host sends again, or by a clean reboot. | warning |
| `reboot` | a new boot ID shows up. Open incidents of the old boot are closed. | info |
| `crash` | a reboot where the old boot left pstore lines, or its last lines match a critical rule. Decided `-crash-wait` after the reboot, so pstore lines have time to arrive. pstore lines that come later still turn the reboot into a crash. Never resolved. | critical |

A clean reboot is a reboot that did not turn into a crash. A crash does not resolve the errors that led to it.

Each incident links to the last kernel lines of its boot and, for crashes, to the pstore lines. The UI shows them side by side, marks the matching line, and opens an incident with `/#incident=ID`. Open incidents are restored after a server restart, and known hosts count as seen at start, so a restart does not make every host look silent.

Built-in rules: `panic`, `lockup`, `oops`, `bug`, `gpf`, `mce`, `memory_failure` (critical), and `rcu_stall`, `hung_task`, `oom`, `io_error`, `fs_error`, `nvme` (warning). A rules file (`-rules`) adds, replaces or removes rules, one per line:

```text
# name      severity  regexp
raid        warning   md/raid\d+:.*: Disk failure
io_error    critical  I/O error, dev nvme
oom         off
```

### Alerts

Each `-alert-webhook` or `-alert-email` is one target.

#### Webhooks

The `-alert-webhook` value is a URL, or options followed by `url=` (last, so the URL may hold commas):

| Option | Meaning |
| --- | --- |
| `name` | target name, shown in the UI and metrics. Default: the URL host, so secrets in the URL stay hidden. Two targets need different names |
| `format` | `json` or `slack` (default `-alert-format`) |
| `min` | lowest severity sent (default `-alert-min-severity`) |
| `key-file` | key that signs the body (default `-alert-key-file`) |
| `rate` | rate limit per host and incident kind (default `-alert-rate-limit`) |

Each target has its own alert state, retries and rate limit, so one target that is down does not hold back the others. The `json` format looks like:

```json
{"text": "[critical] db-01 crashed: Kernel panic - not syncing: Fatal exception https://lastgasp.example.net/#incident=42",
 "url": "https://lastgasp.example.net/#incident=42", "resolved": false, "target": "pager",
 "incident": {"id": 42, "host": "db-01", "kind": "crash", "severity": "critical", "rule": "panic", "...": "..."}}
```

With a key, the body is signed: `X-Lastgasp-Signature: sha256=<hex HMAC-SHA256 of the body>`. An alert is marked sent only after a 2xx answer and is retried with backoff (1 second up to 5 minutes), also after a server restart. Only incidents updated in the last 24 hours are sent, so a new target does not get the whole history. When the rate limit applies, the incident is marked `suppressed` for that target.

#### Email

The `-alert-email` value is a list of options. `to` and `smtp` are required, more recipients follow `to` after commas:

| Option | Meaning |
| --- | --- |
| `to` | recipients, `to=a@example.net,b@example.net` |
| `smtp` | SMTP server `host:port`. Port 465 uses TLS from the start, other ports need STARTTLS, except on localhost |
| `from` | sender, default `lastgasp@<server hostname>` |
| `user`, `password-file` | SMTP login, the password is read from the file |
| `ca-file` | PEM certificate authority to trust for the SMTP server, for internal relays with their own CA |
| `name`, `min`, `rate` | as for webhooks. The default name is `email` |

The subject is the short form, like `[critical] db-01 crashed`. The body has the summary, the incident details and link, the last 40 pstore lines for crashes, and the last 40 kernel lines.

#### Resolved and skipped alerts

When an incident is resolved, every target that sent its alert gets a second one with `"resolved": true` and a `[resolved]` text. A reboot that turns into a crash is alerted again to every target.

A host that goes silent and comes back before a target sent the alert is a short blip: that target sends nothing and marks the incident `skipped`. The incident stays in the UI.

## Login

With `-auth-file`, the UI and API need a login. The file holds one user or API token per line:

```text
# name   role    hash
alice    admin   $2a$10$...
bob      viewer  $2a$10$...
grafana  viewer  sha256:9f86d081...
```

`viewer` can read everything, `admin` can also acknowledge incidents. Users log in with HTTP basic auth (the browser asks), API tokens are sent as `Authorization: Bearer <token>`. `/healthz` is always open, `/metrics` is open unless `-auth-metrics` is set. The UI shows who is logged in and hides what the role may not do. Create lines with:

```sh
lastgasp-server user alice admin          # asks for the password twice, prints the line
lastgasp-server token grafana viewer      # prints a new token and its line
docker compose run --rm -T server user alice admin < password.txt
```

Passwords are checked with bcrypt once, then a SHA-256 of the good password is kept in memory, so the UI polling does not run bcrypt on every request. Basic auth sends the password with every request, so use HTTPS in front of the server when it is not on localhost.

After 5 failed logins within 10 minutes from one address or for one user name, that address or user is refused with `429` and `Retry-After` for 1 minute, then 2, 4 and so on up to 15 minutes. The counter starts over after 10 minutes without failures, and a good login clears the counter of its user. Nothing is locked forever. Behind a reverse proxy, set `-auth-proxy-header` so each client is counted on its own address and not the proxy's.

## Web UI and API

The UI at `http://server:8080/` shows incidents, hosts (up or down, missing, late, agent drops), the missing sequence ranges per agent run, and a live log view with filters by host, level, source and text, plus download.

| Endpoint | Returns |
| --- | --- |
| `GET /api/hosts` | per host counters |
| `GET /api/streams?host=&all=1` | agent runs with missing ranges (all runs with `all=1`) |
| `GET /api/logs?host=&level=&source=&q=&after_id=&before_id=&limit=` | records as JSON, newest first, oldest first with `after_id`. `q` matches text, `%` and `_` included |
| `GET /api/download?...` | same filters, all records as NDJSON |
| `GET /api/incidents?host=&kind=&open=1&limit=` | incidents with their alert state per target, newest first |
| `GET /api/incidents/{id}` | one incident with its kernel lines and pstore lines |
| `POST /api/incidents/{id}/ack` | marks an incident as seen. Needs the admin role and `Content-Type: application/json` |
| `GET /api/me` | the logged in user and role |
| `GET /metrics` | Prometheus metrics |
| `GET /healthz` | `ok` |

### Metrics

| Metric | Labels |
| --- | --- |
| `lastgasp_packets_received_total` | host |
| `lastgasp_packets_missing` | host |
| `lastgasp_packets_gap_total` | host |
| `lastgasp_packets_late_total` | host |
| `lastgasp_packets_duplicate_total` | host |
| `lastgasp_packets_invalid_total` | reason (auth_failed, unknown_host, bad_host, malformed, version) |
| `lastgasp_agent_up`, `lastgasp_agent_last_seen_timestamp_seconds` | host |
| `lastgasp_agent_buffer_dropped_total`, `lastgasp_agent_kmsg_overruns_total`, `lastgasp_agent_send_errors_total`, `lastgasp_agent_buffered_records` | host |
| `lastgasp_records_stored_total`, `lastgasp_records_deduplicated_total` | host, source |
| `lastgasp_records_lost_total`, `lastgasp_store_errors_total`, `lastgasp_server_queue_dropped_total` | |
| `lastgasp_incidents_total` | host, kind |
| `lastgasp_incidents_open` | kind |
| `lastgasp_alerts_total` | target, result (sent, resolved, skipped, failed, suppressed) |
| `lastgasp_auth_failures_total`, `lastgasp_auth_blocked_total` | |
| `lastgasp_key_reloads_total` | result (ok, error) |
| `lastgasp_retention_deleted_total` | table |

## Layout

```text
cmd/lastgasp-agent     agent binary
cmd/lastgasp-server    server binary, and the user and token commands
internal/wire          packet format and encryption
internal/agent         kmsg and pstore readers, memory buffers, DNS cache, sender, hardening
internal/server        gap tracker, ingest, dedup, retention, key reload, login, HTTP API, metrics, web UI
internal/incident      incident rules, detector, webhook and email alerts
internal/store         SQLite and PostgreSQL storage and schema upgrades
deploy/                systemd units and the agent install script
docs/                  feature plans
Dockerfile             server image
compose.yaml           server with PostgreSQL
```

## Known limits

- Encryption stops reading, forging and changing packets. A captured packet sent again is caught by deduplication. The host name and boot ID are visible on the network.
- Basic auth has no logout: the browser keeps the login until it is closed.
- Retention is by age only, there is no limit per host or by size.
- A multi-line kernel message appears as one record in kmsg and as several lines in pstore, so those lines are not deduplicated against each other.
