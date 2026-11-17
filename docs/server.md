# Server

`lastgasp-server` receives agent packets on UDP, stores the logs in SQLite or PostgreSQL, finds incidents, sends alerts and serves the web UI, a JSON API and Prometheus metrics, all from one process.

- [Keys and enrollment](#keys-and-enrollment)
- [Install as a systemd service](#install-as-a-systemd-service)
- [Run with Docker](#run-with-docker)
- [Run with Docker Compose and PostgreSQL](#run-with-docker-compose-and-postgresql)
- [Flags](#flags)
- [Health checks](#health-checks)
- [Database](#database)
- [Retention](#retention)
- [Netconsole](#netconsole)
- [Reload](#reload)
- [Behind a reverse proxy](#behind-a-reverse-proxy)
- [Firewall](#firewall)
- [Stop](#stop)

## Keys and enrollment

Every agent encrypts its packets with a key the server knows. There are two ways to give an agent its key, and both work side by side.

### Enrollment

An admin makes a join token in the UI (Agents, "Add agents") or with the API, and runs the install command it shows on the new machine. The agent proves it knows the token and sends an X25519 public key to the server UDP port, the server answers with its own public key, and both derive the agent key. Neither the key nor the token travels, so this is safe on a network without HTTPS. Enrolled keys are kept in the database. Details in [how-it-works.md](how-it-works.md#enrollment).

| Token setting | Choices in the UI | API field |
| --- | --- | --- |
| uses | 1 agent (default), 10 agents, any number of agents | `uses`, 1 when left out, 0 for no limit |
| valid for | 1 hour, 24 hours, 7 days | `ttl`, from 1m to 8760h |
| comment | free text | `comment` |

- The token is shown once. The database keeps its hash.
- An enrolled host cannot enroll again, so a token cannot take over its key. To enroll it again (a reinstall on a new disk), revoke its key in the Agents table first. Running the install script again on the same machine keeps the key and needs no revoke. A host that has its own line in the key file cannot enroll: the file wins.
- Revoking a token stops new enrollments. Revoking an agent key in the Agents table refuses the packets of that host until it enrolls again.
- Each address may try a few times per second, all addresses together 20 times per second, and an address is ignored for 10 minutes after 10 wrong tokens. A wrong token gets a short answer, smaller than the request, so the port cannot be used to amplify traffic.
- Only a client with a usable token learns whether a host has a line in the key file or is enrolled.

The install command uses `-agent-address` (default: the `-public-url` host with the `-listen` port) and the release of the server version from `-repo-url`. Development builds use the newest installer from the main branch, which installs the newest release.

### Key file

With `-key-file`: one `host hexkey` line per host. `*` matches every host without its own line or enrolled key. Empty lines and `#` comments are ignored. Keys are at least 16 bytes (32 hex characters). Without `-key-file`, or with a key file that has no keys yet, only enrolled agents are accepted.

```text
# /etc/lastgasp/keys
db-01   4f1c0b...e9
web-01  77a2d0...10
*       9a02ff...7b
```

A key is looked up in this order: the host line in the key file, the enrolled key, the `*` line. Packets from a host without a key are dropped and counted as `unknown_host`. The file holds secrets: make it readable only by the server user (see below).

## Install as a systemd service

```sh
curl -fsSLo lastgasp-server https://git.fferrando.cc/rdfilippo/lastgasp/releases/download/v1.0.0/lastgasp-server-linux-amd64
curl -fsSLO https://git.fferrando.cc/rdfilippo/lastgasp/releases/download/v1.0.0/lastgasp-server.service
install -m 755 lastgasp-server /usr/local/bin/
useradd --system --no-create-home --shell /usr/sbin/nologin lastgasp
install -d -m 750 -g lastgasp /etc/lastgasp
install -m 640 -g lastgasp keys /etc/lastgasp/keys      # only with a key file
install -m 644 lastgasp-server.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now lastgasp-server
journalctl -u lastgasp-server -f
```

The unit in `deploy/lastgasp-server.service`:

- runs as the `lastgasp` user with a sandbox (`ProtectSystem=strict`, no capabilities, no new privileges)
- keeps the SQLite database in `/var/lib/lastgasp` (`StateDirectory`)
- listens on UDP `:5140` and on HTTP `127.0.0.1:8080` only, as there is no login by default
- keeps 30 days of data (`-retain 720h`)
- reloads files on `systemctl reload lastgasp-server`
- gives the server 30 seconds to store queued packets on stop

Change the flags with a drop-in: `systemctl edit lastgasp-server`, then

```ini
[Service]
ExecStart=
ExecStart=/usr/local/bin/lastgasp-server -listen :5140 -http 127.0.0.1:8080 -db /var/lib/lastgasp/lastgasp.db \
  -key-file /etc/lastgasp/keys -retain 720h -auth-file /etc/lastgasp/auth -public-url https://lastgasp.example.net
```

## Run with Docker

Each release pushes `git.fferrando.cc/rdfilippo/lastgasp-server` for amd64 and arm64, tagged `v1.2.0`, `1.2.0`, `1.2` and `latest`. `make image` builds the same image from a checkout as `lastgasp-server`. It is a static binary in a distroless image, running as uid 65532, with SQLite in the `/var/lib/lastgasp` volume by default.

```sh
docker run -d --name lastgasp --restart unless-stopped \
  -p 5140:5140/udp -p 127.0.0.1:8080:8080 -v lastgasp:/var/lib/lastgasp \
  git.fferrando.cc/rdfilippo/lastgasp-server:latest
```

The default flags use no key file: agents enroll with join tokens. To use a key file as well, mount it and give the flags, as below. A key file without keys yet is fine.

The image has a health check: it runs `lastgasp-server health`, which asks `/readyz` on port 8080. With another `-http` port, override it (`--health-cmd`, or `healthcheck:` in compose).

Arguments after the image name replace the default flags, so give them all:

```sh
docker run -d --name lastgasp -p 5140:5140/udp -p 127.0.0.1:8080:8080 \
  -v ./keys:/etc/lastgasp/keys:ro -v ./auth:/etc/lastgasp/auth:ro -v lastgasp:/var/lib/lastgasp \
  lastgasp-server -listen :5140 -http :8080 -db /var/lib/lastgasp/lastgasp.db \
  -key-file /etc/lastgasp/keys -auth-file /etc/lastgasp/auth -retain 720h
```

The mounted files must be readable by uid 65532. Instead of making them readable by everyone, give them to that uid: `chown 65532 keys auth && chmod 400 keys auth`.

Helper commands run in the same image:

```sh
docker run --rm -it lastgasp-server user alice admin               # asks for the password
docker run --rm -i lastgasp-server user alice admin < password.txt  # reads one line
docker run --rm lastgasp-server token grafana viewer
docker run --rm lastgasp-server -version
```

## Run with Docker Compose and PostgreSQL

`compose.yaml` runs the server with PostgreSQL 17:

```sh
cp .env.example .env          # set POSTGRES_PASSWORD
echo "*  $(openssl rand -hex 32)" > keys
docker compose up -d --build
```

| Variable (in `.env`) | Default | Meaning |
| --- | --- | --- |
| `POSTGRES_PASSWORD` | | database password (required) |
| `LASTGASP_RETAIN` | 720h | retention |
| `LASTGASP_UDP_PORT` | 5140 | UDP port on the host |
| `LASTGASP_HTTP_BIND` | 127.0.0.1 | address of the web UI on the host |
| `LASTGASP_HTTP_PORT` | 8080 | port of the web UI on the host |

Commented lines in `compose.yaml` enable alerts and login. Reload files with `docker compose kill -s HUP server`.

More compose setups (Telegram, Alertmanager, HTTPS with Caddy, a full production setup) are in [examples/](../examples/README.md).

## Flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `-listen` | :5140 | UDP address for agent packets |
| `-http` | :8080 | web UI, API and `/metrics` |
| `-netconsole-listen` | | UDP address for extended netconsole lines, like `:6666`. Empty to disable. See [Netconsole](#netconsole) |
| `-netconsole-from` | | addresses or CIDR prefixes allowed to send netconsole lines, comma separated. Required with `-netconsole-listen` |
| `-netconsole-hosts` | | file with `ip host` lines that name the netconsole senders, reloaded on `SIGHUP`. Required with `-netconsole-listen` |
| `-netconsole-delay` | 10s | time a netconsole line waits before it is stored, so the agent copy of it wins |
| `-db` | lastgasp.db | SQLite file, or a `postgres://` URL |
| `-key-file` | | `host hexkey` lines. Optional: without it only enrolled agents are accepted |
| `-agent-address` | `-public-url` host, `-listen` port | `host:port` agents send to, shown in install commands |
| `-repo-url` | https://git.fferrando.cc/rdfilippo/lastgasp | repository whose releases hold the agent and installer |
| `-require-forward-secrecy` | false | refuse packets before version 5 (counted as `version`), once every agent sends version 5. Agents with `-wait-ack=false` stop working |
| `-rcvbuf` | 8 MiB | UDP receive buffer. Linux caps it at `net.core.rmem_max` |
| `-stale-after` | 30s | time without packets before a host is shown as down |
| `-retain` | 0 | delete records, closed incidents, old boots, agent runs and silences older than this, at least 1h. 0 keeps everything |
| `-retain-info` | 0 | delete records of level info and debug older than this, at least 1h. 0 uses `-retain` only |
| `-retain-records` | 0 | keep at most this many records in total, oldest deleted first. 0 for no limit |
| `-retain-host-records` | 0 | keep at most this many records per host, oldest deleted first. 0 for no limit |
| `-retain-bytes` | 0 | keep the records under this size, such as `20GiB` (suffixes K, M, G, T are powers of 1024), oldest deleted first. 0 for no limit |
| `-rules` | | extra incident rules, see [incidents-and-alerts.md](incidents-and-alerts.md#rules) |
| `-silent-after` | 2m | time without packets before a `silent` incident, 0 to disable |
| `-crash-wait` | 2m | time after a reboot to wait for pstore lines before deciding crash or reboot |
| `-flap-count` | 3 | reboots or returns from silence within `-flap-window` that open a flapping incident, 0 to disable |
| `-flap-window` | 1h | time window of `-flap-count`, at least 1m |
| `-group-min-hosts` | 3 | hosts that reboot or go silent within `-group-window` to share one alert, 0 to disable |
| `-group-window` | 2m | time window of `-group-min-hosts` |
| `-resolve-after` | 30m | close a kernel error incident as resolved after this long without a new matching line, 0 never |
| `-incident-context` | 200 | log lines shown with an incident, 1 to 10000 |
| `-alert-webhook` | | webhook target, repeatable |
| `-alert-email` | | email target, repeatable |
| `-alert-telegram` | | Telegram target, repeatable |
| `-alert-format` | json | default webhook format: `json`, `slack` for Slack and Mattermost, or `alertmanager` for the Alertmanager v2 API |
| `-alert-key-file` | | default hex key that signs webhook bodies |
| `-alert-min-severity` | warning | default lowest severity: `info`, `warning` or `critical` |
| `-alert-rate-limit` | 10m | default limit of one alert per host, incident kind and rule in this time |
| `-public-url` | | UI address used for links in alerts |
| `-auth-file` | | users and API tokens. Without it there is no login |
| `-auth-metrics` | false | also require a login for `/metrics` |
| `-session-ttl` | 168h | how long a login on the web UI lasts |
| `-version` | | print the version and exit |
| `-auth-proxy-header` | | header with the client address set by a reverse proxy, like `X-Forwarded-For` |
| `-auth-trusted-proxies` | 127.0.0.1,::1 | addresses or CIDR prefixes allowed to set that header |

Bad values stop the server at start with a clear message. Without `-auth-file`, the server logs a warning when `-http` is not a localhost address.

## Health checks

| Check | Answers |
| --- | --- |
| `GET /healthz` | always `ok` while the process serves HTTP. For liveness checks |
| `GET /readyz` | `ok` when the database answers within 3 seconds, the UDP reader and the ingest worker run, and the ingest queue is below 90%. Otherwise 503 `not ready`, with the reason in the server log. For readiness checks and load balancers |
| `lastgasp-server health [URL]` | exits 0 when the URL (default `http://127.0.0.1:8080/readyz`) answers 200. For images without curl |

Both endpoints are open without a login.

## Database

| | SQLite | PostgreSQL |
| --- | --- | --- |
| setup | none, one file | a database and a user |
| `-db` | `/var/lib/lastgasp/lastgasp.db` | `postgres://lastgasp@db:5432/lastgasp?sslmode=require` |
| good for | one server, up to a few hundred hosts | many hosts, shared database, existing backups |
| connections | one, writes are serialized | up to 16 |

SQLite runs in WAL mode with a 5 second busy timeout. The path must not contain `?` or `#`.

For PostgreSQL, keep the password out of the command line with the `PGPASSWORD` environment variable, or a `~/.pgpass` file. All `libpq` variables work (`PGSSLMODE`, `PGSSLROOTCERT`, ...).

The schema has a version and is upgraded on start, in a transaction, for both databases. The server checks the connection at start and fails within 30 seconds when the database is not reachable.

## Retention

A cleanup runs one minute after start and then every 10 minutes when at least one limit is set. All limits can be combined, and each deletes the oldest records first, in batches.

| Flag | Removes | Use it for |
| --- | --- | --- |
| `-retain-info 72h` | info and debug lines (levels 6 and 7) older than 72 hours | the bulk of most kernel logs. Errors and warnings stay longer |
| `-retain-host-records 500000` | the oldest records of each host above 500000 | one noisy host cannot push out the logs of the others |
| `-retain-records 20000000` | the oldest records above 20 million, over all hosts | a hard cap that keeps the database size in check. A record takes about 300 to 500 bytes with indexes |
| `-retain-bytes 20GiB` | the oldest records while the records take more than 20 GiB, down to 90% of it | a cap that follows the disk, without guessing the record size |
| `-retain 720h` | records, closed incidents, boots, agent runs and silences older than 30 days | the general age limit |

The count limits only remove records. Incidents keep their summary, but the log lines shown with an old incident may be gone.

With `-retain`, the newest boot of each host is always kept, so crash logs sent by the next boot still find their boot. Removed boots are remembered by name only, so a boot that sends again after its removal (a replay, or a machine with a wrong boot ID) is not taken for a new boot.

SQLite does not give space back to the file system: it reuses it for new records. To shrink the file, stop the server and run `sqlite3 lastgasp.db VACUUM`.

How `-retain-bytes` measures the size:

- SQLite: the pages of the database file in use, so free pages left by deleted records do not count. The file stops growing near the limit, plus the WAL file.
- PostgreSQL: the size of the record rows, estimated from the newest 1000 rows. Indexes and space waiting for vacuum are not counted, so leave about half of the disk budget for them.

## Netconsole

A kernel panic stops the agent, so the panic text normally only arrives with pstore after the reboot. The kernel netconsole sends kernel lines over UDP from the kernel itself, which still works during a panic. With `-netconsole-listen`, the server takes these lines too: the panic opens a critical incident while the machine is still down, and the reboot after it is found to be a crash, even on machines without pstore.

On the server:

```sh
lastgasp-server ... -netconsole-listen :6666 -netconsole-from 10.0.0.0/24 -netconsole-hosts /etc/lastgasp/netconsole-hosts
```

```text
# /etc/lastgasp/netconsole-hosts: source address, then the host name its agent uses
10.0.0.7  db-01
10.0.0.8  db-02
```

On each machine, load netconsole in extended mode (the `+`), pointing at the server address and port:

```sh
modprobe netconsole netconsole=+@/eth0,6666@10.0.0.5/
# or on the kernel command line: netconsole=+@/eth0,6666@10.0.0.5/
```

- Only extended netconsole lines are taken: they carry the kernel sequence number, so a line that also came from the agent is stored once. Plain lines count as `netconsole_format` in `lastgasp_packets_invalid_total`.
- A line waits `-netconsole-delay` before it is stored. The agent copy usually arrives first and wins. During a panic only netconsole gets through, and its lines are stored with the source `netconsole`.
- Lines belong to the boot the host runs according to its agent. After a reboot, lines arrive before the new agent runs. They are dropped (`netconsole_boot`), as the agent sends the whole kernel buffer when it starts.
- Netconsole is plain text and the sender is only known by its address, which can be faked on a shared network. Keep it on a management network, and limit `-netconsole-from` to it. Lines from other addresses count as `netconsole_source`.

## Reload

`SIGHUP` reloads the key file, the rules file, the auth file and the netconsole hosts file:

```sh
systemctl reload lastgasp-server
docker compose kill -s HUP server
kill -HUP $(pidof lastgasp-server)
```

If a file is broken, the old keys, rules, users or netconsole hosts stay in use and the error is logged. `lastgasp_key_reloads_total{result="error"}` counts failed key reloads.

## Behind a reverse proxy

Put HTTPS in front of the web UI when it is used over the network: basic auth sends the password with every request. Example for nginx on the same machine:

```nginx
server {
    listen 443 ssl;
    server_name lastgasp.example.net;
    ssl_certificate     /etc/ssl/lastgasp.pem;
    ssl_certificate_key /etc/ssl/lastgasp.key;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        # Downloads stream for a long time.
        proxy_buffering off;
        proxy_read_timeout 300s;
    }
}
```

```sh
lastgasp-server ... -http 127.0.0.1:8080 -auth-file /etc/lastgasp/auth \
  -auth-proxy-header X-Forwarded-For -public-url https://lastgasp.example.net
```

The proxy header is only read on requests from `-auth-trusted-proxies` (localhost by default). Requests from other addresses use their own address, so a client cannot pick an address to dodge the login failure limit. When the proxy runs on another machine or container, add its address: `-auth-trusted-proxies 10.0.0.10` or `-auth-trusted-proxies 172.16.0.0/12`.

## Firewall

| Direction | Port | Why |
| --- | --- | --- |
| agents to server | UDP 5140 | packets |
| machines to server | UDP 6666, or the `-netconsole-listen` port | netconsole lines, when enabled |
| server to agents | UDP replies from 5140 | acks. Stateful firewalls allow them as replies |
| users to server | TCP 8080, or 443 on the proxy | web UI and API |
| Prometheus to server | TCP 8080 | `/metrics` |

## Stop

On `SIGTERM` or `SIGINT` the server stops reading UDP, finishes HTTP requests (5 seconds), writes every queued packet in full batches, waits for the incident detector, alert targets and retention, saves the gap state and incident changes, and closes the database. Give it time: `TimeoutStopSec=30` in the unit, `stop_grace_period: 30s` in compose.
