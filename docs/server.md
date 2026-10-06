# Server

`lastgasp-server` receives agent packets on UDP, stores the logs in SQLite or PostgreSQL, finds incidents, sends alerts and serves the web UI, a JSON API and Prometheus metrics, all from one process.

## Key file

One `host hexkey` line per host. `*` matches every host without its own line. Empty lines and `#` comments are ignored. Keys are at least 16 bytes (32 hex characters).

```text
# /etc/lastgasp/keys
db-01   4f1c0b...e9
web-01  77a2d0...10
*       9a02ff...7b
```

Packets from a host without a key are dropped and counted as `unknown_host`. The file holds secrets: make it readable only by the server user (see below).

## Install as a systemd service

```sh
make server
install -m 755 bin/lastgasp-server /usr/local/bin/
useradd --system --no-create-home --shell /usr/sbin/nologin lastgasp
install -d -m 750 -g lastgasp /etc/lastgasp
install -m 640 -g lastgasp keys /etc/lastgasp/keys
install -m 644 deploy/lastgasp-server.service /etc/systemd/system/
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

The image is built from `Dockerfile`: a static binary in a distroless image, running as uid 65532. It uses SQLite in the `/var/lib/lastgasp` volume by default.

```sh
make image
docker run -d --name lastgasp --restart unless-stopped \
  -p 5140:5140/udp -p 127.0.0.1:8080:8080 \
  -v ./keys:/etc/lastgasp/keys:ro -v lastgasp:/var/lib/lastgasp \
  lastgasp-server
```

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

## Flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `-listen` | :5140 | UDP address for agent packets |
| `-http` | :8080 | web UI, API and `/metrics` |
| `-db` | lastgasp.db | SQLite file, or a `postgres://` URL |
| `-key-file` | | `host hexkey` lines (required) |
| `-rcvbuf` | 8 MiB | UDP receive buffer. Linux caps it at `net.core.rmem_max` |
| `-stale-after` | 30s | time without packets before a host is shown as down |
| `-retain` | 0 | delete records, closed incidents, old boots and agent runs older than this, at least 1h. 0 keeps everything |
| `-rules` | | extra incident rules, see [incidents-and-alerts.md](incidents-and-alerts.md#rules) |
| `-silent-after` | 2m | time without packets before a `silent` incident, 0 to disable |
| `-crash-wait` | 2m | time after a reboot to wait for pstore lines before deciding crash or reboot |
| `-resolve-after` | 30m | close a kernel error incident as resolved after this long without a new matching line, 0 never |
| `-incident-context` | 200 | log lines shown with an incident, 1 to 10000 |
| `-alert-webhook` | | webhook target, repeatable |
| `-alert-email` | | email target, repeatable |
| `-alert-format` | json | default format: `json`, or `slack` for Slack and Mattermost |
| `-alert-key-file` | | default hex key that signs webhook bodies |
| `-alert-min-severity` | warning | default lowest severity: `info`, `warning` or `critical` |
| `-alert-rate-limit` | 10m | default limit of one alert per host, incident kind and rule in this time |
| `-public-url` | | UI address used for links in alerts |
| `-auth-file` | | users and API tokens. Without it there is no login |
| `-auth-metrics` | false | also require a login for `/metrics` |
| `-auth-proxy-header` | | header with the client address set by a reverse proxy, like `X-Forwarded-For` |
| `-auth-trusted-proxies` | 127.0.0.1,::1 | addresses or CIDR prefixes allowed to set that header |

Bad values stop the server at start with a clear message. Without `-auth-file`, the server logs a warning when `-http` is not a localhost address.

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

With `-retain`, a cleanup runs one minute after start and then every hour. It deletes records, closed incidents, boots and agent runs older than the limit, in batches. The newest boot of each host is always kept, so crash logs sent by the next boot still find their boot.

SQLite does not give space back to the file system: it reuses it for new records. To shrink the file, stop the server and run `sqlite3 lastgasp.db VACUUM`.

## Reload

`SIGHUP` reloads the key file, the rules file and the auth file:

```sh
systemctl reload lastgasp-server
docker compose kill -s HUP server
kill -HUP $(pidof lastgasp-server)
```

If a file is broken, the old keys, rules or users stay in use and the error is logged. `lastgasp_key_reloads_total{result="error"}` counts failed key reloads.

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
| server to agents | UDP replies from 5140 | acks. Stateful firewalls allow them as replies |
| users to server | TCP 8080, or 443 on the proxy | web UI and API |
| Prometheus to server | TCP 8080 | `/metrics` |

## Stop

On `SIGTERM` or `SIGINT` the server stops reading UDP, finishes HTTP requests (5 seconds), writes every queued packet in full batches, waits for the incident detector, alert targets and retention, saves the gap state and incident changes, and closes the database. Give it time: `TimeoutStopSec=30` in the unit, `stop_grace_period: 30s` in compose.
