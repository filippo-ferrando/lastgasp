# Web UI and API

The server serves a web UI at `/`, a JSON API under `/api/`, Prometheus metrics at `/metrics` and a health check at `/healthz`, all on `-http`.

## Web UI

The page refreshes every 2 seconds, and stops while its browser tab is hidden. A table is only redrawn when its data changes, and not while text in it is selected, so lines can be copied.

| Section | Shows |
| --- | --- |
| Incidents | the newest 50 incidents with severity, host, kind, count, alert state and summary. A click opens the incident with its kernel lines and pstore lines, the matching line marked. "open only" hides closed ones |
| Hosts | up or down, last packet, boots seen, packets received, missing, late, duplicates, agent drops, kernel overruns, send errors and records waiting in the agent. A click filters everything by that host, a second click removes the filter |
| Missing packets | agent runs with missing packets and the missing sequence ranges |
| Logs | live kernel lines, filtered by host, level, source and text. A click on the host of a line filters by that host. "live" off stops new lines. "older" loads 300 more and says when there are none. "download" saves all matching lines as NDJSON. When new lines arrive while the view is scrolled up, a button jumps to them |

The incident window has buttons to copy its link, show the logs of its host, and acknowledge it (admins only). It closes with Escape, the close button or a click outside.

Filters are part of the address (`/?host=db-01&level=3`), so a filtered view can be shared or bookmarked. An incident has its own link: `https://lastgasp.example.net/#incident=42`. Alerts use these links when `-public-url` is set.

| Key | Does |
| --- | --- |
| `/` | jump to the search box |
| Escape | in the search box, clear it. In the incident window, close it |
| Tab, then Enter or Space | open an incident or filter by a host from the keyboard |

## Login

Without `-auth-file` there is no login, and the server warns when `-http` is not a localhost address. With it, every page and API call needs a user or an API token, except `/healthz` (always open) and `/metrics` (open unless `-auth-metrics`).

The auth file holds one user or token per line:

```text
# name    role    hash
alice     admin   $2a$10$Zx...
bob       viewer  $2a$10$Qm...
grafana   viewer  sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
```

| Role | May |
| --- | --- |
| `viewer` | read everything |
| `admin` | also acknowledge incidents |

Create lines with the server binary:

```sh
lastgasp-server user alice admin                 # asks for the password twice, prints the line
lastgasp-server user alice admin < password.txt  # reads one line from a pipe
lastgasp-server token grafana viewer             # prints a new token and its line
```

With Docker:

```sh
docker run --rm -it lastgasp-server user alice admin >> auth
docker compose run --rm -T server user alice admin < password.txt >> auth
docker run --rm lastgasp-server token grafana viewer
```

Then reload: `systemctl reload lastgasp-server`, or `docker compose kill -s HUP server`.

Users log in with HTTP basic auth (the browser asks). API tokens are sent as `Authorization: Bearer <token>`, or as the password of basic auth. Passwords are hashed with bcrypt, tokens with SHA-256. After a good password check, a SHA-256 of the password is kept in memory, so the page refresh does not run bcrypt every time.

### Failed logins

After 5 failed logins within 10 minutes from one address, that address is refused with `429 Too Many Requests` and `Retry-After` for 1 minute, then 2, 4 and so on up to 15 minutes. The counter starts over after 10 minutes without failures. Nothing is locked forever.

User names are counted too, but a blocked user name is only refused for addresses that also failed. Someone guessing passwords for `admin` cannot lock out the real admin, who logs in from a clean address. A good login clears the counter of its user. IPv6 addresses are counted per /64.

Behind a reverse proxy, set `-auth-proxy-header` and, when the proxy is not on localhost, `-auth-trusted-proxies`. See [server.md](server.md#behind-a-reverse-proxy).

### Browser security

Every response forbids framing (`X-Frame-Options: DENY`, `frame-ancestors 'none'`), MIME sniffing and referrers. Acknowledging an incident needs a JSON request, which a form on another site cannot send. Basic auth has no logout: the browser keeps the login until it is closed.

## API

All endpoints return JSON. Times are RFC 3339 in UTC. Examples use a token in `$T`:

```sh
T=3c5e...a1
alias lg='curl -sf -H "Authorization: Bearer $T"'
```

| Endpoint | Returns |
| --- | --- |
| `GET /api/me` | logged in user and role |
| `GET /api/hosts` | per host counters, as in the Hosts table |
| `GET /api/streams?host=&all=1` | agent runs with missing ranges (`all=1` for every run) |
| `GET /api/logs?host=&level=&source=&q=&after_id=&before_id=&limit=` | records, newest first. With `after_id`, oldest first |
| `GET /api/download?host=&level=&source=&q=` | all matching records as NDJSON, oldest first |
| `GET /api/incidents?host=&kind=&open=1&limit=` | incidents with their alert state per target, newest first |
| `GET /api/incidents/{id}` | one incident with its kernel lines and pstore lines |
| `POST /api/incidents/{id}/ack` | marks an incident as seen. Needs the admin role and `Content-Type: application/json` |
| `GET /healthz` | `ok` |
| `GET /metrics` | Prometheus metrics |

### Log filters

| Parameter | Meaning |
| --- | --- |
| `host` | one host |
| `level` | this level and more severe: 0 emerg, 1 alert, 2 crit, 3 err, 4 warning, 5 notice, 6 info |
| `source` | `kmsg` or `pstore` |
| `q` | text contained in the message, case insensitive. `%` and `_` are plain characters |
| `after_id` | records newer than this ID, oldest first. Good for following new lines |
| `before_id` | records older than this ID. Good for paging back |
| `limit` | 1 to 10000, default 500 |

### Examples

```sh
# Errors and worse of one host in the last batch
lg 'http://127.0.0.1:8080/api/logs?host=db-01&level=3&limit=50' | jq -r '.[] | "\(.ts_usec) \(.message)"'

# Follow new lines, like tail -f
last=0
while sleep 2; do
  lg "http://127.0.0.1:8080/api/logs?after_id=$last" > /tmp/new.json
  jq -r '.[] | "\(.host) \(.message)"' /tmp/new.json
  last=$(jq -r --arg l "$last" 'if length > 0 then .[-1].id else $l end' /tmp/new.json)
done

# Everything a host logged, for a bug report
lg 'http://127.0.0.1:8080/api/download?host=db-01' > db-01.ndjson

# Open critical incidents
lg 'http://127.0.0.1:8080/api/incidents?open=1' | jq '.[] | select(.severity == "critical") | {id, host, kind, summary}'

# The lines around incident 42
lg http://127.0.0.1:8080/api/incidents/42 | jq -r '.records[].message'

# Acknowledge it (admin)
lg -X POST -H 'Content-Type: application/json' -d '{}' http://127.0.0.1:8080/api/incidents/42/ack

# Hosts that are down
lg http://127.0.0.1:8080/api/hosts | jq -r '.[] | select(.up | not) | .host'
```

A download cut by a database error ends with a line `{"error": "download incomplete: ..."}`.

## Metrics

| Metric | Labels | Meaning |
| --- | --- | --- |
| `lastgasp_packets_received_total` | host | unique packets received |
| `lastgasp_packets_missing` | host | packets still missing |
| `lastgasp_packets_gap_total` | host | packets found missing, ever |
| `lastgasp_packets_late_total` | host | missing packets that arrived later |
| `lastgasp_packets_duplicate_total` | host | packets received more than once |
| `lastgasp_packets_invalid_total` | reason | refused packets: `auth_failed`, `unknown_host`, `bad_host`, `malformed`, `version` |
| `lastgasp_probes_total` | | probes from agents waiting for an answer |
| `lastgasp_agent_up` | host | 1 when the host sent within `-stale-after` |
| `lastgasp_agent_last_seen_timestamp_seconds` | host | time of the last packet |
| `lastgasp_agent_buffer_dropped_total` | host | records the agent dropped |
| `lastgasp_agent_kmsg_overruns_total` | host | kernel overwrote records before the agent read them |
| `lastgasp_agent_send_errors_total` | host | failed sends reported by the agent |
| `lastgasp_agent_buffered_records` | host | records waiting in the agent |
| `lastgasp_records_stored_total` | host, source | records saved |
| `lastgasp_records_deduplicated_total` | host, source | records skipped as already saved |
| `lastgasp_records_lost_total` | | records lost because the database failed after retries |
| `lastgasp_store_errors_total` | | database errors |
| `lastgasp_server_queue_dropped_total` | | valid packets dropped because the server could not keep up |
| `lastgasp_incidents_total` | host, kind | incidents found |
| `lastgasp_incidents_open` | kind | incidents open now |
| `lastgasp_alerts_total` | target, result | `sent`, `resolved`, `skipped`, `suppressed`, and `failed` per failed try |
| `lastgasp_auth_failures_total` | | requests with a wrong user, password or token |
| `lastgasp_auth_blocked_total` | | requests refused by the failure limit |
| `lastgasp_key_reloads_total` | result | key file reloads, `ok` or `error` |
| `lastgasp_retention_deleted_total` | table | rows deleted by retention |

The Go runtime and process metrics are included too. Per host series of hosts removed by retention disappear.

Prometheus scrape config:

```yaml
scrape_configs:
  - job_name: lastgasp
    static_configs:
      - targets: ["logs.example.net:8080"]
    # With -auth-metrics:
    # authorization:
    #   credentials_file: /etc/prometheus/lastgasp.token
```

Alert rules are in [operations.md](operations.md#monitoring).
