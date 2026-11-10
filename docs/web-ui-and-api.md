# Web UI and API

The server serves a web UI at `/`, a JSON API under `/api/`, Prometheus metrics at `/metrics` and a health check at `/healthz`, all on `-http`.

## Web UI

The header shows the user, the server version and a "log out" button. The page refreshes every 2 seconds, and stops while its browser tab is hidden. A table is only redrawn when its data changes, and not while text in it is selected, so lines can be copied.

| Section | Shows |
| --- | --- |
| Incidents | the newest 50 incidents with severity, host, kind, count, alert state and summary. A click opens the incident with its kernel lines and pstore lines, the matching line marked. "open only" hides closed ones |
| Silences | active and upcoming silences with their host pattern, kind, window, comment and author. Admins add a silence with the form above the table and end one with "end now" |
| Agents | for admins: "add agents" makes a join token and shows the one line install command. Below, the usable tokens (revoke) and the enrolled hosts with the time and address they enrolled from (revoke key) |
| Hosts | up or down, last packet, boots seen, packets received, missing, late, duplicates, agent drops, kernel overruns, send errors, records waiting in the agent, the agent version (marked when it differs from the server version, `old` for agents from before wire version 4), and the wire version of its packets (marked below 5, which has no forward secrecy). A click filters everything by that host, a second click removes the filter |
| Missing packets | agent runs with missing packets and the missing sequence ranges |
| Logs | live kernel lines, filtered by host, level, source and text. A click on the host of a line filters by that host. "live" off stops new lines. "older" loads 300 more and says when there are none. "download" saves all matching lines as NDJSON. When new lines arrive while the view is scrolled up, a button jumps to them |

The incident window shows the kernel lines up to the incident and the next 20 lines after it. It has buttons to copy its link and show the logs of its boot, scrolled to the incident line and marked. Admins also get a note field and buttons to acknowledge, resolve, and silence the host for 1, 4 or 24 hours. The note is saved with acknowledge or resolve and shown on the incident. It closes with Escape, the close button or a click outside.

Filters are part of the address (`/?host=db-01&level=3`, plus `boot=` after "show logs" of an incident, removed with its button), so a filtered view can be shared or bookmarked. An incident has its own link: `https://lastgasp.example.net/#incident=42`. Alerts use these links when `-public-url` is set.

| Key | Does |
| --- | --- |
| `/` | jump to the search box |
| Escape | in the search box, clear it. In the incident window, close it |
| Tab, then Enter or Space | open an incident or filter by a host from the keyboard |

## Login

Without `-auth-file` there is no login, and the server warns when `-http` is not a localhost address. With it, every page and API call needs a user or an API token, except `/healthz` and `/readyz` (always open), the login page, and `/metrics` (open unless `-auth-metrics`).

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
| `admin` | also acknowledge and resolve incidents, manage silences, join tokens and enrolled agents |

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

In a browser, users log in on the login page (`/login`). A good login starts a session: a random token in a cookie that is `HttpOnly`, `SameSite=Lax`, and `Secure` when `-public-url` starts with `https://`. The database keeps only a hash of the token, so logins survive a server restart. A session lasts `-session-ttl` (7 days), and "log out" in the header ends it at once. The user and role are read from the auth file on every request, so removing a user from the file or changing their password, then reloading, ends their sessions, and a changed role applies at once.

Scripts and tools keep using HTTP basic auth (`curl -u alice:...`) or API tokens, sent as `Authorization: Bearer <token>` or as the password of basic auth. Clients that are not browsers still get the `WWW-Authenticate` challenge. Browsers get the login page instead of the basic auth prompt. Passwords are hashed with bcrypt, tokens with SHA-256. After a good password check, a SHA-256 of the password is kept in memory, so the page refresh does not run bcrypt every time.

### Failed logins

After 5 failed logins within 10 minutes from one address, that address is refused with `429 Too Many Requests` and `Retry-After` for 1 minute, then 2, 4 and so on up to 15 minutes. The counter starts over after 10 minutes without failures. Nothing is locked forever. The block only stops password and token checks: browsers that already have a session keep working, so many users behind one proxy address are not locked out together.

The login page and basic auth share these counters. User names are counted too, but a blocked user name is only refused for addresses that also failed. Someone guessing passwords for `admin` cannot lock out the real admin, who logs in from a clean address. A good login clears the counter of its user. IPv6 addresses are counted per /64.

Behind a reverse proxy, set `-auth-proxy-header` and, when the proxy is not on localhost, `-auth-trusted-proxies`. See [server.md](server.md#behind-a-reverse-proxy).

### Browser security

Every response forbids framing (`X-Frame-Options: DENY`, `frame-ancestors 'none'`), MIME sniffing and referrers. A Content Security Policy lets pages load scripts, styles, images and API calls only from the server itself, with no plugins and no `<base>` tag. Every `POST` needs a JSON request, which a form on another site cannot send, and the `SameSite=Lax` cookie is not sent with requests from other sites. The login page only sends the user back to paths on the same server.

## API

All endpoints return JSON. Times are RFC 3339 in UTC. Examples use a token in `$T`:

```sh
T=3c5e...a1
alias lg='curl -sf -H "Authorization: Bearer $T"'
```

| Endpoint | Returns |
| --- | --- |
| `GET /api/me` | logged in user, role, server version, and whether the login is a session |
| `POST /api/login` | starts a session: `{"user": "alice", "password": "..."}`. Sets the cookie |
| `POST /api/logout` | ends the session of the cookie |
| `GET /api/hosts` | per host counters, as in the Hosts table |
| `GET /api/streams?host=&all=1` | agent runs with missing ranges (`all=1` for every run) |
| `GET /api/logs?host=&boot=&level=&source=&q=&after_id=&before_id=&limit=` | records, newest first. With `after_id`, oldest first |
| `GET /api/download?host=&level=&source=&q=` | all matching records as NDJSON, oldest first |
| `GET /api/incidents?host=&kind=&open=1&limit=` | incidents with their alert state per target, newest first |
| `GET /api/incidents/{id}` | one incident with its kernel lines (`records`), the next 20 lines (`after`) and pstore lines |
| `POST /api/incidents/{id}/ack` | marks an incident as seen. Optional body `{"note": "..."}` |
| `POST /api/incidents/{id}/resolve` | closes an incident as resolved and sends resolve alerts. Optional body `{"note": "..."}`. 409 for an open reboot or silent incident |
| `GET /api/silences?all=1` | active and upcoming silences (`all=1` adds those that ended in the last day) |
| `POST /api/silences` | adds a silence: `{"host": "db-*", "kind": "", "duration": "2h", "comment": "..."}`, or `starts_at` and `ends_at` instead of `duration` |
| `DELETE /api/silences/{id}` | ends a silence now |
| `GET /api/enroll-tokens` | join tokens, without the token itself |
| `POST /api/enroll-tokens` | makes a join token: `{"comment": "rack 4", "uses": 10, "ttl": "24h"}`. `uses` is 1 when left out, 0 for no limit. Returns the token and the install command, once |
| `DELETE /api/enroll-tokens/{id}` | revokes a token |
| `GET /api/agents` | enrolled hosts, without their keys |
| `DELETE /api/agents/{host}` | removes the key of an enrolled host, its packets are refused |
| `GET /healthz` | `ok` |
| `GET /readyz` | `ok`, or 503 `not ready` when the database or the packet path does not work. The reason is in the server log |

The `POST` and `DELETE` endpoints need the admin role, except login and logout. `POST` needs `Content-Type: application/json`, so a form on another site cannot call them. The user name of the login is saved as `acked_by` and `created_by`, or `admin` without `-auth-file`.
| `GET /metrics` | Prometheus metrics |

### Log filters

| Parameter | Meaning |
| --- | --- |
| `host` | one host |
| `boot` | one boot ID, as shown on incidents |
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

# Acknowledge it with a note, then resolve it (admin)
lg -X POST -H 'Content-Type: application/json' -d '{"note": "replacing the disk"}' http://127.0.0.1:8080/api/incidents/42/ack
lg -X POST -H 'Content-Type: application/json' -d '{"note": "disk replaced"}' http://127.0.0.1:8080/api/incidents/42/resolve

# No alerts from the db hosts during two hours of maintenance (admin)
lg -X POST -H 'Content-Type: application/json' \
  -d '{"host": "db-*", "duration": "2h", "comment": "kernel update"}' http://127.0.0.1:8080/api/silences

# A join token for 10 machines, and the command to run on each (admin)
lg -X POST -H 'Content-Type: application/json' -d '{"comment": "rack 4", "uses": 10}' \
  http://127.0.0.1:8080/api/enroll-tokens | jq -r .install

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
| `lastgasp_packets_invalid_total` | reason | refused packets: `auth_failed`, `unknown_host`, `bad_host`, `malformed`, `version`, `unknown_session`, `replay` |
| `lastgasp_probes_total` | | probes from version 4 agents waiting for an answer |
| `lastgasp_handshakes_total` | | version 5 handshakes answered, each one starts a session |
| `lastgasp_sessions` | | agent runs with a version 5 session in server memory |
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
| `lastgasp_alerts_total` | target, result | `sent`, `resolved`, `skipped`, `suppressed`, `silenced`, and `failed` per failed try |
| `lastgasp_auth_failures_total` | | requests with a wrong user, password or token |
| `lastgasp_auth_blocked_total` | | requests refused by the failure limit |
| `lastgasp_key_reloads_total` | result | key file reloads, `ok` or `error` |
| `lastgasp_retention_deleted_total` | table | rows deleted by retention |
| `lastgasp_enrollments_total` | result | enrollment requests: `enrolled`, `bad_token`, `host_taken`, `limited`, `malformed`, `dropped` |
| `lastgasp_build_info` | version, goversion | always 1 |
| `lastgasp_agent_info` | host, version | always 1, the version of the newest agent run |
| `lastgasp_agent_wire_version` | host | packet version of the newest agent run. 5 has forward secrecy |

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
