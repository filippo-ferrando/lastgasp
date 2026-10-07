# Operations

## Production checklist

| Item | How |
| --- | --- |
| one key per host, or at least per group | `host hexkey` lines in the key file, see [server.md](server.md#key-file) |
| key and auth files readable only by the server | `root:lastgasp` mode 640, or owned by uid 65532 in Docker |
| login on the UI | `-auth-file`, see [web-ui-and-api.md](web-ui-and-api.md#login) |
| HTTPS in front of the UI | reverse proxy, see [server.md](server.md#behind-a-reverse-proxy) |
| retention | `-retain 720h` or what the disk allows, plus `-retain-info` and the record limits for noisy fleets, see [server.md](server.md#retention) |
| alerts | at least one `-alert-webhook`, `-alert-telegram` or `-alert-email`, with `-public-url` for links |
| monitoring | scrape `/metrics`, rules below |
| backups | see below |
| enrollment | make join tokens short lived and for few uses, revoke unused ones. Set `-agent-address` so install commands are right |
| health checks | `/readyz` in the load balancer or orchestrator, the image health check runs it already |
| pstore on agents | check `/sys/fs/pstore` after a test crash, see [incidents-and-alerts.md](incidents-and-alerts.md#pstore-backends) |
| stash on agents | `/run` is tmpfs, so the default `-stash` works. Check for `stash:` lines in the agent log |
| `kernel.panic` on agents | `sysctl kernel.panic=10`, so a panicked machine reboots and sends its pstore files |
| UDP receive buffer | `sysctl net.core.rmem_max=8388608`, so `-rcvbuf` takes effect |
| stop timeout | 30 seconds (`TimeoutStopSec`, `stop_grace_period`) |

## Monitoring

Prometheus rules for the things that need a human:

```yaml
groups:
  - name: lastgasp
    rules:
      - alert: LastgaspServerDown
        expr: up{job="lastgasp"} == 0
        for: 2m

      - alert: LastgaspAgentDown
        expr: lastgasp_agent_up == 0
        for: 5m
        annotations:
          summary: "{{ $labels.host }} sent nothing for 5 minutes"

      - alert: LastgaspPacketsLost
        expr: increase(lastgasp_packets_gap_total[15m]) > 100
        annotations:
          summary: "{{ $labels.host }} lost {{ $value }} packets in 15 minutes"

      - alert: LastgaspAgentDropping
        expr: increase(lastgasp_agent_buffer_dropped_total[15m]) > 0
        annotations:
          summary: "agent on {{ $labels.host }} dropped records, its buffer was full"

      - alert: LastgaspAgentHolding
        expr: lastgasp_agent_buffered_records > 1000
        for: 10m
        annotations:
          summary: "agent on {{ $labels.host }} keeps records it cannot send"

      - alert: LastgaspServerOverloaded
        expr: increase(lastgasp_server_queue_dropped_total[5m]) > 0

      - alert: LastgaspDatabaseErrors
        expr: increase(lastgasp_store_errors_total[5m]) > 0 or increase(lastgasp_records_lost_total[5m]) > 0

      - alert: LastgaspUnknownHosts
        expr: increase(lastgasp_packets_invalid_total{reason=~"unknown_host|auth_failed"}[15m]) > 0
        annotations:
          summary: "packets with a missing or wrong key, check the key file"

      - alert: LastgaspAlertsFailing
        expr: increase(lastgasp_alerts_total{result="failed"}[30m]) > 3
```

The server also watches most of these counters itself and opens `server` incidents, see [incidents-and-alerts.md](incidents-and-alerts.md#server-incidents). Prometheus is still the only way to notice a server that is down.

The server logs to stderr in `key=value` form (`journalctl -u lastgasp-server`, `docker compose logs server`). Errors are logged with `level=ERROR`.

## Backups

SQLite, while the server runs (WAL mode allows it):

```sh
sqlite3 /var/lib/lastgasp/lastgasp.db ".backup /backup/lastgasp-$(date +%F).db"
```

PostgreSQL:

```sh
pg_dump -Fc -h db -U lastgasp lastgasp > /backup/lastgasp-$(date +%F).dump
```

Also back up the key file, the auth file and the rules file. Enrolled agent keys are in the database, key file keys in the key file: losing them means enrolling or installing new keys on every agent.

## Upgrades

| Part | Order and effect |
| --- | --- |
| server | upgrade first. The schema is upgraded on start. Agents hold records while it restarts and send them when it answers again |
| agents | after the server. A server refuses packets of a newer version than its own (`reason="version"`), so a new agent never gets an ack from an old server |
| wire format | packets have a version. The server accepts versions 2 to 4: version 3 agents work but do not report their version (shown as `old`), version 2 agents also cannot send lost records again. Version 1 agents are refused (`lastgasp_packets_invalid_total{reason="version"}`) and must be upgraded |

Agents can be upgraded by running the install script again, without `--token`: it downloads the agent of its release (or `--version vX.Y.Z`), replaces the binary atomically and restarts the service, keeping the key. The Hosts table and `lastgasp_agent_info` show which agents still run an older version.

## Key rotation

For an enrolled agent: make a token and run the install command again on the host. Enrolling again replaces the key on both sides at once.

For key file lines:

1. Create a new key and add a line for the host to the server key file. A host has one key at a time, so do it host by host: replace the line, reload the server, then install the new key on the agent with `install-agent.sh -s ... -k NEWKEY`.
2. Between the reload and the agent restart, packets of that host fail with `auth_failed`. The agent holds records while no ack comes, so few lines are lost.
3. For the `*` key, move hosts to their own lines first, then change `*`.

## Troubleshooting

| Problem | Cause and fix |
| --- | --- |
| Enrollment: "no answer from the server" | UDP to the server port is blocked, the address is wrong, or the server is older than enrollment. Check `lastgasp_enrollments_total` on the server: no change means no packet arrived |
| Enrollment: "the server refused the token" | the token is wrong, expired, revoked or used up. Make a new one. `lastgasp_enrollments_total{result="bad_token"}` grows |
| Enrollment: "has its own line" | the host is in the key file, which wins over enrollment. Use that key, or remove the line and reload |
| `/readyz` answers 503 | the reason is in the body: the database does not answer, the UDP reader or the ingest worker stopped, or the ingest queue is almost full |
| Logs table empty, host shows up | Only heartbeats arrive. The agent replay went nowhere (older agents without acks), or the machine is quiet. Test with `echo test > /dev/kmsg` on the host |
| Host does not show up at all | No valid packet arrives. Check `lastgasp_packets_invalid_total` by reason, the firewall, and `journalctl -u lastgasp-agent` |
| `unknown_host` grows | The host name is not in the key file and there is no `*` line. The agent log shows the name it sends |
| `auth_failed` grows | Wrong key for that host |
| `version` grows | An old agent, upgrade it |
| Agent holds records forever | The server does not answer: no key, wrong key, or replies blocked by a firewall |
| Many missing packets on one host | Network loss on the path. Lower the agent `-rate` |
| Missing packets on all hosts at once | The server was down or overloaded. Check `lastgasp_server_queue_dropped_total`, raise `-rcvbuf` and `net.core.rmem_max` |
| Crash shows up as reboot | No pstore backend on the host, and nothing critical was sent before the crash |
| `429 Too Many Requests` in the UI | Too many failed logins from this address. Wait for `Retry-After` |
| Alerts not sent | `lastgasp_alerts_total{result="failed"}`, the server log (`alert` lines), the target `min` severity, and the rate limit (`suppressed` in the UI) |
| Database file keeps growing | Set `-retain`, `-retain-info` or `-retain-records`. SQLite reuses freed space but does not shrink the file |

## Security notes

- Packets are encrypted and authenticated. A captured packet sent again is caught by deduplication.
- The host name, boot ID and agent instance ID are visible on the network.
- An agent key lets its holder send logs as any host that uses that key. With `*`, that is every host without its own line.
- The web UI shows kernel logs, which can hold sensitive details. Use a login and HTTPS.
- Webhook alerts can be signed with `-alert-key-file`, so the receiver can check they come from the server.

## Known limits

- Records are sent again only while they are still in the agent buffer, or in the stash after an agent restart. A long outage at full rate can still lose records, and they show up as missing.
- Retention limits count records, not bytes. Size the record limits from the average record size of the database.
- A multi-line kernel message appears as one record in kmsg and as several lines in pstore, so those lines are not deduplicated against each other.
- Records recovered from the stash are sent by the new agent run, so the missing packets of the old run stay counted as missing.
- Alerts are sent at least once. A server stopped right after sending an alert, before saving that it did, sends it again after the restart.
- One server process reads one UDP socket. Several `-server` addresses send every packet to every server: that adds redundancy, not capacity.
