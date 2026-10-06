# Plan: crash incidents and alerts

**Status:** implemented. This document now describes what was built. User docs are in the Incidents, Alerts and Login sections of the README. Open work is listed at the end.

## Why

lastgasp collects the last kernel lines of a dying machine, but nothing pointed at them. An operator had to notice a host was down, open the UI, pick the host, and scroll to the end of the right boot. The data that matters most (the last lines before silence, and the pstore dump after reboot) was stored but not surfaced.

Incidents turn those moments into one record per host and boot that says what happened, links the lines that explain it, and sends alerts.

## Incident kinds

| Kind | Opened when | Closed when | Severity |
| --- | --- | --- | --- |
| `kernel_error` | a kmsg line matches a rule. Grouped per host, boot and rule, with a count. | no new line for `-resolve-after` (resolved), or the boot ends | from the rule |
| `silent` | no packet for `-silent-after` (default 2m, separate from `-stale-after`) | the host sends again (resolved), or the boot ends | warning |
| `reboot` | a new boot ID shows up for a host | `-crash-wait` later, when it is decided crash or reboot | info |
| `crash` | a `reboot` where the old boot has pstore records, or its last kmsg lines match a critical rule | at the decision. Never resolved | critical |

When a reboot is decided as clean (not a crash), the `kernel_error` and `silent` incidents of the old boot are marked resolved. pstore lines that arrive after the decision, even after a server restart, still turn the newest reboot of the host into a crash and reset its alerts.

## Rules

Thirteen built-in regexp rules, first match wins:

- critical: `panic`, `lockup`, `oops`, `bug`, `gpf`, `mce`, `memory_failure`
- warning: `rcu_stall`, `hung_task`, `oom`, `io_error`, `fs_error`, `nvme`

A `-rules` file adds rules or replaces built-in ones (`name severity regexp`), or removes them (`name off`). It is loaded at start and on SIGHUP. Critical rules also decide crashes.

## Design

### Server

- `internal/incident` holds the rules, the `Detector` and the `Notifier`.
- The ingestor tells the detector about every valid packet (`Seen`), every new boot (`NewBoot`, from `Ingestor.ensureBoot`), and every stored batch (`Records`). A ticker calls `Tick` every second for silent hosts, reboot decisions, quiet periods and saving grouped counts.
- The detector keeps small state in memory: per host boot and last seen time, open incidents, and the newest clean reboot per host. Open incidents and that reboot are loaded from the database on start, and known hosts count as seen at start, so a restart does not open silent incidents for every host.
- Incident context is a record ID range, not a copy: the last `-incident-context` kmsg records of the boot up to `last_record_id`, plus all pstore records of the boot.
- Boots first seen in the same batch get increasing times, so the previous boot is always found.

### Store

Schema changes go through numbered migrations recorded in `schema_version`, applied in a transaction on start.

```text
incidents (id, host, boot_id, kind, severity, rule, opened_at, updated_at, closed_at,
           first_record_id, last_record_id, count, summary, resolved, acked_at)
alerts    (incident_id, target, state, updated_at)   primary key (incident_id, target)
```

Times are unix milliseconds, 0 means not set. Retention deletes closed incidents by `updated_at`, and their alert rows.

### Alerts

- `-alert-webhook` and `-alert-email` are repeatable. Each target has a name, minimum severity and rate limit. Webhooks also have a format (`json` or `slack`) and a signing key. Defaults come from the `-alert-*` flags. The default webhook name is the URL host, so secrets in URLs stay out of metrics and the UI.
- Email targets use SMTP with STARTTLS (or TLS on port 465), plain only on localhost, with an optional login and an optional private CA (`ca-file`). The mail has the summary, details, link, and the last 40 pstore and kernel lines.
- One goroutine per target, each with its own backoff (1s to 5m). A target that is down does not hold back the others.
- Alert state is a row per incident and target: `sent`, `suppressed` (rate limit), `skipped` (short blip) or `resolved`. It is written only after the target took the alert, so unsent alerts are retried after a restart.
- A `silent` incident that is already resolved when a target would send it is a short blip: nothing is sent and the state is `skipped`.
- A target sends new incidents at or above its minimum, and a resolved alert for incidents it sent that are now resolved. Only incidents updated in the last 24 hours are considered, so a new target is not flooded with history.
- The body is signed with HMAC-SHA256 in `X-Lastgasp-Signature: sha256=<hex>` when the target has a key.

### API and UI

| Endpoint | Role | Returns |
| --- | --- | --- |
| `GET /api/incidents?host=&kind=&open=1&limit=` | viewer | incidents with alert state per target, newest first |
| `GET /api/incidents/{id}` | viewer | the incident, its kmsg context and pstore lines |
| `POST /api/incidents/{id}/ack` | admin | marks it as seen. Needs `Content-Type: application/json` |
| `GET /api/me` | viewer | the logged in user and role |

Roles come from `-auth-file` (users with bcrypt passwords, API tokens as SHA-256). Without it every request counts as admin. After 5 failed logins in 10 minutes, the client address and the user name are refused with 429 for a delay that doubles from 1 to 15 minutes. There is no permanent lockout, so an attacker cannot lock out a real admin for good.

The UI has an incidents panel above the hosts table and a detail view with the pstore dump and the last kernel lines, the matching line marked. Links use `/#incident=ID`. The ack button is hidden for viewers.

### Metrics

- `lastgasp_incidents_total{host, kind}`
- `lastgasp_incidents_open{kind}`
- `lastgasp_alerts_total{target, result}` with result `sent`, `resolved`, `skipped`, `failed` or `suppressed`
- `lastgasp_auth_failures_total`, `lastgasp_auth_blocked_total`

## Tests

| Area | Covered by |
| --- | --- |
| Store | incidents, per target alert state, resolve and retention on SQLite, and on PostgreSQL with `LASTGASP_TEST_PG`. Upgrade of a version 1 database on SQLite only |
| Rules | built-in rules against real kernel lines, rules file parsing |
| Detector | grouping, silent open and close, crash from pstore, crash from the kmsg tail, plain reboot, late pstore after a restart, quiet period, clean reboot resolves and crash does not, restore after restart |
| Alerts | failing webhook and retry, signing, rate limit, slack format, wake, independent targets, target option parsing, resolved alerts, skipped short blips, email through a fake SMTP server |
| Server | end to end crash through the ingestor and API, ack with roles, login failure delay, boots in one batch |

## Decisions on the open questions

- `silent` has its own `-silent-after` (default 2 minutes), longer than `-stale-after`, as a network split looks the same as a dead host.
- Ack needs the admin role when login is on. A JSON content type is always required, so a form on another site cannot call it.
- Email is a target type next to webhooks, with the same state, retries and rate limit.
- Short silent blips send nothing, the incident stays visible in the UI.
- Repeated failed logins get a growing delay, not a lockout. Basic auth stays, so there is no logout.
- Retention stays by age only.

## Related work done with this feature

| Feature | Notes |
| --- | --- |
| Retention | `-retain`, by age. Records, closed incidents, old boots (newest per host kept) and agent runs. |
| Login | `-auth-file` with viewer and admin roles, basic auth and bearer tokens, reloaded on SIGHUP, failure delay per address and user. |
| pstore queue on the agent | pstore lines have their own queue, sized to hold all of them, sent first. |
| Key reload on SIGHUP | keys, rules and users. A broken file keeps the old ones. |
| Encrypted packets | AES-256-GCM with a key per agent run, wire version 2. |

## Checked end to end

- PostgreSQL 17: all store tests, including the upgrade of a version 1 database.
- The Docker image and `compose.yaml` with PostgreSQL, the real agent, webhooks, and email through an SMTP server with STARTTLS, login and a private CA.
- The web UI in headless Chromium: login and roles, incident list and view, ack, filters, links, dark mode and phone width.
- The agent unit installed by `install-agent.sh` under systemd.

## Open work

- The agent locks all its memory, including address space the Go runtime only reserves. Check whether `MCL_ONFAULT` for future pages keeps the disk-failure guarantee with less locked memory.
