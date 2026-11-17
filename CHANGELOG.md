# Changelog

All notable changes to lastgasp are listed in this file, newest first. Entries under
**Upgrade** need an action when upgrading.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). The release
workflow puts the section of the tag in the release notes, so keep `## [Unreleased]` at the top
and rename it to the version when cutting a release.

## [Unreleased]

### Added

- `CONTRIBUTING.md` and this changelog, which replaces `docs/upgrade-notes.md`.

### Changed

- README and docs restructured, with a new header image and a section list on every page.
- CI runs only when code, build files, deploy files or examples change. Docs and Markdown
  changes are skipped.
- The release notes are the changelog section of the tag, followed by the install line and the
  image and chart names.

## [0.2.1] - 2026-11-11

### Changed

- License changed from Apache-2.0 to GPL-3.0.

### Fixed

- Every server restart left about 2 packets per host counted as missing for good: the heartbeats
  sent while the server was down. The agent now sends lost heartbeats again, so they count as
  late. Upgrade the agents to get this; servers need no change.
- Journal lines were escaped like kernel lines, so newlines, backslashes and non-ASCII text
  appeared as `\xNN` (`mnt-a\x5cx2db.mount`, `dumped core.\x0a\x0aStack trace`). They now keep
  their text, and a journal incident has the first line of a multi-line message as its summary.
  Lines stored before the upgrade keep the old form.
- The web UI scrolled back to a clicked host or incident row on every refresh.

### Upgrade

- Custom `@journal` rules that match `\x0a` or `\x5c` need the plain characters.

## [0.2.0] - 2026-11-10

### Upgrade

- Install the new agent unit together with the new agent: the unit is now `Type=notify`, and an
  older agent never reports ready to it. `install-agent.sh` installs both.
- Upgrade the server before turning on `-journal` on agents: older servers refuse these packets.
- Corrected machine check lines (`Machine check events logged`) used to open a critical `mce`
  incident each time, now they open a warning when they pile up. Add `mce_corrected off` to the
  rules file to get the old behavior.
- Custom rules that match pstore text with tabs, backslashes or non-ASCII bytes need the escaped
  `\xNN` form.
- Incidents have a new `group_id` field; the schema upgrade adds the column on start.

### Added

- Agents can send userspace lines from journald with `-journal` (off by default). New incident
  kind `journal_error` and journal rules `coredump` and `unit_failed`. Rules files take
  `@journal` after the severity.
- The server can take extended netconsole lines (`-netconsole-listen`, `-netconsole-from`,
  `-netconsole-hosts`), so a panic arrives during the panic, without pstore. Records get the new
  source `netconsole`. See [Netconsole](docs/server.md#netconsole).
- The agent writes records no server confirmed to `/dev/pmsg0` when it stops (`-pmsg`,
  `-pmsg-max`), and the next boot sends them from pstore. Nothing changes on machines without a
  ramoops pmsg zone.
- Reboots or silent incidents of 3 or more hosts within 2 minutes form a group and get one alert
  per target (`-group-min-hosts`, `-group-window`). The other members get the alert state
  `grouped`. Set `-group-min-hosts 0` to keep one alert per host.
- New incident kind `flapping`: 3 reboots or returns from silence within 1 hour (`-flap-count`,
  `-flap-window`). While it is open, the reboot and silent alerts of that host are suppressed.
  Set `-flap-count 0` to turn it off.
- Rules take an optional count, `name severity 10/1h regexp`: the incident opens once that many
  lines matched within that time. New built-in rules `mce_corrected` and `edac_ce` (warning,
  10 in 1 hour) and `edac_ue` (critical).
- "Show logs" of an incident opens the logs of its boot at the incident line. `/api/logs` takes
  `boot=`, and `/api/incidents/{id}` adds the next 20 lines as `after`.
- New `-retain-bytes` flag (Helm `server.retainBytes`): keeps the records under a size such as
  `20GiB`.
- Helm chart: new values `server.incidents.*`, `server.netconsole.*`, `agent.pmsg` and
  `agent.journal.*`, all off apart from the incident defaults. A new image,
  `lastgasp-agent-journal`, is used with `agent.journal.enabled`. See
  [Kubernetes](docs/kubernetes.md).

### Changed

- Web UI: incidents and hosts side by side, logs below them in dense terminal rows, silences and
  agents in the last row with their forms behind a button. The Hosts table lists only the
  counters above 0. The kernel lines of an incident show in a dark block, the line that explains
  it marked.
- Kernel lines from pstore are escaped like `/dev/kmsg` lines, and the lines of one multi-line
  record are joined into one record. Pstore copies of multi-line records are now deduplicated
  against kmsg.
- An ack lists up to 64 missing ranges instead of 32, so heavy loss is repaired in half the
  heartbeats. The server sends 64 only to agents of v0.1.6 or newer (development builds get 32),
  so agents and server can be upgraded in any order.

### Fixed

- `systemd-pstore.service` moved pstore files away before the agent read them, so crash logs
  were lost on systemd distributions, and always in Kubernetes. The agent unit now runs before
  `systemd-pstore`, and the agent also reads the files moved in this boot from
  `/var/lib/systemd/pstore` (`-pstore-archive`; the Helm chart mounts it).
- Pstore lines from kernels with `CONFIG_PRINTK_CALLER` kept the caller ID (`[ T2048]`), so they
  were not matched with their kmsg copy.

## [0.1.5] - 2026-10-10

### Added

- The web UI offers join tokens valid for 1 year, as the API already allowed. Useful for a
  Kubernetes DaemonSet, where new nodes enroll with the same token.

### Changed

- The server retries the database for up to 30 seconds at start instead of exiting on the first
  refused connection. A new Kubernetes pod is often refused for a moment until network policies
  know its address.
- Helm chart: with `agent.enroll` and no `key.extraLines` or `key.existingSecret`, the chart
  makes no key secret and the server runs without a key file. A key secret kept only for the
  server can be removed by dropping `key.existingSecret`.
- `docs/kubernetes.md`: generic-device-plugin names the resource `devic.es/kmsg` by default.

### Removed

- Helm chart: the `image.digest` values. Images are pulled by tag, the chart appVersion by
  default.

### Fixed

- The web UI showed "server not reachable" when a host had gaps older than the agent buffer, as
  `/api/streams` sent `"missing_ranges": null` for them. It now sends an empty list.

## [0.1.4] - 2026-10-10

### Upgrade

- An agent started with `-stash` outside `/run/lastgasp` needs a drop-in with `ReadWritePaths=`
  for that directory, as the unit is now sandboxed.
- A stash file bigger than `-stash-size` is not read, so lowering `-stash-size` drops the
  records kept across that restart.
- Web UI sessions made before this release end once, and users log in again.
- `POST /api/enroll-tokens` without `uses` now makes a token for 1 agent, not one with no limit.
  Scripts that need a token for many agents send `"uses": 0` (no limit) or a number.
- To enroll a reinstalled host again, revoke its key in the Agents table first. The agent
  otherwise logs that the host is taken.

### Added

- `lastgasp-agent enroll` takes `-token-file`, `LASTGASP_TOKEN` and `-if-missing`.
- `install-agent.sh` reads `LASTGASP_TOKEN` and `LASTGASP_KEY`, which keep the secret out of
  `ps`.
- Helm chart: `agent.enroll.tokenSecret` gives each node its own key through an enroll init
  container, and drops the `*` line from the generated server key file. See
  [Keys](docs/kubernetes.md#keys).
- Helm chart: `agent.kmsgHostPath`, `agent.podSecurityContext` and `image.digest` allow a non
  privileged agent with a device plugin, and images pinned by digest.

### Security

- `install-agent.sh` stops when no `sha256sum`, `shasum` or `openssl` is found, instead of
  installing an unchecked download.
- The agent unit is sandboxed: the system is read-only apart from `/run/lastgasp`.
- The agent refuses a stash path that is a symlink or not a regular file.
- Web UI sessions are tied to the password of the user, so a changed password ends old sessions
  after a reload.
- `/readyz` no longer puts the reason in its 503 answer, as it needs no login. The reason is
  logged by the server.
- An address blocked after failed logins only stops password and token checks. Requests with a
  valid session cookie still work.
- A host that is enrolled already cannot enroll again, so a join token can no longer replace the
  key of another host.
- Helm chart: `/dev/kmsg` is mounted read only, and the server pod gets no service account
  token.

## [0.1.3] - 2026-10-08

Packet version 5 adds forward secrecy: agent and server agree on new keys with a Noise handshake
every 2 minutes, so a key stolen later cannot open traffic recorded before. See
[Forward secrecy](docs/forward-secrecy.md).

### Upgrade

**Upgrade the servers before the agents.** A new agent sends version 5 by default, and a server
older than this release never answers it. The agent then holds its records and logs
`waiting for a server to answer a handshake`. Nothing is lost while it waits, as long as the
buffer holds, but nothing arrives either.

| Setup | What to do |
| --- | --- |
| systemd, release binaries | upgrade the server, then the agents with the install script as usual |
| an agent must go first | install it with `--args "-forward-secrecy=false"`, and run the install script again without it once the server is upgraded |
| Helm chart | nothing: agent and server come from the same release. Agents outside the cluster follow the rows above |
| agents with `-wait-ack=false` | nothing, they keep sending version 4 without forward secrecy, and log so at start |

Once every agent sends version 5, the server can refuse the older versions:

1. Check the Hosts table: the new Wire column shows 5 for every host. In Prometheus,
   `lastgasp_agent_wire_version < 5` returns nothing.
2. Start the server with `-require-forward-secrecy` (Helm: `server.requireForwardSecrecy: true`).

### Added

- Packet version 5 with a Noise handshake and new keys every 2 minutes.
- Metrics `lastgasp_handshakes_total`, `lastgasp_sessions` and `lastgasp_agent_wire_version`,
  and the reasons `unknown_session` and `replay` in `lastgasp_packets_invalid_total`. A few
  `unknown_session` right after a server restart are normal.
- A `replay` server incident and a `LastgaspReplayedPackets` Prometheus rule, for many version 5
  packets seen twice.

### Changed

- The longest message per packet is 5 bytes shorter, so very long kernel lines are split a
  little earlier.

## [0.1.2] - 2026-10-08

### Added

- Kubernetes test of the Helm chart.

## [0.1.1] - 2026-10-07

### Fixed

- The copy button of the web UI.
- The server accepts an empty key file.

## [0.1.0] - 2026-10-07

First release: agent, server, web UI, incidents and alerts, Helm chart.

[Unreleased]: https://git.fferrando.cc/rdfilippo/lastgasp/compare/v0.2.1...HEAD
[0.2.1]: https://git.fferrando.cc/rdfilippo/lastgasp/releases/tag/v0.2.1
[0.2.0]: https://git.fferrando.cc/rdfilippo/lastgasp/releases/tag/v0.2.0
[0.1.5]: https://git.fferrando.cc/rdfilippo/lastgasp/releases/tag/v0.1.5
[0.1.4]: https://git.fferrando.cc/rdfilippo/lastgasp/releases/tag/v0.1.4
[0.1.3]: https://git.fferrando.cc/rdfilippo/lastgasp/releases/tag/v0.1.3
[0.1.2]: https://git.fferrando.cc/rdfilippo/lastgasp/releases/tag/v0.1.2
[0.1.1]: https://git.fferrando.cc/rdfilippo/lastgasp/releases/tag/v0.1.1
[0.1.0]: https://git.fferrando.cc/rdfilippo/lastgasp/releases/tag/v0.1.0
