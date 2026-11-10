# Upgrade notes

Changes that need an action on upgrade, newest first. The release workflow puts the section named like the tag (for example `## v0.2.0`), or `## Unreleased` when there is none, at the top of the release notes. Rename `Unreleased` to the tag when cutting the release, and start a new `Unreleased` section above it (the tests need one).

## Unreleased

- Kernel lines from pstore are escaped like `/dev/kmsg` lines (tabs, backslashes and non-ASCII bytes appear as `\xNN`), and the lines of one multi-line record are joined into one record. Pstore copies of multi-line records are now deduplicated against kmsg. Custom rules that match pstore text with such characters need the escaped form.
- New `-retain-bytes` flag (Helm `server.retainBytes`): keeps the records under a size such as `20GiB`.
- An ack lists up to 64 missing ranges instead of 32, so heavy loss is repaired in half the heartbeats. The server sends 64 only to agents of v0.1.6 or newer (development builds get 32), so agents and server can be upgraded in any order.
- Helm chart: the `image.digest` values are removed. Images are pulled by tag, the chart appVersion by default.

## v0.1.5

- The server retries the database for up to 30 seconds at start instead of exiting on the first refused connection. A new Kubernetes pod is often refused for a moment until network policies know its address.
- The web UI offers join tokens valid for 1 year, as the API already allowed. Useful for a Kubernetes DaemonSet, where new nodes enroll with the same token.
- Helm chart: with `agent.enroll` and no `key.extraLines` or `key.existingSecret`, the chart makes no key secret and the server runs without a key file. A key secret kept only for the server can be removed by dropping `key.existingSecret`.
- Fixed: the web UI showed "server not reachable" when a host had gaps older than the agent buffer, as `/api/streams` sent `"missing_ranges": null` for them. It now sends an empty list.
- docs/kubernetes.md: generic-device-plugin names the resource `devic.es/kmsg` by default.

## v0.1.4

Security changes in the agent and its install files:

- `install-agent.sh` stops when no `sha256sum`, `shasum` or `openssl` is found, instead of installing an unchecked download. It reads `LASTGASP_TOKEN` and `LASTGASP_KEY`, which keep the secret out of `ps`.
- `lastgasp-agent enroll` takes `-token-file`, `LASTGASP_TOKEN` and `-if-missing`.
- The agent unit is sandboxed: the system is read-only apart from `/run/lastgasp`. An agent started with `-stash` elsewhere needs a drop-in with `ReadWritePaths=` for that directory.
- The agent refuses a stash path that is a symlink or not a regular file. A stash file bigger than `-stash-size` is not read, so lowering `-stash-size` drops the records kept across that restart.

Web UI changes:

- Web UI sessions are tied to the password of the user, so a changed password ends old sessions after a reload. Sessions made before this release end once, and users log in again.
- `/readyz` no longer puts the reason in its 503 answer, as it needs no login. The reason is logged by the server.
- An address blocked after failed logins only stops password and token checks. Requests with a valid session cookie still work.

Enrollment changes:

- `POST /api/enroll-tokens` without `uses` now makes a token for 1 agent, not one with no limit. Scripts that need a token for many agents send `"uses": 0` (no limit) or a number.
- A host that is enrolled already cannot enroll again, so a join token can no longer replace the key of another host. To enroll a reinstalled host again, revoke its key in the Agents table first. The agent then logs that the host is taken.

Helm chart changes:

- `agent.enroll.tokenSecret` gives each node its own key through an enroll init container, and drops the `*` line from the generated server key file. See [kubernetes.md](kubernetes.md#keys).
- `agent.kmsgHostPath`, `agent.podSecurityContext` and `image.digest` allow a non privileged agent with a device plugin, and images pinned by digest.
- `/dev/kmsg` is mounted read only, and the server pod gets no service account token.

## v0.1.3

Packet version 5 adds forward secrecy: agent and server agree on new keys with a Noise handshake every 2 minutes, so a key stolen later cannot open traffic recorded before. See [forward-secrecy.md](forward-secrecy.md).

**Upgrade the servers before the agents.** A new agent sends version 5 by default, and a server older than this release never answers it. The agent then holds its records and logs `waiting for a server to answer a handshake`. Nothing is lost while it waits, as long as the buffer holds, but nothing arrives either.

| Setup | What to do |
| --- | --- |
| systemd, release binaries | upgrade the server, then the agents with the install script as usual |
| an agent must go first | install it with `--args "-forward-secrecy=false"`, and run the install script again without it once the server is upgraded |
| Helm chart | nothing: agent and server come from the same release. Agents outside the cluster follow the rows above |
| agents with `-wait-ack=false` | nothing, they keep sending version 4 without forward secrecy, and log so at start |

Once every agent sends version 5, the server can refuse the older versions:

1. Check the Hosts table: the new Wire column shows 5 for every host. In Prometheus, `lastgasp_agent_wire_version < 5` returns nothing.
2. Start the server with `-require-forward-secrecy` (Helm: `server.requireForwardSecrecy: true`).

Also new in this release:

- Metrics `lastgasp_handshakes_total`, `lastgasp_sessions` and `lastgasp_agent_wire_version`, and the reasons `unknown_session` and `replay` in `lastgasp_packets_invalid_total`. A few `unknown_session` right after a server restart are normal.
- A `replay` server incident and a `LastgaspReplayedPackets` Prometheus rule, for many version 5 packets seen twice.
- The longest message per packet is 5 bytes shorter, so very long kernel lines are split a little earlier.
