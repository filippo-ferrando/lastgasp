# Upgrade notes

Changes that need an action on upgrade, newest first. The release workflow puts the section named like the tag (for example `## v0.2.0`), or `## Unreleased` when there is none, at the top of the release notes. Rename `Unreleased` to the tag when cutting the release.

## Unreleased

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
