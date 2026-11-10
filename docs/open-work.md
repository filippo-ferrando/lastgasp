# Open work

Known gaps, ordered by how much they matter. None of them loses data in normal use.

- An ack lists at most 64 missing ranges. Heavy loss spread over many ranges takes several heartbeats to repair.
- The names of boots removed by retention are kept forever, one small row per boot.
- Userspace logs (journald or syslog) are not collected. They could come from a separate reader on the agent, kept apart from the hardened kmsg path so a stuck journald can never block kernel lines.
- The stash keeps records across agent restarts, not across reboots, as pstore covers crashes. Records still waiting for a confirmation when a machine reboots are not sent again: the agent only gets 2 seconds to send them while it stops.
- Version 5 packets still carry the host name, boot ID and instance ID in clear text, as the server needs them to pick the key. Hiding them would need a server public key and a lookup by session ID only.
