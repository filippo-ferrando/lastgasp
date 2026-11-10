# Open work

Known gaps, ordered by how much they matter. None of them loses data in normal use.

- An ack lists at most 64 missing ranges. Heavy loss spread over many ranges takes several heartbeats to repair.
- The names of boots removed by retention are kept forever, one small row per boot.
- Userspace logs come from journald only, through `journalctl`. Machines without systemd (plain syslog) send kernel lines only.
- Records still waiting for a confirmation when a machine reboots only survive through pmsg, which needs a ramoops backend with a pmsg zone and a warm reboot.
- Version 5 packets still carry the host name, boot ID and instance ID in clear text, as the server needs them to pick the key. Hiding them would need a server public key and a lookup by session ID only.
