# Open work

Known gaps, ordered by how much they matter. None of them loses data in normal use.

- Sent records live only in the memory of one agent run. After an agent restart, records sent but not confirmed are not sent again: the kernel buffer replay covers kmsg lines, but not lines already pushed out of it.
- An ack lists at most 32 missing ranges. Heavy loss spread over many ranges takes several heartbeats to repair.
- The names of boots removed by retention are kept forever, one small row per boot.
