# Open work

Known gaps, ordered by how much they matter. None of them loses data in normal use.

- The incident detector runs its database queries while holding its lock, and the ingest worker waits for that lock on every packet. Indexes keep the queries short, but a very slow database can still slow down ingest. Run the queries outside the lock.
- When retention deletes the boot row of an old boot and that boot sends again (a machine with a wrong boot ID, or a replay), it is taken for a new boot and a false reboot is reported.
- Two servers sharing one database can assign the same pstore file to different boots if both see it at the same moment. The stored assignment wins, but the losing server keeps its own answer in memory until restart.
- The agent locks all its memory, including address space the Go runtime only reserves. Check whether `MCL_ONFAULT` for future pages keeps the disk-failure guarantee with less locked memory.
- Acks only tell that a server listens. A cumulative ack (highest sequence number received without gaps) would let the agent send lost records again.
