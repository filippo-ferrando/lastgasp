# How it works

```text
 machine (agent)                                    server
 ┌──────────────────────────────┐                   ┌──────────────────────────────────────┐
 │ /sys/fs/pstore ──► pstore    │                   │ UDP listener ──► decrypt, check key  │
 │                    queue ──┐ │   encrypted UDP   │        │   └──► ack to heartbeats    │
 │ /dev/kmsg ──► ring buffer ─┴─┼──────────────────►│        ▼                             │
 │                    sender ◄──┼─── acks ──────────│ queue ─► gap tracker ─► database     │
 └──────────────────────────────┘                   │                 │                    │
                                                    │                 ▼                    │
                                                    │ incident detector ─► alert targets   │
                                                    │ web UI, JSON API, /metrics           │
                                                    └──────────────────────────────────────┘
```

## The agent

The agent assumes the machine can fail in every way while it runs. Its job is to get the last lines out.

| Failure | What the agent does |
| --- | --- |
| Disk fails | Static binary with no libc. Config, key, hostname and boot ID are read once at start. Memory is locked with `mlockall`, so no page is ever read back from disk: pages mapped at start (the binary too) are read in and locked at once, new memory is locked when first used. Its own logs go to stderr through a non-blocking writer, never to files. |
| DNS or `/etc/resolv.conf` gone | Addresses are cached. A failed lookup never removes a known address. `-dns ip:port` skips `resolv.conf`, plain IPs skip DNS. |
| Network down | Records wait in a fixed size ring buffer (`-buffer`). When it is full, the oldest records are dropped: sent ones first, which most likely arrived, then unsent ones, which are counted. |
| Packets lost on the way | Sent records stay in the buffer until a server confirms them. Records a server reports missing are sent again. See [Acks](#acks). |
| No server listening yet | The agent holds its records and sends a probe every second until a server answers. See [Acks](#acks). |
| Kernel overwrites its buffer | `EPIPE` from `/dev/kmsg` is counted and reading goes on with the oldest record left. |
| `/dev/kmsg` read error | The device is opened again. Records already read are skipped, so the buffer is not filled with copies. |
| Out of memory | `oom_score_adj` is -1000 and a Go memory limit is set. |
| journald dies or hangs | `SIGPIPE` is ignored and log lines are dropped instead of blocking. |
| Internal bug | Each worker restarts after a panic. systemd restarts the process. The encryption state is kept across a restart, so no nonce is used twice. |
| Crash and reboot | On start, pstore files (logs the kernel saved before the crash) are read and sent first, from a queue of their own, so a full buffer never drops them. The whole kernel buffer is replayed too. The server removes what it already has. |
| Shutdown | On `SIGTERM` the agent sends what is left in its buffer for up to 2 seconds. |
| One server down | Several servers can be given with `-server a:5140,b:5140`. Every packet goes to all of them. |

The agent has three workers, each restarted on panic:

- **kmsg reader**: reads `/dev/kmsg` one record at a time and splits long messages into parts that fit one packet.
- **sender**: takes records from the pstore queue first, then from the ring buffer, encrypts and sends them, paced by `-rate`. Records to send again go before new ones. It sends a heartbeat every `-heartbeat`, and earlier when half the buffer waits for a server to confirm it.
- **resolver**: refreshes server addresses every `-resolve-every`.

## Packets

Each datagram holds one record, one heartbeat or one ack. It stays under 1400 bytes, so it is never fragmented, and is encrypted with AES-256-GCM.

| Part | Clear or encrypted | Content |
| --- | --- | --- |
| header | clear, authenticated | magic `LGP1`, version 3, host name, boot ID, instance ID, nonce counter |
| body | encrypted | kind, sequence number, send time, then the record (priority, kmsg sequence or pstore line, timestamp, pstore file ID, part, parts, text) or the heartbeat counters and the oldest sequence number the agent can still send again |
| tag | | 16 byte GCM tag |

Only the host name, boot ID, instance ID and nonce counter travel in clear text, because the server needs them to pick the key. The key of each agent run is derived from the shared key with HKDF-SHA256 over the boot ID and the instance ID. Every packet uses a new nonce from a counter, so a nonce is never used twice with the same derived key. A changed header makes the packet fail.

Version 2 packets (heartbeats without the oldest sequence number, acks without the receive state) are still accepted, so agents can be upgraded after the server. Version 1 packets (HMAC only, no encryption) are refused and counted as `version`.

## Sequence numbers

Every packet of an agent run has a sequence number, starting at 1. The number is used only when the local send worked, so a local network error does not look like a lost packet. Heartbeats carry agent counters (records read, kernel overruns, buffer drops, send errors, records buffered, uptime) and also reveal losses at the end of a burst.

## Acks

UDP gives no delivery receipt. Without help, an agent that starts before the server, or before its key is in the server key file, would send its whole boot log into nothing.

1. The server answers every valid heartbeat with an ack, sent from the listen port back to the address of the heartbeat. A heartbeat is answered once the batch it came in is stored, so the ack covers every record that arrived before it.
2. The ack echoes the sequence number and send time of the heartbeat. It is encrypted with a key derived with a different HKDF label, so server and agent nonces never meet.
3. The agent accepts an ack only for its own agent run and only when it answers one of its 16 newest heartbeats. A replayed old ack is ignored.
4. Until an ack arrives, the agent holds its records and sends a **probe** every second: a heartbeat with sequence number 0. Probes get an ack but are not counted, so probes that nobody received do not show up as missing.
5. When no ack arrives for 3 heartbeats (15 seconds by default), the agent holds records again until a server answers.
6. The server sends at most one ack per agent run every 200 ms, so a replayed heartbeat cannot turn it into a reflector.

The agent clock for acks is monotonic, so a clock step at boot (RTC wrong, NTP fixes it) does not change anything.

### Sending lost records again

An ack also says what arrived: every packet up to a sequence number, except a list of missing ranges (at most 32, the rest is left for the next ack).

1. The agent keeps every sent record in its buffer until an ack covers it. Then the record is done.
2. A record that an ack lists as missing is sent again with its first sequence number, so the server counts it as late. It is sent again only if its last send came before the heartbeat that the ack answers, so a record still on its way is not sent twice.
3. Each heartbeat carries the oldest sequence number the agent still holds. The server forgets missing ranges below it: they stay counted as missing, but no ack asks for them again. Lost heartbeats and records pushed out of a full buffer end up there.
4. When a record cannot be stored (the database is down for longer than the retries), the server marks its packet as missing again, so the agent sends it again.
5. With several servers, the first ack that covers a record is enough.

So records sent in the 15 seconds before the agent notices a dead server are not lost: when a server answers again, it lists them as missing and the agent sends them again, as long as they are still in the buffer. `-wait-ack=false` turns acks off, for networks where replies cannot reach the agent. Records are then done once sent.

## The server

1. The UDP listener decodes each datagram, looks up the key of the host and decrypts it. Bad packets are counted by reason (`auth_failed`, `unknown_host`, `bad_host`, `malformed`, `version`) and dropped. Probes and version 2 heartbeats get an ack at once.
2. Valid packets go into a queue of 65536 packets. When the queue is full, packets are dropped and counted (`lastgasp_server_queue_dropped_total`).
3. A worker takes packets in batches of up to 512, updates the gap tracker, saves new boots and writes the records in one transaction. A failed write is retried 5 times with backoff. Then the heartbeats of the batch get their ack.
4. The incident detector looks at every stored kernel line, at new boots and at hosts that stopped sending. Its slow queries (the crash check, the last line of a silent host) run without its lock, so the worker never waits for them.
5. Alert targets send incidents to webhooks and email, each with its own state and retries.

On stop the server closes the UDP socket, finishes HTTP requests, writes every queued packet in full batches, saves the gap state and the incident changes, then closes the database.

## Missing packets

For each agent run the server keeps the highest sequence number and the missing ranges. Ranges the agent can no longer send again are dropped from the list, but stay counted.

| Counter | Meaning |
| --- | --- |
| Missing | packets that never arrived |
| Late | missing packets that arrived later, out of order |
| Duplicates | packets received more than once |
| Agent drops | records the agent dropped because its buffer was full, or long messages cut at 255 parts. These never got a sequence number, so the agent reports them in its heartbeat |
| Kernel overruns | times the kernel overwrote records before the agent read them |

Gap state is saved to the database every 5 seconds and on stop, so a server restart keeps it. Packets sent while the server was down show up as missing.

## Deduplication

The same line can arrive more than once: an agent restart replays the kernel buffer, a pstore line was already sent live before the crash, a pstore file stays after several reboots. Each record has a key, and a record with a known key is skipped.

| Case | Key |
| --- | --- |
| Agent restart replays the kernel buffer | host, boot ID, kmsg sequence number, part |
| pstore line that also arrived through kmsg before the crash | host, previous boot ID, timestamp, message, part |
| Same pstore file sent again after later reboots | host, file content hash, line number, part |

A pstore file belongs to the boot seen just before the boot that sent it, and keeps that boot.
