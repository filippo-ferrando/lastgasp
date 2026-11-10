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
| No server listening yet | The agent holds its records and sends a handshake init (or a probe, for version 4) every second until a server answers. See [Acks](#acks). |
| Kernel overwrites its buffer | `EPIPE` from `/dev/kmsg` is counted and reading goes on with the oldest record left. |
| `/dev/kmsg` read error | The device is opened again. Records already read are skipped, so the buffer is not filled with copies. |
| Out of memory | `oom_score_adj` is -1000 and a Go memory limit is set. |
| journald dies or hangs | `SIGPIPE` is ignored and log lines are dropped instead of blocking. |
| Internal bug | Each worker restarts after a panic. systemd restarts the process. The encryption state is kept across a restart, so no nonce is used twice. |
| Agent restart or upgrade | Every queued record is also copied to a ring in a tmpfs file (`-stash`). A new run of the same boot sends the records the old run had not got confirmed. See [the stash](agent.md#the-stash). |
| Crash and reboot | On start, pstore files (logs the kernel saved before the crash) are read and sent first, from a queue of their own, so a full buffer never drops them. The whole kernel buffer is replayed too. The server removes what it already has. |
| Shutdown | On `SIGTERM` the agent sends what is left in its buffer for up to 2 seconds. |
| One server down | Several servers can be given with `-server a:5140,b:5140`. Every packet goes to all of them. |

The agent has three workers, each restarted on panic:

- **kmsg reader**: reads `/dev/kmsg` one record at a time and splits long messages into parts that fit one packet.
- **sender**: takes records from the first queue (pstore lines and records from the stash) first, then from the ring buffer, encrypts and sends them, paced by `-rate`. Records to send again go before new ones. It sends a heartbeat every `-heartbeat`, and earlier when half the buffer waits for a server to confirm it.
- **resolver**: refreshes server addresses every `-resolve-every`.

## Packets

Each datagram holds one record, one heartbeat, one ack or one handshake message. It stays under 1400 bytes, so it is never fragmented.

Agents send version 5 by default: a Noise handshake with each server gives session keys that change every 2 minutes, so a key stolen later cannot open recorded traffic. The design, the reasons and the packet layout are in [forward-secrecy.md](forward-secrecy.md). Agents with `-wait-ack=false` or `-forward-secrecy=false` send version 4, described here:

| Part | Clear or encrypted | Content |
| --- | --- | --- |
| header | clear, authenticated | magic `LGP1`, version 4, host name, boot ID, instance ID, nonce counter |
| body | encrypted | kind, sequence number, send time, then the record (priority, kmsg sequence or pstore line, timestamp, pstore file ID, part, parts, text) or the heartbeat counters, the oldest sequence number the agent can still send again, and the agent version |
| tag | | 16 byte GCM tag |

Only the host name, boot ID, instance ID and nonce counter travel in clear text, because the server needs them to pick the key. The key of each agent run is derived from the shared key with HKDF-SHA256 over the boot ID and the instance ID. Every packet uses a new nonce from a counter, so a nonce is never used twice with the same derived key. A changed header makes the packet fail.

Version 4 packets are encrypted with AES-256-GCM. Version 2 and 3 packets are still accepted, so agents can be upgraded after the server: version 3 heartbeats have no agent version, version 2 heartbeats also lack the oldest sequence number. Each ack has the version of the heartbeat it answers, so an older agent can read it. Version 1 packets (HMAC only, no encryption) are refused and counted as `version`.

## Enrollment

An agent can get its key from the server instead of a key file, with a join token made in the web UI. Enrollment packets use the same UDP port with their own magic, `LGE1`, and no encryption: they only carry public values.

The token itself never travels. Both sides use its SHA-256, which is also all the server keeps of it.

1. The agent makes an X25519 key pair and sends its host name, its public key and a proof: an HMAC of the host name and the public key, keyed with the token hash.
2. The server finds the usable token (not expired, not revoked, uses left) whose hash gives the same proof, makes its own X25519 key pair and computes the shared secret.
3. Both sides derive the agent key: HKDF-SHA256 over the shared secret, with the token hash as salt and the host name in the label. The server counts one use of the token, saves the key, and answers with its public key and an HMAC of the host name made with the new key.
4. The agent derives the same key, checks the HMAC, and saves the key to `/etc/lastgasp/agent.key`.

| Someone who | Gets |
| --- | --- |
| watches the network | two public keys and a proof. Not the key, not the token |
| replays a request | the same answer, useless without the private key of the agent |
| changes the agent public key on the way | a proof that does not match, so the request is refused |
| changes the server answer on the way | an answer the agent refuses: the check needs the token hash |
| guesses tokens | 128 random bits, a few tries per second, and 10 minutes of silence after 10 wrong ones |

The agent sends its request again every second until an answer comes. The server answers a repeated request with the same reply, without using the token again. A wrong token gets a short refusal, so the installer can say what went wrong.

## Sequence numbers

Every packet of an agent run has a sequence number, starting at 1. The number is used only when the local send worked, so a local network error does not look like a lost packet. Heartbeats carry agent counters (records read, kernel overruns, buffer drops, send errors, records buffered, uptime) and also reveal losses at the end of a burst.

## Acks

UDP gives no delivery receipt. Without help, an agent that starts before the server, or before its key is in the server key file, would send its whole boot log into nothing.

1. The server answers every valid heartbeat with an ack, sent from the listen port back to the address of the heartbeat. A heartbeat is answered once the batch it came in is stored, so the ack covers every record that arrived before it.
2. The ack echoes the sequence number and send time of the heartbeat. It is encrypted with a key derived with a different HKDF label, so server and agent nonces never meet.
3. The agent accepts an ack only for its own agent run and only when it answers one of its 16 newest heartbeats. A replayed old ack is ignored.
4. Until an ack arrives, the agent holds its records and sends a **probe** every second: a heartbeat with sequence number 0. Probes get an ack but are not counted, so probes that nobody received do not show up as missing. With version 5 the handshake init takes the place of the probe, and a finished handshake counts as the first ack.
5. When no ack arrives for 3 heartbeats (15 seconds by default), the agent holds records again until a server answers.
6. The server sends at most one ack per agent run every 200 ms, so a replayed heartbeat cannot turn it into a reflector.

The agent clock for acks is monotonic, so a clock step at boot (RTC wrong, NTP fixes it) does not change anything.

### Sending lost records again

An ack also says what arrived: every packet up to a sequence number, except a list of missing ranges (at most 64, the rest is left for the next ack). Agents older than v0.1.6 refuse more than 32, so they get at most 32.

1. The agent keeps every sent record in its buffer until an ack covers it. Then the record is done.
2. A record that an ack lists as missing is sent again with its first sequence number, so the server counts it as late. It is sent again only if its last send came before the heartbeat that the ack answers, so a record still on its way is not sent twice.
3. Each heartbeat carries the oldest sequence number the agent still holds. The server forgets missing ranges below it: they stay counted as missing, but no ack asks for them again. Lost heartbeats and records pushed out of a full buffer end up there.
4. When a record cannot be stored (the database is down for longer than the retries), the server marks its packet as missing again, so the agent sends it again.
5. With several servers, the first ack that covers a record is enough.

So records sent in the 15 seconds before the agent notices a dead server are not lost: when a server answers again, it lists them as missing and the agent sends them again, as long as they are still in the buffer. `-wait-ack=false` turns acks off, for networks where replies cannot reach the agent. Records are then done once sent.

## The server

1. The UDP listener decodes each datagram, looks up the key of the host and decrypts it. Bad packets are counted by reason (`auth_failed`, `unknown_host`, `bad_host`, `malformed`, `version`, and for version 5 `unknown_session` and `replay`) and dropped. Probes, handshake inits and version 2 heartbeats get an answer at once.
2. Valid packets go into a queue of 65536 packets. When the queue is full, packets are dropped and counted (`lastgasp_server_queue_dropped_total`).
3. A worker takes packets in batches of up to 512, updates the gap tracker, saves new boots and writes the records in one transaction. A failed write is retried 5 times with backoff. Then the heartbeats of the batch get their ack.
4. The incident detector looks at every stored kernel line, at new boots and at hosts that stopped sending. Its slow queries (the crash check, the last line of a silent host) run without its lock, so the worker never waits for them.
5. Alert targets send incidents to webhooks, Telegram, Alertmanager and email, each with its own state and retries. Silences hold back alerts of matching incidents.
6. A self check looks at the server counters every 10 seconds and opens a `server` incident when the database fails, packets are dropped, alerts fail, or packets come with an unknown host or a wrong key.

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
| Agent restart replays the kernel buffer, or sends records from the stash | host, boot ID, kmsg sequence number, part |
| pstore line that also arrived through kmsg before the crash | host, previous boot ID, timestamp, message, part |
| Same pstore file sent again after later reboots | host, file content hash, line number, part |

A pstore file belongs to the boot seen just before the boot that sent it, and keeps that boot.
