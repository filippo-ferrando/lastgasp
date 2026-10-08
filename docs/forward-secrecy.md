# Forward secrecy

Design of packet version 5: agent and server agree on fresh keys with the [Noise Protocol Framework](https://noiseprotocol.org/noise.html), so a key stolen later cannot open traffic recorded earlier.

## Why

Up to version 4 the key of an agent run is derived from the shared key with HKDF over the boot ID and the instance ID. The boot ID and the instance ID travel in clear text. Someone who records the UDP traffic today and gets the shared key later (a stolen `/etc/lastgasp/agent.key`, a server database backup, a leaked key file) can derive every run key and read every line ever sent with that key.

Kernel logs hold more than it seems: IP and MAC addresses, user names in OOM reports, file paths, device serials, command lines of crashed processes, sometimes secrets passed on the command line. Logs of a machine also stay interesting for a long time, so traffic recorded once is worth keeping for an attacker.

Forward secrecy closes this gap: each session key comes from short lived key pairs that are thrown away, so the shared key alone is not enough to read old traffic.

## Goals

- Use a published, analysed protocol and a maintained library. No home made key exchange or ratchet.
- No extra wait before the first line goes out. The agent already holds its records until a server answers a probe, so the handshake takes the place of the probe.
- Keep key files, the `*` default key and enrollment as they are.
- Keep every loss recovery rule: acks, missing ranges, resends, the stash, several servers.
- New keys every few minutes, so a memory dump of a running agent or server opens only the last minutes.
- Old agents keep working with a new server.

Not goals of this version:

- Hiding host name, boot ID and instance ID. They stay in clear text, the server needs them to pick the key.
- Forward secrecy with `-wait-ack=false`. Without a way back from the server there is no key exchange, so these agents keep version 4.

## Options looked at

| Option | Why not chosen |
| --- | --- |
| DTLS (pion/dtls) | One or two round trips before data and a full new handshake after every server restart or NAT change. One session state machine per server. A large dependency in a small static agent. |
| QUIC datagrams (quic-go) | Solid TLS 1.3 security, but a heavy dependency, and Go TLS has no external pre-shared keys, so enrollment would have to issue certificates. |
| WireGuard tunnel between agent and server | The best proven option and no code at all. Still possible as a deployment choice, but every agent would need a tunnel set up, and the kernel log path would depend on one more component staying up. |
| HPKE to a server public key (Go standard library) | One way encryption. Stealing the server private key opens all old traffic, so it is not forward secrecy. |
| Own ratchet over HKDF | Exactly what this design avoids: a new protocol nobody has analysed. |
| **Noise `NNpsk0`** (`github.com/flynn/noise`) | Chosen. Handshake patterns with published proofs, the same framework as WireGuard and Nebula. Nebula runs `flynn/noise` over UDP with lost and reordered packets, which is the lastgasp case. Pure Go, only needs `golang.org/x/crypto`. |

## Protocol

Name: `Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s`. The same primitives as WireGuard.

```text
NNpsk0:
  -> psk, e
  <- e, ee
```

- **psk**: 32 bytes derived from the agent key with HKDF-SHA256, label `lastgasp v5 psk`. Only someone with the agent key can make or answer a handshake, as before.
- **e**: a new X25519 key pair on each side for every handshake. The session key depends on `ee`, the result of the key exchange between the two short lived keys, so it is gone once both private keys are wiped.
- **prologue**: `lastgasp v5`, host, boot ID, instance ID and session ID. A handshake cannot be moved to another host, boot, run or session.

A quantum computer that breaks X25519 still needs the pre-shared key to open recorded traffic, as the key is mixed in.

### Packets

Every version 5 datagram starts with the same clear header:

| Field | Size |
| --- | --- |
| magic `LGP1` | 4 |
| version `5` | 1 |
| host length, host | 1 + up to 255 |
| boot ID | 16 |
| instance ID | 8 |
| type | 1 |
| session ID | 4 |
| counter | 8 |

| Type | Direction | Body |
| --- | --- | --- |
| 1 handshake init | agent to server | Noise message 1: agent public key, encrypted payload with the handshake number |
| 2 handshake reply | server to agent | Noise message 2: server public key, empty encrypted payload |
| 3 data | agent to server | record or heartbeat, the same content as version 4 |
| 4 ack | server to agent | ack, the same content as version 4 |

The agent picks a random session ID for each handshake. Data and acks are sealed with the two Noise transport keys, one per direction. The counter is the nonce: it is sent in clear text and passed to the cipher, as WireGuard does, so lost or reordered packets do not break anything. The whole header is authenticated as additional data.

### Sessions

The server keeps these sessions per agent run, in memory only:

- **pending**: answered handshakes with no data seen yet, at most 4
- **current**: the newest session that carried data
- **previous**: the one before, for packets still on the way

A pending session becomes current with its first valid data packet, as in WireGuard, and older pending ones are dropped. A replayed handshake can only make a pending session that never carries data, it never replaces a working one.

Each data packet passes a replay window of 4096 counters after it is decrypted. Older or repeated counters are dropped and counted as `replay`. Records sent again by the agent use a new counter, so resends still pass.

### Timers

The values come from WireGuard:

| Timer | Value | Meaning |
| --- | --- | --- |
| rekey after | 2 minutes | the agent starts a new handshake with a server |
| reject after | 3 minutes | a session is no longer used or accepted |
| handshake retry | 1 second | time between handshake inits to one server |

The agent keeps sending with the current session while the new handshake runs. When it does not complete within a minute, the old session expires, the server counts as not answering and records are held, as when acks stop today.

### Handshake replay

The handshake init payload holds a handshake number that grows for every handshake of an agent run. The server refuses a number that is not higher than the last one it answered for that run, as long as it holds a session of that run. After a server restart, or once all sessions of the run expired, a replayed init makes only a pending session, see above.

### Cost for the server

The server checks the init with the pre-shared key before it does any key exchange, so packets without the key cost one symmetric decrypt. Handshake replies use the same limit as acks, one per agent run every 200 ms, and a reply is smaller than the init, so the server cannot be used to amplify traffic.

## Effect on the rest of the design

| Area | Effect |
| --- | --- |
| Probe | Replaced by the handshake init. A completed handshake counts as the first ack. |
| Server restart | Sessions are in memory only and lost. Agents get no acks, drop the session after three heartbeats, start a new handshake and send again what the server lists as missing. |
| Several servers | One session per server. Each packet is sealed once per server. A server without a session gets handshake inits, not records. |
| Agent restart, stash | A new agent run means a new handshake. Stashed records are sealed with the new session. |
| Panic in the sender | Sessions are kept, as the nonce counter is today. |
| Key removed or changed | Data of a host whose key is gone is refused at once. A changed key applies from the next handshake. |
| Packet size | The header is 5 bytes larger, so the longest message per packet is 5 bytes shorter, for every version. |
| Memory | The private keys of a handshake are wiped as soon as it ends. Go gives no way to wipe the expanded cipher keys inside the library, they are freed by the garbage collector. With `mlockall` they never reach swap. |

## Compatibility and upgrade

- The server accepts versions 2 to 5. Upgrade servers first, as for every version change.
- A new agent speaks version 5 when `-wait-ack` is on, which is the default. `-forward-secrecy=false` keeps version 4, for servers not upgraded yet.
- The agent never falls back to version 4 by itself. A fallback would let anyone who drops handshake packets switch forward secrecy off.
- `-wait-ack=false` keeps version 4. The agent logs this at start.
- `-require-forward-secrecy` on the server refuses versions 2 to 4, counted as `version`, once all agents are upgraded.

## What forward secrecy covers

| Someone who | Gets |
| --- | --- |
| records traffic, steals the agent key later | nothing of the recorded traffic. The key lets them make new handshakes as the agent, as today |
| records traffic, steals the server database or key file later | nothing of the recorded traffic |
| dumps the memory of the agent or the server | the sessions of the last 3 minutes at most |
| has the agent key during a handshake and sits on the path | the traffic of that session, as with any pre-shared key protocol. Forward secrecy protects the past, not the present |
| watches the network | host names, boot IDs, instance IDs and packet sizes, as today |

## Tests

- `internal/wire`: handshake round trip, wrong key, init moved to another run or session, data and ack round trip, changed header, replay window (new, repeated, too old, out of order), private keys wiped.
- `internal/server`: handshake reply, handshake number replay, pending session promoted by data, previous session still accepted, expiry after 3 minutes, unknown session counted, `-require-forward-secrecy`.
- `internal/agent`: records held until the handshake ends, rekey after 2 minutes while sending goes on, a new handshake after acks stop, one session per server.
- End to end: agent and server over loopback with version 5, a server restart in the middle.
