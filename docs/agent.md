# Agent

`lastgasp-agent` runs on every machine whose kernel logs should be kept. It needs root, or the capabilities `CAP_SYSLOG` (read `/dev/kmsg`) and `CAP_IPC_LOCK` (lock memory).

## Install in one line

Make a join token in the web UI (Agents, "add agents") and run the command it shows, as root, on each new machine:

```sh
curl -fsSL https://git.fferrando.cc/rdfilippo/lastgasp/releases/download/v1.0.0/install-agent.sh | sudo sh -s -- --server 10.0.0.5:5140 --token lgj_3f9a...
```

The install script of a release:

1. downloads `lastgasp-agent-linux-<arch>` and `lastgasp-agent.service` of its own release (amd64, arm64 or 32 bit arm), with `curl` or `wget`
2. checks both against the `SHA256SUMS` of the release, and stops on a mismatch
3. enrolls with the token: the agent gets its own key from the server, see [server.md](server.md#enrollment). Nothing is installed when this fails
4. copies the binary to `/usr/local/sbin/lastgasp-agent` (copy then rename, so a running agent never sees a half written file), with the key in `/etc/lastgasp/agent.key` (mode 600, folder mode 700)
5. installs `lastgasp-agent.service` and a drop-in with the flags, enables and starts the service and checks that it runs

The script from the main branch (`.../raw/branch/main/deploy/install-agent.sh`) installs the newest release, found with the Forgejo API. Run from a checkout, it uses `bin/lastgasp-agent` when it exists.

## Install with the script

The same script with a binary at hand, or a key instead of a token:

```sh
make agent
scp bin/lastgasp-agent deploy/install-agent.sh deploy/lastgasp-agent.service root@db-01:/tmp/lg/
ssh root@db-01 /tmp/lg/install-agent.sh -s logs.example.net:5140 -n db-01
```

| Option | Meaning |
| --- | --- |
| `-s`, `--server LIST` | servers, `host:port[,host:port...]` (required to install) |
| `-t`, `--token TOKEN` | join token: enroll with the first server and get a key from it |
| `-k`, `--key HEX` | agent key in hex, at least 32 characters |
| `--key-file PATH` | read the key from a file |
| `-n`, `--hostname NAME` | name sent to the server, default the kernel hostname |
| `-b`, `--binary PATH` | agent binary, default `bin/lastgasp-agent` or `./lastgasp-agent`, else downloaded |
| `-V`, `--version TAG` | release to download, like `v1.2.0`. Default: the release of the script, or the newest one |
| `--repo URL` | repository with the releases, default `https://git.fferrando.cc/rdfilippo/lastgasp` (or `LASTGASP_REPO`) |
| `-a`, `--args "FLAGS"` | extra agent flags, like `"-dns 10.0.0.53:53 -buffer 32768"` |
| `--no-start` | install and enable, but do not start now |
| `--no-systemd` | only copy files |
| `--uninstall` | stop the service and remove the binary and unit |
| `--purge` | with `--uninstall`, also remove `/etc/lastgasp` and the key |

`LASTGASP_TOKEN` and `LASTGASP_KEY` can replace `--token` and `--key`. Values given as options show up in `ps` and in the shell history, so the environment is the better place for them. To keep the token out of the history too, read it at a prompt: `read -r LASTGASP_TOKEN && export LASTGASP_TOKEN`, then run the script. `sudo` drops most of the environment, so run the script from a root shell or with `sudo --preserve-env=LASTGASP_TOKEN`.

A download is checked against the release checksums with `sha256sum`, `shasum` or `openssl`, the first one found. Without any of them the script stops.

Without `-t`, `-k` or `--key-file`, an existing key is kept, or a new one is created and the line for the server key file is printed:

```text
install-agent: created a new key. Add this line to the server key file:
db-01 3f9a...c1
```

Running the script again updates the binary and flags and keeps the key. It is safe to run from configuration management.

The flags live in a systemd drop-in (`/etc/systemd/system/lastgasp-agent.service.d/10-install.conf`), not in an environment file. systemd keeps it in memory, so a restart does not read config from a failing disk. `%`, `$` and `\` in `--args` are escaped, so they reach the agent as typed.

### Many machines

With a token for several uses, the one line install works from any loop or configuration management tool:

```sh
for h in db-01 db-02 web-01; do
  ssh root@$h "curl -fsSL https://git.fferrando.cc/rdfilippo/lastgasp/releases/download/v1.0.0/install-agent.sh | sh -s -- -s logs.example.net:5140 -t lgj_..."
done
```

With one shared key instead:

```sh
for h in db-01 db-02 web-01; do
  scp bin/lastgasp-agent deploy/install-agent.sh deploy/lastgasp-agent.service root@$h:/tmp/lg/
  ssh root@$h /tmp/lg/install-agent.sh -s logs.example.net:5140 --key-file /dev/stdin < agent.key
done
```

### Uninstall

```sh
ssh root@db-01 /tmp/lg/install-agent.sh --uninstall           # keeps /etc/lastgasp/agent.key
ssh root@db-01 /tmp/lg/install-agent.sh --uninstall --purge   # removes the key too
```

## Enroll by hand

The install script runs this, which can also be used on its own:

```sh
lastgasp-agent enroll -server logs.example.net:5140 -token-file /run/secrets/lastgasp-token -key-file /etc/lastgasp/agent.key
LASTGASP_TOKEN=lgj_3f9a... lastgasp-agent enroll -server logs.example.net:5140 -if-missing
```

A token given with `-token` shows up in `ps` and in the shell history, so `-token-file` or `LASTGASP_TOKEN` is the better choice. With `-if-missing` the command can run at every start, for example in a Kubernetes init container: it only enrolls when there is no valid key yet.

| Flag | Default | Meaning |
| --- | --- | --- |
| `-server` | | server `host:port`, the first of a comma separated list is used (required) |
| `-token-file` | | file with the join token |
| `-token` | | join token. Exactly one of `-token` and `-token-file` is needed, `LASTGASP_TOKEN` is used when neither is set |
| `-if-missing` | false | exit without enrolling when the key file already holds a valid key |
| `-hostname` | kernel hostname | name to enroll, must match the `-hostname` the agent runs with |
| `-key-file` | /etc/lastgasp/agent.key | where to save the key |
| `-timeout` | 30s | how long to wait for an answer |

## Run by hand

```sh
lastgasp-agent -server logs.example.net:5140 -key-file /etc/lastgasp/agent.key
LASTGASP_KEY=4f1c...e9 lastgasp-agent -server 10.0.0.5:5140,10.0.0.6:5140 -hostname db-01
```

## Flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `-server` | | comma separated `host:port` list (required). Every packet goes to every server |
| `-key-file` | | file with the hex key. `LASTGASP_KEY` is used when not set |
| `-hostname` | kernel hostname | name sent to the server: UTF-8, no spaces or control characters, at most 255 bytes |
| `-dns` | | DNS server `ip:port`, skips `/etc/resolv.conf` |
| `-buffer` | 16384 | records kept in memory until a server confirms them, 1 to 1048576. pstore lines have their own queue on top |
| `-rate` | 2000 | max packets per second, 0 for no limit |
| `-heartbeat` | 5s | heartbeat interval, 0 or at least 100ms |
| `-wait-ack` | true | hold records until a server answers a heartbeat. Needs `-heartbeat` above 0 |
| `-forward-secrecy` | true | send version 5 packets with a handshake per server, so a stolen key cannot open old traffic, see [forward-secrecy.md](forward-secrecy.md). Needs `-wait-ack`. Set to false only for servers that do not know version 5 yet |
| `-resolve-every` | 1m | DNS refresh interval, at least 1s |
| `-pstore` | /sys/fs/pstore | pstore folder, empty to disable |
| `-kmsg` | /dev/kmsg | kernel log device |
| `-boot-id` | /proc/sys/kernel/random/boot_id | boot ID file. A random ID is used when it cannot be read |
| `-mlock` | true | lock all memory |
| `-memory-limit` | 64 MiB | soft Go memory limit in bytes |
| `-stash` | /run/lastgasp/agent.stash | file that keeps unconfirmed records across agent restarts, empty to disable. Must be on tmpfs or ramfs, see [The stash](#the-stash) |
| `-stash-size` | 8 MiB | stash size in bytes, 64 KiB to 1 GiB |
| `-version` | | print the version and exit. The agent also sends its version in every heartbeat, shown in the Hosts table |

Bad values stop the agent at start with a clear message, instead of failing later.

## The stash

Records the agent sent but no server confirmed yet live in memory, so an agent restart (an upgrade, a crash, `systemctl restart`) used to lose them. The kernel buffer replay covers kmsg lines still in the kernel buffer, but not older ones, and not pstore lines that `systemd-pstore` already moved away.

The stash fixes this without touching a disk. Every record the agent queues is also copied into a ring in a file under `/run`, which is tmpfs, so the file lives in RAM. The agent keeps the file mapped and notes which records a server confirmed. When the agent starts again in the same boot, it reads the records that were still unconfirmed, sends them before anything else, and starts a new ring. The server removes the duplicates.

- The agent refuses to use a stash file that is not on tmpfs or ramfs, logs it, and runs without one.
- The space is reserved at start. A full `/run` disables the stash instead of killing the agent later.
- The ring keeps the newest records. If more than `-stash-size` bytes of records wait for a confirmation, the oldest are only in the agent memory and are lost on a restart. 8 MiB holds about 50000 typical kernel lines.
- A reboot empties `/run`, which is fine: the next boot has a new boot ID, and pstore covers the crash.
- `install-agent.sh --uninstall` removes `/run/lastgasp`.

## The systemd unit

`deploy/lastgasp-agent.service`:

- starts early in boot (`DefaultDependencies=no`, before `sysinit.target`), so boot messages are read while still in the kernel buffer
- restarts forever, one second apart (`Restart=always`, `StartLimitIntervalSec=0`)
- is never chosen by the OOM killer (`OOMScoreAdjust=-1000`)
- may lock unlimited memory (`LimitMEMLOCK=infinity`)

## Sizing

| Setting | Effect |
| --- | --- |
| `-buffer` | each slot holds one record of up to about 1.3 KB, from when it is read until a server confirms it. 16384 slots cover a full default kernel buffer several times. Raise it for machines with a large `log_buf_len` or long server outages. Lost records can be sent again only while they are still in the buffer |
| `-rate` | the boot replay and error floods are paced to this rate. 2000 packets per second is about 2.6 MB/s. Lower it on slow links |
| `-heartbeat` | shorter means faster loss detection, lost records sent again sooner, and a faster switch to holding when the server dies, at the cost of more packets |
| `-memory-limit` | the agent normally uses a few MB. The limit only matters with a very large `-buffer` |
| `-stash-size` | locked RAM on top of the agent memory. Size it like the buffer: about 140 bytes per typical kernel line |

## Where the agent logs

The agent writes to stderr, which systemd sends to the journal:

```sh
journalctl -u lastgasp-agent -f
```

| Line | Meaning |
| --- | --- |
| `send: waiting for a server to answer before sending records` | started, no ack yet |
| `send: a server answered, sending N buffered records` | a server acked, records flow |
| `send: no answer from any server for 15s, holding records` | the server stopped answering |
| `dns: initial lookup: ...` | the first lookup failed, it keeps trying |
| `dns: ... (keeping last known addresses)` | a refresh failed, the cached addresses stay in use |
| `kmsg: open /dev/kmsg: permission denied` | not root and no `CAP_SYSLOG` |
| `pstore: queued N lines from the previous boot` | crash logs found and queued |
| `stash: N records from the previous run will be sent again` | the agent restarted and found unconfirmed records |
| `stash: ... is not on tmpfs or ramfs ...` | the stash path is on a disk, the agent runs without a stash. Use a path under `/run` |
| `<worker>: panic: ...` | a bug, the worker restarted. Please report it with the stack |

## Troubleshooting

| Problem | Check |
| --- | --- |
| Agent says "waiting for a server to answer a handshake" forever | As below, or the server is too old for version 5 packets: upgrade the server, or set `-forward-secrecy=false` until then |
| Agent says "waiting for a server to answer" forever | The server is not reachable on UDP, the host has no key in the server key file (server metric `lastgasp_packets_invalid_total{reason="unknown_host"}`), the key is wrong (`reason="auth_failed"`), or replies are blocked by a firewall. As a last resort `-wait-ack=false` sends without acks |
| Host shows up but no logs | Look at the agent log for kmsg errors. Write a test line: `echo test > /dev/kmsg` |
| Many missing packets | Network loss, or the server queue is full (`lastgasp_server_queue_dropped_total`). Lower `-rate`, raise the server `-rcvbuf` |
| Agent drops grow | The buffer filled up during an outage. Raise `-buffer` |
| Kernel overruns grow | The kernel logs faster than the agent reads. Raise the kernel buffer with `log_buf_len=` on the kernel command line |
| `harden: mlockall: ...` or `harden: cannot raise memlock limit` at start | Missing `CAP_IPC_LOCK` or a low `LimitMEMLOCK`. The agent keeps running, but pages may be read back from disk |
