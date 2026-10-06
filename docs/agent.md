# Agent

`lastgasp-agent` runs on every machine whose kernel logs should be kept. It needs root, or the capabilities `CAP_SYSLOG` (read `/dev/kmsg`) and `CAP_IPC_LOCK` (lock memory).

## Install with the script

`deploy/install-agent.sh` installs the agent as a systemd service:

1. copies the binary to `/usr/local/sbin/lastgasp-agent` (copy then rename, so a running agent never sees a half written file)
2. writes the key to `/etc/lastgasp/agent.key` (mode 600, folder mode 700)
3. installs `lastgasp-agent.service` and a drop-in with the flags
4. enables and starts the service and checks that it runs

```sh
make agent
scp bin/lastgasp-agent deploy/install-agent.sh deploy/lastgasp-agent.service root@db-01:/tmp/lg/
ssh root@db-01 /tmp/lg/install-agent.sh -s logs.example.net:5140 -n db-01
```

| Option | Meaning |
| --- | --- |
| `-s`, `--server LIST` | servers, `host:port[,host:port...]` (required to install) |
| `-k`, `--key HEX` | agent key in hex, at least 32 characters |
| `--key-file PATH` | read the key from a file |
| `-n`, `--hostname NAME` | name sent to the server, default the kernel hostname |
| `-b`, `--binary PATH` | agent binary, default `bin/lastgasp-agent` or `./lastgasp-agent` |
| `-a`, `--args "FLAGS"` | extra agent flags, like `"-dns 10.0.0.53:53 -buffer 32768"` |
| `--no-start` | install and enable, but do not start now |
| `--no-systemd` | only copy files |
| `--uninstall` | stop the service and remove the binary and unit |
| `--purge` | with `--uninstall`, also remove `/etc/lastgasp` and the key |

Without `-k` or `--key-file`, an existing key is kept, or a new one is created and the line for the server key file is printed:

```text
install-agent: created a new key. Add this line to the server key file:
db-01 3f9a...c1
```

Running the script again updates the binary and flags and keeps the key. It is safe to run from configuration management.

The flags live in a systemd drop-in (`/etc/systemd/system/lastgasp-agent.service.d/10-install.conf`), not in an environment file. systemd keeps it in memory, so a restart does not read config from a failing disk. `%`, `$` and `\` in `--args` are escaped, so they reach the agent as typed.

### Many machines

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
| `-resolve-every` | 1m | DNS refresh interval, at least 1s |
| `-pstore` | /sys/fs/pstore | pstore folder, empty to disable |
| `-kmsg` | /dev/kmsg | kernel log device |
| `-boot-id` | /proc/sys/kernel/random/boot_id | boot ID file. A random ID is used when it cannot be read |
| `-mlock` | true | lock all memory |
| `-memory-limit` | 64 MiB | soft Go memory limit in bytes |

Bad values stop the agent at start with a clear message, instead of failing later.

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
| `<worker>: panic: ...` | a bug, the worker restarted. Please report it with the stack |

## Troubleshooting

| Problem | Check |
| --- | --- |
| Agent says "waiting for a server to answer" forever | The server is not reachable on UDP, the host has no key in the server key file (server metric `lastgasp_packets_invalid_total{reason="unknown_host"}`), the key is wrong (`reason="auth_failed"`), or replies are blocked by a firewall. As a last resort `-wait-ack=false` sends without acks |
| Host shows up but no logs | Look at the agent log for kmsg errors. Write a test line: `echo test > /dev/kmsg` |
| Many missing packets | Network loss, or the server queue is full (`lastgasp_server_queue_dropped_total`). Lower `-rate`, raise the server `-rcvbuf` |
| Agent drops grow | The buffer filled up during an outage. Raise `-buffer` |
| Kernel overruns grow | The kernel logs faster than the agent reads. Raise the kernel buffer with `log_buf_len=` on the kernel command line |
| `harden: mlockall: ...` or `harden: cannot raise memlock limit` at start | Missing `CAP_IPC_LOCK` or a low `LimitMEMLOCK`. The agent keeps running, but pages may be read back from disk |
