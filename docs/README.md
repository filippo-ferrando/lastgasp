# lastgasp documentation

lastgasp ships kernel logs off a Linux machine over encrypted UDP, so the last lines before a crash, a hang or a dead disk are saved somewhere else. A small agent runs on every machine, a server stores the logs, finds missing packets, turns crashes and kernel errors into incidents and sends alerts.

| Page | Content |
| --- | --- |
| [Getting started](getting-started.md) | first server, first agent in one line, check that logs arrive |
| [How it works](how-it-works.md) | agent and server design, packets, acks, missing packets, deduplication |
| [Forward secrecy](forward-secrecy.md) | why and how version 5 packets use a Noise handshake, options looked at, upgrade |
| [Agent](agent.md) | one line install, enrollment, install script, flags, systemd unit, stash, sizing, troubleshooting |
| [Server](server.md) | keys and enrollment, binary, systemd, Docker, health checks, database, retention, reload, reverse proxy |
| [Kubernetes](kubernetes.md) | Helm chart: agent DaemonSet, server, keys, Prometheus |
| [Incidents and alerts](incidents-and-alerts.md) | incident kinds, rules, webhooks, email, testing incidents |
| [Web UI and API](web-ui-and-api.md) | login and sessions, roles, JSON API with examples, Prometheus metrics |
| [Operations](operations.md) | production checklist, monitoring, backups, upgrades, troubleshooting, limits |
| [Upgrade notes](upgrade-notes.md) | actions needed when upgrading to a release |
| [Releasing](releasing.md) | CI, release files, server image, secrets |
| [Open work](open-work.md) | ideas not done yet |

## Words used in these pages

| Word | Meaning |
| --- | --- |
| host | a machine running the agent, named by `-hostname` or the kernel hostname |
| boot | one run of the kernel, named by the kernel boot ID (`/proc/sys/kernel/random/boot_id`) |
| agent run | one start of the agent process, named by a random instance ID. A boot can have several agent runs |
| record | one kernel log line, or one part of a line too long for one packet |
| kmsg | the live kernel log, read from `/dev/kmsg` |
| pstore | kernel logs saved in persistent memory or EFI variables before a crash, read after the next boot from `/sys/fs/pstore` |
| sequence number | a counter in every packet of an agent run, used to find missing packets |
| ack | the answer of the server to an agent heartbeat. It says which packets arrived, so the agent can send lost ones again |
| incident | something worth a look: a crash, a reboot, a silent host or a kernel error |
| target | where alerts go: a webhook, Alertmanager, Telegram or an email address list |
| join token | a secret made in the web UI that lets new agents enroll |
| enrollment | an agent getting its own key from the server with a join token |
