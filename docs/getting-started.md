# Getting started

This page sets up one server and one agent, then checks that logs arrive. Details for each part are in [agent.md](agent.md) and [server.md](server.md).

- [Requirements](#requirements)
- [1. Start the server](#1-start-the-server)
- [2. Install the agent](#2-install-the-agent)
- [3. Check that logs arrive](#3-check-that-logs-arrive)
- [4. Next steps](#4-next-steps)
- [Building from source](#building-from-source)

## Requirements

| Part | Needs |
| --- | --- |
| agent | Linux on amd64, arm64 or 32 bit arm, root, systemd for the install script, `curl` or `wget` |
| server | Docker, or the release binary on Linux. SQLite is built in, PostgreSQL optional |
| network | UDP from the agents to the server port (5140 by default), and UDP replies back (stateful firewalls allow them) |
| build from source | only to change the code: Go 1.27 or newer, `make` |

Releases are on [git.fferrando.cc/rdfilippo/lastgasp/releases](https://git.fferrando.cc/rdfilippo/lastgasp/releases): the agent and server for each architecture, the install script, systemd units and checksums. The server image is `git.fferrando.cc/rdfilippo/lastgasp-server`.

## 1. Start the server

### Option A: Docker with SQLite

```sh
docker run -d --name lastgasp -p 5140:5140/udp -p 127.0.0.1:8080:8080 -v lastgasp:/var/lib/lastgasp \
  git.fferrando.cc/rdfilippo/lastgasp-server:latest \
  -listen :5140 -http :8080 -db /var/lib/lastgasp/lastgasp.db -agent-address 10.0.0.5:5140
```

`-agent-address` is the address agents send to, here the LAN address of the Docker host. It only fills in the install command shown in the UI.

### Option B: Docker Compose

Ready setups with SQLite, PostgreSQL, HTTPS, Telegram and Alertmanager are in [examples/](../examples/README.md).

### Option C: binary

```sh
curl -fsSLO https://git.fferrando.cc/rdfilippo/lastgasp/releases/download/v1.0.0/lastgasp-server-linux-amd64
chmod +x lastgasp-server-linux-amd64
./lastgasp-server-linux-amd64 -db lastgasp.db -http 127.0.0.1:8080 -agent-address 10.0.0.5:5140
```

For a systemd service, see [server.md](server.md#install-as-a-systemd-service).

The log line `lastgasp-server started` shows the version and the UDP and HTTP addresses in use. Open `http://127.0.0.1:8080`.

## 2. Install the agent

In the UI, the Agents section has an "Add agents" button. It makes a join token and shows the command that installs an agent with it:

```sh
curl -fsSL https://git.fferrando.cc/rdfilippo/lastgasp/releases/download/v1.0.0/install-agent.sh | sudo sh -s -- --server 10.0.0.5:5140 --token lgj_3f9a...
```

Run it on the machine to watch. The script downloads the agent of the same release, checks it against the release checksums, enrolls it, and starts the service. Enrolling gives the agent its own key: the agent and the server agree on it over UDP, and the key is never sent over the network. A token works for 1 agent (the default), 10 agents or any number, for 1 hour up to 7 days, and can be revoked.

The agent log shows the connection:

```sh
journalctl -u lastgasp-agent -n 20
# agent: version=v1.0.0 host=db-01 boot=... instance=... servers=10.0.0.5:5140
# send: waiting for a server to answer before sending records
# send: a server answered, sending 1834 buffered records
```

### Without enrollment

Keys can also be managed by hand, for example from configuration management. The server key file has one `host hexkey` line per host, and `*` matches every host without a line of its own:

```sh
openssl rand -hex 32 > agent.key
echo "*  $(cat agent.key)" > keys                       # start the server with -key-file keys
curl -fsSL https://git.fferrando.cc/rdfilippo/lastgasp/releases/download/v1.0.0/install-agent.sh |
  sudo sh -s -- --server 10.0.0.5:5140 --key "$(cat agent.key)"
```

Key file lines and enrolled agents work side by side. See [server.md](server.md#keys-and-enrollment).

## 3. Check that logs arrive

The host shows up in the Hosts table with its agent version, the kernel boot log in the Logs table.

Write a test line into the kernel log on the agent machine:

```sh
echo "hello from lastgasp" | sudo tee /dev/kmsg
```

The line shows up in the UI within about two seconds. The API gives the same:

```sh
curl -s 'http://127.0.0.1:8080/api/logs?q=hello&limit=5'
```

## 4. Next steps

- Add a login before opening the UI to the network: [web-ui-and-api.md](web-ui-and-api.md#login).
- Send alerts to chat, Telegram or email: [incidents-and-alerts.md](incidents-and-alerts.md#alerts).
- Set retention and monitoring: [operations.md](operations.md).
- Cause a test incident on a test machine: [incidents-and-alerts.md](incidents-and-alerts.md#testing-incidents).

## Building from source

```sh
make            # bin/lastgasp-agent and bin/lastgasp-server, static binaries
make test       # all tests with the race detector, plus the script tests
make image      # lastgasp-server Docker image
```

`deploy/install-agent.sh` run from a checkout uses `bin/lastgasp-agent` when it exists, and downloads the newest release otherwise. Tests and the code layout are in [CONTRIBUTING.md](../CONTRIBUTING.md).
