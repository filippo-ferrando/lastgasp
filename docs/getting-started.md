# Getting started

This page sets up one server and one agent, then checks that logs arrive. Details for each part are in [agent.md](agent.md) and [server.md](server.md).

## Requirements

| Part | Needs |
| --- | --- |
| build | Go 1.27 or newer, `make` |
| agent | Linux, root (or `CAP_SYSLOG` and `CAP_IPC_LOCK`), systemd for the install script |
| server | Linux, macOS or any Go platform. Docker optional. SQLite is built in, PostgreSQL optional |
| network | UDP from the agents to the server port (5140 by default), and UDP replies back (stateful firewalls allow them) |

## 1. Build

```sh
make            # bin/lastgasp-agent and bin/lastgasp-server, static binaries
make test       # all tests with the race detector, plus the install script test
make image      # lastgasp-server:latest Docker image
```

Both binaries are static (no libc). The agent binary can be copied to any Linux machine of the same CPU type.

## 2. Create a key

Agents and the server share a key. One key for all hosts is the simplest setup. One key per host limits the damage of a leaked key.

```sh
openssl rand -hex 32 > agent.key
```

The server key file has one `host hexkey` line per host. `*` matches every host without a line of its own:

```text
# keys
*  4f1c0b...e9
```

```sh
echo "*  $(cat agent.key)" > keys
```

## 3. Start the server

### Option A: Docker Compose with PostgreSQL

```sh
cp .env.example .env          # set POSTGRES_PASSWORD
chmod 644 keys                # the container runs as uid 65532
docker compose up -d --build
docker compose logs -f server
```

The UI is on `http://127.0.0.1:8080`. UDP port 5140 is open to the network.

### Option B: Docker with SQLite

```sh
make image
docker run -d --name lastgasp -p 5140:5140/udp -p 127.0.0.1:8080:8080 \
  -v ./keys:/etc/lastgasp/keys:ro -v lastgasp:/var/lib/lastgasp lastgasp-server
```

### Option C: binary

```sh
./bin/lastgasp-server -key-file keys -db lastgasp.db -http 127.0.0.1:8080
```

The log line `lastgasp-server started` shows the UDP and HTTP addresses in use.

## 4. Install the agent

Copy the binary, the install script and the unit to the machine, then run the script as root:

```sh
scp bin/lastgasp-agent deploy/install-agent.sh deploy/lastgasp-agent.service root@db-01:/tmp/
ssh root@db-01 /tmp/install-agent.sh -s logs.example.net:5140 -k "$(cat agent.key)" -n db-01
```

Without `-k` the script creates a new key and prints the line to add to the server key file. After editing the key file, reload the server (`systemctl reload lastgasp-server`, or `docker compose kill -s HUP server`).

The agent log shows the connection:

```sh
ssh root@db-01 journalctl -u lastgasp-agent -n 20
# agent: host=db-01 boot=... instance=... servers=logs.example.net:5140
# send: waiting for a server to answer before sending records
# send: a server answered, sending 1834 buffered records
```

## 5. Check that logs arrive

Open the UI. The host shows up in the Hosts table, the kernel boot log in the Logs table.

Write a test line into the kernel log on the agent machine:

```sh
echo "hello from lastgasp" > /dev/kmsg
```

The line shows up in the UI within about two seconds. The API gives the same:

```sh
curl -s 'http://127.0.0.1:8080/api/logs?q=hello&limit=5'
```

## 6. Next steps

- Add a login before opening the UI to the network: [web-ui-and-api.md](web-ui-and-api.md#login).
- Send alerts to chat or email: [incidents-and-alerts.md](incidents-and-alerts.md#alerts).
- Set retention and monitoring: [operations.md](operations.md).
- Cause a test incident on a test machine: [incidents-and-alerts.md](incidents-and-alerts.md#testing-incidents).
