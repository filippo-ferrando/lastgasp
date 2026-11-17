# Contributing to lastgasp

Bug reports, test results from other kernels and pstore backends, documentation fixes and code
are all welcome.

## Reporting bugs

Open an issue on the [issue tracker](https://git.fferrando.cc/rdfilippo/lastgasp/issues) and
include:

- the agent and server versions (shown in the web UI header and the Hosts table),
- the distribution, kernel version and architecture of the agent machine,
- how the agent and server run (install script, Docker, Helm chart),
- the agent log (`journalctl -u lastgasp-agent`) and the server log around the problem,
- for missing crash logs: the pstore backend (EFI, ramoops) and whether `systemd-pstore` runs.

## Development setup

Needs Go 1.27 or newer and `make`. `helm` and Docker Compose are optional: without them the
chart tests and the compose file checks are skipped.

```sh
git clone https://git.fferrando.cc/rdfilippo/lastgasp.git
cd lastgasp
make            # bin/lastgasp-agent and bin/lastgasp-server, static binaries
```

`deploy/install-agent.sh` run from a checkout uses `bin/lastgasp-agent` when it exists, and
downloads the newest release otherwise.

## Running the tests

```sh
make test       # Go tests with the race detector, plus the install script, examples and Helm chart tests
```

The PostgreSQL tests run when `LASTGASP_TEST_PG` points at a database:

```sh
docker run -d --rm --name pg -e POSTGRES_PASSWORD=test -p 127.0.0.1:55432:5432 postgres:17-alpine
LASTGASP_TEST_PG='postgres://postgres:test@127.0.0.1:55432/postgres?sslmode=disable' go test ./internal/store/
```

Other targets:

```sh
make dist VERSION=v1.2.0   # the release files in dist/
make image                 # server Docker image
make image-agent           # agent Docker image (make image-agent-journal for the journal variant)
```

## Project layout

```text
cmd/lastgasp-agent     agent binary
cmd/lastgasp-server    server binary, plus the "user" and "token" helper commands
internal/wire          packet format and encryption
internal/agent         kmsg and pstore readers, buffers, DNS cache, sender, hardening
internal/server        ingest, enrollment, gap tracking, retention, login sessions, HTTP API, metrics, web UI
internal/incident      incident rules and detection, webhook and email alerts
internal/store         SQLite and PostgreSQL storage and schema upgrades
internal/version       build version
deploy/                systemd units, the agent install script and the Helm chart
.forgejo/              CI and release workflows
examples/              Docker Compose setups of the server
docs/                  documentation
```

[How it works](docs/how-it-works.md) explains how these pieces fit together.

## Pull requests

- Every new feature comes with a test, unit or integration.
- Run `gofmt` and `go vet ./...` before pushing; CI checks both.
- Notable changes go in [CHANGELOG.md](CHANGELOG.md) under `## [Unreleased]`, and actions
  needed on upgrade under its `### Upgrade` heading.
- Keep comments short (two lines at most) and in plain language.

Releases are described in [Releasing](docs/releasing.md).
