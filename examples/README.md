# Examples

Docker Compose setups of the server. Each folder holds one `compose.yaml` with the setup steps at the top. They run the server as uid 65532 and publish UDP 5140 for agents. `sqlite` and `production` use the released image `git.fferrando.cc/rdfilippo/lastgasp-server`, the others build it from this checkout (`build: ../..`). Either line works in every example.

| Folder | Shows |
| --- | --- |
| [sqlite](sqlite/compose.yaml) | the simplest setup: one container, SQLite in a volume, UI on localhost, agents enroll with join tokens |
| [postgres](postgres/compose.yaml) | PostgreSQL, with retention by age, by level and per host |
| [telegram](telegram/compose.yaml) | alerts to a Telegram chat, the bot token as a compose secret |
| [alertmanager](alertmanager/compose.yaml) | incidents sent to Alertmanager for routing, and Prometheus with rules for the health of the server |
| [https](https/compose.yaml) | Caddy in front with automatic HTTPS, a login, and the client address passed to the login limit |
| [production](production/compose.yaml) | all of it together: PostgreSQL, HTTPS, login, enrollment, `/metrics` behind the login, Telegram and retention limits |

## Common steps

The sqlite and production examples need no key file: open the UI, click "add agents" and run the command it shows on each machine. The others use a key file:

```sh
cd examples/postgres                          # or another folder with -key-file
openssl rand -hex 32 > agent.key
echo "*  $(cat agent.key)" > keys             # "*" accepts every host with this key
sudo chown 65532:65532 keys && chmod 600 keys
docker compose up -d
docker compose logs -f server
```

Then install agents with `agent.key` (`install-agent.sh --key`), see [docs/agent.md](../docs/agent.md). A test line on an agent host shows up in the UI at once:

```sh
echo "<3>BUG: lastgasp test" > /dev/kmsg     # also opens a kernel_error incident and sends an alert
```

## Notes

- Files mounted into the server (`keys`, `auth`, `telegram.token`) must be readable by uid 65532. Keep them mode 600 and owned by 65532, they hold secrets.
- `.env` holds the values the compose file asks for, like `POSTGRES_PASSWORD` or `TELEGRAM_CHAT`. Compose reads it from the folder of the compose file.
- Reload keys, rules and users without a restart: `docker compose kill -s HUP server`.
- The image has a health check on `/readyz`, so `docker compose ps` shows `healthy` once the server works.
- The examples without a login only publish the UI on `127.0.0.1`. Use the https example before opening it to the network.
- Upgrades: `git pull`, then `docker compose build server && docker compose up -d`. The database schema is upgraded on start.
- Secret files created in these folders are in `.gitignore` and `.dockerignore`.
- `make test-examples` checks that every server flag in these files exists, and runs `docker compose config` on each when docker is installed.
