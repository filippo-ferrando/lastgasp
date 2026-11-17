# Incidents and alerts

The server turns the moments that matter into incidents, one per host, boot, kind and rule, and sends them to alert targets.

- [Incident kinds](#incident-kinds)
- [Rules](#rules)
- [Working with incidents](#working-with-incidents)
- [Alerts](#alerts)
- [Testing incidents](#testing-incidents)

## Incident kinds

| Kind | Opened when | Closed when | Severity |
| --- | --- | --- | --- |
| `kernel_error` | a kernel line matches a rule. Lines of the same rule and boot are grouped and counted | `-resolve-after` without a new matching line (resolved), or a clean reboot | from the rule |
| `journal_error` | a journal line (agents with `-journal`) matches a journal rule. Grouped and closed like `kernel_error` | like `kernel_error` | from the rule |
| `silent` | no packet for `-silent-after` | the host sends again (resolved), or a clean reboot | warning |
| `reboot` | a new boot ID shows up. Open incidents of the old boot are closed | after `-crash-wait`, when the crash check finds nothing | info |
| `crash` | a reboot where the old boot left pstore lines, or its last kernel lines match a critical rule | never resolved | critical |
| `flapping` | `-flap-count` reboots or returns from silence within `-flap-window` (3 in 1 hour by default). Reboot and silent alerts of the host are held back (`suppressed`) while it is open | `-flap-window` without a new one (resolved) | warning |
| `server` | a problem of the lastgasp server itself, see [Server incidents](#server-incidents) | 5 minutes without a new problem (resolved) | from the check |

When `-group-min-hosts` hosts (3 by default) reboot, or go silent, within `-group-window` (2 minutes), their incidents share a group: a power cut, a network outage or a rolling upgrade. Each alert target sends one alert for the group that names its hosts, the other members get the alert state `grouped`. Members alerted before the group formed keep their own alert. The UI marks group members in the incident list.

A clean reboot is a reboot that did not turn into a crash. A crash does not resolve the errors that led to it.

Any incident except an open `reboot` or `silent` one can also be resolved by hand, see [Working with incidents](#working-with-incidents).

### Server incidents

The server checks its own counters every 10 seconds. When one grows, it opens a `server` incident with host `@server`, or adds to the open one. It goes through the alert targets like any other incident, so problems of the server reach someone even without Prometheus.

| Rule | Severity | Counter |
| --- | --- | --- |
| `records_lost` | critical | records lost because the database kept failing after retries |
| `database` | warning | database errors, retried ones included |
| `queue` | warning | packets dropped because the server queue was full |
| `alerts` | warning | alert sends that failed |
| `keys` | warning | packets with an unknown host or a wrong key |
| `replay` | warning | 20 or more version 5 packets or handshakes seen twice within one check. A few come from the network, many mean someone sends recorded traffic again |

Agent hosts should not be named `@server`. The Prometheus rules in [operations.md](operations.md#monitoring) cover the same problems and also notice a server that is down, which a server cannot report about itself.

### How a crash is found

1. A new boot ID arrives. The server opens a `reboot` incident for the old boot.
2. It waits `-crash-wait` (2 minutes), so the new boot has time to send its pstore files.
3. It looks for pstore lines of the old boot, and for a critical rule match in the last `-incident-context` kernel lines of the old boot.
4. If either is found, the incident becomes a `crash`, with the first critical line as summary. Otherwise it stays a `reboot`.
5. pstore lines that arrive later still turn the reboot into a crash, and alerts start over.

If the database fails during the check, the reboot stays open and the check runs again on the next second, so a crash is never logged as a clean reboot because of a database error.

A kernel panic stops the whole machine at once, including the agent, so the panic line itself only reaches the server through pstore, or through [netconsole](server.md#netconsole) when it is set up. Without either, a panic shows up as a `reboot`, unless critical lines were sent before it.

### pstore backends

Check after a reboot with `ls /sys/fs/pstore`.

| Machine | Backend |
| --- | --- |
| UEFI machine or VM (OVMF) | `efi_pstore` module. Compressed records (`.enc.z`) are skipped |
| any machine with reserved RAM | `ramoops`, set up with `ramoops.mem_address=`, `ramoops.mem_size=` or a device tree node |
| server with ACPI ERST | `erst` backend |

Set `kernel.panic=10` (sysctl) so a panicked machine reboots by itself and the pstore files get read.

## Rules

A rule has a name, a severity, an optional count and a regular expression ([Go syntax](https://pkg.go.dev/regexp/syntax)), matched against each kernel line. The first matching rule wins. A rule with a count, like `10/1h`, opens an incident only once that many lines matched within that time, for errors that are harmless when rare. The count does not apply to crash detection: such rules never make a reboot a crash.

| Name | Severity | Matches |
| --- | --- | --- |
| `panic` | critical | `Kernel panic - not syncing` |
| `lockup` | critical | `soft lockup - CPU#`, `Watchdog detected hard LOCKUP` |
| `oops` | critical | `Oops: ` at the start, or `Oops ... [#N]` |
| `bug` | critical | `BUG: ` at the start |
| `gpf` | critical | `general protection fault` |
| `mce_corrected` | warning, 10/1h | `Machine check events logged`, `[Hardware Error]: Corrected error` or `event severity: corrected` |
| `edac_ce` | warning, 10/1h | EDAC corrected memory errors (`EDAC MC0: 1 CE ...`) |
| `edac_ue` | critical | EDAC uncorrected memory errors (`EDAC MC0: 1 UE ...`) |
| `mce` | critical | any other `[Hardware Error]` |
| `memory_failure` | critical | `Memory failure: ` |
| `rcu_stall` | warning | `rcu_... detected stall`, `detected stalls on CPUs` |
| `hung_task` | warning | `blocked for more than N seconds` |
| `oom` | warning | `Out of memory: Killed process` |
| `io_error` | warning | `I/O error, dev `, `Buffer I/O error` |
| `fs_error` | warning | `EXT4-fs error`, XFS corruption or metadata I/O error, `BTRFS error` or `critical` |
| `nvme` | warning | NVMe I/O timeout, `controller is down` |
| `coredump` | warning, journal | `Process N (name) of user N dumped core` or `terminated abnormally` |
| `unit_failed` | warning, journal | `: Failed with result '`, a systemd unit that failed |

Rules marked journal match userspace lines from journald, which start with the unit or program name. The others match kernel lines. In a rules file, `@journal` after the severity makes a journal rule. A journal rule matches the text as journald has it, with real newlines and backslashes, not `\xNN`. `.` does not match a newline, so `(?s)` is needed to match across the lines of a message like a core dump. The incident summary is the first line of the message.

A rules file (`-rules`) adds, replaces or removes rules, one per line:

```text
# name      severity  [count/window]  regexp
raid        warning   md/raid\d+:.*: Disk failure
io_error    critical  I/O error, dev nvme
link_down   info      (eth|en)\w+: Link is Down
link_flap   warning   5/10m (eth|en)\w+: Link is Up
ssh_fail    warning   @journal 10/5m sshd.*: Failed password
oom         off
```

- a new name adds a rule at the end
- a known name replaces that rule in place
- `name off` removes it

The file is checked at start and on `SIGHUP`. A broken file keeps the old rules.

## Working with incidents

Admins can act on an incident from its page in the UI, or through the [API](web-ui-and-api.md#api):

| Action | Effect |
| --- | --- |
| acknowledge | marks the incident as seen, with the user name and an optional note. Alerts are not changed |
| resolve | closes the incident as resolved, with an optional note. Targets that got its alert get a resolve alert. A new matching line opens a new incident. Not possible for an open `reboot` (the crash check decides) or an open `silent` incident (it closes when the host sends again) |
| silence host | adds a silence for the host of the incident, see below |

### Silences

A silence holds back alerts of matching incidents, for example during maintenance. Incidents are still opened and shown, but their alert state becomes `silenced` and nothing is sent. Resolve alerts are not sent either, as no alert went out.

| Field | Meaning |
| --- | --- |
| host | a host name or a pattern: `db-01`, `db-*`, `web-[12]`, or `*` for every host |
| kind | an incident kind, or empty for every kind |
| start, end | the window. It starts now by default, and can start later |
| comment | why, shown in the UI |

An incident is silenced when it was opened during the window, or when its alert would be sent during the window. So a reboot at the end of a maintenance window stays quiet, even though its alert waits for the crash check. Ending a silence early stops it for new incidents.

Silences are created and ended in the UI (the Silences section, or "Silence host" on an incident) or through the API. Silences that ended more than `-retain` ago are deleted.

## Alerts

Each `-alert-webhook`, `-alert-telegram` or `-alert-email` is one target. Each target has its own alert state, retries and rate limit, so one target that is down does not hold back the others.

| Rule | Detail |
| --- | --- |
| delivery | an alert is marked sent only after the target took it (webhook 2xx, mail accepted). Not sent alerts are sent after a server restart |
| retries | backoff from 1 second up to 5 minutes |
| giving up | a permanent refusal (webhook 4xx other than 408 and 429, SMTP 5xx), or 10 failed tries, marks the alert `failed` for that target, so it cannot block the alerts after it |
| age | only incidents updated in the last 24 hours are sent, so a new target does not get the whole history |
| rate limit | one alert per host, kind and rule per `-alert-rate-limit`. More are marked `suppressed`. A warning never holds back a critical line of another rule |
| min severity | incidents below the target `min` are not sent |
| resolved | when an incident is resolved, every target that sent its alert gets a second one with `"resolved": true` |
| skipped | a host that goes silent and comes back before a target sent the alert is a short blip: that target sends nothing and marks it `skipped` |
| crash after reboot | a reboot that turns into a crash is alerted again to every target |
| silenced | an incident matching an active silence is marked `silenced` and not sent |

The alert state per target shows in the UI next to each incident, for example `chat sent, pager suppressed`.

### Webhooks

The value is a URL, or options followed by `url=` (last, so the URL may hold commas):

```sh
-alert-webhook https://hooks.example.net/lastgasp
-alert-webhook 'name=chat,format=slack,url=https://hooks.slack.com/services/T000/B000/XXXX'
-alert-webhook 'name=pager,min=critical,rate=1h,key-file=/etc/lastgasp/alert.key,url=https://pager.example.net/hook'
```

| Option | Meaning |
| --- | --- |
| `name` | target name, shown in the UI and metrics. Default: the URL host, so secrets in the URL stay hidden. Two targets need different names |
| `format` | `json`, `slack` or `alertmanager` (default `-alert-format`) |
| `min` | lowest severity sent (default `-alert-min-severity`) |
| `key-file` | key that signs the body (default `-alert-key-file`) |
| `rate` | rate limit (default `-alert-rate-limit`) |

The request is a `POST` with `Content-Type: application/json` and a 10 second timeout.

`json` body:

```json
{
  "text": "[critical] db-01 crashed: Kernel panic - not syncing: Fatal exception https://lastgasp.example.net/#incident=42",
  "url": "https://lastgasp.example.net/#incident=42",
  "resolved": false,
  "target": "pager",
  "incident": {
    "id": 42, "host": "db-01", "boot_id": "6f1c...", "kind": "crash", "severity": "critical", "rule": "panic",
    "summary": "Kernel panic - not syncing: Fatal exception", "count": 37, "opened_at": "2026-10-06T08:12:03Z", "...": "..."
  }
}
```

`slack` body, for Slack and Mattermost incoming webhooks:

```json
{"text": "[critical] db-01 crashed: Kernel panic - not syncing: Fatal exception https://lastgasp.example.net/#incident=42"}
```

### Alertmanager

With `format=alertmanager` the target is the Alertmanager v2 API, and Alertmanager does the routing, grouping and silencing:

```sh
-alert-webhook 'name=am,format=alertmanager,url=http://alertmanager:9093/api/v2/alerts'
```

Each incident is one alert:

```json
[{
  "labels": {"alertname": "LastgaspCrash", "host": "db-01", "kind": "crash", "severity": "critical", "rule": "panic", "incident": "42"},
  "annotations": {"summary": "[critical] db-01 crashed", "description": "Kernel panic - not syncing: Fatal exception",
    "url": "https://lastgasp.example.net/#incident=42"},
  "startsAt": "2026-10-06T08:12:03Z",
  "endsAt": "2026-10-06T09:14:03Z",
  "generatorURL": "https://lastgasp.example.net/#incident=42"
}]
```

| Incident | `endsAt` |
| --- | --- |
| open (`silent`, `kernel_error`, `server`) | 5 minutes ahead. The server sends every open incident again each minute, so it keeps firing until it is resolved, and stops firing within 5 minutes if the lastgasp server dies |
| closed but not resolved (`crash`, `reboot`) | one hour after it was sent. These are events, they fire once and then end |
| resolved | the time it closed |

The alert name is `Lastgasp` plus the kind: `LastgaspCrash`, `LastgaspReboot`, `LastgaspSilent`, `LastgaspKernelError`, `LastgaspServer`. With a `key-file`, the body is signed like any webhook, but Alertmanager does not check it. Route on the `severity` and `host` labels in the Alertmanager configuration.

### Signed webhooks

With a key, the body is signed: `X-Lastgasp-Signature: sha256=<hex HMAC-SHA256 of the body>`. The key file holds hex, like the agent key:

```sh
openssl rand -hex 32 > /etc/lastgasp/alert.key
```

Check the signature on the receiving side before trusting the body. Python:

```python
import hashlib, hmac

key = bytes.fromhex(open("alert.key").read().strip())

def valid(body: bytes, header: str) -> bool:
    want = "sha256=" + hmac.new(key, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, header)
```

Shell:

```sh
printf '%s' "$BODY" | openssl dgst -sha256 -mac HMAC -macopt hexkey:"$(cat alert.key)"
```

### Email

The value is a list of options. `to` and `smtp` are required, more recipients follow `to` after commas:

```sh
-alert-email 'to=ops@example.net,smtp=mail.example.net:587,user=lastgasp,password-file=/etc/lastgasp/smtp.pw'
-alert-email 'name=oncall,min=critical,to=a@example.net,b@example.net,smtp=localhost:25'
-alert-email 'to=ops@example.net,smtp=relay.internal:465,ca-file=/etc/lastgasp/internal-ca.pem'
```

| Option | Meaning |
| --- | --- |
| `to` | recipients |
| `smtp` | SMTP server `host:port`. Port 465 uses TLS from the start, other ports need STARTTLS, except on localhost |
| `from` | sender, default `lastgasp@<server hostname>` |
| `user`, `password-file` | SMTP login, the password is read from the file. Login is only sent over TLS |
| `ca-file` | PEM certificate authority to trust, for internal relays with their own CA |
| `name`, `min`, `rate` | as for webhooks. The default name is `email` |

The subject is the short form, like `[critical] db-01 crashed`. The body has the summary, the incident details and link, the last 40 pstore lines for crashes, and the last 40 kernel lines. Host names and log lines cannot add headers or end the message early.

### Telegram

The value is a list of options. `chat` and `token-file` are required:

```sh
-alert-telegram 'chat=-1001234567890,token-file=/etc/lastgasp/telegram.token'
-alert-telegram 'name=oncall,min=critical,chat=@lastgasp_alerts,token-file=/etc/lastgasp/telegram.token'
```

| Option | Meaning |
| --- | --- |
| `chat` | chat ID (a group or channel ID like `-1001234567890`, or a user ID) or `@channelname` |
| `token-file` | file with the bot token from BotFather, like `123456:ABC-DEF...`. Readable only by the server |
| `api` | another Bot API server, default `https://api.telegram.org` |
| `name`, `min`, `rate` | as for webhooks. The default name is `telegram` |

Setup: create a bot with [@BotFather](https://t.me/BotFather), add it to the group or channel, then find the chat ID, for example by sending a message to the group and opening `https://api.telegram.org/bot<token>/getUpdates`.

The message is plain text: the short form, the summary and the link. The token never shows in logs, metrics or the UI.

## Testing incidents

Run these as root on a test machine with the agent installed. Writing to `/dev/kmsg` adds a line to the kernel log, which the agent sends like any other.

| Goal | Commands | Result |
| --- | --- | --- |
| kernel error, critical | `echo "<3>BUG: lastgasp test" > /dev/kmsg` | `kernel_error` with rule `bug`, at once |
| kernel error, warning | `echo "<4>INFO: task foo:1 blocked for more than 120 seconds." > /dev/kmsg` | `kernel_error` with rule `hung_task` |
| custom rule | add `test warning lastgasp-test` to the rules file, reload, then `echo "lastgasp-test" > /dev/kmsg` | `kernel_error` with rule `test` |
| clean reboot | `reboot` | `reboot`, closed after `-crash-wait` |
| crash without pstore | `echo "<2>Kernel panic - not syncing: lastgasp test" > /dev/kmsg; sleep 2; echo 1 > /proc/sys/kernel/sysrq; echo b > /proc/sysrq-trigger` | `reboot`, turns into `crash` after `-crash-wait`, as the last lines hold a critical match |
| real panic | `sysctl kernel.panic=10; echo 1 > /proc/sys/kernel/sysrq; echo c > /proc/sysrq-trigger` | `crash` with the pstore lines when a pstore backend works, otherwise `reboot` |
| silent host | `systemctl stop lastgasp-agent; sleep 150; systemctl start lastgasp-agent` | `silent` after `-silent-after`, resolved when the agent is back |
| silent host, network | block UDP to the server for longer than `-silent-after` | same as above |

`echo b > /proc/sysrq-trigger` reboots at once without syncing disks, and `echo c` crashes the kernel. Use them on test machines only.
