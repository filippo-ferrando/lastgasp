# Incidents and alerts

The server turns the moments that matter into incidents, one per host, boot, kind and rule, and sends them to alert targets.

## Incident kinds

| Kind | Opened when | Closed when | Severity |
| --- | --- | --- | --- |
| `kernel_error` | a kernel line matches a rule. Lines of the same rule and boot are grouped and counted | `-resolve-after` without a new matching line (resolved), or a clean reboot | from the rule |
| `silent` | no packet for `-silent-after` | the host sends again (resolved), or a clean reboot | warning |
| `reboot` | a new boot ID shows up. Open incidents of the old boot are closed | after `-crash-wait`, when the crash check finds nothing | info |
| `crash` | a reboot where the old boot left pstore lines, or its last kernel lines match a critical rule | never resolved | critical |

A clean reboot is a reboot that did not turn into a crash. A crash does not resolve the errors that led to it.

### How a crash is found

1. A new boot ID arrives. The server opens a `reboot` incident for the old boot.
2. It waits `-crash-wait` (2 minutes), so the new boot has time to send its pstore files.
3. It looks for pstore lines of the old boot, and for a critical rule match in the last `-incident-context` kernel lines of the old boot.
4. If either is found, the incident becomes a `crash`, with the first critical line as summary. Otherwise it stays a `reboot`.
5. pstore lines that arrive later still turn the reboot into a crash, and alerts start over.

If the database fails during the check, the reboot stays open and the check runs again on the next second, so a crash is never logged as a clean reboot because of a database error.

A kernel panic stops the whole machine at once, including the agent, so the panic line itself only reaches the server through pstore. Without a pstore backend, a panic shows up as a `reboot`, unless critical lines were sent before it.

### pstore backends

Check after a reboot with `ls /sys/fs/pstore`.

| Machine | Backend |
| --- | --- |
| UEFI machine or VM (OVMF) | `efi_pstore` module. Compressed records (`.enc.z`) are skipped |
| any machine with reserved RAM | `ramoops`, set up with `ramoops.mem_address=`, `ramoops.mem_size=` or a device tree node |
| server with ACPI ERST | `erst` backend |

Set `kernel.panic=10` (sysctl) so a panicked machine reboots by itself and the pstore files get read.

## Rules

A rule has a name, a severity and a regular expression ([Go syntax](https://pkg.go.dev/regexp/syntax)), matched against each kernel line. The first matching rule wins.

| Name | Severity | Matches |
| --- | --- | --- |
| `panic` | critical | `Kernel panic - not syncing` |
| `lockup` | critical | `soft lockup - CPU#`, `Watchdog detected hard LOCKUP` |
| `oops` | critical | `Oops: ` at the start, or `Oops ... [#N]` |
| `bug` | critical | `BUG: ` at the start |
| `gpf` | critical | `general protection fault` |
| `mce` | critical | `[Hardware Error]` |
| `memory_failure` | critical | `Memory failure: ` |
| `rcu_stall` | warning | `rcu_... detected stall`, `detected stalls on CPUs` |
| `hung_task` | warning | `blocked for more than N seconds` |
| `oom` | warning | `Out of memory: Killed process` |
| `io_error` | warning | `I/O error, dev `, `Buffer I/O error` |
| `fs_error` | warning | `EXT4-fs error`, XFS corruption or metadata I/O error, `BTRFS error` or `critical` |
| `nvme` | warning | NVMe I/O timeout, `controller is down` |

A rules file (`-rules`) adds, replaces or removes rules, one per line:

```text
# name      severity  regexp
raid        warning   md/raid\d+:.*: Disk failure
io_error    critical  I/O error, dev nvme
link_down   info      (eth|en)\w+: Link is Down
oom         off
```

- a new name adds a rule at the end
- a known name replaces that rule in place
- `name off` removes it

The file is checked at start and on `SIGHUP`. A broken file keeps the old rules.

## Alerts

Each `-alert-webhook` or `-alert-email` is one target. Each target has its own alert state, retries and rate limit, so one target that is down does not hold back the others.

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
| `format` | `json` or `slack` (default `-alert-format`) |
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
