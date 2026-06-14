<!--
SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks

SPDX-License-Identifier: BSD-3-Clause
-->

# BOOT.md -- System Initialisation Reference

**File:** `/etc/rc.local`
**Shell:** `/bin/ksh`
**Invoked by:** OpenBSD `/etc/rc` at the end of the base system boot sequence
**Purpose:** Start all appliance daemons and WebUI runner services in dependency order

---

## Overview

`rc.local` is the single authoritative entry point for the Tangent appliance's
boot sequence. OpenBSD's base `rc` script handles the kernel, network
interfaces, and system daemons (sshd, httpd, dhcpd, unbound, rad, ftp-proxy)
via `rcctl`. It also invokes `reorder_libs` and runs `tangent_logrotate.sh`
before starting network daemons. Everything above that -- the security stack,
the proxy layer, the traffic accounting system, and the entire WebUI service
infrastructure -- is started here in `rc.local`.

The script is written in ksh with `set -euo pipefail` enforced from the first
line. This means any unhandled error, unset variable reference, or failed pipe
exits the script immediately. Every section is therefore written defensively:
binary existence is checked with `-x` before invocation, directories are
created before use, stale PID files and sockets are cleaned before daemons
start, and startup verification is done via PID file polling rather than
assumption.

All output -- stdout and stderr -- is redirected to the boot log from the top of
the script via `exec`. Every log entry goes through the global `log()` function
which writes a timestamped, structured line to both the boot log and the
service-specific log simultaneously via `tee`.

---

## Shell Environment

```sh
#!/bin/ksh
set -euo pipefail
PATH="/sbin:/usr/sbin:/bin:/usr/bin:/usr/X11R6/bin:/usr/local/sbin:/usr/local/bin"
```

`set -e` exits on any command returning non-zero. `set -u` treats unset
variables as errors. `set -o pipefail` causes a pipeline to return the exit
status of the rightmost failed command rather than the last command. Together
these make silent failures impossible -- any misconfiguration surfaces
immediately at boot rather than leaving a daemon in an indeterminate state.

The PATH is set explicitly rather than inherited. At the point rc.local runs,
the environment is minimal and inherited PATH cannot be trusted to include
`/usr/local/sbin` and `/usr/local/bin` where most appliance binaries live.

---

## Global Initialisation

### truncate Availability Check

Before anything else, the script verifies that the `truncate` binary is present:

```sh
if ! command -v truncate > /dev/null 2>&1; then
  echo "$(date) [WARN] truncate not found -- installing via pkg_add"
  pkg_add -Iv truncate
  if command -v truncate > /dev/null 2>&1; then
    echo "$(date) [INFO] truncate successfully installed and verified"
  else
    echo "$(date) [ERROR] truncate installation attempt completed but binary not in PATH"
  fi
fi
```

`truncate` is used later to zero out PID files and logs without deleting them.
If it is not present, the script installs it immediately via `pkg_add`. This
guard exists because the rest of the script depends on it and there is no
graceful fallback.

### Logging Setup

```sh
SERVICE_LOG_DIR="/var/www/htdocs/tn/data/logs/bootlog"
RCLOGFILE="/var/www/htdocs/tn/data/logs/bootlog/rc.local.log"

install -d -o root -g wheel -m 750 "$SERVICE_LOG_DIR"
exec > "$RCLOGFILE" 2>&1
```

The boot log directory is created with `install -d` rather than `mkdir -p`.
`install` sets ownership and permissions atomically in one operation, avoiding
a window where the directory exists but has incorrect permissions. Ownership
is `root:wheel` mode `750` -- readable by root and wheel members, not world
readable.

`exec > "$RCLOGFILE" 2>&1` redirects all subsequent stdout and stderr from the
entire script to the boot log file. This is a single redirect at the top rather
than per-command redirection throughout. Any command that does not explicitly
redirect elsewhere goes to the boot log.

### PID File Truncation

```sh
find /var/www/htdocs/tn/data/ -type f -name "*.pid" -exec truncate -s 0 {} \;
```

All PID files under the data directory are truncated to zero bytes at boot,
not deleted. Truncation rather than deletion is deliberate -- it preserves the
file's existence and permissions while clearing stale PID content. This
prevents any service that checks `[ -f pidfile ]` from finding a stale PID
from the previous boot session and incorrectly concluding a service is already
running.

### Log Truncation

```sh
find /var/www/tmp -type f -name 'control-[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9].log' -exec rm -f {} \;
find /var/www/tmp -type f -name "*.log" -exec truncate -s 0 {} +
```

Date-stamped control logs from the previous session are deleted. All other log
files under `/var/www/tmp` are truncated. This is the appliance's approach to
log management for the chroot web directory -- it does not use OpenBSD's
`newsyslog(8)` for these files. The logging README documents this design
decision in full.

### log() Function

```sh
log() {
    local service="$1"
    local level="$2"
    local message="$3"
    local logfile="${4:-$RCLOGFILE}"
    printf "[$(date '+%Y-%m-%d %H:%M:%S')] %s: [%s] %s\n" \
        "$service" "$level" "$message" | tee -a "$logfile"
}
```

The `log()` function is used throughout the script for all structured output.
It takes four arguments: service name, severity level, message text, and an
optional logfile path that defaults to `$RCLOGFILE` if omitted. `tee -a`
appends to the specified logfile while also writing to stdout -- which is
redirected to the boot log by the `exec` above. The result is that every log
call writes to both the service-specific log and the boot log simultaneously,
giving the boot log a complete chronological record of everything that happened
during startup.

Log output format:

```
[2026-03-22 10:32:14] CLAMAV: [INFO] Starting Antivirus Program
[2026-03-22 10:32:14] CLAMAV: [INFO] (waiting for socket)
[2026-03-22 10:33:44] CLAMAV: [INFO] ready
```

---

## What Happens Before rc.local

The base `rc` script runs `reorder_libs` to rebuild the shared library cache,
then immediately invokes `tangent_logrotate.sh` before any network daemons are
started:

```sh
reorder_libs 2>&1 |&
# Tangent Log Rotation Hook
if [ -x /usr/local/sbin/tangent_logrotate.sh ]; then
        echo -n 'rotating logs'
        /usr/local/sbin/tangent_logrotate.sh >/dev/null 2>&1
        echo '.'
fi
start_daemon slaacd dhcpleased resolvd >/dev/null 2>&1
echo 'starting network'
```

`tangent_logrotate.sh` runs synchronously in this window, before the network
stack is up and before any appliance daemons exist. This makes it the
appropriate place for log rotation that must not race with running services.
Only after it completes does `rc` bring up SLAAC, DHCP, and the resolver, and
only after all of that does `rc.local` execute.

---

## Boot Sequence

Services are started in dependency order. The security and inspection layer
(Snort, e2guardian) starts first. Infrastructure daemons (ClamAV, collectd,
pmacct) follow. Protocol proxies (p3scan, smtp-gated, SSLproxy, imspector,
sockd, spamd) come next. PF logging is established. The WebUI runner services
are started last via the `start_service()` function.

### Snort IDS and IPS

Snort is started in two independent instances: one for passive intrusion
detection (IDS) and one for inline intrusion prevention (IPS).

**IDS instance:**

```sh
/usr/local/bin/snort -i em1 -d -c /etc/snort/snort.conf \
    -u _snort -g _snort -b -l /var/www/htdocs/tn/data/logs/snort \
    --pid-path /var/www/htdocs/tn/data/run/snort \
    2>&1 | logger -t snort_ids -p daemon.info
```

Snort IDS listens passively on `em1` (the LAN interface) in binary logging
mode (`-b`). It runs as `_snort:_snort`. Output is piped to `logger` which
forwards it to syslog under the `daemon.info` facility with the tag
`snort_ids`. The PID file written is `snort_em1.pid` -- the interface name is
appended by Snort automatically.

Startup verification polls for the PID file for up to 15 seconds (1 second
intervals). When found, the PID file permissions are fixed to `0644` -- Snort
writes the PID file as `_snort` and the file may be created with restrictive
permissions. The web UI needs to read it.

**IPS instance:**

```sh
/usr/local/bin/snort -d -Q -c /etc/snort/snortinline.conf \
    -u _snort -g _snort -b -l /var/www/htdocs/tn/data/logs/snort \
    --pid-path /var/www/htdocs/tn/data/run/snort \
    2>&1 | logger -t snort_ips -p daemon.info
```

The `-Q` flag enables inline (IPS) mode. Snort IPS receives packets via PF's
`divert-packet` mechanism (port 700 in `pf.conf`) rather than capturing from
an interface directly -- hence no `-i` flag. The PID file written is
`snort_.pid` (no interface suffix since no `-i` is specified). Startup
verification polls for 10 seconds.

Both Snort instances use `umask 0022` within their launch subshell to ensure
log files are created world-readable. The run directory is owned `_snort:wheel`
mode `0755`.

### SnortSentry

```sh
/usr/local/sbin/snortsentry -f /etc/snort/snortsentry.conf
```

This script reads Snort's alert output and populates PF's `<snort_block>`
table with hostile source addresses in real time. It is the bridge between
Snort's detection and PF's enforcement. Startup verification polls for its
PID file for up to 5 seconds.

### e2guardian

```sh
/usr/local/sbin/e2guardian
```

e2guardian is the web content filter. It receives HTTP and HTTPS traffic
diverted from PF (ports 8081 and 8443) and applies category-based filtering,
phrase matching, and MIME type controls. Its working directory
`/var/www/htdocs/tn/data/tmp/e2guardian` is created if absent and ownership
is set to `_e2guardian:_clamav` -- e2guardian integrates with ClamAV for
antivirus scanning of web content, requiring group access to ClamAV's socket.

e2guardian does not have a startup polling loop here -- it daemonises quickly
and its WebUI runners (`e2g_status_writer_runner.sh`,
`e2g_queue_processor_runner.sh`, `e2g_user_filter_runner.sh`) handle ongoing
status monitoring.

### collectd

```sh
/usr/local/sbin/collectd -C "$COLLECTD_CONF"
```

collectd is the system statistics collection daemon. It gathers CPU, memory,
network interface counters, and custom metrics and makes them available to the
web UI dashboard. The collectd Unix socket at
`/var/www/htdocs/tn/data/sockets/collectd/collectd.sock` is removed before
startup -- collectd will not overwrite an existing socket and will fail to start
if a stale one is present. A 2-second sleep follows collectd startup to allow
the socket to be created before dependent services attempt to connect.

### ClamAV

ClamAV is the most carefully started daemon in the script because it is slow
to initialise and other daemons (e2guardian, p3scan, smtp-gated) depend on its
socket being ready before they can scan content.

```sh
/usr/local/sbin/clamd -c /etc/clamd.conf
```

Pre-start checks: the run directory (`$CLAMRUN`) and temp directory (`$CLAMTMP`)
are created if absent. Ownership is verified with `stat -f '%Su'` / `stat -f
'%Sg'` (OpenBSD `stat` format) and corrected if wrong. If a PID file exists,
`pgrep -F` checks whether the recorded process is actually running -- if yes,
clamd is already running and is not started again; if no, the stale PID file
is removed.

Startup verification waits up to 90 seconds for the clamd Unix socket to
appear at `/var/www/htdocs/tn/data/tmp/clamav/clamd.socket`. A progress dot
is logged every 10 seconds. ClamAV loads its full virus signature database
into memory at startup -- on the target hardware with a current signature set
this takes 30-60 seconds. The 90-second timeout accommodates this without
failing prematurely.

Once the socket appears, `freshclam -d` is started as a background daemon to
keep virus signatures current.

### p3scan

```sh
/usr/local/sbin/p3scan -f /etc/p3scan/p3scan.conf
```

p3scan is the transparent POP3 and POP3S proxy. It intercepts mail retrieval
connections diverted by PF (ports 8994 and 8995) and scans them through ClamAV
before delivering to the client. The run directory is created and owned
`_p3scan:wheel` before start. Any stale PID file is removed explicitly -- p3scan
refuses to start if its PID file already exists even if the file is empty.

### pmacct

pmacct (`pmacctd`) is the IP network traffic accounting daemon. Three instances
are started serving different purposes:

**MFS instances (started immediately):**

Two instances are started at boot without delay -- `ext_if_json_mfs` captures
WAN interface traffic and `int_if_json_mfs` captures LAN interface traffic.
Both write JSON flow records to the MFS (memory filesystem) for real-time
display in the web UI traffic monitor. Pre-created log files are given `0644`
permissions before the daemons start so the web UI can read them immediately.

Each instance is launched with `umask 022; exec pmacctd -f conf` inside a
subshell. The `exec` replaces the subshell with pmacctd directly, ensuring the
PID file written by pmacctd matches the actual process rather than a wrapper
shell. A 2-second sleep after each launch allows the PID file to be written
before verification.

**Log instance (started at quarter-hour boundary):**

The `ext_if_json_log` instance writes persistent traffic records for historical
analysis. It is started in a background subshell that sleeps until the next
wall-clock quarter-hour boundary before launching:

```sh
PMACCT_OFFSET=$((15 - (10#$PMACCT_MIN % 15)))
[ "$PMACCT_OFFSET" -eq 15 ] && PMACCT_OFFSET=0
PMACCT_SLEEP_FOR=$((PMACCT_OFFSET * 60 - 10#$PMACCT_SEC))
```

The `10#` prefix forces decimal interpretation of minute and second values --
without it, values like `08` and `09` are interpreted as invalid octal in ksh.
The calculation finds the number of seconds to the next 15-minute mark
(00, 15, 30, 45) and sleeps that long before starting. If already exactly on
a boundary the sleep is zero and the daemon starts immediately.

This alignment is required because pmacct's log rotation is configured to
rotate files at 15-minute intervals. Starting the daemon mid-interval would
produce an incomplete first record. The quarter-hour-aligned start guarantees
the first log file covers a complete interval.

**Background permission fixer:**

```sh
while true; do
    sleep 8
    find "$PMACCT_MFS_DIR" -type f -name "*.log" -exec chmod 644 {} + 2>/dev/null
    find "$PMACCT_EXT_IF_DIR" -type f -name "*.json" -exec chmod 644 {} + 2>/dev/null
done
```

pmacctd creates new output files as it rotates through intervals. New files
inherit whatever umask is in effect and may not be readable by the web UI.
The permission fixer runs as a background loop every 8 seconds, ensuring all
pmacct output files remain `0644` regardless of when they were created. This
is the primary mechanism for permission enforcement -- the one-time `find` at
the end of the quarter-hour subshell is a supplementary sweep.

**Log rotation at boot:**

At each boot, pmacct's external interface directory is checked for files dated
yesterday. Text and JSON files from the previous day are merged into single
dated archives (`YYYY-MM-DD.txt` and `YYYY-MM-DD.json`). Files older than 7
days are deleted. This keeps the directory manageable without a separate cron
job.

Yesterday's date is calculated via Perl to avoid platform-specific `date`
arithmetic:

```sh
PMACCT_YESTERDAY="$(perl -e '@t=localtime(time - 86400); printf("%4d%02d%02d\n", $t[5]+1900, $t[4]+1, $t[3]);')"
```

### Dante (sockd)

```sh
/usr/local/sbin/sockd -D -p /var/www/htdocs/tn/data/run/sockd/sockd.pid
```

Dante is the SOCKS proxy server. It provides SOCKS4/SOCKS5 proxy access for
LAN clients on port 1080 (permitted by PF). The `-D` flag daemonises it. PID
file path is passed explicitly on the command line.

### spamd

```sh
/usr/local/bin/spamd -L -d -x -u _spamdaemon \
    -r /var/www/htdocs/tn/data/run/spamd/spamd.pid
```

OpenBSD's `spamd(8)` is a spam deferral daemon that implements greylisting and
real-time blacklist enforcement. `-L` enables greylisting, `-d` daemonises,
`-x` disables whitelisting of greylisted hosts that eventually pass, `-u
_spamdaemon` drops privileges after binding. Note this is OpenBSD's native
`spamd`, not SpamAssassin.

### smtp-gated

```sh
SMTP_GATED_PIDFILE="/var/www/htdocs/tn/data/run/smtp-gated/smtp-gated.pid"
SMTPGATED_LOGFILE="/var/www/htdocs/tn/data/logs/smtp-gated/smtp-gated.log"

/usr/local/sbin/smtp-gated /usr/local/etc/smtp-gated/smtp-gated.conf
```

smtp-gated is the transparent SMTP scanning proxy. It intercepts outbound mail
on ports 25, 465, and 587 (diverted by PF to ports 8464, 8465, 8466) and
scans through ClamAV before forwarding. Both the PID file variable and log
file variable are declared at the top of the block before either is used --
this ensures the log call that immediately follows has a valid logfile target.
The PID file is explicitly removed before start; smtp-gated will not start if
its PID file exists.

### SSLproxy

```sh
/usr/local/bin/sslproxy -f /usr/local/etc/sslproxy/sslproxy.conf
```

SSLproxy performs transparent TLS interception. HTTP and HTTPS traffic from
LAN clients is diverted by PF (ports 8081 and 8443) to SSLproxy, which
terminates the TLS connection, passes the plaintext to the content inspection
pipeline, and re-encrypts toward the real destination. Configuration includes
the CA certificate used to sign intercepted connections.

### imspector

```sh
/usr/local/sbin/imspector -c /usr/local/etc/imspector/imspector.conf
```

imspector is the transparent instant messaging proxy. It intercepts traffic on
the IM ports defined in `pf.conf` (`$im_ports`: 1863, 5190, 5050, 6667) which
are diverted by PF to port 16667. imspector logs and optionally filters IM
sessions. Its working directory `/tmp/imspector` is created if absent and
owned `_imspector:_imspector`.

### PF Mirror Sync

```sh
/usr/local/sbin/pf_mirror_sync.sh
```

Synchronises PF table contents and ruleset assets to the web UI's data
directory. Run synchronously (not backgrounded) so the web UI has current PF
state before the runner services start. Output is suppressed -- errors are
silent at boot but logged by the script itself.

### PF Logging (tcpdump on em1)

```sh
TCPDUMP="/usr/sbin/tcpdump"
PFIF="em1"
$TCPDUMP -n -e -ttt -i "$PFIF" >> "$PFLOG_FILE" 2>&1 &
```

A `tcpdump` process is started to capture all traffic logged through `em1`
and write it in human-readable form to
`/var/www/htdocs/tn/data/logs/pf/pflog1.log`. This feeds the web UI's traffic
viewer and the pmacct traffic accounting pipeline.

The flags `-n` (no DNS resolution), `-e` (include link-layer headers including
PF rule information), `-ttt` (delta timestamps between packets) produce output
suitable for both human review and machine parsing.

Before starting, any stale tcpdump process matching the same interface is
killed with `pkill -f`. The interface is verified to exist with `ifconfig`
before attempting to start tcpdump. A 1-second sleep after start confirms the
process is still running before logging success.

The log file is owned `www:wheel` mode `644` so the web UI's httpd process can
read it directly.

---

## Process Monitor Scheduling

```sh
(
    if [ "$current_minute" -le 15 ]; then
        target_offset_s=900
    elif [ "$current_minute" -le 30 ]; then
        target_offset_s=1800
    elif [ "$current_minute" -le 45 ]; then
        target_offset_s=2700
    else
        target_offset_s=3600
    fi
    target_time_in_minute_s=$((target_offset_s + 60))
    sleep_duration_s=$((target_time_in_minute_s - current_time_in_minute_s))
) >/dev/null 2>&1 &
```

`process_monitor.pl` is a fast service status checker that generates a service
status report. It is scheduled to run at 1 minute past the next wall-clock
quarter-hour boundary.

The timing is deliberate and coordinates with pmacct. The `ext_if_json_log`
pmacct instance starts at the quarter-hour boundary and takes up to 15 seconds
to write its PID file. By scheduling process_monitor for 1 minute past the
boundary, it runs after pmacct has fully initialised and its PID is recorded.
This ensures the status report accurately reflects pmacct's running state.

The stepped `if/elif` against absolute minute values is intentional -- it always
targets the next absolute quarter-hour mark (00, 15, 30, 45) rather than using
modulo arithmetic. This is correct for wall-clock alignment.

The entire scheduling and execution block runs in a background subshell with
output redirected to `/dev/null` -- it must not interfere with the main boot
log's `exec` redirect. The status report is written to its own dedicated file
`/var/www/htdocs/tn/data/logs/bootlog/services.log`.

---

## PF Table Population

```sh
if [ -x /usr/local/sbin/pf_tables_load.sh ]; then
    /usr/local/sbin/pf_tables_load.sh
fi
```

Run synchronously after the IPv6 route check. Populates PF's persistent tables
(blocklists, allowlists, geographic address sets) from disk before any traffic
reaches the rule set. Running this before the WebUI runners start ensures the
firewall is in a consistent state from the moment services become available.

---

## start_service() -- WebUI Runner Management

```sh
start_service() {
    local script="$1"
    local name="$2"
    local pidfile="/var/www/htdocs/tn/data/run/webui/${3:-${name}}.pid"
    ...
}
```

`start_service()` is the generic launcher for all WebUI runner services. It
takes three arguments: the script path, a human-readable service name, and an
optional PID filename (defaults to `${name}.pid` if omitted).

The function:

1. Verifies the script is executable -- logs an error and returns 1 if not
2. Creates the webui run directory owned `www:www` mode `750`
3. Checks for an existing PID file -- if the recorded process is alive via
   `kill -0`, logs "already running" and returns without starting a duplicate
4. Removes a stale PID file if the recorded process is dead
5. Starts the script backgrounded with stdin, stdout, and stderr all closed
   (`</dev/null >/dev/null 2>&1`) -- runner services must not inherit the boot
   log's `exec` redirect
6. Sleeps 0.2 seconds and verifies the process is still alive via `kill -0`
7. Writes the PID to the webui PID file on success, logs error on failure

The 0.2-second verification catches immediate crashes -- a script that fails on
the first line will not have a PID file written for it.

### Runner Pattern

Every service started via `start_service()` follows the same runner pattern:

```sh
#!/bin/sh
PIDFILE="/var/www/htdocs/tn/data/run/webui/servicename.pid"
echo $$ > "$PIDFILE"
trap "rm -f $PIDFILE" EXIT INT TERM

while true; do
    /usr/local/sbin/actual_worker_script.sh
    sleep N
done
```

The runner writes its own `$$` to the PID file immediately -- this is the
runner shell's PID, not the worker's. The `trap` removes the PID file on any
exit signal, ensuring the PID file never persists after the runner stops. The
infinite loop re-invokes the worker script every N seconds, providing automatic
restart on worker failure without a separate supervisor daemon.

This creates two PID references per service: the runner's own PID file (written
by the runner, managed by the trap) and the `start_service()`-written webui PID
file (used by the web UI's service manager for status checking and control).
The optional third argument to `start_service()` allows the webui PID filename
to differ from the default service name when needed -- for example,
`pf_tcpdump_runner.sh` is registered as `pflog_maint` so its webui PID file is
`pflog_maint.pid` rather than the full runner script name.

---

## WebUI Runner Services

The following services are started via `start_service()` in boot order. All
runner scripts live in `/usr/local/sbin/` and their PID files in
`/var/www/htdocs/tn/data/run/webui/`.

`queue_processor_runner.sh` -- General web UI command queue processor. Handles
user-initiated actions from the web interface that require shell execution.

`unbound_stats_runner.sh` -- Collects DNS resolver statistics from
`unbound-control stats_noreset` every 5 seconds and writes JSON for the DNS
dashboard. Documented in full in `UNBOUND_SYSTEM.md`.

`dashboard_stats_runner.sh` -- Collects system-wide statistics (CPU, memory,
load, interface counters) for the main dashboard display.

`service_monitor_runner.sh` -- Monitors the health of all appliance services
and updates status indicators in the web UI.

`pf_stats_runner.sh` -- Collects PF state table statistics, rule match counts,
and table sizes for the firewall dashboard.

`pf_tcpdump_runner.sh` (registered as `pflog_maint`) -- Manages the tcpdump
process on `pflog0` (blocks only) and handles log maintenance for the block
log. Distinct from the em1 tcpdump started directly earlier in the script.

`pmacct_mfs_manage_runner.sh` -- Manages the pmacct MFS log files, handling
rotation and cleanup of the in-memory traffic records.

`pf_change_detector_runner.sh` -- Detects changes to the PF ruleset and
triggers web UI updates when rules are reloaded.

`e2g_user_filter_runner.sh` -- Processes user-specific e2guardian filter
configuration changes from the web UI.

`unbound_queue_runner.sh` -- Processes DNS management commands from the web UI
queue. Documented in full in `UNBOUND_SYSTEM.md`.

`e2g_status_writer_runner.sh` -- Writes e2guardian status information for web
UI display.

`e2g_queue_processor_runner.sh` -- Processes e2guardian configuration change
requests from the web UI queue.

`pf_monitor_runner.sh` -- Monitors PF state and interface statistics at regular
intervals for real-time display.

`integrity_check_runner.sh` -- Runs the system integrity verification suite at
scheduled intervals. Documented in the integrity check documentation.

`powermgmt_runner.sh` -- Monitors system power state and handles graceful
shutdown/reboot requests from the web UI.

`pf_asn_runner.sh` (registered as `pf_asn_lookip`) -- Performs ASN lookups for
IP addresses in the PF state table and block log, enriching traffic display
with network ownership information.

`dhcpd_lease_watcher_runner.sh` (registered as `dhcpd_watcher`) -- Watches the
DHCP lease file for changes and updates the web UI's client list in real time.

`pf_anchor_sync_runner.sh` -- Synchronises PF anchor contents between the
running ruleset and persistent storage, ensuring addon anchor rules survive
reloads.

---

## RRD Map Self-Healer

```sh
if [ -f /etc/collectd_reconciler.pm ]; then
    /usr/bin/perl -T /etc/collectd_reconciler.pm
fi
```

Run synchronously as the final step before `exit 0`. `collectd_reconciler.pm`
reconciles the RRD file map at boot time, ensuring the set of RRD files on
disk matches what collectd is currently configured to produce. Any RRD files
for metrics that no longer exist are retired, and any missing RRD files for
active metrics are created with correct schema. Running this after all runners
are up means collectd has had time to create any new RRD files before the
reconciler inspects them. The `-T` flag enables taint mode, consistent with
the rest of the appliance's Perl execution policy.

---

## Boot Log

The complete boot log is written to:

```
/var/www/htdocs/tn/data/logs/bootlog/rc.local.log
```

It contains a full chronological record of every service start attempt,
success, failure, and timing event across the entire boot sequence. It is the
first place to look when a service is not running after boot.

Individual service logs are written to:

```
/var/www/htdocs/tn/data/logs/<service>/<service>.log
```

Each service log contains only that service's entries. The boot log contains
all service entries interleaved in time order. Both are written simultaneously
by the `log()` function's `tee`.

---

## Startup Verification Reference

To verify all WebUI runner services are running after boot:

```sh
ps aux | grep runner
```

To check a specific service PID file:

```sh
cat /var/www/htdocs/tn/data/run/webui/<service>.pid
kill -0 $(cat /var/www/htdocs/tn/data/run/webui/<service>.pid) && echo running
```

To review the boot log:

```sh
cat /var/www/htdocs/tn/data/logs/bootlog/rc.local.log
```

To check a specific service's boot-time startup:

```sh
grep CLAMAV /var/www/htdocs/tn/data/logs/bootlog/rc.local.log
```

To manually restart a WebUI runner service:

```sh
# Stop
kill $(cat /var/www/htdocs/tn/data/run/webui/<service>.pid)

# Start (using the same call as rc.local)
start_service "/usr/local/sbin/<runner>.sh" "<name>"
```

Note: `start_service()` is defined in rc.local and is not available in a
regular shell session. To restart a runner manually, invoke the runner script
directly:

```sh
/usr/local/sbin/<runner>.sh &
```

The runner will write its own PID file via its internal `echo $$ > "$PIDFILE"`
on startup.

---

## Author and Attribution

Primary Author: David Peter
Organization:   Tangent Networks
Web:            https://tangentnet.top
Email:          tangent.net@zohomail.in

---

## License

BSD 3-Clause License (Simplified)

Copyright (c) 2025-2026 David Peter, Tangent Networks
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions, and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions, and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY CLAIM,
DAMAGES, OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR
THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---

*END of BOOT.md*
