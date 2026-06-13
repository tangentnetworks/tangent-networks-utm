<!--
SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks

SPDX-License-Identifier: BSD-3-Clause
-->

# Tangent Networks UTM

> **Disclaimer**
>
> This software is provided "as is", without warranty of any kind, express or implied. The authors and contributors accept no responsibility or liability for any damage, data loss, system instability, or other adverse outcomes arising from its use. It is not intended for general use outside this project or closely related derivative systems. Use at your own risk.

> [!NOTE]
> Back up your existing system configuration before installation, including `/etc/rc.local`, `/etc/httpd.conf`, `/etc/hostname.*`, `/etc/mygate`, `/etc/syslog.conf`, `/etc/newsyslog.conf`, `/etc/rc.conf.local`, `/etc/rc`, `/etc/pf.conf`, and related files. While the installer incorporates safeguards, an independent backup remains the most reliable recovery mechanism.

A Unified Threat Management platform built on OpenBSD 7.8 / 7.9. Self-hosted, open source (BSD 3-Clause), zero cloud dependency.

This is not a wrapper around an existing firewall distribution. It is a ground-up implementation of a privilege-separated UTM stack with a browser-based management interface, written on top of a stock OpenBSD install. Every component -- the boot orchestration, the WebUI, the inspection chain, the privilege separation model, the log rotation framework -- is purpose-built for this platform.


> [!IMPORTANT]
> **This version of Tangent Networks UTM supports one WAN interface and one LAN segment.**
>
> The LAN segment may be a single physical interface or a bridge combining two or more
> physical interfaces (wired and/or wireless) into a single L2 domain. The WAN interface
> may be wired ethernet, PPPoE, or wireless.
>
> | WAN | LAN | Status |
> |-----|-----|--------|
> | Wired ethernet | Wired ethernet (single) | Validated |
> | Wired ethernet | Bridge (wired + wireless AP) | Validated |
> | Wired ethernet | Wireless AP (single) | Present, not validated in v1.0 |
> | Wireless client | Wired ethernet | Present, not validated in v1.0 |
>
> **Bridge LAN topology** uses `vether0` as the routable LAN anchor (holds the IP,
> binds all services) and `bridge0` as a pure L2 forwarder. Physical members
> (`em1`, `athn0`, etc.) are enslaved to `bridge0` with no IP assigned. This is
> required for correct PF divert and UTM inspection pipeline behaviour -- assigning
> an IP directly to the bridge pseudo-interface causes divert rules keyed on it to
> silently not match traffic arriving on physical ports.
>
> Multi-interface topologies beyond a single bridge (additional LANs, VLANs, LAGG)
> are not supported in this release and are gated for 8.0.
>
> ### Stability Considerations
>
> Attempting to force unsupported multi-interface configurations without redesigning
> the underlying process-spawning and interface-management architecture may result in
> BPF contention, unstable daemon lifecycle states, inconsistent packet inspection
> behaviour, degraded IDS/IPS reliability, and undefined runtime behaviour. These
> limitations are architectural and intentional in the current branch.

---

## Table of Contents

- [Platform Overview](#platform-overview)
- [Requirements](#requirements)
- [Installation](#installation)
- [Directory Structure](#directory-structure)
- [Dependencies](#dependencies)
- [Component Overview](#component-overview)
- [Network Architecture](#network-architecture)
- [Boot Sequence](#boot-sequence)
- [Configuration Files](#configuration-files)
- [Privilege Separation Model](#privilege-separation-model)
- [WebUI Runner Architecture](#webui-runner-architecture)
- [Log Management](#log-management)
- [MFS Memory Filesystems](#mfs-memory-filesystems)
- [Silent Hard Dependencies](#silent-hard-dependencies)
- [Contributing](#contributing)
- [Licence](#licence)

---

## Platform Overview

Tangent Networks UTM chains six inspection services behind OpenBSD's PF packet filter. Traffic from LAN clients passes through PF divert rules into a sequence of user-space daemons before being forwarded to the internet. The management interface is a CGI application running inside the `/var/www` chroot with no privilege path to the host system.

```
LAN client
    |
    | PF divert-to lo (per protocol, per address family)
    v
SSLproxy (TLS interception, IPv4/IPv6 protocol boundary)
    |
    | re-originates as IPv4 on loopback
    v
PF divert-packet port 700
    v
Snort IPS (inline deep packet inspection)
    |
    v
e2guardian / p3scan / smtp-gated (content layer)
    |
    v
PF NAT44 / NAT66 / NAT64
    |
    v
Internet ($ext_if)
```

SSLproxy acts as the IPv6/IPv4 protocol boundary. IPv6 LAN flows are diverted to SSLproxy's `::1` listeners. SSLproxy re-originates all traffic as IPv4 on loopback, so every downstream daemon (p3scan, smtp-gated, imspector, ClamAV) sees only IPv4 connections regardless of the originating client's protocol family.

---

## Requirements

**Operating system:** OpenBSD 7.8 or 7.9 (`amd64`, `arm64`).

**Required installation sets:**
* `bsd`
* `bsd.mp`
* `bsd.rd`
* `manXX.tgz`
* `baseXX.tgz`
* `xbaseXX.tgz`

Where `XX` corresponds to the installed OpenBSD release (e.g. `base79.tgz`, `xbase79.tgz`).

**Hardware minimum:**

* 2-core CPU
* 4 GB RAM
* 128 GB SSD
* 2 or more network interfaces

**Hardware recommended:**

* 4-core CPU
* 8 GB RAM
* 256 GB SSD
* 2 or more Intel Ethernet adapters

**Network interfaces:**

* Any OpenBSD-supported network interface may be used.
* A minimum of two interfaces is required to establish ingress and egress networks.
* Supported deployments include wired/wired, wired/wireless, wireless/wireless, `vether(4)`, and `bridge(4)`-based configurations.
* Intel `em(4)`, `igc(4)`, `igb(4)`, and `ix(4)` adapters are recommended for production environments.
* Wireless interfaces are supported where appropriate.
* USB network adapters are not recommended.

**Dependencies:**

* Required: `git`
* Optional but recommended: `nano`, `most`, `colorls`, `colordiff` and `truncate`

**Critical kernel dependencies** (applied by `UTM_INSTALL.sh`, lost after sysupgrade -- see [Silent Hard Dependencies](#silent-hard-dependencies)):

| Parameter | Required value | Default | Effect if wrong |
|---|---|---|---|
| `net.bpf.bufsize` | `2097152` | `32768` | pflog1 and pmacct silently drop packets under load |
| `net.bpf.maxbufsize` | `2097152` | `32768` | Same as above |
| `kern.shminfo.shmmax` | `536870912` | low | e2guardian starts but does not filter content |
| `login.conf daemon datasize` | `8192M` | low | e2guardian and ClamAV hit resource limits silently |
| `login.conf daemon openfiles-max` | `65536` | low | Same as above |

---

## Installation

Clone the repository and run the install script as root on a fresh OpenBSD version 7.8 or 7.9 install.

```ksh
git clone https://gitlab.com/tangentnetworks/tangent-networks-utm.git
cd tangent-networks-utm
chmod +x *.sh *.pl
```
> **For further instructions, see [INSTALL.md](INSTALL.md).**

**Before running the installer, place your Snort oinkcode in the project root:**

```ksh
echo 'oinkcode="YOUR_OINKCODE"' > oinkcode
```

The oinkcode is the 40-character hex token from your [Snort registered-user account](https://snort.org/users/register). It is required to fetch the full Snort VRT ruleset -- the IDS/IPS runs on bundled rules only without it, which go stale immediately and leave critical coverage gaps.

The installer reads this file automatically during Stage 1 (TN_NET_SET.sh). Supplying it here avoids having to type or paste a 40-character token on the console during an interactive session where input is sanitized and echo is suppressed. The file is sourced, validated for correct format (exactly 40 lowercase hex characters), and its contents are never written to any log or inventory file. You may delete it after the installer completes.

If the file is absent or contains an invalid value, Stage 1 will fall back to prompting for the code interactively.

```ksh
ksh TN_UTM_INSTALLER.sh
```

`UTM_INSTALL.sh` performs the following in order:

1. Validates the running OpenBSD version and hardware
2. Installs all required packages via `pkg_add`
3. Writes `/etc/sysctl.conf` with required kernel tuning values
4. Patches `/etc/login.conf` for the `daemon` resource class and runs `cap_mkdb`
5. Creates the full directory tree under `/var/www/htdocs/tn/`
6. Installs and configures all service binaries and their config files
7. Installs the WebUI source under the chroot
8. Configures `/etc/pf.conf`, `/var/unbound/etc/unbound.conf`, `/etc/dhcpd.conf`, `/etc/rad.conf`
9. Creates `/etc/hostname.pflog1` containing `up`
10. Adds MFS entries to `/etc/fstab`
11. Injects the `tangent_logrotate.sh` hook into `/etc/rc`
12. Writes `/etc/rc.local`
13. Runs `rcctl enable` for all required base system daemons
14. Performs an initial boot sequence dry-run check

After installation, reboot. The full service stack starts from `/etc/rc.local`. Check `/var/www/htdocs/tn/data/logs/bootlog/rc.local.log` if anything is wrong after the first boot.

**Post-install configuration required:**

- Edit `/etc/hostname.vio0` and `/etc/hostname.vio1` with your actual interface names and addresses
- Edit `/etc/mygate` and `/etc/mygate6` with your gateway addresses
- Set the `ext_if` and `int_if` variables at the top of `/etc/pf.conf`
- Access the WebUI at `https://10.10.10.1` from a LAN client to complete initial setup

---

## Directory Structure

Everything Tangent Networks owns lives under `/var/www/htdocs/tn/`. The chroot boundary is `/var/www`. Paths below are from the host shell perspective. CGI scripts inside the chroot see `/htdocs/tn/` as root.

```
/var/www/htdocs/tn/
├── documentation.html          # Documentation SPA shell
├── assets/
│   ├── css/docs.css            # Documentation stylesheet
│   └── js/doc.js               # Documentation SPA script
├── docs/                       # HTML doc fragments served by SPA
├── view/                       # Perl HTML view templates (9 files)
└── data/
    ├── config/                 # 4 config files -- root-owned, not readable by www
    ├── db/                     # SQLite databases
    │   ├── geoip.db
    │   ├── e2g.db
    │   ├── pf.db
    │   ├── snortsentry.db
    │   ├── sslproxy.db
    │   └── unbound.db
    ├── keys/                   # 2 key files -- root-owned 0600, never served
    ├── lib/                    # Perl library modules -- root-owned
    │   ├── TNEnv.pm
    │   ├── TNConfig.pm
    │   ├── TNAuth.pm
    │   ├── TNSecurity.pm
    │   ├── TNSecurityCheck.pm
    │   └── TNWAF.pm
    ├── logs/                   # All runtime logs
    │   ├── bootlog/
    │   │   ├── rc.local.log    # Full boot log -- first diagnostic after reboot
    │   │   ├── services.log    # Plain-text service status (~16min after boot)
    │   │   └── services.json   # Live service status JSON (written continuously)
    │   ├── pf/
    │   │   └── pflog1.log      # MFS 128MB -- live tcpdump of all PF traffic
    │   ├── snort/
    │   │   └── alert.log       # Shared by IDS and IPS (_snort:www 0644)
    │   ├── waf/
    │   │   └── access.log      # TNWAF request log
    │   └── [service]/          # Per-service log directories
    ├── network/
    │   └── pmacct/ext/         # pmacct disk archive (quarter-hour JSON, persistent)
    ├── pipes/
    │   └── pmacct/             # MFS 64MB -- live pmacct flow feeds
    ├── run/                    # PID files for all services and WebUI runners
    │   └── webui/              # 17 WebUI runner PID files
    ├── services/
    │   ├── queue/              # WebUI operation queues
    │   │   ├── pf-rules/       # Firewall change pipeline
    │   │   ├── e2gfilters/     # e2guardian filter queue
    │   │   └── unbound/        # Unbound config queue
    │   └── status/             # 38 service status subdirectories
    ├── sockets/
    │   └── collectd/
    │       └── collectd.sock   # collectd unix socket (primary dashboard data source)
    └── tmp/
        └── clamav/
            └── clamd.socket    # ClamAV unix socket (created by clamd at startup)

/var/www/cgi-bin/               # 29 CGI scripts -- all routed via router.pl through TNWAF
```

**MFS paths** (swap-backed, contents lost on every reboot):
- `/var/www/htdocs/tn/data/logs/pf/` -- 128 MB
- `/var/www/htdocs/tn/data/pipes/pmacct/` -- 64 MB

Both are declared in `/etc/fstab`. If missing from fstab, these become regular disk directories with no size limit.

---

## Dependencies

All installed via `pkg_add` by `UTM_INSTALL.sh`.

**Security and inspection:**

| Package | Notes |
|---|---|
| `snort` | Custom build patched with SSLproxy integration |
| `snortsentry` | v8.1.6 -- Tangent-authored dynamic PF blocker |
| `e2guardian` | Custom build patched with SSLproxy integration |
| `clamav` | Malware scanning via clamd unix socket |
| `sslproxy` | Transparent TLS interception proxy |
| `p3scan` | Custom build patched with SSLproxy integration |
| `smtp-gated` | Transparent SMTP scanning proxy |
| `imspector` | Custom build patched with SSLproxy integration |

**Network services:**

| Package | Notes |
|---|---|
| `unbound` | Recursive DNS-over-TLS resolver with DNS64 |
| `dante` | SOCKS proxy (sockd) |
| `spamd` | Spam deferral daemon |
| `pmacctd` | Network flow accounting -- 3 instances |
| `collectd` | System statistics daemon |

**Perl modules (CGI layer):**

| Module | Role |
|---|---|
| `DBI` + `DBD::SQLite` | SQLite database access |
| `JSON` | JSON encode/decode |
| `Digest::SHA` | SHA256 for integrity checks and CSRF tokens |
| `File::Spec` | Safe path construction -- never string concatenation |
| `MIME::Base64` | Session token encoding |
| `LWP::UserAgent` | Feed downloads in validator |

**System utilities:**

| Utility | Role |
|---|---|
| `oinkmaster` | Snort rule updates |
| `jq` | JSON encoding for queue outcomes |
| `tcpdump` | pflog1 pipeline (base system) |

---

## Component Overview

### PF Firewall (`/etc/pf.conf`)

The ruleset is structured in labelled sections A through X. Key points:

- **[B]** `match log (to pflog1) on { $ext_if $int_if }` -- loopback deliberately excluded from logging
- **[C]** `block return on { $ext_if $int_if } all` -- loopback has no default deny (see below)
- **[D]** `pass in quick on lo proto tcp to port { 8080 8110 9199 } divert-packet port 700`
- **[R]** Application proxy diverts -- must precede [S], all rules use `quick`
- **[S]** `pass in on $int_if from <lan_nets> keep state` -- placed after [R] so quick divert rules fire first

Loopback is not skipped (`set skip on lo` is absent). PF must process loopback for the Snort IPS `divert-packet` rule to fire on proxy re-originated flows. A global block on loopback would catch reinjected packets and break the inspection chain.

Every application proxy divert uses two rules (`inet` and `inet6`) both with `divert-to lo`. The qualifier is required: without it PF resolves `lo` to `::1` only, silently leaving IPv4 clients unintercepted. With it, PF resolves `lo` to `127.0.0.1` for `inet` and `::1` for `inet6`.

### Snort (`/usr/local/bin/snort`)

Custom build patched with SSLproxy integration. Two instances:

- **IDS**: passive on `$int_if`, config `/etc/snort/snort.conf`, syslog tag `snort_ids`
- **IPS**: divert-packet mode (`-Q`), config `/etc/snort/snortinline.conf`, syslog tag `snort_ips`

Both write to `data/logs/snort/alert.log` (`_snort:www 0644`). snortsentry reads this file.

### snortsentry (`/usr/local/sbin/snortsentry`)

Tangent-authored IPv4+IPv6 dynamic PF blocker, v8.1.6. Config: `/etc/snort/snortsentry.conf`. State file: `/var/db/snortsentry.state` (persists across reboots). See `snortsentry(8)`.

To reset block escalation state:

```ksh
rcctl stop snortsentry
rm /var/db/snortsentry.state
rcctl start snortsentry
```

### e2guardian (`/usr/local/sbin/e2guardian`)

Custom build patched with SSLproxy integration. Config: `/etc/e2guardian/`. User: `_e2guardian`. Requires the ClamAV socket and handles the wait internally at startup.

Three filter modes: ChildSafe, General, Custom. Mode switching rewrites the active crontab entry and sends SIGHUP to e2guardian.

### SSLproxy (`/usr/local/bin/sslproxy`)

Transparent TLS interception proxy. Config: `/usr/local/etc/sslproxy/sslproxy.conf`. Listens on `lo:8081` (HTTP) and `lo:8443` (HTTPS). Acts as the IPv6/IPv4 protocol boundary: IPv6 LAN flows are diverted to `::1` listeners, decrypted, and re-originated as IPv4 on loopback.

### pmacct (`/usr/local/sbin/pmacctd`)

Three instances with distinct roles:

| Instance | Config | Output | Start timing |
|---|---|---|---|
| `ext_if_json_mfs` | `ext_if_json_mfs.conf` | `data/pipes/pmacct/ext_if_json.log` (MFS) | Immediately at boot |
| `int_if_json_mfs` | `int_if_json_mfs.conf` | `data/pipes/pmacct/int_if_json.log` (MFS) | Immediately at boot |
| `ext_if_json_log` | `ext_if_json_log.conf` | `data/network/pmacct/ext/ext_if-%Y%m%d-%H%M.json` | Next quarter-hour boundary (up to 15 min delay) |

The disk archive PID file is empty for up to 15 minutes after boot. This is correct behaviour.

### collectd (`/usr/local/sbin/collectd`)

System statistics daemon. Config: `/etc/collectd.conf`. Socket: `data/sockets/collectd/collectd.sock`. The socket is removed at boot start and recreated by collectd. `rc.local` sleeps 2 seconds after starting collectd before proceeding.

### TNWAF.pm

Web Application Firewall Perl module. All CGI scripts are routed through `router.pl` via TNWAF. Handles request validation, rate limiting, and HTTP access logging. Writes httpd logs directly because syslogd routing does not work for httpd on OpenBSD.

### TNSecurityCheck.pm

Security enforcement module. Called before any business logic in every CGI script. Enforces three operation tiers:

| Tier | Requirement |
|---|---|
| `standard` | Valid session cookie |
| `protected` | Valid session + per-request CSRF token |
| `restricted` | Valid session + CSRF token + elevated admin role |

---

## Network Architecture

**Single-interface LAN:**

```
Internet
    |
$ext_if (em0) -- WAN
    IPv4: DHCP-assigned or static
    IPv6: SLAAC or DHCPv6-PD
    |
    | PF: NAT44, NAT66, NAT64, bogon blocks, dynamic blocklists
    |
$int_if (em1) -- LAN
    IPv4: 10.10.10.1/24 (DHCPv4 pool .10 to .245)
    IPv6: fd10:10:10::1/64 (SLAAC via rad)
    |
    | PF: divert chain [R], broad pass [S]
    |
LAN clients
```

**Bridge LAN (vether0 architecture):**

```
Internet
    |
$ext_if (em0) -- WAN
    |
    | PF: NAT44, NAT66, NAT64
    |
bridge0 -- L2 forwarder (no IP)
    |--- em1   (wired member)
    |--- athn0 (wireless AP member, hostap mode)
    |--- vether0
          |
          $int_if = vether0 -- LAN anchor
              IPv4: 172.16.5.1/24
              IPv6: fdac:1005::1/64
              All services bind here: dhcpd, rad, unbound, pf diverts
```

`vether0` is a virtual Ethernet pair endpoint. It holds the LAN IP and is the
interface all PF rules, divert sockets, dhcpd, rad, and unbound bind to. Physical
bridge members carry no IP -- they forward L2 frames only. This is required for the
UTM inspection pipeline: PF divert rules keyed on `vether0` correctly match traffic
arriving on all bridge members.

**PF tables:**

| Table | Populated by | Contents |
|---|---|---|
| `<snort_block>` persist | snortsentry | Dynamic blocks from Snort alerts -- IPv4 and IPv6 |
| `<blocklist>` persist | pfblock.sh | Threat intelligence feed IPs |
| `<bogons>` persist | pfblock.sh | Bogon address ranges |
| `<lan_nets>` | pf.conf | `INT_NET4`, `INT_NET6` |

**PF divert chain (section [R]):**

| LAN port | Diverted to | Service |
|---|---|---|
| 21 (FTP) | lo:8021 | ftp-proxy |
| 80 (HTTP) | lo:8081 | SSLproxy |
| 443 (HTTPS) | lo:8443 | SSLproxy |
| 110 (POP3) | lo:8994 | SSLproxy to p3scan |
| 995 (POP3S) | lo:8995 | SSLproxy to p3scan |
| 25 (SMTP) | lo:8464 | SSLproxy to smtp-gated |
| 465 (SMTPS) | lo:8465 | SSLproxy to smtp-gated |
| 587 (submission) | lo:8466 | SSLproxy to smtp-gated |
| 1863, 5190, 5050, 6667 (IM) | lo:16667 | imspector (IPv4 only) |
| lo:8080, lo:8110, lo:9199 | divert-packet:700 | Snort IPS |

**NAT:**

| Mechanism | Rule | Purpose |
|---|---|---|
| NAT44 | `match out on $ext_if inet from $int_net4 nat-to ($ext_if)` | IPv4 LAN masquerade |
| NAT66 | `match out on $ext_if inet6 from $int_net6 nat-to ($ext_if)` | IPv6 ULA behind WAN GUA |
| NAT64 | `pass in on $int_if inet6 from $int_net6 to 64:ff9b::/96 af-to inet from ($ext_if)` | IPv6 clients to IPv4 internet |

NAT64 requires a static route on `$int_if`:

```ksh
# /etc/hostname.vio1 (or equivalent)
route add -inet6 64:ff9b::/96 fd10:10:10::1
```

---

## Boot Sequence

`/etc/rc.local` runs with `set -euo pipefail`. Any unhandled failure exits the script and leaves all subsequent services unstarted. Check `data/logs/bootlog/rc.local.log` first when anything is dark after a reboot.

The `tangent_logrotate.sh` hook in `/etc/rc` runs before step 1, injected after `reorder_libs` and before the first `start_daemon` call. It is self-healing: if a sysupgrade replaces `/etc/rc`, the next invocation detects the missing hook and reinjects it automatically.

```
rc.local start order:

 1. PID file truncation + /var/www/tmp housekeeping
 2. Snort IDS          -- waits up to 15s for snort_vio1.pid
 3. Snort IPS          -- waits up to 10s for snort_.pid
 4. snortsentry        -- waits up to 5s for PID file
 5. e2guardian
 6. collectd           -- sleeps 2s after start for socket readiness
 7. p3scan
 8. ClamAV / clamd     -- polls up to 90s for clamd.socket (not a hang)
 9. freshclam          -- starts only after clamd.socket is confirmed present
10. pmacct ext_if_json_mfs   -- starts immediately
11. pmacct int_if_json_mfs   -- starts immediately
12. pmacct ext_if_json_log   -- delayed to next quarter-hour boundary
13. sockd (Dante)
14. spamd
15. smtp-gated
16. SSLproxy
17. imspector
18. pf_mirror_sync.sh  -- synchronous, no &
19. tcpdump on pflog1  -- writes to data/logs/pf/pflog1.log (MFS)
20. process_monitor.pl -- delayed to 1 min past next 15-min boundary
21. start_service() x 16 WebUI runners
```

---

## Configuration Files

| File | Purpose | Notes |
|---|---|---|
| `/etc/pf.conf` | PF ruleset | Set `ext_if` and `int_if` for your hardware |
| `/etc/pf/pf-addons.conf` | WebUI-managed anchor rules | Managed by pf_monitor.sh -- do not edit directly |
| `/etc/unbound/unbound.conf` | Unbound resolver | IPv6 forwarders commented out for dev env |
| `/etc/dhcpd.conf` | DHCPv4 server | Bound to `$int_if` only |
| `/etc/rad.conf` | IPv6 router advertisement | Announces `fd10:10:10::/64` and NAT64 prefix |
| `/etc/snort/snort.conf` | Snort IDS config | |
| `/etc/snort/snortinline.conf` | Snort IPS config | |
| `/etc/snort/snortsentry.conf` | snortsentry config | |
| `/etc/oinkmaster.conf` | Snort rule update config | Rule source URL and suppression lists |
| `/etc/e2guardian/` | e2guardian config directory | |
| `/etc/clamd.conf` | ClamAV daemon config | Socket path must match `data/tmp/clamav/clamd.socket` |
| `/etc/collectd.conf` | collectd config | Socket path must match `data/sockets/collectd/collectd.sock` |
| `/usr/local/etc/sslproxy/sslproxy.conf` | SSLproxy config | |
| `/usr/local/etc/smtp-gated/smtp-gated.conf` | smtp-gated config | |
| `/usr/local/etc/imspector/imspector.conf` | imspector config | |
| `/etc/p3scan/p3scan.conf` | p3scan config | |
| `/etc/sysctl.conf` | Kernel tuning | `net.bpf.bufsize` critical -- verify after every sysupgrade |
| `/etc/login.conf` | Resource limits | `daemon` class -- verify after sysupgrade, run `cap_mkdb` after edits |
| `/etc/fstab` | MFS mount entries | If missing, MFS paths become regular disk directories |
| `/etc/hostname.pflog1` | pflog1 interface | Must contain `up` -- if missing, all traffic logging is dark |
| `/etc/rc.conf.local` | Base daemon flags | `resolvd_flags=NO`, `dhcpd_flags=vio1` |
| `/etc/mygate` | IPv4 default gateway | |
| `/etc/mygate6` | IPv6 default gateway | |
| `/var/db/snortsentry.state` | snortsentry block state | Persists across reboots |
| `/var/db/dhcpd.leases` | DHCP lease ground truth | More reliable than WebUI in first minute after boot |

---

## Privilege Separation Model

```
/var/www (chroot boundary)
|
+-- www process (slowcgi + all CGI scripts)
|       Reads:   data/services/queue/*/outcome files
|       Writes:  data/services/queue/*/request files
|       Cannot:  execute pfctl, unbound-control, rcctl, ksh, or any system binary
|                read /etc, /usr, /bin, /sbin, or anything outside /var/www
|
+-- Root daemons (outside chroot, full system access)
        pf_monitor.sh       -- polls queue/pf-rules/triggers/, executes pfctl
        pf_anchor_sync.sh   -- syncs live anchor state, writes active-addons.json
        manage_unbound.sh   -- executes unbound-control
        e2g_*_filter.sh     -- downloads feeds, reloads e2guardian
        dashboard_stats_runner.sh -- reads collectd socket, writes stats JSON
        [13 additional runners]
```

The CGI layer communicates with root daemons exclusively through files in `data/services/queue/`. There are no sockets, no shared memory, no IPC channels, and no internal HTTP API between the two tiers.

All CGI scripts run under Perl `-T` (taint mode). Every value from the browser must pass an explicit untaint regex before reaching the filesystem or any system call. `File::Spec` is used for all path construction. String concatenation for paths is not used anywhere in the codebase.

---

## WebUI Runner Architecture

17 persistent shell loop scripts started by `rc.local` via `start_service()`. Each runner invokes a Perl or shell script on a fixed interval. All PID files live under `data/run/webui/`.

`start_service()` validates executability, ensures the PID directory exists at `www:www 0750`, checks for a live existing process, launches the script with stdin/stdout/stderr redirected to `/dev/null`, waits 200ms, then verifies the process is still alive before writing the PID file.

| Runner | PID file | Function | If stopped |
|---|---|---|---|
| `queue_processor_runner.sh` | `queue_runner.pid` | PF rules and e2guardian filter queues | Rule changes queue but never apply |
| `unbound_stats_runner.sh` | `unbound_stats_runner.pid` | DNS statistics collection | DNS stats panel goes stale |
| `dashboard_stats_runner.sh` | `dashboard_stats_runner.pid` | collectd metrics export | CPU, memory, network, disk panels go stale |
| `service_monitor_runner.sh` | `service_monitor_runner.pid` | Runs monitor.pl, writes services.json | Services panel shows last known state |
| `pf_stats_runner.sh` | `pf_stats_runner.pid` | PF firewall statistics | PF stats panel goes stale |
| `pf_tcpdump_runner.sh` | `pflog_maint.pid` | pflog1 MFS feed and archiving | PF log panel goes dark |
| `pmacct_mfs_manage_runner.sh` | `pmacct_mfs_manage_runner.pid` | MFS trim before 64MB fills | MFS fills within hours, flow accounting dark |
| `pf_change_detector_runner.sh` | `pf_change_detector.pid` | Detects external PF rule changes | Dashboard PF state drifts from actual ruleset |
| `e2g_user_filter_runner.sh` | `e2g_user_filter_detector.pid` | Per-user filter change detection | Per-user overrides do not apply |
| `unbound_queue_runner.sh` | `unbound_queue_runner.pid` | Unbound config queue processing | DNS config changes queue but never apply |
| `e2g_status_writer_runner.sh` | `e2g_status_writer.pid` | e2guardian status JSON writer | Content filter status panel goes stale |
| `e2g_queue_processor_runner.sh` | `e2g_queue_processor.pid` | Filter mode switch processor | Mode switches queue but never execute |
| `pf_monitor_runner.sh` | `pf_monitor.pid` | PF rule validation pipeline | Submitted rule changes never complete |
| `integrity_check_runner.sh` | `integrity_check.pid` | TNAudit integrity checks | Integrity status panel goes stale |
| `powermgmt_runner.sh` | `powermgmt.pid` | WebUI reboot and shutdown requests | Power management panel has no effect |
| `pf_asn_runner.sh` | `pf_asn_lookip.pid` | ASN lookups for firewall panel | ASN info missing from firewall panel |

Check all runner PID files:

```ksh
for f in /var/www/htdocs/tn/data/run/webui/*.pid; do
    pid=$(cat "$f" 2>/dev/null)
    name=$(basename "$f" .pid)
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        echo "OK   $name ($pid)"
    else
        echo "DEAD $name"
    fi
done
```

---

## Log Management

All logs under `data/logs/` are on disk except the two MFS paths. Rotation is handled by `tangent_logrotate.sh`.

**Rotation schedule:**
- At boot, before any daemon starts: full rotation run
- Every 10 minutes via cron: incremental check
- Daily at 01:00 via cron: full daily run

Rotated files are renamed to `name_YYYY-MM-DD.log` and kept for 7 days. The script uses triple verification to prevent duplicate rotation: stamp file check, archive file presence check, then rotation proceeds only if both checks fail.

After rotating httpd logs, `USR1` is sent to httpd via `pkill -USR1` to reopen log file descriptors. This is required because TNWAF.pm writes httpd logs directly rather than through syslog.

The two MFS paths use newsyslog for in-place truncation rather than rotation.

---

## MFS Memory Filesystems

Two swap-backed memory filesystems are mounted at boot and their contents are destroyed on every reboot including WebUI-initiated reboots.

| Path | Size | Contents | Truncation |
|---|---|---|---|
| `data/logs/pf/` | 128 MB | `pflog1.log` -- live tcpdump of all PF traffic | newsyslog at 64MB, calls `pf-tcpdump.sh` before truncation |
| `data/pipes/pmacct/` | 64 MB | `ext_if_json.log`, `int_if_json.log` | newsyslog at ~16MB each, sends SIGHUP to pmacctd |

Both paths are declared in `/etc/fstab`. If the MFS entries are missing, these become regular disk directories with no size limit and the disk will eventually fill.

`rc.local` pre-creates the required files inside each MFS before starting tcpdump and pmacctd. Empty MFS files after reboot are correct.

---

## Silent Hard Dependencies

These four dependencies fail silently after a sysupgrade with no obvious error message. Check all four after every upgrade.

**1. BPF buffer size**

```ksh
# /etc/sysctl.conf -- must contain:
net.bpf.bufsize=2097152
net.bpf.maxbufsize=2097152
```

Default of 32768 causes silent packet drops in pflog1 and pmacct under load. Verify:

```ksh
sysctl net.bpf.bufsize net.bpf.maxbufsize
```

**2. login.conf daemon class**

```
daemon:\
    :ignorenologin:\
    :datasize=8192M:\
    :maxproc=infinity:\
    :openfiles-max=65536:\
    :openfiles-cur=8192:\
    :stacksize-cur=16M:\
    :tc=default:
```

If missing or set to defaults, e2guardian and ClamAV start without error but operate incorrectly. After any edit:

```ksh
cap_mkdb /etc/login.conf
```

**3. /etc/hostname.pflog1**

Must exist and contain only `up`. If missing, pflog1 never comes up and all traffic logging is dark.

```ksh
echo up > /etc/hostname.pflog1
sh /etc/netstart pflog1
```

**4. MFS entries in /etc/fstab**

If missing, `data/logs/pf/` and `data/pipes/pmacct/` become regular disk directories. Verify:

```ksh
mount | grep mfs
```

---

## Contributing

The project is in active development. Source code, contribution guidelines, and issue templates will be published here as the first public release is prepared.

For bug reports and security issues, use the GitLab issue tracker. For security-sensitive reports, contact via the website before opening a public issue.

Code style conventions:
- Shell scripts: ksh with `set -eu`
- Perl: `-T` taint mode, `use strict; use warnings;` in all CGI and library code
- Path construction: `File::Spec` throughout -- no string concatenation for paths
- Input validation: explicit untaint regex before any value reaches the filesystem or a system call

---

> [!IMPORTANT]
> ## Roadmap to OpenBSD 8.0
>
> ### The Hardware-Agnostic Evolution
>
> By the release of OpenBSD 8.0, the Tangent Networks (TN) UTM will transition from a fixed-interface deployment model to a **hardware-agnostic orchestration framework**.
>
> The system will treat network interfaces as dynamic assets, utilizing an inventory-driven architecture to instantiate security services dynamically without manual script intervention or hardcoded interface logic.
>
> ---
>
> ### Core Technical Objectives
>
> #### 1. Transition to Inventory-Driven Service Instantiation
>
> **Current Limitation**
>
> Current `rc.local` and `service_manager.sh` logic relies on token substitution (`%%INT_IF%%`), which becomes increasingly fragile in N+1 interface scenarios or complex VLAN/bridge topologies.
>
> **OpenBSD 8.0 Strategy**
>
> Introduce `/etc/tn-interfaces` as the authoritative inventory source. Management components will be refactored into iterative runtime engines capable of dynamically instantiating service instances per interface.
>
> #### 2. Asynchronous & Sequential Service Plumbing
>
> **Current Limitation**
>
> Parallel initialization of BPF-dependent services such as Snort, pmacct, and tcpdump may cause kernel buffer contention and race conditions during early boot.
>
> **OpenBSD 8.0 Strategy**
>
> Introduce a serialized initialization pipeline with controlled interface bring-up sequencing and staggered packet-capture attachment.
>
> This ensures deterministic BPF attachment ordering and reliable PID/state tracking across all physical and logical interfaces.
>
> #### 3. Decoupling Configuration from Execution
>
> **OpenBSD 8.0 Strategy**
>
> - Adopt a `service@interface` execution model (`snort@em1`, `snort@vlan10`)
> - Standardize runtime state tracking under `/var/run/tn/`
> - Replace static monitoring arrays with dynamic filesystem discovery
> - Eliminate hardcoded service/interface assumptions
>
> #### 4. Modular Hook Architecture for WebUI/CLI
>
> `service_manager.sh` will evolve into a lightweight abstraction layer over `rcctl(8)`, dynamically discovering generated `rc.d` instances and exposing them to both the WebUI and CLI management layers.
>
> ---
>
> ### Proposed Hardware-Agnostic Workflow
>
> 1. `TN_NET_SET.sh` probes and inventories hardware
> 2. `tn_materialize` generates runtime configuration fragments
> 3. Service orchestration dynamically spawns tagged instances
> 4. `monitor.pl` discovers and tracks active runtime state automatically
>
> ```bash
> for iface in $(get_tn_interfaces); do
>     spawn_instance "snort" "$iface" \
>         --mode "$(get_role "$iface")"
> done
> ```
>
> ---
>
> ### Release Targets
>
> - Full VLAN and bridge transparency
> - Zero-edit NIC scaling
> - Atomic per-interface IDS restarts
> - Hardened Perl monitoring architecture
> - Dynamic runtime service discovery
>
> ---
>
> ### Developer Note
>
> This strategy eliminates the operational complexity associated with hardcoded interface assumptions and static service orchestration.
>
> The long-term objective is to treat the UTM as a modular service fabric operating against a dynamic hardware inventory model.
---

## Author and Attribution

**Author:** David Peter
**Organization:** Tangent Networks
**Web:** [https://tangentnet.top](https://tangentnet.top)
**Email:** [tangent.net@zohomail.in](mailto:tangent.net@zohomail.in)

See [CREDITS.md](CREDITS.md) for attribution and acknowledgments.

---

## License

**BSD 3-Clause License (Simplified)**

Copyright (c) 2025–2026
David Peter, Tangent Networks
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions, and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions, and the following disclaimer in the documentation and/or other materials provided with the distribution.
3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---

*End of README.md*
