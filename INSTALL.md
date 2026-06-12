<!--
SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks

SPDX-License-Identifier: BSD-3-Clause
-->

# Tangent Networks UTM — Installation Guide

## Versions

| Script               | Version        |
|----------------------|----------------|
| TN_UTM_INSTALLER.sh  | 1.1.0          |
| TN_NET_SET.sh        | 5.0.2-dual-lan |
| TN_SUBSTITUTE.sh     | 5.1.0          |
| TN_PKG_INSTALL.sh    | 6.4.0          |
| TN_CHROOT_SETUP.sh   | 4.2.0          |

---

## Requirements

**Platform:** OpenBSD only. Scripts will refuse to run on any other OS.

**Shell:** `/bin/ksh` (pdksh). All scripts use `#!/bin/ksh`. Do not run
with bash, dash, or sh on any other platform.

**Privileges:** All scripts must run as root. Use `ksh <script>` — do
not use `sudo` or `doas`.

**Network topology:** One WAN interface and one LAN segment. The LAN segment may be
a single physical interface or a bridge combining two or more physical interfaces
(wired and/or wireless AP) into one L2 domain. See [Topology Constraint](#topology-constraint)
below for full details. Multi-WAN, additional LAN interfaces, VLAN multi-tenancy,
LAGG, and CARP/HA are present in the scripts but dormant — they are not
production-ready and will be enabled in release 8.0.

**Internet access:** Required during Stage 3 for `syspatch` and `pkg_add`.
The package mirror defaults to `cloudflare.cdn.openbsd.org`. Custom local
packages must be present under `packages/amd64/` or `packages/aarch64/`
relative to the installer directory before Stage 3 runs.

**Directory layout:** All five scripts must be present in the same
directory. The installer creates and expects the following layout relative
to that directory:

```
./
├── TN_CHROOT_SETUP.sh
├── TN_DISCOVERY.sh
├── TN_NET_SET.sh
├── TN_PKG_INSTALL.sh
├── TN_RECON.sh
├── TN_SUBSTITUTE.sh
├── TN_TOKENIZE.sh
├── TN_UTM_INSTALLER.sh
├── TN_UTM_UNINSTALLER.sh
├── TN_WEBUI_ASSETS_INVENTORY.pl
├── oinkcode                     <-- create this before running (see below)
├── payload/
│   ├── etc/
│   └── usr/local/etc/
├── packages/
├── 7.8
│   ├── aarch64
│   └── amd64
├── 7.9
│   ├── aarch64
│   └── amd64
├── schema.sql
└── logs/                        <-- created automatically
```

---

## Snort Oinkcode

Stage 1 (TN_NET_SET.sh) requires a Snort registered-user oinkcode to
configure the IDS/IPS rule update pipeline. The oinkcode is a 40-character
hex token issued by snort.org to registered accounts and is used by
oinkmaster to authenticate rule downloads.

**Place the oinkcode in a file in the project root before running the
installer:**

```ksh
cd tangent-networks-utm
echo 'oinkcode="YOUR_OINKCODE"' > oinkcode
```

Replace `YOUR_OINKCODE` with your actual 40-character hex token. To obtain
one, register free at [https://snort.org/users/register](https://snort.org/users/register)
and copy the oinkcode from your account profile page.

**Why a file rather than console entry:** The oinkcode is 40 hex characters.
Typing or pasting it on the console during an interactive install session —
where echo is suppressed for credential safety — creates unnecessary risk of
transcription error with no visual feedback. Reading it from a file before
the session begins is reliable, repeatable, and avoids the problem entirely.

**What the installer does with it:** Stage 1 sources the file, validates
that the value is exactly 40 lowercase hex characters, and patches it into
`payload/etc/oinkmaster.conf`. It is never written to `/etc/tn-interfaces`,
any log file, or any inventory file. The file can be deleted after the
installer completes.

**If the file is absent or invalid:** Stage 1 falls back to an interactive
prompt. A correctly formatted value is still required — the install will
not proceed without one.

**File format:** The file is sourced by ksh. Either of the following forms
is accepted:

```ksh
oinkcode="fead876bb1e***********************56c02e"
```

```ksh
OINKCODE="fead876bb1e***********************56c02e"
```

Case is normalised automatically. Whitespace around the value is stripped.

---

## Quick Start

For a normal first-time installation, place the oinkcode file as described
above, then run the master orchestrator as root from the installer
directory:

```sh
ksh TN_UTM_INSTALLER.sh
```

This runs all four stages in sequence. Two confirmation pauses (guards) are
inserted at points where it is worth reviewing what the previous stage
produced before continuing. Ctrl-C at any guard aborts cleanly.

The master log is written to:

```
logs/utm_installer_<YYYYMMDD_HHMMSS>.log
```

---

## Manual Sequence

If you need to run stages individually — to resume after a failure, to
re-run a specific stage, or to debug a specific phase — run each script
directly in order from the installer directory:

```sh
ksh TN_NET_SET.sh
ksh TN_SUBSTITUTE.sh
ksh TN_PKG_INSTALL.sh
ksh TN_CHROOT_SETUP.sh
```

Each script is independently idempotent or checkpoint-aware (see
Resuming a Failed Installation below). Running an already-completed
script again will prompt before overwriting any prior work.

---

## What Each Stage Does

### Stage 1 — TN_NET_SET.sh

Probes hardware, optionally updates firmware for wireless interfaces, and
walks the operator through 24 interactive stages covering:

- WAN interface selection and type (ethernet, PPPoE, wireless)
- PPPoE credentials and wireless WAN SSID/passphrase (if applicable)
- Optional multi-WAN configuration (failover / load-balance / policy)
- Optional VLAN and LAGG/trunk bonding
- Primary LAN interface selection — single interface or bridge LAN
  (combines two or more physical interfaces into one L2 segment)
- In bridge mode: creates `bridge0` (L2 forwarder) and `vether0`
  (LAN IP anchor); all services bind to `vether0`
- Subnet assignment with automatic MTU/MSS derivation
- Wireless AP configuration (if applicable, including bridge member mode)
- Optional CARP/HA configuration (requires second physical node)
- Hostname assignment
- Connectivity tests and deployment classification
  (cgnat / dedicated / public / ipv6-only)
- SSL CA and server certificate generation
- Oinkcode configuration for Snort rule updates (file-first, keyboard
  fallback — see [Snort Oinkcode](#snort-oinkcode) above)

Writes `/etc/tn-interfaces` — the single source of truth consumed by all
subsequent stages. Also writes `/etc/hostname.*` interface files directly
to `/etc/` and `/etc/mygate`.

**Interactive:** Yes. Expect to spend 10–20 minutes depending on topology
complexity.

**Logs:** `logs/network-setup.log`

**Completion sentinel:** `/etc/tn-network-setup.status`

**Credential handling:** All SSIDs, passphrases, PSKs, and PPPoE
credentials are read with echo disabled and written only to
`/etc/hostname.*` files (mode 640, root:wheel). They are never written to
`/etc/tn-interfaces`, the log, or any inventory file. The in-memory
variable is zeroed immediately after each write. The oinkcode follows the
same policy: it is patched into `payload/etc/oinkmaster.conf` and never
appears in any log or inventory file.

---

### Stage 2 — TN_SUBSTITUTE.sh

Non-interactive. Reads `/etc/tn-interfaces` and expands all `%%TOKEN%%`
placeholders across every text file in `payload/`. Also:

- Sets the live hostname via `/etc/myname`
- Renames any `.template` files by stripping the suffix
- Recomputes SHA-384 SRI hashes for all JS assets referenced in HTML files
- Runs a second defensive pass over system-critical files to catch any
  tokens missed by the primary pass
- Fails hard if any `%%TOKEN%%` pattern remains in any payload file after
  expansion

A dry run (no files modified) is available for rehearsal:

```sh
ksh TN_SUBSTITUTE.sh --dry-run
```

**Interactive:** No.

**Logs:** `logs/substitute.log`

---

### Stage 3 — TN_PKG_INSTALL.sh

The longest stage. Runs 13 phases, each checkpointed so a restart resumes
from the first incomplete phase rather than from the beginning:

| Phase | What it does |
|-------|--------------|
| 00 | `syspatch` (system patches) and `pkg_add -u` (package upgrades) |
| 01 | SHA256 hash verification of custom local packages |
| 02 | Mirror package installation |
| 03 | Version-resolved package installation |
| 04 | Unflavored package installation |
| 05 | Custom local package installation |
| 06 | Installation verification (all expected packages present) |
| 07 | Bootstrap infrastructure (dirs, MFS, pmacct profiles) |
| 08 | Payload deploy — `/usr/local/sbin/`, `/etc/`, webroot |
| 09 | System config merges (sysctl, syslog, httpd, crontab) |
| 10 | AuthDB initialisation (schema, admin account) |
| 11 | Service smoke tests for all UTM daemons |
| 12 | `pf.conf` syntax validation and deploy, `pfctl` reload |

On any phase failure the operator is prompted:

- `y` — problem fixed, retry the failed step immediately
- `n` — write a phase checkpoint and exit; re-run the script to resume

No automatic rollback is performed. A pre-install package snapshot and
backed-up configs are preserved in `rollback/<timestamp>/` for manual
recovery if needed.

If a public domain is configured, a DNS propagation confirmation prompt
is shown before package installation begins. Answering `n` continues the
install with a self-signed certificate instead.

**Interactive:** Yes (retry prompts, DNS confirmation, rollback prompt on
failure).

**Logs:** `logs/pkg-install.log`

**Phase state file:** `.install_phases` (in installer directory)

**Completion sentinel:** `/root/packages-setup`

---

### Stage 4 — TN_CHROOT_SETUP.sh

Populates the `/var/www` chroot for the web stack. Copies:

- Perl binary and all required `perl5` and `site_perl` libraries
  (collectd XS modules excluded — they run outside the chroot)
- All shared libraries resolved via `ldd`
- `ld.so.hints` (via `ldconfig` inside the chroot, with host-hints
  fallback)
- Timezone data
- Device nodes (`/var/www/dev/`)
- Runtime directories with correct ownership and permissions
- Session key files (root:wheel 600, frozen after write)

After copying, runs a live Perl module load test inside the chroot to
verify the environment is functional. Writes a manifest of every file
copied (`chroot-manifest.txt`) and its SHA256 (`chroot-manifest.sha256`).

Re-runs are safe — the script verifies the manifest SHA256 on entry and
prompts before overwriting a prior successful setup.

A verify-only mode (no writes) is available:

```sh
ksh TN_CHROOT_SETUP.sh --verify
```

**Interactive:** Yes (idempotency re-run confirmation).

**Logs:** `logs/chroot-setup.log`

**Completion sentinel:** `~/chroot-setup`

---

## Logs

All logs are written to the `logs/` directory relative to the installer:

| Log file                               | Written by           |
|----------------------------------------|----------------------|
| `logs/network-setup.log`              | TN_NET_SET.sh        |
| `logs/substitute.log`                 | TN_SUBSTITUTE.sh     |
| `logs/pkg-install.log`                | TN_PKG_INSTALL.sh    |
| `logs/chroot-setup.log`               | TN_CHROOT_SETUP.sh   |
| `logs/utm_installer_<timestamp>.log`  | TN_UTM_INSTALLER.sh  |

The master log contains orchestration events only (stage transitions,
guard confirmations, abort reasons). Operational detail is in the
individual script logs.

---

## Resuming a Failed Installation

The master orchestrator has no checkpoint system of its own. On failure,
identify which stage failed from the master log, then re-run that script
directly:

```sh
ksh TN_NET_SET.sh       # re-prompts all 24 stages; prior status file
                              # is overwritten on completion
ksh TN_SUBSTITUTE.sh    # safe to re-run; re-expands all tokens
ksh TN_PKG_INSTALL.sh   # resumes from first incomplete phase via
                              # .install_phases checkpoint file
ksh TN_CHROOT_SETUP.sh  # idempotent; prompts before overwriting
                              # a prior successful run
```

To force `TN_PKG_INSTALL.sh` to restart from phase 0 rather than resuming,
delete the phase state file before re-running:

```sh
rm .install_phases
ksh TN_PKG_INSTALL.sh
```

---

## Topology Constraint

This installer supports the following topology:

- One WAN interface (ethernet, PPPoE, or wireless)
- One LAN segment — either a single physical interface, or a bridge
  combining two or more physical interfaces into one L2 domain
- Single machine (no clustering)

**Bridge LAN** is fully supported. During Stage 11, TN_NET_SET.sh prompts
`[A] Single Interface` or `[B] Bridge LAN`. Selecting B creates `bridge0`
(pure L2 forwarder, no IP) and `vether0` (LAN IP anchor). Physical members
are enslaved to the bridge with no IP assigned. All downstream services —
dhcpd, rad, unbound, pf diverts, pmacct — bind to `vether0`. The bridge
topology is recorded in `/etc/tn-interfaces` as:

```
INT_IF="vether0"
INT_BRIDGE_IF="bridge0"
INT_BRIDGE_MEMBERS="em1 athn0"
INT_IS_BRIDGE="1"
HAS_BRIDGE="1"
```

The following features are implemented in the scripts but not
production-ready and must not be enabled:

| Feature | Status |
|---------|--------|
| Multi-WAN (failover / load-balance / policy) | Dormant — gated for 8.0 |
| VLAN multi-tenancy | Dormant — gated for 8.0 |
| N+1 LAN scaling | Dormant — gated for 8.0 |
| CARP / HA (requires second physical node) | Dormant — gated for 8.0 |

---

## Credential Handling

Credentials entered during Stage 1 (PPPoE username/password, wireless
passphrases, CARP shared secret, oinkcode) are handled as follows:

- Read with terminal echo disabled via `_read_secret`, or sourced from the
  `oinkcode` file in the project root (oinkcode only)
- Written only to `/etc/hostname.<ifname>` (mode 640, root:wheel) for
  network credentials; patched into `payload/etc/oinkmaster.conf` for the
  oinkcode
- Never written to `/etc/tn-interfaces`, any log file, or any inventory
  file — the inventory stores the marker string `(stored in hostname file)`
  in place of actual network credential values
- Zeroed in memory immediately after each write via `_clear_secret`

The SSL CA private key and server private key generated in Stage 1 are
written to their standard paths under `/etc/ssl/` with mode 600.

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
modification, are permitted provided that the following conditions are met:

1. Redistribution of source code must retain the above copyright notice,
   this list of conditions, and the following disclaimer.
2. Redistribution in binary form must reproduce the above copyright notice,
   this list of conditions, and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
3. Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM, OUT OF
OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

*End of INSTALL.md*
