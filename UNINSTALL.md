<!--
SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks

SPDX-License-Identifier: BSD-3-Clause
-->

# TN_UTM_UNINSTALLER.sh — README

## Overview

`TN_UTM_UNINSTALLER.sh` removes the Tangent Networks UTM installation from
an OpenBSD machine in a controlled, step-by-step sequence. Every destructive
action pauses for explicit operator confirmation so you can inspect, backup,
or skip anything before it is removed or restored.

Each uninstall step is **sentinel-gated** — it only runs if the installer
script that owns it completed successfully. This makes the uninstaller safe
for partial installs and for installs where individual scripts were run
independently rather than via `TN_UTM_INSTALLER.sh`.

> NOTE: Run script as root.

---

## Sentinel Gates

Each install script writes a sentinel file on successful completion.
The uninstaller reads these before each step and skips any step whose
sentinel is absent:

| Sentinel | Written by | Gates |
|----------|-----------|-------|
| `/etc/tn-network-setup.status` | `TN_NET_SET.sh` | Step 7 (restore system files), Step 8 (SSL certs) |
| `/root/packages-setup` | `TN_PKG_INSTALL.sh` | Steps 1–5 (services, packages, sbin, webroot, authdb) |
| `~/chroot-setup` | `TN_CHROOT_SETUP.sh` | Step 6 (chroot removal) |

Steps 9 and 10 are not gated — always safe regardless of install state.

---

## net-backup/ Coverage

`net-backup/` is written by two scripts and covers all system files the
installer pipeline modifies:

**`TN_NET_SET.sh` backs up:**
```
/etc/myname          /etc/mygate          /etc/resolv.conf
/etc/rc              /etc/rc.conf.local   /etc/sysctl.conf
/etc/syslog.conf     /etc/newsyslog.conf  /etc/crontab
/etc/pf.conf         /etc/hostname.*      /etc/fstab
/etc/mail/smtpd.conf
```

**`TN_PKG_INSTALL.sh` backs up (if present before install):**
```
/etc/rc.local
```

Files absent from `net-backup/` were not present before the install.
The uninstaller truncates rather than restores those files — specifically
`/etc/rc.local` and `/etc/crontab` which are not present on all OpenBSD
systems by default.

---

## Before You Begin

>MFS NOTE:
   The UTM mounts two MFS volumes under the webroot at runtime:
     /var/www/htdocs/tn/data/logs/pf       (pf log buffer)
     /var/www/htdocs/tn/data/pipes/pmacct  (pmacct pipe)
   Step 7 unmounts these after restoring fstab. Step 10 catches
   any that survive. Active log mounts that cannot be force-unmounted
   are released automatically on reboot -- after rebooting run:
   ```sh
   rm -rf /var/www/htdocs/tn
   ```

### 2. You need net-backup/

`TN_NET_SET.sh` creates `net-backup/` in the installer directory on first
run. If it is missing, Step 7 is skipped and you must restore system config
files manually from your own backups or OpenBSD defaults.

### 3. Remove the TN CA certificate from your devices

The installer generates a local CA (`tn-ca.crt`) installed in `/etc/ssl/`.
If you distributed this to browsers or devices on your network for SSL
inspection trust, remove it from those devices before or immediately after
running the uninstaller. After the CA private key is deleted, any
certificate signed by it will produce trust errors.

### 4. Plan for a reboot

A reboot is required after uninstalling. The hostname.* and mygate files
restored in Step 7 do not take effect until the system restarts.

### 5. Run from the installer directory

The uninstaller must be run from the same directory that contains the
installer scripts, `net-backup/`, `chroot-manifest.txt`, and `rollback/`.

---

## Usage

```sh
ksh TN_UTM_UNINSTALLER.sh
```

Must be run as root.

---

## Confirmation Model

Each step presents:

```
  Proceed? [y/N/q]:
```

- **y** — proceed with this step
- **n** (or Enter) — skip this step, continue to the next
- **q** — quit immediately, no further steps executed

Before any step runs, type `CONFIRM` at the master prompt. Anything other
than the exact word `CONFIRM` aborts cleanly. Skipped steps are logged.
Re-run the uninstaller and answer `n` to already-completed steps.

---

## Installation Status Summary

Before asking for `CONFIRM`, the uninstaller prints what completed and
what will be skipped, for example:

```
[OK]    TN_NET_SET.sh:      complete  (/etc/tn-network-setup.status)
[OK]    TN_PKG_INSTALL.sh:  complete  (/root/packages-setup)
[WARN]  TN_CHROOT_SETUP.sh: sentinel not found -- Step 6 will be skipped
        If mfs was used, unmount manually first.
[OK]    net-backup/:          present
[WARN]  chroot-manifest.txt:  not found -- Step 6 removal skipped
[OK]    sbin-manifest.txt:    present
```

---

## Install Date Resolution

Resolved in order:

1. `TN_INSTALL_DATE` stamped into script by `TN_UTM_INSTALLER.sh`
2. `/etc/tn-install-date` written by `TN_CHROOT_SETUP.sh`
3. Date extracted from first line of `/etc/tn-network-setup.status`
4. Falls back to `unknown`

Used for informational purposes only. All steps are sentinel-gated.

---

## What Each Step Does

### Step 1 — Stop and Disable Services
*Gated by: `/root/packages-setup`*

Stops and disables all UTM services via `rcctl`. Local services stopped
before base services. `cron` and `syslogd` stopped last.

### Step 2 — Remove Packages
*Gated by: `/root/packages-setup`*

Removes all packages installed by `TN_PKG_INSTALL.sh` via `pkg_delete -f`.
Custom packages removed first. Only actually-installed packages are acted on.

### Step 3 — Remove /usr/local/sbin Files
*Gated by: `/root/packages-setup` and `rollback/sbin-manifest.txt`*

Removes UTM binaries from `/usr/local/sbin/` per the sbin manifest.
Only listed files removed.

### Step 4 — Remove Webroot
*Gated by: `/root/packages-setup`*

Removes `/var/www/htdocs/tn/` entirely. Wholly our creation.

### Step 5 — Remove AuthDB and Session Keys
*Gated by: `/root/packages-setup`*

Removes `auth.db`, `session.key`, and `hmac.key`. Wholly our creation.

### Step 6 — Remove Chroot Additions
*Gated by: `~/chroot-setup` and `chroot-manifest.txt`*

### Step 7 — Restore System Config Files
*Gated by: `/etc/tn-network-setup.status` or `/root/packages-setup`*

Restores original system files from `net-backup/`:

- Files present in `net-backup/` are restored to `/etc/` verbatim
- `/etc/rc.local` absent from `net-backup/` → truncated (did not exist before install)
- `/etc/crontab` absent from `net-backup/` → truncated (did not exist before install)

**A reboot is required after this step.**

### Step 8 — Remove SSL Certificates and CA
*Gated by: `/etc/tn-network-setup.status`*

Removes `tn-ca.crt`, `tn-ca.serial`, and the server cert/key. `CERT_CN`
read from `/etc/tn-interfaces` while it still exists — runs before Step 9.

### Step 9 — Remove Sentinels and Inventory Files
*Not gated*

Removes all installer state files including `/etc/tn-interfaces`,
`/etc/tn-install-date`, `/root/packages-setup`, `~/chroot-setup`,
`/etc/tn-network-setup.status`, and `.install_phases`.

### Step 10 — Remove Installer Logs and Rollback Directory
*Not gated — optional*

Removes `logs/` and `rollback/` including the uninstall log itself.
Copy the log elsewhere before confirming if you need a permanent record.

---

## What the Uninstaller Does Not Do

- **Does not reboot.** Reboot manually after completion.
- **Does not remove the installer directory** itself.
- **Does not remove OpenBSD base packages** or system users from `pkg_add`.
- **Does not touch `/var/www/` base chroot** outside `chroot-manifest.txt`.

---

## Resuming a Partial Uninstall

Re-run the script. Steps whose targets are already absent skip cleanly.
Answer `n` to steps you know are already done.

---

## After Uninstall

1. **Reboot** the machine.
2. Verify network connectivity from the pre-install config.
3. Remove `tn-ca.crt` from browsers and devices on your network.
4. Remove the installer directory when satisfied:
   ```sh
   rm -rf /path/to/installer/
   ```
**Post-Reboot Cleanup**

If the uninstaller reported that `/var/www/htdocs/tn` could not be fully removed due to an active MFS log mount (`data/logs/pf`), this is expected. The MFS mount is released automatically when the system shuts down.

After the mandatory reboot, verify the mount is gone:

```sh
mount | grep mfs
```

If nothing is returned, remove the remaining webroot:

```sh
rm -rf /var/www/htdocs/tn
```

If an MFS mount is still listed after reboot, it means an entry in `/etc/rc.local` or `/etc/fstab` is remounting it at boot. Check both:

```sh
grep -i mfs /etc/fstab
grep -i mfs /etc/rc.local
```

Remove any TN-related MFS entries found there, then reboot once more and retry the removal.

---

## Logs

```
<installer_dir>/logs/uninstall_<YYYYMMDD_HHMMSS>.log
```

Every action, confirmation, skip, and warning is recorded. Copy before
confirming Step 10 if you need a permanent record.

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

**End of TNWAF.md**
