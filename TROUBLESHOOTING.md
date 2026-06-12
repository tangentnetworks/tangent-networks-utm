<!--
SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks

SPDX-License-Identifier: BSD-3-Clause
-->

# Tangent Networks UTM -- Troubleshooting Guide

> **Interface names, IP addresses, and paths in this guide use the reference
> configuration.** Your deployment will have different values set by
> `TN_UTM_INSTALL.sh` at install time. Substitute your actual values where
> needed -- check `/etc/tn-interfaces` for your interface names and addresses.

---

## Before You Start

> NOTE: Run scripts as root.

Every troubleshooting session should begin with two checks:

```sh
# Are services running?
rcctl check httpd slowcgi unbound sslproxy e2guardian snort sockd

# Are there recent errors?
tail -40 /var/www/htdocs/tn/data/logs/waf/error.log
```

If you are not sure where to start, use the **System Discovery** tool first —
it gives you a complete picture of the live system in one run:

```sh
ksh ${HOME}/UTM/TN_DISCOVERY.sh
```

The report is written to `/tmp/tn_system_discovery_<timestamp>.txt`. Open it
and read the interface section and the package ownership section before doing
anything else.

---

## Tool Reference

| Script | Purpose | Run as |
|---|---|---|
| `TN_DISCOVERY.sh` | Full system scan -- files, interfaces, packages, recommendations | root |
| `TN_RECON.sh` | Network topology discovery -- writes `/etc/tn-tokens` | root |
| `TN_WEBUI_ASSETS_INVENTORY.pl` | Web UI asset audit -- JS, CSS, CGI health check | root |
| `TN_PERL_TRACER.pl` | CGI module dependency tracer -- chroot completeness | root |
| `TN_TEST_CHROOT.pl` | Chroot vitality audit -- devices, binaries, Perl modules | root |
| `TN_GENERATE_SRI.pl` | SRI hash generator and verifier for TNWAF | root |
| `TN_GET_SRI.sh` + `TN_UPDATE_SRI.sh` | Generate and apply SRI hashes to HTML/view files | root |

---

## Symptom Index

- [Web interface won't load -- blank page or connection refused](#web-interface-wont-load)
- [Web interface loads but shows errors or broken layout](#web-interface-loads-but-broken)
- [Can't log in -- authentication fails](#cant-log-in)
- [LAN clients can't reach the internet](#lan-clients-cant-reach-the-internet)
- [Specific protocol not working (email, FTP, IM)](#specific-protocol-not-working)
- [HTTPS inspection not working -- SSL errors on client](#https-inspection-not-working)
- [DNS not resolving](#dns-not-resolving)
- [Snort blocking legitimate traffic](#snort-blocking-legitimate-traffic)
- [SRI errors in browser console](#sri-errors-in-browser-console)
- [After install -- services won't start](#after-install--services-wont-start)
- [After tokenisation -- wrong addresses in config](#after-tokenisation--wrong-addresses-in-config)
- [Chroot missing modules or devices](#chroot-missing-modules-or-devices)

---

## Web interface won't load

**Symptom:** Browser shows connection refused, timeout, or blank page at
`https://172.16.15.1/`.

**Step 1 -- Check httpd and slowcgi:**
```sh
rcctl check httpd
rcctl check slowcgi
# If not running:
rcctl start httpd
rcctl start slowcgi
```

**Step 2 -- Check httpd error log:**
```sh
tail -50 /var/www/htdocs/tn/data/logs/httpd/httpd_error.log
```

**Step 3 -- Check pf is not blocking the request:**
```sh
# Watch live -- connect from a LAN client while this runs
tcpdump -n -i em1 port 80 or port 443
```
If you see packets arriving but no response, pf is likely blocking. Check:
```sh
pfctl -sr | grep '443\|80'
```

**Step 4 -- Verify router.pl is present and executable:**
```sh
ls -la /var/www/htdocs/tn/cgi-bin/router.pl
```
If missing, the TNWAF has no entry point -- the web UI will not work at all.
Redeploy the payload.

**Step 5 -- Run the asset inventory:**
```sh
perl ${HOME}/UTM/TN_WEBUI_ASSETS_INVENTORY.pl
```
Look for `router.pl : *** MISSING FROM DISK ***` or orphaned CGI scripts.

---

## Web interface loads but broken

**Symptom:** Page loads but layout is wrong, JavaScript errors in browser
console, or features return errors.

**Step 1 -- Check for SRI failures:**

Open browser developer tools → Console. If you see errors like:
```
Failed to find a valid digest in the 'integrity' attribute for resource
```
the SRI hashes in the HTML do not match the files on disk. See
[SRI errors in browser console](#sri-errors-in-browser-console).

**Step 2 -- Check WAF is serving assets:**
```sh
tail -30 /var/www/htdocs/tn/data/logs/waf/access.log
tail -30 /var/www/htdocs/tn/data/logs/waf/security.log
```
Look for `BLOCKED` or `SRI_TAMPER` entries.

**Step 3 -- Run asset inventory:**
```sh
perl ${HOME}/UTM/TN_WEBUI_ASSETS_INVENTORY.pl
```
The report shows which JS and CSS files are loaded versus present on disk.
A JS file on disk but never loaded, or loaded but missing from disk, will
cause silent feature failures.

**Step 4 -- Check devel.js:**

The inventory report shows whether `devel.js` is present and whether any page
loads it. In production, `devel.js` should either be absent or present but not
loaded. If a page is loading `devel.js` unexpectedly, that page will behave
differently from the rest of the UI.

---

## Can't log in

**Symptom:** Login page appears but credentials are rejected, or session
expires immediately.

**Step 1 -- Verify the auth database exists and is non-empty:**
```sh
ls -lh /var/www/htdocs/tn/data/db/auth.db
sqlite3 /var/www/htdocs/tn/data/db/auth.db "SELECT username, role FROM users;"
```
If the database is missing or empty, run `create_first_user.pl` to
initialise it:
```sh
perl -T /var/www/htdocs/tn/data/scripts/create_first_user.pl \
    --schema /var/www/htdocs/tn/data/db/auth.sql
```

**Step 2 -- Check database ownership:**
```sh
ls -la /var/www/htdocs/tn/data/db/auth.db
```
Must be `www:www 0600`. If wrong:
```sh
chown www:www /var/www/htdocs/tn/data/db/auth.db
chmod 0600 /var/www/htdocs/tn/data/db/auth.db
```

**Step 3 -- Check session key exists:**
```sh
ls -la /var/www/htdocs/tn/data/keys/
```
`session.key` and `hmac.key` must be present. If missing, sessions cannot
be signed and every login will fail immediately.

**Step 4 -- Check security.conf:**
```sh
cat /var/www/htdocs/tn/data/config/security.conf
```
If the `[mode]` section is missing or the file is unreadable, TNConfig fails
closed: all security features are forced on and DEVEL mode is disabled.
The CGI error log will show `TNConfig CRITICAL:` entries if this is happening.

---

## LAN clients can't reach the internet

**Symptom:** Devices on `172.16.15.0/24` or `fdac:1005::/64` cannot browse
or reach external addresses.

**Step 1 -- Verify the gateway itself has internet access:**
```sh
ping -c 3 1.1.1.1
ping6 -c 3 2606:4700:4700::1111
```
If the gateway cannot reach the internet, the problem is upstream -- check
your WAN interface, default route, and ISP connection before investigating
further.

**Step 2 -- Check NAT is active:**
```sh
pfctl -sn
```
You should see `match out on em0 inet from 172.16.15.0/24 nat-to (em0)`.
If NAT rules are absent, pf may not have loaded the new ruleset. Load it:
```sh
pfctl -f /etc/pf.conf
```

**Step 3 -- Check the inspection chain is running:**
```sh
rcctl check sslproxy e2guardian
```
HTTP/HTTPS traffic is diverted through SSLproxy before it reaches the WAN.
If SSLproxy is down, all web traffic from LAN clients will fail silently
because pf diverts it but nothing picks it up.

**Step 4 -- Watch traffic from a LAN client:**
```sh
# On the gateway, watch for the client's IP
tcpdump -n -i em1 host 172.16.15.x
```
If you see packets from the client arriving but nothing going out on em0,
the inspection chain or NAT is broken.

**Step 5 -- Check DNS:**
```sh
rcctl check unbound
dig @172.16.15.1 google.com
```
If Unbound is down, clients get no DNS and nothing will load even if routing
is correct. See [DNS not resolving](#dns-not-resolving).

---

## Specific protocol not working

### Email (POP3, POP3S, IMAPS, SMTP, SMTPS, SUBMISSION)

All mail protocols are transparently diverted through SSLproxy then to p3scan
(incoming) or smtp-gated (outgoing). If a mail client is failing:

```sh
rcctl check sslproxy p3scan smtp-gated
tail -30 /var/www/htdocs/tn/data/logs/sslproxy/sslproxy_connect.log
tail -30 /var/www/htdocs/tn/data/logs/p3scan/p3scan.log
```

Check the divert rules are present:
```sh
pfctl -sr | grep 'port = 993\|port = 995\|port = 110\|port = 25'
```

### FTP

ftp-proxy handles FTP. Check its anchor is loaded:
```sh
pfctl -sr | grep ftp-proxy
pfctl -a ftp-proxy -sr
```

If the anchor is empty, ftp-proxy is not running or did not register:
```sh
rcctl check ftpproxy
```

### IM and IRC (ports 1863, 5190, 5050, 6667)

IM traffic is diverted to imspector on IPv4 only. IPv6 IM passes uninspected
by design -- imspector has no IPv6 socket. If IPv4 IM is failing:

```sh
rcctl check imspector
tail -20 /var/www/htdocs/tn/data/logs/imspector/imspector.log
```

---

## HTTPS inspection not working

**Symptom:** Clients get SSL certificate errors, or TLS connections to HTTPS
sites fail entirely.

HTTPS inspection requires clients to trust the SSLproxy CA certificate. Without
this, every HTTPS connection will show a certificate warning.

**Step 1 -- Verify the CA certificate exists:**
```sh
ls -la /usr/local/etc/sslproxy/ca.crt
ls -la /usr/local/etc/sslproxy/ca.key   # must be 600 root:wheel
```

**Step 2 -- Distribute the CA certificate to clients:**

The CA certificate must be installed as a trusted root authority on every
client device. Export it:
```sh
cat /usr/local/etc/sslproxy/ca.crt
```

Install on clients:
- **Windows:** `certmgr.msc` → Trusted Root Certification Authorities → Import
- **macOS:** Keychain Access → System → import, set to Always Trust
- **Linux:** copy to `/usr/local/share/ca-certificates/` and run
  `update-ca-certificates`
- **Firefox:** Preferences → Privacy → Certificates → Import
- **Android/iOS:** install via MDM or device settings

**Step 3 -- Check SSLproxy listeners:**
```sh
rcctl check sslproxy
# Verify listeners are bound
netstat -an | grep '8081\|8443\|8993\|8994\|8995'
```

---

## DNS not resolving

**Symptom:** `nslookup` or `dig` from LAN clients times out or returns
`SERVFAIL`.

**Step 1:**
```sh
rcctl check unbound
# Test from the gateway itself
dig @127.0.0.1 google.com
dig @::1 google.com
```

**Step 2 -- Check Unbound config:**
```sh
unbound-checkconf /var/unbound/etc/unbound.conf
```

**Step 3 -- Check pf allows DNS from LAN:**
```sh
pfctl -sr | grep 'port = 53'
```
You should see rules allowing `172.16.15.0/24` and `fdac:1005::/64` to query
`(em1)` on port 53.

**Step 4 -- DNS64 (for IPv6-only clients reaching IPv4 destinations):**
```sh
# Test DNS64 synthesis
dig @::1 AAAA ipv4only.arpa
```
Should return a `64:ff9b::/96` address. If not, check Unbound's `dns64` module
is enabled in `unbound.conf`.

---

## Snort blocking legitimate traffic

**Symptom:** Specific sites or services are intermittently blocked; Snort log
shows false positives.

```sh
tail -50 /var/www/htdocs/tn/data/logs/snort/snort.log
# Check what is in the block table
pfctl -t snort_block -T show
```

To temporarily flush a specific IP from the block table:
```sh
pfctl -t snort_block -T delete <IP_ADDRESS>
```

To flush all Snort blocks (emergency use only):
```sh
pfctl -t snort_block -T flush
```

Check whether a rule is triggering incorrectly -- note the SID from the Snort
log and suppress it in `snort.conf` if it is a confirmed false positive:
```
suppress gen_id 1, sig_id <SID>
```

---

## SRI errors in browser console

**Symptom:** Browser console shows `integrity` attribute mismatch errors.
Pages load partially or JavaScript features stop working.

This happens when the SRI hashes in the HTML/view files do not match the
actual JS files on disk -- either because JS files were updated without
regenerating hashes, or because `TN_TOKENIZE.sh` / `TN_SUBSTITUTE.sh` ran
and changed file content.

**Step 1 -- Verify which hashes are wrong:**
```sh
perl ${HOME}/UTM/TN_GENERATE_SRI.pl --verify
```
This compares every entry in `TNWAF.pm` against the current files on disk.
`TAMPERED` means the file changed. `MISSING` means the file was removed.

**Step 2 -- Regenerate and apply:**
```sh
# Recompute hashes from current JS files on disk
perl ${HOME}/UTM/TN_GENERATE_SRI.pl > /tmp/new_sri.txt
cat /tmp/new_sri.txt   # review before applying

# Update integrity= attributes in all HTML and view files
sh ${HOME}/UTM/TN_GET_SRI.sh /var/www/htdocs/tn/assets/js
sh ${HOME}/UTM/TN_UPDATE_SRI.sh

# Update TNWAF.pm sri_hashes block with the output from TN_GENERATE_SRI.pl
# Paste the sri_hashes => { ... } block into TNWAF.pm replacing the old one
```

**Step 3 -- After tokenisation:**

If `TN_SUBSTITUTE.sh` ran and modified JS files, all SRI hashes are
invalidated. Always run the SRI update pipeline after tokenisation:
```sh
perl ${HOME}/UTM/TN_GENERATE_SRI.pl > /tmp/sri.txt
sh ${HOME}/UTM/TN_GET_SRI.sh /var/www/htdocs/tn/assets/js
sh ${HOME}/UTM/TN_UPDATE_SRI.sh
# Then update TNWAF.pm sri_hashes manually with output from TN_GENERATE_SRI.pl
```

The correct order after any JS or view file change is always:
1. Make your changes to JS files
2. `TN_GET_SRI.sh` -- compute new hashes
3. `TN_UPDATE_SRI.sh` -- apply to HTML and view files
4. `TN_GENERATE_SRI.pl` -- generate new TNWAF.pm block
5. Paste new `sri_hashes` block into `TNWAF.pm`
6. `TN_GENERATE_SRI.pl --verify` -- confirm everything matches

---

## After install -- services won't start

**Symptom:** `TN_PKG_INSTALL.sh` completed but one or more services fail to
start, or the smoke tests in Phase 14 show failures.

**Step 1 -- Check rc.d status:**
```sh
rcctl check sslproxy e2guardian snort sockd p3scan smtp-gated imspector
```

**Step 2 -- Check individual daemon logs:**
```sh
tail -30 /var/www/htdocs/tn/data/logs/sslproxy/sslproxy_connect.log
tail -30 /var/www/htdocs/tn/data/logs/e2guardian/e2guardian.log
tail -30 /var/www/htdocs/tn/data/logs/snort/snort.log
```

**Step 3 -- Check file ownership:**
```sh
# Run/socket directories must be owned by the correct daemon user
ls -la /var/www/htdocs/tn/data/run/
```
If ownership is wrong the daemon will start but immediately fail to create
its socket or PID file.

**Step 4 -- Check for stale PID files from a previous run:**
```sh
find /var/www/htdocs/tn/data/run -name '*.pid' | xargs ls -la
# Remove stale PIDs if the process is not running
```

**Step 5 -- Check pf syntax before loading:**
```sh
pfctl -nf /etc/pf.conf
```
If syntax errors are present, pf will refuse to load and all transparent
divert will be missing -- services will start but nothing will flow through them.

---

## After tokenisation -- wrong addresses in config

**Symptom:** After running `TN_SUBSTITUTE.sh`, config files contain wrong
addresses, old lab addresses, or unfilled `%%TOKEN%%` placeholders.

**Step 1 -- Check `/etc/tn-interfaces` is correct:**
```sh
cat /etc/tn-interfaces
```
This file is the source of truth for `TN_SUBSTITUTE.sh`. If it contains wrong
values, run `TN_NET_SET.sh` again to regenerate it from the live system.

**Step 2 -- Search for unfilled tokens:**
```sh
grep -r '%%' /var/www/htdocs/tn/ /etc/pf.conf /var/unbound/etc/ \
    /usr/local/etc/sslproxy/ /usr/local/etc/e2guardian/ 2>/dev/null
```
Any `%%TOKEN%%` that remains was either not in `/etc/tn-interfaces` or the
substitution did not reach that file. Add the missing value to
`/etc/tn-interfaces` and re-run `TN_SUBSTITUTE.sh`.

**Step 3 -- Check for old lab addresses:**
```sh
# Replace with your lab subnet if different
grep -r '10\.10\.10\.' /etc/pf.conf /var/unbound/etc/ \
    /usr/local/etc/ 2>/dev/null
```

**Step 4 -- Run recon to verify the token map is complete:**
```sh
ksh ${HOME}/UTM/TN_RECON.sh --dry-run
```
The dry-run prints what would be written to `/etc/tn-tokens` without touching
the file. Review it for empty values -- any empty token that should have a value
indicates a detection failure that needs investigation.

---

## Chroot missing modules or devices

**Symptom:** CGI scripts return 500 errors, Perl modules cannot be found, or
`/dev/urandom` is not accessible inside the chroot.

**Step 1 -- Run the chroot audit:**
```sh
perl ${HOME}/UTM/TN_TEST_CHROOT.pl
```
This checks:
- `/dev/urandom`, `/dev/random`, `/dev/null` inside `/var/www/dev/`
- Executables present in `/var/www/bin/`
- `libsqlite3.so` present in `/var/www/usr/local/lib/`
- All Perl modules required by TN CGI scripts are present under the chroot

Look for `MISSING` or `WRECKAGE DETECTED` in the output.

**Step 2 -- Run the module dependency tracer:**
```sh
perl ${HOME}/UTM/TN_PERL_TRACER.pl
```
This walks all CGI scripts and TN library modules, resolves every `use`
statement, traces transitive dependencies, and writes:
- `tn_perl_modules.txt` -- full list of `.pm` and `.so` files needed
- `tn_perl_allowlist.txt` -- top-level module names for `TN_CHROOT_SETUP.sh`

If the tracer reports modules that cannot be resolved, those modules need to
be installed via `pkg_add` before the chroot can be rebuilt.

**Step 3 -- Rebuild the chroot after adding missing modules:**

After installing any missing packages, re-run `TN_CHROOT_SETUP.sh` to copy
the new module files into the chroot. Then re-run `TN_TEST_CHROOT.pl` to
confirm.

**Common missing items:**

| Symptom | Likely cause |
|---|---|
| `DBD::SQLite` not found | `p5-DBD-SQLite` not installed |
| `JSON` not found | `p5-JSON` not installed |
| `CGI` not found | `p5-CGI` not installed |
| `/dev/urandom` missing in chroot | `TN_CHROOT_SETUP.sh` not run or failed |
| `libsqlite3.so` missing | SQLite shared lib not copied to chroot |

---

## Getting further help

If you have worked through the relevant section above and the problem persists,
collect the following before asking for help -- it avoids back-and-forth:

```sh
# System discovery report
ksh ${HOME}/UTM/TN_DISCOVERY.sh
# Asset inventory
perl ${HOME}/UTM/TN_WEBUI_ASSETS_INVENTORY.pl
# Chroot audit
perl ${HOME}/UTM/TN_TEST_CHROOT.pl
# Relevant log tail (adjust for the failing component)
tail -100 /var/www/htdocs/tn/data/logs/waf/error.log
tail -100 /var/www/htdocs/tn/data/logs/httpd/httpd_error.log
# pf ruleset
pfctl -sr
# Service status
rcctl check httpd slowcgi unbound sslproxy e2guardian snort sockd \
    p3scan smtp-gated imspector ftpproxy
```

Contact: **tangent.net@zohomail.in** -- include the output of the above commands.

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

1. Redistribution of source code must retain the above copyright
   notice, this list of conditions, and the following disclaimer.

2. Redistribution in binary form must reproduce the above copyright
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

**End of TROUBLESHOOTING.md**
