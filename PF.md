<!--
SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks

SPDX-License-Identifier: BSD-3-Clause
-->

# Tangent Networks UTM -- pf Ruleset Reference

> **Interface names used throughout this document (`em0`, `em1`) are illustrative only.**
> The actual interface names on your hardware are set at install time by `TN_UTM_INSTALL.sh`,
> which rewrites all pf rules, daemon configs, and related artifacts to match the detected
> hardware. Never edit interface names manually post-install.

---

## Interface Roles

| Symbolic Role | pf variable | Reference name | Faces |
|---|---|---|---|
| WAN | `$ext_if` | `em0` | Upstream / internet |
| LAN (single) | `$int_if` | `em1` | Internal network |
| LAN (bridge anchor) | `$int_if` | `vether0` | Internal network — holds LAN IP in bridge mode |
| Bridge forwarder | — | `bridge0` | L2 only — no IP, not referenced in pf rules |
| Bridge members | — | `em1`, `athn0` | Enslaved to bridge0 — no IP |

In bridge mode `$int_if` resolves to `vether0`. All pf rules, divert sockets,
dhcpd, rad, and unbound bind to `vether0`. `bridge0` and its physical members
are invisible to the ruleset — traffic arrives on `vether0` after L2 forwarding.

---

## Network Topology

| Segment | IPv4 | IPv6 |
|---|---|---|
| LAN clients | `172.16.15.0/24` | `fdac:1005::/64` |
| Gateway LAN address | `172.16.15.1` | `fdac:100f::1` |
| NAT64 prefix | -- | `64:ff9b::/96` |
| Dante IPv6 listener | -- | `fd0a:0005::1:1080` |

---

## Architecture Overview

Tangent Networks UTM is a full dual-stack transparent inspection gateway. Every protocol
listed in the proxy coverage table below is intercepted at the firewall level —
LAN clients require no manual proxy configuration for inspected traffic.

The inspection chain for a typical HTTPS flow looks like this:

```
LAN client (IPv4 or IPv6)
    |
    | PF divert-to lo port 8443  [transparent, client unaware]
    v
SSLproxy  --  TLS decryption, re-originates as IPv4 on loopback
    |
    | forwards decrypted stream to lo:8080 (e2guardian)
    v
PF divert-packet port 700  --  Snort IPS intercepts before daemon receives
    v
Snort IPS  --  deep packet inspection, rejects or reinjects
    |
    v
e2guardian  --  content filtering
    |
    v
NAT / WAN egress
```

SSLproxy acts as the IPv6/IPv4 protocol boundary. IPv6 LAN flows are diverted to
SSLproxy's `::1` listeners. SSLproxy decrypts and re-originates traffic as IPv4 on
loopback, so all downstream daemons (p3scan, smtp-gated, e2guardian, Snort) see only
IPv4 loopback connections regardless of the client's address family.

---

## Proxy Inspection Coverage

| Protocol | Port | IPv4 | IPv6 | Inspection chain |
|---|---|---|---|---|
| HTTP | 80 | SSLproxy | SSLproxy | SSLproxy → e2guardian → Snort |
| HTTPS | 443 | SSLproxy | SSLproxy | SSLproxy → e2guardian → Snort |
| POP3 | 110 | SSLproxy | SSLproxy | SSLproxy → p3scan → Snort |
| POP3S | 995 | SSLproxy | SSLproxy | SSLproxy (decrypt) → p3scan → Snort |
| IMAP/S | 993 | SSLproxy | SSLproxy | SSLproxy (decrypt) → p3scan → Snort |
| SMTP | 25 | SSLproxy | SSLproxy | SSLproxy → smtp-gated → Snort |
| SMTPS | 465 | SSLproxy | SSLproxy | SSLproxy (decrypt) → smtp-gated → Snort |
| SUBMISSION | 587 | SSLproxy | SSLproxy | SSLproxy (autossl) → smtp-gated → Snort |
| FTP | 21 | ftp-proxy | ftp-proxy | Dual-stack via divert-to lo |
| IM/IRC | 1863, 5190, 5050, 6667 | imspector | -- | IPv4 only -- see note below |
| SOCKS | 1080 | Dante | Dante | Client-explicit -- see below |
| DNS | 53 | Unbound | Unbound | Dual-stack, DNS64 for NAT64 |
| SSH | 22 | direct | direct | Management only, LAN-restricted |

**IM/IRC IPv6 note:** imspector has no IPv6 socket. IPv6 IM traffic passes
uninspected by explicit pf rule -- this is a known daemon limitation, not a ruleset
oversight. If your policy requires IM blocking on IPv6, add a `block` rule for
`$im_ports` on `inet6` at section `[R]` in `pf.conf`.

---

## What the Ruleset Does

### Default Posture

All traffic on both interfaces is blocked and returned by default -- TCP RST for TCP,
ICMP unreachable for UDP. Every permitted flow is an explicit exception. All traffic
on both real interfaces is logged to `pflog1`. Loopback is not logged -- proxy relay
traffic between daemons has no security value and would generate enormous volume.

### Loopback and Snort IPS

Loopback is intentionally not skipped (`set skip on lo` is absent). PF must see
loopback traffic so the Snort IPS `divert-packet` rule fires on proxy-re-originated
flows. After SSLproxy decrypts and forwards a stream to a downstream daemon port,
PF intercepts it on loopback and sends it to Snort's ipfw DAQ on port 700. Snort
inspects the plaintext and reinjects clean traffic. Without loopback visibility the
entire inspection chain is bypassed.

The three loopback interception points are:

| Loopback port | Daemon | Traffic |
|---|---|---|
| 8080 | e2guardian | Decrypted HTTP / HTTPS |
| 8110 | p3scan | Decrypted POP3 / POP3S / IMAPS |
| 9199 | smtp-gated | Decrypted SMTP / SMTPS / SUBMISSION |

### Antispoofing

Packets claiming loopback sources (`127.0.0.0/8`, `::1`) on any real interface are
silently dropped. LAN-side antispoofing blocks packets on `em1` whose source address
falls outside the legitimate LAN subnets, preventing compromised hosts from forging
source addresses to bypass source-based rules. NDP link-local traffic (`fe80::/10`)
is exempted before these blocks fire.

Teredo (UDP 3544) and 6to4 (protocol 41) are blocked on WAN ingress -- both create
unmonitored IPv6 tunnels that bypass the inspection chain entirely.

### Bogon and Blocklist Filtering

Three tables gate traffic before any pass rule is reached:

- `<bogons>` -- unroutable and reserved address space, populated at boot.
- `<blocklist>` -- dynamically populated by SSH brute-force overload rules.
- `<snort_block>` -- populated at runtime by Snort IPS for active threats.

All three use `block drop` -- silent discard with no RST or ICMP response to
known-bad sources.

### NAT44, NAT66, NAT64

NAT44 masquerades LAN IPv4 clients behind the current WAN IPv4 address. The
`($ext_if)` syntax resolves the address at translation time, so DHCP address
changes are handled without reloading rules.

NAT66 masquerades LAN ULA clients (`fdac:1005::/64`) behind the WAN IPv6 GUA.
This is a fallback for ISPs that do not delegate a DHCPv6-PD prefix. When a prefix
delegation is available, assign it to `em1`, advertise via `rad(8)`, and remove the
NAT66 `match` rule -- native routing is always preferred.

NAT64 allows IPv6-only LAN clients to reach IPv4-only internet destinations.
Unbound DNS64 synthesises `AAAA` records under `64:ff9b::/96` for IPv4-only names.
The client sends IPv6 to `64:ff9b::x.x.x.x` and PF translates it to IPv4 via
`af-to inet`, then NAT44 masquerades the outbound packet.

### SOCKS Proxy -- Dante (port 1080)

Dante listens on `172.16.15.1:1080` (IPv4) and `fd0a:0005::1:1080` (IPv6). Port
1080 is **not** transparently intercepted -- clients must explicitly configure their
application or operating system to use it. Traffic exiting via Dante bypasses the
SSLproxy inspection chain and exits directly through NAT.

IPv6 clients addressing Dante via its NAT64 representation (`64:ff9b::a0a:a01:1080`)
are intercepted before the NAT64 `af-to` rule fires and diverted directly to Dante's
IPv6 listener, keeping the connection IPv6 end-to-end.

### SSH Access

SSH (port 22) is accepted on both interfaces with connection-rate limiting per source:

- Maximum 10 simultaneous connections.
- Maximum 5 new connections per 30 seconds.
- Sources exceeding either limit are added to `<blocklist>` and all existing states
  from that source are flushed globally.

### DNS

LAN clients may only query the local Unbound resolver on port 53. Direct DNS to
external resolvers is not permitted -- all DNS exits via Unbound, which also provides
DNS64 synthesis for NAT64. The gateway's own processes query Unbound on loopback.

### DHCP / DHCPv6

DHCPv4 (UDP 67/68) is accepted from LAN clients. DHCPv6 (UDP 546/547) is handled on
both interfaces using link-local addresses per RFC 8415. The gateway acts as a
DHCPv6 client on WAN (`dhcp6leased`) requesting prefix delegation, and `rad(8)`
responds to DHCPv6 solicitations from LAN clients.

### ICMPv4

Echo requests, unreachables, and time-exceeded are accepted inbound. All ICMP is
permitted outbound.

### ICMPv6 (RFC 4890)

Path MTU (Too Big, type 2) is passed stateless and quick on all interfaces -- it
must never be filtered. Error messages (unreachable, time-exceeded, parameter-problem)
are passed stateful. NDP and MLD are handled correctly on both interfaces. WAN
inbound echo is restricted to monitor sources only; LAN echo is fully permitted.

MSS clamping is applied on ingress: 1412 bytes for IPv6, 1432 bytes for IPv4. Values
are determined at boot by `tn-mtu-probe.sh` and written to `/etc/tn-interfaces`.
IPv4 DF bits are cleared and IP IDs randomised on ingress to prevent PMTUD blackholes
and OS fingerprinting.

### Daemon Isolation

Proxy daemons receive traffic exclusively via PF divert -- they cannot accept direct
connections from LAN or WAN:

| Daemon | Restriction |
|---|---|
| `_e2guardian`, `_p3scan`, `_smtp-gated` | `block drop on any` -- no direct connections, both families |
| `_sockd` (Dante) | `block drop in on any` -- inbound only via SOCKS listener rules |
| `_snort` | `block drop out on any` -- listens only, no outbound |
| `_pbuild` | `block return out` -- ports build user, no internet access |

### Firebase Cloud Messaging

Ports 5228–5230 are permitted outbound from LAN without interception, used by Android
devices and other clients for Google push notifications.

### Addons Anchor

`anchor "addons"` accepts dynamically loaded rules without modifying the base ruleset.

```sh
# Load:  pfctl -a addons -f /etc/pf/pf-addons.conf
# Flush: pfctl -a addons -F all
# Show:  pfctl -a addons -sr
```

---

## Using the Dante SOCKS5 Proxy

Dante listens on **`172.16.15.1:1080`** (IPv4) and **`fd0a:0005::1:1080`** (IPv6).
Traffic routed through it exits the gateway directly, bypassing the transparent
SSLproxy inspection chain. This is opt-in -- the firewall does not redirect any
traffic to Dante automatically.

> **Note:** Dante access is restricted to LAN clients. Authentication requirements
> depend on `danted.conf` -- check with your administrator.

---

### Option 1 -- Environment Variables

Most Unix/Linux/macOS tools (`curl`, `wget`, many language runtimes) honour these
variables. Set them in your shell profile or export per-command.

**SOCKS5:**
```sh
export ALL_PROXY=socks5://172.16.15.1:1080
export all_proxy=socks5://172.16.15.1:1080   # some tools check lowercase
```

**HTTP/HTTPS via SOCKS (for tools that only understand http_proxy):**
```sh
export http_proxy=http://172.16.15.1:1080
export https_proxy=http://172.16.15.1:1080
export HTTP_PROXY=http://172.16.15.1:1080
export HTTPS_PROXY=http://172.16.15.1:1080
```

**Restore normal (inspected) routing:**
```sh
unset ALL_PROXY all_proxy http_proxy https_proxy HTTP_PROXY HTTPS_PROXY
```

**Per-command:**
```sh
ALL_PROXY=socks5://172.16.15.1:1080 curl https://example.com
```

---

### Option 2 -- System-wide Proxy (per OS)

#### macOS

System Preferences → Network → select your interface → Advanced → Proxies.

- Enable **SOCKS Proxy**: server `172.16.15.1`, port `1080`.

Or via `networksetup` (replace `Wi-Fi` with your service name):
```sh
networksetup -setsocksfirewallproxy Wi-Fi 172.16.15.1 1080
networksetup -setsocksfirewallproxystate Wi-Fi on
```

To disable:
```sh
networksetup -setsocksfirewallproxystate Wi-Fi off
```

#### Windows

Settings → Network & Internet → Proxy → Manual proxy setup.

- Enable **Use a proxy server**, address `172.16.15.1`, port `1080`.

For SOCKS5 specifically, Windows does not expose it in the GUI proxy settings. Use
environment variables in a command prompt, or a helper such as Proxifier.

#### Linux (GNOME)

Settings → Network → Network Proxy → Manual.

- Socks Host: `172.16.15.1`, Port: `1080`.

Or add to `/etc/environment` for system-wide effect:
```
ALL_PROXY=socks5://172.16.15.1:1080
all_proxy=socks5://172.16.15.1:1080
```

---

### Option 3 -- Per-application Configuration

#### Firefox

Settings → General → Network Settings → Manual proxy configuration.

- SOCKS Host: `172.16.15.1`, Port: `1080`, select **SOCKS v5**.
- Tick **Proxy DNS when using SOCKS v5** to route DNS through Dante and prevent DNS
  leaking back through the inspected Unbound resolver.

#### curl
```sh
curl --proxy socks5h://172.16.15.1:1080 https://example.com
# socks5h = remote DNS resolution through Dante (no local DNS leak)
```

#### git
```sh
git config --global http.proxy  socks5h://172.16.15.1:1080
git config --global https.proxy socks5h://172.16.15.1:1080
```

To remove:
```sh
git config --global --unset http.proxy
git config --global --unset https.proxy
```

#### Python (requests)
```python
import requests
proxies = {
    "http":  "socks5h://172.16.15.1:1080",
    "https": "socks5h://172.16.15.1:1080",
}
r = requests.get("https://example.com", proxies=proxies)
```
Requires `pip install requests[socks]` (installs `PySocks`).

#### SSH via SOCKS (ProxyCommand)
```sh
ssh -o ProxyCommand='nc -x 172.16.15.1:1080 %h %p' user@remote.host
```

Permanently in `~/.ssh/config`:
```
Host *
    ProxyCommand nc -x 172.16.15.1:1080 %h %p
```

---

### Option 4 -- proxychains-ng (any application, no native proxy support)

`proxychains-ng` intercepts `connect()` calls via `LD_PRELOAD`, forcing any
dynamically linked application through SOCKS without modifying it.

Install: OpenBSD ports `net/proxychains-ng`; GNULinux `proxychains4`.

Edit `/etc/proxychains.conf` (or `~/.proxychains/proxychains.conf`):
```ini
[ProxyList]
socks5  172.16.15.1  1080
```

Usage:
```sh
proxychains4 curl https://example.com
proxychains4 ssh user@remote.host
```

---

## Deployment Note

All interface names, LAN subnets, and gateway addresses in this document reflect the
**reference configuration**. `TN_UTM_INSTALL.sh` probes the hardware at install time
and rewrites every relevant configuration file -- pf rules, daemon configs, and
ancillary scripts -- to match the actual interface names and addresses of the target
machine. Do not edit these values by hand after installation; re-run the installer or
use the provided management tools to make topology changes.

---

## Author and Attribution

Primary Author: David Peter
Organization:   Tangent Networks
Web:            https://tangentnet.top
Email:          tangent.net@zohomail.in

---

## License

BSD 3-Clause License

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

**End of PF.md**
