<!--
SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
SPDX-License-Identifier: BSD-3-Clause
-->

# NETWORK.md — Network Architecture & Stack Reference

> [!NOTE]
> The examples in this guide assume an OpenBSD host configured with a single
> external (egress) interface and a `vether(4)` virtual Ethernet interface
> serving as the internal (ingress) network. Interface names, routing
> directives, and PF rules should be adapted as required for deployments
> utilizing multiple interfaces, VLANs, or bridged networks.

**Role:** Dual-stack (IPv4 + IPv6) firewall, router, and UTM appliance
**Platform:** OpenBSD — bare metal (x86, aarch64) or QEMU/KVM

---

## Overview

Tangent Networks UTM is a self-contained network appliance built on OpenBSD. It sits
between an upstream WAN connection and a trusted LAN segment, providing NAT44, NAT64,
DNS64, recursive DNS-over-TLS, DHCPv4, IPv6 router advertisement, traffic proxying,
content inspection, and an authenticated SOCKS5 proxy for selective content-filter bypass.

The full software stack:

- **PF** — stateful packet filtering, NAT44, NAT64 (`af-to`), traffic diversion
- **dhcpd(8)** — DHCPv4 for LAN clients
- **rad(8)** — IPv6 router advertisement and PREF64 distribution
- **unbound(8)** — recursive DNS-over-TLS forwarder with DNS64 synthesis
- **sockd (Dante)** — authenticated SOCKS5 proxy for content-filter bypass
- **e2guardian** — HTTP/HTTPS content inspection and filtering
- **clamd (ClamAV)** — antivirus scanning integrated with e2guardian
- **httpd(8)** — local web UI served on the LAN interface

The proxy and inspection layer and their interaction with PF are documented in
`FIREWALL.md`. This document covers the network layer: interfaces, addressing,
routing, DNS, NAT, SOCKS proxy, kernel tuning, and resource limits.

---

## LAN Topologies

`TN_NET_SET.sh` supports two LAN topologies. The topology is selected during Stage 11
and recorded in `/etc/tn-interfaces`. Everything downstream — PF rules, dhcpd, rad,
unbound, sockd — binds to `vether0` regardless of which topology is in use.

### Topology A — Dual Physical NIC

One WAN interface and one LAN interface, each a physical NIC. The LAN interface holds
the LAN IP directly.

```
Internet
    |
em0  (WAN)  — inet autoconf / inet6 autoconf -temporary
    |
    | PF: NAT44, NAT66, NAT64, bogon blocks, dynamic blocklists
    |
em1  (LAN)  — 172.16.5.1/24  fdac:1005::1/64
    |
LAN clients
```

> **Example interfaces used throughout this document:** `em0` (WAN), `em1` (LAN).
> On your hardware these will be whatever `TN_NET_SET.sh` detected and recorded as
> `EXT_IF` and `INT_IF` in `/etc/tn-interfaces`. The actual names (`re0`, `bge0`,
> `athn0`, etc.) do not matter — the scripts and PF use the symbolic token throughout.

**Supported dual-NIC combinations:**

| WAN | LAN | Notes |
|-----|-----|-------|
| Wired ethernet | Wired ethernet | Recommended, fully validated |
| Wired ethernet | Wireless AP (`athn0`, `iwx0`, etc.) | hostap mode on LAN NIC |
| Wireless client | Wired ethernet | WAN NIC in station mode |

Hostname files for Topology A:

```
# /etc/hostname.em0  (WAN)
inet autoconf
inet6 autoconf -temporary
up

# /etc/hostname.em1  (LAN)
inet 172.16.5.1 255.255.255.0
inet6 fdac:1005::1 64
!route add -inet6 64:ff9b::/96 fdac:1005::1
up
```

---

### Topology B — Bridge LAN (vether0 anchor)

Two or more physical interfaces combined into one L2 segment via `bridge0`.
A virtual interface `vether0` serves as the routable LAN anchor and holds the LAN IP.
All services bind to `vether0`. Physical bridge members carry no IP.

```
Internet
    |
em0   (WAN)  — inet autoconf / inet6 autoconf -temporary
    |
    | PF: NAT44, NAT66, NAT64
    |
bridge0  (L2 forwarder — no IP)
    |--- em1    wired member
    |--- athn0  wireless AP member (hostap mode)
    |--- vether0
          |
         vether0  (LAN anchor — INT_IF)
              172.16.5.1/24  fdac:1005::1/64
              All services bind here: dhcpd, rad, unbound, pf diverts, sockd
```

**Why vether0 and not bridge0 for the IP?**

PF divert rules are keyed on the interface where a packet arrives. If the LAN IP lives
on `bridge0` directly, PF sees traffic arriving on the physical ports (`em1`, `athn0`)
— not on `bridge0` — and divert rules keyed on `bridge0` silently never match. Placing
the IP on `vether0` (a member of `bridge0`) means all L2-forwarded traffic surfaces on
`vether0`, divert rules fire correctly, and the UTM inspection pipeline works as
intended.

Hostname files for Topology B:

```
# /etc/hostname.em0  (WAN — identical to Topology A)
inet autoconf
inet6 autoconf -temporary
up

# /etc/hostname.vether0  (LAN anchor — holds the IP, INT_IF)
inet 172.16.5.1 255.255.255.0
inet6 fdac:1005::1 64
!route add -inet6 64:ff9b::/96 fdac:1005::1
up

# /etc/hostname.bridge0  (L2 forwarder — no IP)
add em1
add athn0
add vether0
up

# /etc/hostname.em1  (wired bridge member — no IP)
-tso4
-tso6
up

# /etc/hostname.athn0  (wireless bridge member — hostap, no IP)
mediaopt hostap
chan 6
nwid ExampleAP
wpakey (stored in hostname file)
-powersave
up
```

**tn-interfaces variables set in bridge mode:**

```sh
INT_IF="vether0"          # LAN anchor — what PF, dhcpd, rad, unbound see
INT_BRIDGE_IF="bridge0"   # L2 forwarder
INT_BRIDGE_MEMBERS="em1 athn0"
INT_IS_BRIDGE="1"
HAS_BRIDGE="1"
WIFI_IS_BRIDGE_MEMBER="1"
```

---

## Addressing

Addresses below use the development environment values as examples. Your actual values
are recorded in `/etc/tn-interfaces` and substituted into all config files by
`TN_SUBSTITUTE.sh`.

### WAN (`em0`)

`inet autoconf` enables DHCPv4. `inet6 autoconf -temporary` enables SLAAC without
generating a privacy-extension temporary address — the stable SLAAC address is used.
This is correct for a router acting as an upstream client: it needs a stable,
predictable WAN IPv6 address so PF rules referencing `($ext_if)` resolve consistently.

Gateways are recorded in `/etc/mygate` by `TN_NET_SET.sh` after address acquisition.

### LAN (`vether0`)

The LAN interface carries:

- `%%INT_IP4%%` — private IPv4 address (`172.16.5.1`)
- `%%INT_NET4%%` — subnet (`172.16.5.0/24`)
- `%%INT_IP6%%` — ULA IPv6 address (`fdac:1005::1`)
- `%%INT_NET6%%` — ULA prefix (`fdac:1005::/64`)

The `!route add -inet6 64:ff9b::/96 %%INT_IP6%%` line in the hostname file installs
the NAT64 static route at boot. Without it the kernel rejects packets destined for
`64:ff9b::` before PF is consulted, causing NAT64 to silently fail.

The subnet mask is written in dotted-decimal in hostname files (`255.255.255.0`).
PF receives it as a CIDR prefix derived from `%%INT_MASK4%%`.

### Hostname and Hosts File

The system hostname is set in `/etc/myname`. `/etc/hosts` maps the LAN IP to the
hostname so daemons that bind on `%%INT_IP4%%` can resolve their own hostname:

```
127.0.0.1   localhost
::1         localhost
172.16.5.1  tangent.localdomain tangent
```

---

## DHCPv4 — `dhcpd(8)`

DHCPv4 is served by the OpenBSD base `dhcpd(8)`, configured in `/etc/dhcpd.conf`.
In both topologies `dhcpd` listens on `vether0` — `em1` for Topology A,
`vether0` for Topology B. The bridge members themselves are not visible to dhcpd.

```
option domain-name "tangent.localdomain";
option domain-name-servers %%INT_IP4%%;

subnet %%INT_NET4%% netmask %%INT_MASK4%% {
    option routers             %%INT_IP4%%;
    option subnet-mask         %%INT_MASK4%%;
    option broadcast-address   %%INT_BC4%%;
    range %%DHCPD_INT_IF4_START_ADDR%% %%DHCPD_INT_IF4_END_ADDR%%;
}
```

The dynamic pool runs from `.10` to `.245`, leaving `.2`–`.9` for static
infrastructure (APs, switches) and `.246`–`.254` as a reserved block.

Clients are directed to use `%%INT_IP4%%` as their DNS resolver. This is not optional
— DNS64 synthesis happens in Unbound on this appliance. A client that bypasses the
local resolver will not receive synthesised AAAA records and will fail to reach
IPv4-only destinations over IPv6.

---

## IPv6 Router Advertisement — `rad(8)`

`rad(8)` advertises the LAN IPv6 prefix to clients via SLAAC and distributes the
NAT64 prefix via PREF64 RA option (RFC 8781). It binds to `vether0`.

```
interface vether0 {
    default router yes
    prefix %%INT_NET6%%
    dns {
        lifetime 604800
        nameserver %%INT_IP6%%
        search home.arpa
    }
}

nat64 prefix 64:ff9b::/96
```

The `nat64 prefix` directive is placed **outside** the `interface` block — this is a
syntax requirement of `rad.conf`. It advertises the NAT64 well-known prefix
(`64:ff9b::/96`, RFC 6052) so RFC 8781-capable clients can discover it without
relying solely on DNS64 synthesis.

In bridge mode `rad` sends RA packets on `vether0`. Clients connected to any bridge
member (`em1` or `athn0`) receive them via L2 forwarding through `bridge0`.

---

## DNS — `unbound(8)` with DNS-over-TLS and DNS64

`unbound(8)` operates as a forwarding resolver with DNS-over-TLS upstream, DNS64
synthesis, and strict access controls. It listens on `127.0.0.1`, `::1`,
`%%INT_IP4%%`, and `%%INT_IP6%%`.

### Access Control

All traffic is refused by default. Access is explicitly permitted for RFC1918 ranges,
ULA (`fc00::/7`), link-local (`fe80::/10`), and loopback. Unbound will not respond to
queries arriving from the WAN under any circumstances.

`insecure-lan-zones: yes` prevents rejection of private reverse-DNS zones as
DNSSEC-insecure. `private-domain: localdomain` prevents the search domain leaking
upstream.

### DNS64

Two directives activate DNS64:

- `dns64-prefix: 64:ff9b::/96` inside the `server:` block
- `module-config: "dns64 iterator"` as a top-level standalone directive

Placement matters. On OpenBSD's base Unbound, either directive in the wrong block
produces `unknown keyword` parse errors and Unbound refuses to start.

When a client queries for a AAAA record for an IPv4-only host, the dns64 module
synthesises a AAAA record by prepending `64:ff9b::/96` to the IPv4 address. The
client sends an IPv6 packet to that address, PF intercepts it on `vether0`,
translates it to IPv4 via `af-to`, and NAT44 masquerades it out the WAN.

### Upstream — Quad9 DNS-over-TLS

All queries are forwarded over TLS (port 853) to Quad9's `dns11.quad9.net`:

```
forward-addr: 9.9.9.11@853#dns11.quad9.net
forward-addr: 149.112.112.11@853#dns11.quad9.net
forward-addr: 2620:fe::11@853#dns11.quad9.net
forward-addr: 2620:fe::fe:11@853#dns11.quad9.net
```

`prefer-ip6: yes` causes Unbound to prefer IPv6 upstreams where the WAN provides a
globally routable GUA. In lab environments with a ULA WAN, it falls back to IPv4
upstreams silently.

Local DNSSEC validation is deliberately disabled — `module-config: "dns64 iterator"`
rather than `"dns64 validator iterator"`. Quad9 performs DNSSEC validation upstream;
double-validation in a forwarding configuration increases fragility without improving
security.

### Caching and Performance

Message cache (`msg-cache-size: 128m`) and RRset cache (`rrset-cache-size: 256m`)
consume up to 384 MB, appropriate for 8 GB hardware. `num-threads: 4` matches
quad-core target hardware. `prefetch: yes` and `prefetch-key: yes` refresh popular
entries before expiry.

---

## NAT44 — IPv4 Masquerade

A single PF `match` rule masquerades all LAN IPv4 traffic behind the WAN address:

```
match out on $ext_if inet from $int_net4 to any nat-to ($ext_if)
```

The parentheses around `($ext_if)` cause PF to resolve the current WAN address
dynamically, correct for DHCP-assigned WAN addresses that may change.

---

## NAT64 — IPv6-to-IPv4 Translation

NAT64 is implemented natively in the OpenBSD PF kernel via the `af-to` keyword.

### Packet Flow

1. Client queries DNS. Unbound's DNS64 synthesises a AAAA record by embedding the
   IPv4 address in `64:ff9b::/96`.
2. Client sends an IPv6 packet to `64:ff9b::x.x.x.x` toward its default gateway
   (`%%INT_IP6%%`), arriving on `vether0`.
3. The kernel checks the routing table. The route `64:ff9b::/96 → %%INT_IP6%%`
   (installed by the `!route add` line in the hostname file) confirms the prefix is
   reachable on `vether0`, so the packet is accepted and passed to PF.
4. PF matches the NAT64 rule and performs `af-to inet` — the IPv6 header is replaced
   with an IPv4 header, the destination extracted from the lower 32 bits of the
   `64:ff9b::` address, the source set to the WAN IPv4 address.
5. The translated IPv4 packet hits the NAT44 rule and exits the WAN.
6. The IPv4 reply arrives, is de-masqueraded by NAT44 state, de-translated by PF's
   `af-to` state back to IPv6, and forwarded to the client.

### PF Rule

```
pass in on $int_if inet6 from any to $nat64_pfx af-to inet from ($ext_if) to 0.0.0.0/0
```

No `proto` restriction is specified. Specifying a protocol list causes PF to append
`flags S/SA` to the TCP sub-rule, silently dropping non-SYN TCP packets and ICMPv6
echo requests. The correct form has no protocol restriction.

### In Bridge Mode

The NAT64 packet arrives on `vether0` (INT_IF) after L2 forwarding through `bridge0`.
The PF rule fires on `vether0` identically to how it fires on a physical NIC in
Topology A. No rule changes are required between topologies.

---

## IPv6 Egress Strategy

**Native routing (preferred):** If the ISP delegates a GUA prefix via DHCPv6-PD,
that prefix is assigned to `vether0`, advertised via `rad(8)`, and routed natively.

**NAT66 fallback:** If a GUA prefix is not available, ULA traffic can be masqueraded
behind the WAN IPv6 address. The rule is present in `pf.conf` but commented out.

---

## SOCKS5 Proxy — Dante (`sockd`)

### Purpose

The content inspection layer (e2guardian) intercepts and filters HTTP/HTTPS from all
LAN clients. The appliance runs a Dante SOCKS5 proxy on port 1080 as a controlled
bypass path for traffic that should not be inspected — developer testing, applications
that break under TLS inspection, or administrative access.

### Binding

Dante binds on both `%%INT_IP4%%:1080` and `%%INT_IP6%%:1080`. In bridge mode these
addresses belong to `vether0`. Bridge member interfaces are transparent to Dante.

### Key Design Decisions

**`to: 0/0` in SOCKS pass rules:** Using `to: ::/0` for IPv6 clients locks the
destination address family to IPv6, causing Dante to fail when Unbound returns a
synthesised `64:ff9b::` address (technically IPv6, but requiring an outbound IPv4
connection). `to: 0/0` allows Dante to select the outbound address family based on
what is available on the WAN interface. This is mandatory in a NAT64/DNS64 environment.

**`external: em0`:** Dante uses the WAN interface for all outbound connections
and lets the kernel select the source address dynamically.

**`socksmethod: none`:** No password is required. Access is enforced by `client pass`
rules restricting connections to LAN subnets only. Since the proxy is unreachable from
WAN (PF blocks it), password authentication adds friction without security benefit.

### Access Control

```
client pass  { from: %%INT_NET4%%  to: 0/0 }
client pass  { from: %%INT_NET6%%  to: 0/0 }
client block { from: 0/0           to: 0/0 }
```

### Destination Restrictions

Block rules (evaluated before pass rules) reject:
loopback, RFC1918 and ULA (anti-pivot), link-local, multicast, privileged ports via
BIND (≤1023), SMTP (25), SMB (445), RDP (3389), Tor default (9050), and all UDP.

### Using SOCKS on LAN Clients

```sh
# IPv4 client
curl --proxy socks5h://%%INT_IP4%%:1080 https://example.com

# IPv6 client
curl --proxy socks5h://[%%INT_IP6%%]:1080 https://example.com
```

The `socks5h` scheme sends hostname resolution to the proxy — always prefer this to
avoid DNS leaks and ensure DNS64 synthesis still applies.

---

## Kernel Tuning — `sysctl.conf`

### IP Forwarding

```
net.inet.ip.forwarding=1
net.inet6.ip6.forwarding=1
```

Both must be enabled. Without them the kernel silently drops packets that should be
forwarded between interfaces.

### Kernel Limits

`kern.maxfiles=65536` and `kern.maxproc=8192` — required by the proxy and inspection
daemons which maintain per-connection file descriptors.

`kern.maxclusters=524288` — doubles the default mbuf cluster count. Calculated as
`(8 GB × 0.25) / 4096`. Exhausting mbufs causes packet drops at the driver level
before PF is involved. Reduce to 262144 on 4 GB hardware.

### TCP Tuning

`net.inet.tcp.mssdflt=1460` — default TCP MSS for standard Ethernet.

`net.inet.tcp.always_keepalive=1` — detects and cleans up dead connections.

`net.inet.tcp.synuselimit=500000` / `synhashsize=1024` — SYN cache sizing for router
connection rates. Absorbs SYN floods without creating full state entries.

`net.inet.tcp.ecn=1` — Explicit Congestion Notification (RFC 3168).

Keepalive timers shortened: `keepidle=300` (from 2 hours), `keepintvl=10` (from 75s).
Appropriate for a router seeing many short-lived connections.

### UDP Tuning

`net.inet.udp.recvspace=1048576` (1 MB) / `sendspace=262144` (256 KB) — increased
socket buffers for Unbound handling high DNS query volumes.

### BPF Buffer

`net.bpf.bufsize=2097152` / `maxbufsize=2097152` — 2 MB BPF capture buffer.
The default 32 KB causes mbuf allocation failures when both `pflog0` and `pflog1` are
simultaneously active under load.

### Shared Memory and Semaphores (e2guardian)

`kern.shminfo.*` and `kern.seminfo.*` allocate 512 MB shared memory and configure
semaphore counts required by e2guardian's System V IPC. Without these e2guardian
refuses to start on OpenBSD.

---

## Resource Limits — `login.conf`

### `daemon` class

```
daemon:\
    :datasize=8192M:\
    :maxproc=infinity:\
    :openfiles-max=65536:\
    :openfiles-cur=8192:\
    :stacksize-cur=16M:\
    :tc=default:
```

### `e2guardian` class (`/etc/login.conf.d/e2guardian`)

```
e2guardian:\
    :openfiles-cur=2048:\
    :openfiles-max=4096:\
    :datasize-cur=256M:\
    :datasize-max=512M:\
    :tc=daemon:
```

4096 open files supports approximately 1300 concurrent inspected connections. After
modifying any `login.conf` file, rebuild the database: `cap_mkdb /etc/login.conf`.

---

## Service Summary

| Daemon | Role | Binds to | Config |
|--------|------|----------|--------|
| `dhcpd` | DHCPv4 for LAN clients | `vether0` | `/etc/dhcpd.conf` |
| `rad` | IPv6 RA, SLAAC, PREF64 | `vether0` | `/etc/rad.conf` |
| `unbound` | Recursive DNS-over-TLS, DNS64 | `vether0`, loopback | `/var/unbound/etc/unbound.conf` |
| `sockd` | SOCKS5 proxy for filter bypass | `vether0:1080` | `/etc/sockd.conf` |
| `e2guardian` | HTTP/HTTPS content inspection | — | `/etc/e2guardian/` |
| `clamd` | Antivirus for e2guardian | — | `/etc/clamd.conf` |
| `httpd` | Local web UI | `vether0` | `/etc/httpd.conf` |

In bridge mode every daemon in this table binds to `vether0` regardless of how many
physical interfaces are in the bridge. The bridge members and `bridge0` itself are
invisible to daemons.

---

## Troubleshooting and Verification

### Interface Check

**Topology A:**
```sh
ifconfig em0    # DHCP-acquired IPv4 + SLAAC IPv6
ifconfig vether0    # %%INT_IP4%%/24 + %%INT_IP6%%/64
```

**Topology B (bridge):**
```sh
ifconfig vether0    # LAN IP — %%INT_IP4%%/24 + %%INT_IP6%%/64
ifconfig bridge0    # no inet/inet6 lines; members: em1 athn0 vether0
ifconfig em1        # no inet/inet6 lines; status: active
ifconfig athn0      # no inet/inet6 lines; mediaopt hostap
```

### NAT64 Route

```sh
route -n show -inet6 | grep ff9b
# Expected: 64:ff9b::/96 -> %%INT_IP6%%  (UGS on vether0)
```

### Bridge Membership (Topology B only)

```sh
brconfig bridge0
# Expected: member em1 flags=...  member athn0 flags=...  member vether0 flags=...
```

### DNS and DNS64

```sh
dig @%%INT_IP4%% example.com A
dig @%%INT_IP4%% ipv4.google.com AAAA    # should return 64:ff9b:: synthesised record
unbound-control status
```

### NAT64 Packet Flow

```sh
# From an IPv6-only LAN client using %%INT_IP6%% as resolver:
ping6 64:ff9b::8.8.8.8
pfctl -ss | grep 64:ff9b           # watch for af-to state entries on appliance
```

### SOCKS5 Proxy

```sh
curl --proxy socks5h://%%INT_IP4%%:1080 https://example.com
netstat -an | grep 1080    # should show LISTEN on %%INT_IP4%% and %%INT_IP6%%
tail -f /var/www/htdocs/tn/data/logs/sockd/sockd.log
```

### PF State Table

```sh
pfctl -ss                          # all active states
pfctl -si | grep "current entries" # state count
pfctl -sr                          # loaded ruleset
pfctl -sn                          # NAT rules
```

---

## Deployment Notes for Production

**Interface names:** `TN_NET_SET.sh` detects and records real NIC names in
`/etc/tn-interfaces`. `TN_SUBSTITUTE.sh` expands `em0`, `vether0`, and all
other tokens into every config file. No manual find-and-replace is required.

**MTU:** QEMU/KVM requires `mtu 1472` to account for VirtIO overhead. On bare metal
with standard Ethernet, remove the `mtu` directive from hostname files and `rad.conf`,
or set it to `1500`. Adjust downward only if the upstream path MTU requires it
(e.g. PPPoE at 1492).

**Bogon blocks:** The WAN bogon block in `pf.conf` omits RFC1918 ranges in QEMU
because the lab WAN is `192.168.122.0/24`. In production, add `10.0.0.0/8`,
`172.16.0.0/12`, `192.168.0.0/16` to the WAN IPv4 bogon block, and `fc00::/7` to the
WAN IPv6 bogon block.

**DHCPv6-PD:** If the ISP delegates a GUA prefix, configure `dhcp6leased` on the WAN
interface and assign the delegated prefix to `vether0`. Update `rad.conf` to
advertise the GUA prefix instead of the ULA.

**SOCKS proxy exposure:** Confirm PF blocks port 1080 on `em0`. The SOCKS
proxy must never be reachable from outside the LAN.

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

Redistribution and use in source and binary forms, with or without modification, are
permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list
   of conditions, and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list
   of conditions, and the following disclaimer in the documentation and/or other
   materials provided with the distribution.
3. Neither the name of the copyright holder nor the names of its contributors may be
   used to endorse or promote products derived from this software without specific
   prior written permission.

THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---

*End of NETWORK.md*
