#!/bin/ksh
# =============================================================================
# TN_TOKENIZE.sh -- Tokenize payload/ using /etc/tn-tokens
# =============================================================================
# VERSION: 3.1.0
#
# Run on the LAB machine after TN_RECON.sh has written /etc/tn-tokens.
# Converts every deployment-specific value in payload/ into %%TOKEN%%
# placeholders so the tree can be committed to source control and deployed
# to any target by TN_SUBSTITUTE.sh.
#
# IMPORTANT: /etc/tn-tokens must reflect the interface names that are
# PRESENT IN THE PAYLOAD, not necessarily the lab machine's own interfaces.
# If the payload was built on a VM with vio0/vio1, set EXT_IF=vio0 and
# INT_IF=vio1 in tn-tokens before running, even if the lab NIC is em0/em1.
#
# STAGE ARCHITECTURE
# ------------------
# Stage 1  Canonical service config templates
#   Writes %%TOKEN%%-only versions of the four fully topology-driven service
#   configs (dhcpd.conf, rad.conf, sockd.conf, unbound.conf) and all
#   pmacct/*.conf files directly from heredocs.  No sed required because the
#   entire content of these files is determined by network topology.
#   These paths are recorded in _SKIP_FILES so Stage 2 leaves them alone.
#
# Stage 2  Exact value substitution
#   Iterates every text file not in _SKIP_FILES.  Replaces all known values
#   from tn-tokens with their %%TOKEN%% counterparts using literal sed.
#   Substitution order: IPv4 networks before host addresses (longer strings
#   first prevents partial substitution); IPv6 host before monitor before
#   network (/64) for the same reason.  Interface names use compound patterns
#   first (e.g. interface-em0, snort_em1.pid) then bare word-boundary match.
#
# Stage 3  Stale / legacy value recovery
#   Scans every text file for RFC1918 or ULA addresses that differ from the
#   current tn-tokens values -- i.e. left over from a previous lab subnet or
#   an old broken ULA prefix.  Replaces them with %%STALE_ADDR%% so they are
#   visible during Verify and can be audited before committing.
#
# Stage 4  dhcpd.conf canonical check
#   Confirms Stage 1 produced a clean token-only template.  No mutations.
#
# Verify   Critical invariant check
#   Fails hard if any raw RFC1918/ULA address or current-lab IF name survives
#   in the payload.  Zero warnings is the only acceptable result before commit.
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PAYLOAD="$SCRIPT_DIR/payload"
VERSION="3.1.0"

# -----------------------------------------------------------------------------
# Colours -- suppressed when stdout is not a tty
# -----------------------------------------------------------------------------
if [ -t 1 ]; then
  GREEN='\033[0;32m'
  YELLOW='\033[1;33m'
  BLUE='\033[0;34m'
  RED='\033[0;31m'
  CYAN='\033[0;36m'
  NC='\033[0m'
else
  GREEN=''
  YELLOW=''
  BLUE=''
  RED=''
  CYAN=''
  NC=''
fi

ok() { printf "  ${GREEN}[OK]${NC}    %s\n" "$1"; }
info() { printf "  ${BLUE}[INFO]${NC}  %s\n" "$1"; }
warn() { printf "  ${YELLOW}[WARN]${NC}  %s\n" "$1"; }
err() { printf "  ${RED}[ERR]${NC}   %s\n" "$1"; }

print_header() {
  echo ""
  echo "============================================================"
  printf "  %s\n" "$1"
  echo "============================================================"
}

[ -d "$PAYLOAD" ] || {
  err "payload/ not found at $PAYLOAD"
  exit 1
}
print_header "TN Payload Tokenizer v${VERSION}"
info "Payload: $PAYLOAD"

# =============================================================================
# LOAD /etc/tn-tokens
# =============================================================================
TN_TOKENS="/etc/tn-tokens"
[ -f "$TN_TOKENS" ] || {
  err "$TN_TOKENS not found -- run TN_RECON.sh first"
  exit 1
}

# Reject files with embedded shell logic before sourcing
if grep -qE "^[[:space:]]*(if|for|while|case)[[:space:]]" "$TN_TOKENS"; then
  err "$TN_TOKENS contains embedded shell logic -- regenerate with TN_RECON.sh"
  exit 1
fi

. "$TN_TOKENS"

# Map sourced variables into D_ locals so the origin is unambiguous throughout
D_EXT_IF="${EXT_IF:-}"
D_INT_IF="${INT_IF:-}"
D_INT_IP4="${INT_IP4:-}"
D_INT_NET4="${INT_NET4:-}"
D_INT_MASK4="${INT_MASK4:-}"
D_INT_NET4_ADDR="${INT_NET4_ADDR:-}"
D_INT_BROADCAST4="${INT_BROADCAST4:-}"
D_DHCP_RANGE_START="${DHCP_RANGE_START:-}"
D_DHCP_RANGE_END="${DHCP_RANGE_END:-}"
D_INT_IP6="${INT_IP6:-}"
D_INT_NET6="${INT_NET6:-}"
D_NAT64_PFX="64:ff9b::/96"
D_NAT64_INT_IP4="${NAT64_INT_IP4:-}"
D_MONITOR_V6_HOST="${MONITOR_V6_HOST:-}"

# Validate required tokens
_miss=""
for _t in D_EXT_IF D_INT_IF D_INT_IP4 D_INT_NET4 D_INT_NET4_ADDR \
  D_INT_BROADCAST4 D_DHCP_RANGE_START D_DHCP_RANGE_END \
  D_NAT64_PFX; do
  eval "_v=\$$_t"
  [ -z "$_v" ] && _miss="$_miss $_t"
done
[ -n "$_miss" ] && {
  err "Missing required tokens in $TN_TOKENS:$_miss"
  err "Re-run TN_RECON.sh to regenerate."
  exit 1
}

# Reject loopback values -- indicates RECON ran on a misconfigured machine
case "$D_INT_IF" in lo*)
  err "INT_IF is '$D_INT_IF' (loopback) -- fix lab networking and re-run TN_RECON.sh"
  exit 1
  ;;
esac
case "$D_INT_IP4" in 127.*)
  err "INT_IP4 is '$D_INT_IP4' (loopback) -- same cause as above"
  exit 1
  ;;
esac
case "$D_INT_IP6" in ::1 | ::1/*)
  err "INT_IP6 is '$D_INT_IP6' (loopback) -- same cause as above"
  exit 1
  ;;
esac

info "Tokens loaded:"
printf "    EXT_IF=%-10s  INT_IF=%s\n" "$D_EXT_IF" "$D_INT_IF"
printf "    INT_IP4=%-9s  INT_NET4=%s\n" "$D_INT_IP4" "$D_INT_NET4"
printf "    NET4_ADDR=%-7s  BROADCAST4=%s\n" "$D_INT_NET4_ADDR" "$D_INT_BROADCAST4"
printf "    DHCP=%s .. %s\n" "$D_DHCP_RANGE_START" "$D_DHCP_RANGE_END"
printf "    INT_IP6=%s\n" "${D_INT_IP6:-(not set)}"
printf "    INT_NET6=%s\n" "${D_INT_NET6:-(not set)}"
printf "    MONITOR_V6_HOST=%s\n" "${D_MONITOR_V6_HOST:-(not set)}"
echo ""

# =============================================================================
# FILE LIST
# Excludes binary formats, backup suffixes, and trees that must never be
# modified: e2guardian blocklists, snort rules, runtime pipes/logs/queues,
# and CSS assets (class names can match interface-name patterns).
# =============================================================================
_FILELIST=$(mktemp)
find "$PAYLOAD" -type f \
  ! -path "*/e2guardian/*" \
  ! -path "*/snort/*" \
  ! -path "*/assets/css/*" \
  ! -path "*/data/pipes/*" \
  ! -path "*/data/logs/*" \
  ! -name "firewall.pl" \
  ! -name "pf-tcpdump.sh" \
  ! -path "*/services/queue/*" \
  ! -name "*.orig" ! -name "*.orig.stale" \
  ! -name "*.backup*" ! -name "*.pre-tn*" \
  ! -name "*.png" ! -name "*.gif" ! -name "*.ico" ! -name "*.jpg" \
  ! -name "*.rrd" ! -name "*.db" ! -name "*.gz" ! -name "*.tgz" \
  ! -name "*.tar" ! -name "*.zip" ! -name "*.so" ! -name "*.a" \
  2> /dev/null > "$_FILELIST"

# =============================================================================
# HELPERS
# Defined after the file list, before any stage, so all stages can use them.
# =============================================================================

# _is_text FILE -- returns 0 if FILE is a readable text file.
# Uses OpenBSD file(1) syntax; --mime is not supported on OpenBSD.
_is_text() {
  [ -f "$1" ] && [ -r "$1" ] && file "$1" 2> /dev/null | grep -q "text"
}

# _backup FILE -- copies FILE to FILE.orig exactly once (idempotent).
_backup() {
  [ -f "${1}.orig" ] || cp "$1" "${1}.orig"
}

# _write_template PATH
# Backs up PATH unconditionally before the caller overwrites it.
# The previous guard "! grep -q '^%%'" skipped the backup when a prior
# partial run had already written some tokens into the file, leaving no
# clean recovery copy on subsequent runs.
_write_template() {
  _wt_path="$1"
  mkdir -p "$(dirname "$_wt_path")"
  if [ -f "$_wt_path" ]; then
    cp "$_wt_path" "${_wt_path}.orig.stale"
    info "  backed up: ${_wt_path#$PAYLOAD/} -> $(basename "$_wt_path").orig.stale"
  fi
}

# =============================================================================
# STAGE 1  CANONICAL SERVICE CONFIG TEMPLATES
# =============================================================================
# dhcpd.conf, rad.conf, sockd.conf, unbound.conf, and pmacct/*.conf are files
# whose entire content is determined by network topology.  Tokenizing them from
# a live system copy is unreliable for three reasons:
#   (a) the live copy carries whatever subnet the lab machine used
#   (b) partial tokenization leaves stale values from previous deployments
#   (c) derived values such as broadcast address and DHCP range are not
#       captured individually in tn-tokens and cannot be found by literal sed
#
# The correct approach is to write canonical %%TOKEN%%-only versions directly.
# TN_SUBSTITUTE.sh expands them on the target after TN_PKG_INSTALL.sh has
# created the required directories.
#
# All paths written here are added to _SKIP_FILES so Stage 2 does not
# attempt to re-process them.
# =============================================================================
print_header "Stage 1: Canonical Service Config Templates"

# -- dhcpd.conf ---------------------------------------------------------------
_wt_dhcpd="$PAYLOAD/etc/dhcpd.conf"
_write_template "$_wt_dhcpd"
cat > "$_wt_dhcpd" << 'TMPL'
## /etc/dhcpd.conf -- Tangent Networks UTM DHCP Server
## Canonical template; all values supplied by TN_SUBSTITUTE.sh
## Tokens:
##   %%DHCPD_FQDN%%                 domain name served to clients
##   %%INT_IF4%%                    LAN IPv4 address (router option + DNS)
##   %%DHCPD_SUBNET%%               network address   (e.g. 172.16.25.0)
##   %%DHCPD_NETMASK%%              subnet mask       (e.g. 255.255.255.0)
##   %%DHCPD_BROADCAST%%            broadcast address (e.g. 172.16.25.255)
##   %%DHCPD_INT_IF4_START_ADDR%%   first client address (e.g. 172.16.25.10)
##   %%DHCPD_INT_IF4_END_ADDR%%     last client address  (e.g. 172.16.25.245)

option domain-name "%%DHCPD_FQDN%%";
option domain-name-servers %%INT_IF4%%;

subnet %%DHCPD_SUBNET%% netmask %%DHCPD_NETMASK%% {
    option routers           %%INT_IF4%%;
    option subnet-mask       %%DHCPD_NETMASK%%;
    option broadcast-address %%DHCPD_BROADCAST%%;
    range %%DHCPD_INT_IF4_START_ADDR%% %%DHCPD_INT_IF4_END_ADDR%%;
}
TMPL
ok "template written: ${_wt_dhcpd#$PAYLOAD/}"

# -- rad.conf -----------------------------------------------------------------
_wt_rad="$PAYLOAD/etc/rad.conf"
_write_template "$_wt_rad"
printf '## /etc/rad.conf -- Tangent Networks UTM IPv6 Router Advertisement Daemon\n' > "$_wt_rad"
printf '## Canonical template; all values supplied by TN_SUBSTITUTE.sh\n' >> "$_wt_rad"
printf '## Tokens:\n' >> "$_wt_rad"
printf '##   %%INT_IF%%      LAN interface name       (e.g. vio1)\n' >> "$_wt_rad"
printf '##   %%INT_NET6%%    LAN IPv6 /64 prefix      (e.g. fdac:1019::/64)\n' >> "$_wt_rad"
printf '##   %%INT_IP6%%     LAN IPv6 gateway address (e.g. fdac:1019::1)\n' >> "$_wt_rad"
printf '##   %%NAT64_PFX%%   NAT64 well-known prefix  (e.g. 64:ff9b::/96)\n' >> "$_wt_rad"
printf '## Constants:\n' >> "$_wt_rad"
printf '##   mtu 1472   PPPoE-safe MTU -- identical on all deployments\n' >> "$_wt_rad"
printf 'interface %%%%INT_IF%%%% {\n' >> "$_wt_rad"
printf '\tdefault router yes\n' >> "$_wt_rad"
printf '\tprefix %%%%INT_NET6%%%%\n' >> "$_wt_rad"
printf '\tmtu 1472\n' >> "$_wt_rad"
printf '\tdns {\n' >> "$_wt_rad"
printf '\t\tlifetime 604800\n' >> "$_wt_rad"
printf '\t\tnameserver %%%%INT_IP6%%%%\n' >> "$_wt_rad"
printf '\t\tsearch home.arpa\n' >> "$_wt_rad"
printf '\t}\n' >> "$_wt_rad"
printf '}\n' >> "$_wt_rad"
printf 'nat64 prefix %%%%NAT64_PFX%%%%\n' >> "$_wt_rad"
ok "template written: ${_wt_rad#$PAYLOAD/}"

# -- sockd.conf ---------------------------------------------------------------
_wt_sockd="$PAYLOAD/etc/sockd.conf"
_write_template "$_wt_sockd"
printf '## /etc/sockd.conf -- Dante SOCKS5 Server -- Tangent Networks UTM\n' > "$_wt_sockd"
printf '## Canonical template; all values supplied by TN_SUBSTITUTE.sh\n' >> "$_wt_sockd"
printf '## Tokens: %%%%INT_IP4%%%%, %%%%INT_IP6%%%%, %%%%INT_NET4%%%%, %%%%INT_NET6%%%%, %%%%EXT_IF%%%%\n' >> "$_wt_sockd"
printf '##\n' >> "$_wt_sockd"
printf '## NOTE: "to: 0/0" in pass rules is intentional. Dante selects the outbound\n' >> "$_wt_sockd"
printf '## address family based on EXT_IF availability. Using "::/0" locks the\n' >> "$_wt_sockd"
printf '## destination to IPv6 and breaks NAT64-synthesised (64:ff9b::) destinations.\n' >> "$_wt_sockd"
printf '##\n' >> "$_wt_sockd"
printf '## SYNTAX NOTE: Dante does not use semicolons as statement terminators.\n' >> "$_wt_sockd"
printf '## Each directive must be on its own line. A semicolon inside a rule block\n' >> "$_wt_sockd"
printf '## causes a parse error. Do NOT add semicolons anywhere in this file.\n' >> "$_wt_sockd"
printf 'logoutput: /var/www/htdocs/tn/data/logs/sockd/sockd.log\n' >> "$_wt_sockd"
printf 'internal: %%%%INT_IP4%%%% port = 1080\n' >> "$_wt_sockd"
printf 'internal: %%%%INT_IP6%%%% port = 1080\n' >> "$_wt_sockd"
printf 'external: %%%%EXT_IF%%%%\n' >> "$_wt_sockd"
printf 'socksmethod: none\n' >> "$_wt_sockd"
printf 'user.notprivileged: _sockd\n' >> "$_wt_sockd"
printf 'timeout.connect:      30\n' >> "$_wt_sockd"
printf 'timeout.io:           86400\n' >> "$_wt_sockd"
printf 'timeout.tcp_fin_wait: 10\n' >> "$_wt_sockd"
printf '# Allow LAN clients\n' >> "$_wt_sockd"
printf 'client pass {\n' >> "$_wt_sockd"
printf '    from: %%%%INT_NET4%%%% to: 0/0\n' >> "$_wt_sockd"
printf '    log: connect disconnect error\n' >> "$_wt_sockd"
printf '}\n' >> "$_wt_sockd"
printf 'client pass {\n' >> "$_wt_sockd"
printf '    from: %%%%INT_NET6%%%% to: 0/0\n' >> "$_wt_sockd"
printf '    log: connect disconnect error\n' >> "$_wt_sockd"
printf '}\n' >> "$_wt_sockd"
printf '# Block everything else at the client level\n' >> "$_wt_sockd"
printf 'client block {\n' >> "$_wt_sockd"
printf '    from: 0/0 to: 0/0\n' >> "$_wt_sockd"
printf '    log: connect error\n' >> "$_wt_sockd"
printf '}\n' >> "$_wt_sockd"
printf '# Block loopback\n' >> "$_wt_sockd"
printf 'socks block {\n' >> "$_wt_sockd"
printf '    from: 0/0 to: 127.0.0.0/8\n' >> "$_wt_sockd"
printf '    log: connect error\n' >> "$_wt_sockd"
printf '}\n' >> "$_wt_sockd"
printf 'socks block {\n' >> "$_wt_sockd"
printf '    from: 0/0 to: ::1/128\n' >> "$_wt_sockd"
printf '    log: connect error\n' >> "$_wt_sockd"
printf '}\n' >> "$_wt_sockd"
printf '# Block RFC1918 private ranges\n' >> "$_wt_sockd"
printf 'socks block {\n' >> "$_wt_sockd"
printf '    from: 0/0 to: 10.0.0.0/8\n' >> "$_wt_sockd"
printf '    log: connect error\n' >> "$_wt_sockd"
printf '}\n' >> "$_wt_sockd"
printf 'socks block {\n' >> "$_wt_sockd"
printf '    from: 0/0 to: 172.16.0.0/12\n' >> "$_wt_sockd"
printf '    log: connect error\n' >> "$_wt_sockd"
printf '}\n' >> "$_wt_sockd"
printf 'socks block {\n' >> "$_wt_sockd"
printf '    from: 0/0 to: 192.168.0.0/16\n' >> "$_wt_sockd"
printf '    log: connect error\n' >> "$_wt_sockd"
printf '}\n' >> "$_wt_sockd"
printf '# Block ULA and link-local IPv6\n' >> "$_wt_sockd"
printf 'socks block {\n' >> "$_wt_sockd"
printf '    from: 0/0 to: fc00::/7\n' >> "$_wt_sockd"
printf '    log: connect error\n' >> "$_wt_sockd"
printf '}\n' >> "$_wt_sockd"
printf 'socks block {\n' >> "$_wt_sockd"
printf '    from: 0/0 to: fe80::/10\n' >> "$_wt_sockd"
printf '    log: connect error\n' >> "$_wt_sockd"
printf '}\n' >> "$_wt_sockd"
printf '# Block multicast\n' >> "$_wt_sockd"
printf 'socks block {\n' >> "$_wt_sockd"
printf '    from: 0/0 to: 224.0.0.0/4\n' >> "$_wt_sockd"
printf '    log: connect error\n' >> "$_wt_sockd"
printf '}\n' >> "$_wt_sockd"
printf 'socks block {\n' >> "$_wt_sockd"
printf '    from: 0/0 to: ff00::/8\n' >> "$_wt_sockd"
printf '    log: connect error\n' >> "$_wt_sockd"
printf '}\n' >> "$_wt_sockd"
printf '# Block privileged port binding\n' >> "$_wt_sockd"
printf 'socks block {\n' >> "$_wt_sockd"
printf '    from: 0/0 to: 0/0 port le 1023\n' >> "$_wt_sockd"
printf '    command: bind\n' >> "$_wt_sockd"
printf '    log: connect error\n' >> "$_wt_sockd"
printf '}\n' >> "$_wt_sockd"
printf '# Block abuse-prone service ports\n' >> "$_wt_sockd"
printf 'socks block {\n' >> "$_wt_sockd"
printf '    from: 0/0 to: 0/0 port = 25\n' >> "$_wt_sockd"
printf '    log: connect error\n' >> "$_wt_sockd"
printf '}\n' >> "$_wt_sockd"
printf 'socks block {\n' >> "$_wt_sockd"
printf '    from: 0/0 to: 0/0 port = 445\n' >> "$_wt_sockd"
printf '    log: connect error\n' >> "$_wt_sockd"
printf '}\n' >> "$_wt_sockd"
printf 'socks block {\n' >> "$_wt_sockd"
printf '    from: 0/0 to: 0/0 port = 3389\n' >> "$_wt_sockd"
printf '    log: connect error\n' >> "$_wt_sockd"
printf '}\n' >> "$_wt_sockd"
printf 'socks block {\n' >> "$_wt_sockd"
printf '    from: 0/0 to: 0/0 port = 9050\n' >> "$_wt_sockd"
printf '    log: connect error\n' >> "$_wt_sockd"
printf '}\n' >> "$_wt_sockd"
printf '# Block UDP tunnelling\n' >> "$_wt_sockd"
printf 'socks block {\n' >> "$_wt_sockd"
printf '    from: 0/0 to: 0/0\n' >> "$_wt_sockd"
printf '    protocol: udp\n' >> "$_wt_sockd"
printf '    log: connect error\n' >> "$_wt_sockd"
printf '}\n' >> "$_wt_sockd"
printf '# Allow LAN TCP CONNECT outbound\n' >> "$_wt_sockd"
printf 'socks pass {\n' >> "$_wt_sockd"
printf '    from: %%%%INT_NET4%%%% to: 0/0\n' >> "$_wt_sockd"
printf '    command: connect\n' >> "$_wt_sockd"
printf '    protocol: tcp\n' >> "$_wt_sockd"
printf '    log: connect disconnect iooperation\n' >> "$_wt_sockd"
printf '}\n' >> "$_wt_sockd"
printf 'socks pass {\n' >> "$_wt_sockd"
printf '    from: %%%%INT_NET6%%%% to: 0/0\n' >> "$_wt_sockd"
printf '    command: connect\n' >> "$_wt_sockd"
printf '    protocol: tcp\n' >> "$_wt_sockd"
printf '    log: connect disconnect iooperation\n' >> "$_wt_sockd"
printf '}\n' >> "$_wt_sockd"
ok "template written: ${_wt_sockd#$PAYLOAD/}"
# -- unbound.conf -------------------------------------------------------------
_wt_unbound="$PAYLOAD/var/unbound/etc/unbound.conf"
_write_template "$_wt_unbound"
printf '## /var/unbound/etc/unbound.conf -- Tangent Networks UTM Unbound Resolver\n' > "$_wt_unbound"
printf '## Canonical template; all values supplied by TN_SUBSTITUTE.sh\n' >> "$_wt_unbound"
printf '## Tokens: %%%%INT_IP4%%%%, %%%%INT_IP6%%%%, %%%%CPU_CORES%%%%, %%%%NAT64_PFX%%%%\n' >> "$_wt_unbound"
printf '# $OpenBSD: unbound.conf,v 1.21 2020/10/28 11:35:58 sthen Exp $\n' >> "$_wt_unbound"
printf 'server:\n' >> "$_wt_unbound"
printf '\tinterface: 127.0.0.1\n' >> "$_wt_unbound"
printf '\tinterface: ::1\n' >> "$_wt_unbound"
printf '\tinterface: %%%%INT_IP4%%%%\n' >> "$_wt_unbound"
printf '\tinterface: %%%%INT_IP6%%%%\n' >> "$_wt_unbound"
printf '\taccess-control: 0.0.0.0/0 refuse\n' >> "$_wt_unbound"
printf '\taccess-control: ::0/0 refuse\n' >> "$_wt_unbound"
printf '\taccess-control: 10.0.0.0/8 allow\n' >> "$_wt_unbound"
printf '\taccess-control: 172.16.0.0/12 allow\n' >> "$_wt_unbound"
printf '\taccess-control: 192.168.0.0/16 allow\n' >> "$_wt_unbound"
printf '\taccess-control: fc00::/7 allow\n' >> "$_wt_unbound"
printf '\taccess-control: fe80::/10 allow\n' >> "$_wt_unbound"
printf '\taccess-control: 127.0.0.0/8 allow\n' >> "$_wt_unbound"
printf '\taccess-control: ::1/128 allow\n' >> "$_wt_unbound"
printf '\tinsecure-lan-zones: yes\n' >> "$_wt_unbound"
printf '\tprivate-address: 10.0.0.0/8\n' >> "$_wt_unbound"
printf '\tprivate-address: 172.16.0.0/12\n' >> "$_wt_unbound"
printf '\tprivate-address: 192.168.0.0/16\n' >> "$_wt_unbound"
printf '\tprivate-domain: localdomain\n' >> "$_wt_unbound"
printf '\tdo-ip6: yes\n' >> "$_wt_unbound"
printf '\tprefer-ip6: no\n' >> "$_wt_unbound"
printf '\tdns64-prefix: %%%%NAT64_PFX%%%%\n' >> "$_wt_unbound"
printf '\ttls-cert-bundle: "/etc/ssl/cert.pem"\n' >> "$_wt_unbound"
printf '\ttcp-idle-timeout: 30000\n' >> "$_wt_unbound"
printf '\tedns-tcp-keepalive: yes\n' >> "$_wt_unbound"
printf '\tedns-tcp-keepalive-timeout: 30000\n' >> "$_wt_unbound"
printf '\tuse-syslog: yes\n' >> "$_wt_unbound"
printf '\tlog-queries: yes\n' >> "$_wt_unbound"
printf '\tverbosity: 1\n' >> "$_wt_unbound"
printf '\thide-identity: yes\n' >> "$_wt_unbound"
printf '\thide-version: yes\n' >> "$_wt_unbound"
printf '\tqname-minimisation: yes\n' >> "$_wt_unbound"
printf '\t#auto-trust-anchor-file: "/var/unbound/etc/root.key"\n' >> "$_wt_unbound"
printf '\tval-log-level: 2\n' >> "$_wt_unbound"
printf '\taggressive-nsec: yes\n' >> "$_wt_unbound"
printf '\tcache-max-ttl: 604800\n' >> "$_wt_unbound"
printf '\tcache-min-ttl: 1800\n' >> "$_wt_unbound"
printf '\tinfra-cache-numhosts: 100000\n' >> "$_wt_unbound"
printf '\tinfra-cache-slabs: 4\n' >> "$_wt_unbound"
printf '\tkey-cache-slabs: 4\n' >> "$_wt_unbound"
printf '\tmsg-cache-size: 128m\n' >> "$_wt_unbound"
printf '\tmsg-cache-slabs: 4\n' >> "$_wt_unbound"
printf '\trrset-cache-size: 256m\n' >> "$_wt_unbound"
printf '\trrset-cache-slabs: 4\n' >> "$_wt_unbound"
printf '\tnum-threads: %%%%CPU_CORES%%%%\n' >> "$_wt_unbound"
printf '\tprefetch: yes\n' >> "$_wt_unbound"
printf '\tprefetch-key: yes\n' >> "$_wt_unbound"
printf '\tso-sndbuf: 0\n' >> "$_wt_unbound"
printf '\tso-rcvbuf: 0\n' >> "$_wt_unbound"
printf '\tso-reuseport: yes\n' >> "$_wt_unbound"
printf 'module-config: "dns64 iterator"\n' >> "$_wt_unbound"
printf 'remote-control:\n' >> "$_wt_unbound"
printf '\tcontrol-enable: yes\n' >> "$_wt_unbound"
printf '\tcontrol-interface: /var/run/unbound.sock\n' >> "$_wt_unbound"
printf 'forward-zone:\n' >> "$_wt_unbound"
printf '\tname: "."\n' >> "$_wt_unbound"
printf '\tforward-ssl-upstream: yes\n' >> "$_wt_unbound"
printf '\tforward-first: no\n' >> "$_wt_unbound"
printf '\tforward-addr: 9.9.9.11@853#dns11.quad9.net\n' >> "$_wt_unbound"
printf '\tforward-addr: 149.112.112.11@853#dns11.quad9.net\n' >> "$_wt_unbound"
printf '\tforward-addr: 1.1.1.1@853#cloudflare-dns.com\n' >> "$_wt_unbound"
printf '\tforward-addr: 1.0.0.1@853#cloudflare-dns.com\n' >> "$_wt_unbound"
printf '\tforward-addr: 2620:fe::11@853#dns11.quad9.net\n' >> "$_wt_unbound"
printf '\tforward-addr: 2620:fe::fe:11@853#dns11.quad9.net\n' >> "$_wt_unbound"
printf '\tforward-addr: 2606:4700:4700::1111@853#cloudflare-dns.com\n' >> "$_wt_unbound"
printf '\tforward-addr: 2606:4700:4700::1001@853#cloudflare-dns.com\n' >> "$_wt_unbound"
ok "template written: ${_wt_unbound#$PAYLOAD/}"

# -- pmacct/*.conf ------------------------------------------------------------
# pmacct configs contain mostly static measurement policy. Only the
# pcap_interface line is deployment-specific. We rewrite that one directive
# and preserve everything else verbatim.
# Mapping is filename-driven (unambiguous, no heuristics required):
#   ext_if_*.conf  ->  pcap_interface: %%EXT_IF%%
#   int_if_*.conf  ->  pcap_interface: %%INT_IF%%
_PMACCT_DIR="$PAYLOAD/etc/pmacct"
if [ -d "$_PMACCT_DIR" ]; then
  for _pmf in "$_PMACCT_DIR"/*.conf; do
    [ -f "$_pmf" ] || continue
    _pmf_base=$(basename "$_pmf")
    case "$_pmf_base" in
      ext_if_*) _pcap_tok="%%EXT_IF%%" ;;
      int_if_*) _pcap_tok="%%INT_IF%%" ;;
      *)
        warn "pmacct: skipping $_pmf_base (no ext_if_/int_if_ prefix)"
        continue
        ;;
    esac
    cp "$_pmf" "${_pmf}.orig.stale"
    _pmf_tmp=$(mktemp)
    sed "s|^pcap_interface:.*|pcap_interface: ${_pcap_tok}|" \
      "$_pmf" > "$_pmf_tmp"
    mv "$_pmf_tmp" "$_pmf"
    ok "template written: ${_pmf#$PAYLOAD/}  (pcap_interface -> ${_pcap_tok})"
  done
else
  info "payload/etc/pmacct/ not found -- skipping pmacct templates"
fi

# Record all Stage 1 output paths so Stage 2 skips them
_SKIP_FILES="$_wt_dhcpd
$_wt_rad
$_wt_sockd
$_wt_unbound"
[ -d "$_PMACCT_DIR" ] && for _pmf in "$_PMACCT_DIR"/*.conf; do
  [ -f "$_pmf" ] && _SKIP_FILES="${_SKIP_FILES}
${_pmf}"
done

# =============================================================================
# STAGE 2  EXACT VALUE SUBSTITUTION
# =============================================================================
# Iterates every text file not in _SKIP_FILES and replaces all known values
# from tn-tokens with their %%TOKEN%% counterparts using literal sed only.
# No ERE, no generic RFC1918 patterns, no alternation groups -- the exact
# strings to replace are all known from tn-tokens.
#
# Substitution order within each file:
#   IPv4: CIDR network -> broadcast -> bare network -> host
#         Longer strings must be replaced first so a host address that appears
#         inside a network string is not consumed before the network token.
#   IPv6: host -> monitor (::254) -> network (/64)
#         Same reason: replacing /64 first would clobber ::1 host addresses.
#   Interface names: compound context patterns -> bare word-boundary
#         "interface-em0" must become "interface-%%EXT_IF%%" atomically
#         before the bare word-boundary pattern for "em0" runs.
# =============================================================================
print_header "Stage 2: Exact Value Substitution"
_S2_FIXED=0

while IFS= read -r _f; do
  _is_text "$_f" || continue
  echo "$_SKIP_FILES" | grep -qF "$_f" && continue

  # Pre-check: skip files containing none of our known values.
  # grep -F is a literal string match -- no regex, no ERE, no surprises.
  # Loopback values are excluded from the search list; they are intentional
  # constants in many config files and must never be treated as tokens.
  _hit=0
  for _chk in "$D_EXT_IF" "$D_INT_IF" "$D_INT_IP4" "$D_INT_NET4" \
    "$D_INT_NET4_ADDR" "$D_INT_BROADCAST4" \
    "$D_DHCP_RANGE_START" "$D_DHCP_RANGE_END" \
    "${D_INT_IP6:-SKIP}" "${D_INT_NET6:-SKIP}" \
    "${D_MONITOR_V6_HOST:-SKIP}" \
    "${EXT_GW4:-SKIP}" "${EXT_GW6:-SKIP}"; do
    [ "$_chk" = "SKIP" ] && continue
    case "$_chk" in 127.* | ::1 | lo[0-9]*) continue ;; esac
    grep -qF "$_chk" "$_f" 2> /dev/null && {
      _hit=1
      break
    }
  done
  [ "$_hit" -eq 0 ] && continue

  _backup "$_f"
  _t=$(mktemp)
  cp "$_f" "$_t"

  # IPv4 -- networks before addresses; never substitute loopback
  case "$D_INT_NET4" in 127.*) ;; *) sed -i "s|${D_INT_NET4}|%%INT_NET4%%|g" "$_t" ;; esac
  case "$D_INT_BROADCAST4" in 127.*) ;; *) sed -i "s|${D_INT_BROADCAST4}|%%INT_BROADCAST4%%|g" "$_t" ;; esac
  case "$D_INT_NET4_ADDR" in 127.*) ;; *) sed -i "s|${D_INT_NET4_ADDR}|%%INT_NET4_ADDR%%|g" "$_t" ;; esac
  case "$D_INT_IP4" in 127.*) ;; *) sed -i "s|${D_INT_IP4}|%%INT_IP4%%|g" "$_t" ;; esac

  [ -n "$D_DHCP_RANGE_START" ] && case "$D_DHCP_RANGE_START" in 127.*) ;; *)
    sed -i "s|${D_DHCP_RANGE_START}|%%DHCP_RANGE_START%%|g" "$_t"
    ;;
  esac
  [ -n "$D_DHCP_RANGE_END" ] && case "$D_DHCP_RANGE_END" in 127.*) ;; *)
    sed -i "s|${D_DHCP_RANGE_END}|%%DHCP_RANGE_END%%|g" "$_t"
    ;;
  esac

  # IPv6 substitution order is critical:
  #   1. INT_NET6  (e.g. fdac:100f::/64)  -- longest match, must go first
  #   2. MONITOR_V6_HOST (e.g. fdac:100f::254) -- before host to avoid
  #      partial overlap if monitor address shares prefix with gateway
  #   3. INT_IP6   (e.g. fdac:100f::1)   -- shortest, must go last
  # Replacing INT_IP6 before INT_NET6 corrupts the network string:
  #   fdac:100f::/64 → %%INT_IP6%%/64 (broken) instead of %%INT_NET6%%
  # Never substitute ::1 (loopback).
  [ -n "$D_INT_NET6" ] && case "$D_INT_NET6" in ::1*) ;; *)
    sed -i "s|${D_INT_NET6}|%%INT_NET6%%|g" "$_t"
    ;;
  esac
  [ -n "$D_MONITOR_V6_HOST" ] && case "$D_MONITOR_V6_HOST" in ::1*) ;; *)
    sed -i "s|${D_MONITOR_V6_HOST}|%%MONITOR_V6_HOST%%|g" "$_t"
    ;;
  esac
  [ -n "$D_INT_IP6" ] && case "$D_INT_IP6" in ::1*) ;; *)
    sed -i "s|${D_INT_IP6}|%%INT_IP6%%|g" "$_t"
    ;;
  esac
  sed -i "s|${D_NAT64_PFX}|%%NAT64_PFX%%|g" "$_t"
  [ -n "${D_NAT64_INT_IP4:-}" ] \
    && sed -i "s|${D_NAT64_INT_IP4}|%%NAT64_INT_IP4%%|g" "$_t"

  # WAN gateways
  [ -n "${EXT_GW4:-}" ] && sed -i "s|${EXT_GW4}|%%WAN_GW4%%|g" "$_t"
  [ -n "${EXT_GW6:-}" ] && sed -i "s|${EXT_GW6}|%%WAN_GW6%%|g" "$_t"

  # Interface names -- compound context patterns first, then word-boundary.
  # Compound patterns cover: collectd RRD paths, snort pid/sentinel files,
  # pmacct pcap_interface, Dante external:/internal:, pf.conf assignments,
  # snort -i flag, and dhcpd_flags.
  sed -i \
    -e "s|interface-${D_EXT_IF}|interface-%%EXT_IF%%|g" \
    -e "s|interface-${D_INT_IF}|interface-%%INT_IF%%|g" \
    -e "s|snort_${D_EXT_IF}\.pid|snort_%%EXT_IF%%.pid|g" \
    -e "s|snort_${D_INT_IF}\.pid|snort_%%INT_IF%%.pid|g" \
    -e "s|snort_${D_EXT_IF}\.launching|snort_%%EXT_IF%%.launching|g" \
    -e "s|snort_${D_INT_IF}\.launching|snort_%%INT_IF%%.launching|g" \
    -e "s|-i ${D_EXT_IF}|-i %%EXT_IF%%|g" \
    -e "s|-i ${D_INT_IF}|-i %%INT_IF%%|g" \
    -e "s|pcap_interface: ${D_EXT_IF}|pcap_interface: %%EXT_IF%%|g" \
    -e "s|pcap_interface: ${D_INT_IF}|pcap_interface: %%INT_IF%%|g" \
    -e "s|external: ${D_EXT_IF}|external: %%EXT_IF%%|g" \
    -e "s|internal: ${D_INT_IF}|internal: %%INT_IF%%|g" \
    -e "s|ext_if = \"${D_EXT_IF}\"|ext_if = \"%%EXT_IF%%\"|g" \
    -e "s|int_if = \"${D_INT_IF}\"|int_if = \"%%INT_IF%%\"|g" \
    "$_t"

  # Bare interface name -- OpenBSD sed BRE word-boundary syntax
  sed -i \
    -e "s|[[:<:]]${D_EXT_IF}[[:>:]]|%%EXT_IF%%|g" \
    -e "s|[[:<:]]${D_INT_IF}[[:>:]]|%%INT_IF%%|g" \
    "$_t"

  # Certificate organisation name
  [ -n "${CERT_ORG:-}" ] && sed -i "s|${CERT_ORG}|%%CERT_ORG%%|g" "$_t"

  mv "$_t" "$_f"
  ok "tokenized: ${_f#$PAYLOAD/}"
  _S2_FIXED=$((_S2_FIXED + 1))
done < "$_FILELIST"

info "Stage 2 complete: $_S2_FIXED files tokenized"
rm -f "$_FILELIST"

# =============================================================================
# STAGE 3  STALE / LEGACY VALUE RECOVERY
# =============================================================================
# Handles payloads that were authored against a different lab machine -- a
# different RFC1918 subnet, a different ULA prefix, or a previous broken ULA
# formula (6-char prefix fdac10:0a00::).
#
# Any RFC1918 or ULA address that survived Stage 2 is by definition not in
# tn-tokens and therefore cannot be mapped to a specific token.  We replace
# it with %%STALE_ADDR%% so it is visible during Verify and can be audited
# before committing.
#
# Static policy lines that legitimately reference RFC1918 ranges -- Dante
# socks block rules, Unbound access-control and private-address directives --
# are excluded by grep post-filter and sed address guards.
# =============================================================================
print_header "Stage 3: Stale / Legacy Value Recovery"
_S3_FIXED=0

_STALE_PAT='172\.1[6-9]\.\|172\.2[0-9]\.\|172\.3[01]\.\|10\.[0-9][0-9]*\.[0-9][0-9]*\.\|192\.168\.\|fd[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f][0-9a-f][0-9a-f]:'

find "$PAYLOAD" -type f \
  ! -path "*/e2guardian/*" ! -path "*/snort/*" ! -path "*/assets/css/*" \
  ! -path "*/data/pipes/*" ! -path "*/data/logs/*" ! -path "*/services/queue/*" \
  ! -name "*.orig" ! -name "*.orig.stale" ! -name "*.pre-tn*" \
  ! -name "*.png" ! -name "*.gif" ! -name "*.ico" ! -name "*.jpg" \
  ! -name "*.rrd" ! -name "*.db" ! -name "*.gz" ! -name "*.tgz" \
  ! -name "*.tar" ! -name "*.zip" ! -name "*.so" ! -name "*.a" \
  2> /dev/null | while IFS= read -r _f; do
  _is_text "$_f" || continue
  echo "$_SKIP_FILES" | grep -qF "$_f" && continue

  # Check for stale addresses, excluding static policy lines
  _stale_hits=$(grep "$_STALE_PAT" "$_f" 2> /dev/null \
    | grep -v "%%" \
    | grep -v "access-control:" \
    | grep -v "private-address:" \
    | grep -v "socks block" \
    | grep -v "from: 10\." | grep -v "from: 172\." | grep -v "from: 192\." \
    | grep -v "to: 10\." | grep -v "to: 172\." | grep -v "to: 192\." \
    | grep -v "127\." || true)
  [ -z "$_stale_hits" ] && continue

  _backup "$_f"
  _t=$(mktemp)
  sed \
    -e "/access-control:/!  s|172\.1[6-9]\.[0-9][0-9]*\.[0-9][0-9]*|%%STALE_ADDR%%|g" \
    -e "/access-control:/!  s|172\.2[0-9]\.[0-9][0-9]*\.[0-9][0-9]*|%%STALE_ADDR%%|g" \
    -e "/access-control:/!  s|172\.3[01]\.[0-9][0-9]*\.[0-9][0-9]*|%%STALE_ADDR%%|g" \
    -e "/private-address:/! s|10\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*|%%STALE_ADDR%%|g" \
    -e "/private-address:/! s|192\.168\.[0-9][0-9]*\.[0-9][0-9]*|%%STALE_ADDR%%|g" \
    -e "s|fd[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f][0-9a-f][0-9a-f]:[^:][^ ]*|%%STALE_ADDR%%|g" \
    "$_f" > "$_t"
  mv "$_t" "$_f"
  warn "stale values replaced: ${_f#$PAYLOAD/}"
  _S3_FIXED=$((_S3_FIXED + 1))
done

info "Stage 3 complete: $_S3_FIXED files had stale values replaced with %%STALE_ADDR%%"

# =============================================================================
# STAGE 4  dhcpd.conf CANONICAL CHECK
# =============================================================================
# Stage 1 wrote a token-only dhcpd.conf.  This stage confirms it is present
# and contains no raw subnet lines.  It makes no modifications.
# =============================================================================
print_header "Stage 4: dhcpd.conf Canonical Check"

_DHCPD="$PAYLOAD/etc/dhcpd.conf"
if [ ! -f "$_DHCPD" ]; then
  warn "dhcpd.conf not found in payload -- Stage 1 may have failed"
elif grep -qE "^subnet [0-9]" "$_DHCPD" 2> /dev/null; then
  warn "dhcpd.conf contains a raw subnet line -- Stage 1 did not run cleanly"
  grep -n "^subnet" "$_DHCPD" | sed 's/^/    /'
else
  ok "dhcpd.conf is a clean token-only template"
fi

# =============================================================================
# VERIFY  Critical Invariant Check
# =============================================================================
# Zero raw addresses or current-lab interface names in the payload is the only
# acceptable result before committing to source control.
# =============================================================================
print_header "Verify: Critical Invariants"

_FAIL=0

# -- 1. Current tn-tokens values must not appear in any payload file ----------
for _v in "$D_EXT_IF" "$D_INT_IF" "$D_INT_IP4" "$D_INT_NET4_ADDR" \
  "$D_INT_NET4" "$D_INT_BROADCAST4"; do
  [ -z "$_v" ] && continue
  case "$_v" in 127.* | ::1* | lo[0-9]*) continue ;; esac
  _hits=$(find "$PAYLOAD" -type f \
    ! -name "*.orig" ! -name "*.orig.stale" ! -name "*.pre-tn*" \
    ! -name "*.gz" ! -name "*.tgz" ! -name "*.tar" \
    ! -name "*.zip" ! -name "*.db" ! -name "*.rrd" \
    ! -name "*.png" ! -name "*.jpg" ! -name "*.gif" \
    ! -path "*/e2guardian/*" ! -path "*/snort/*" \
    2> /dev/null | xargs grep -lF "$_v" 2> /dev/null \
    | grep -v "\.orig" || true)
  if [ -n "$_hits" ]; then
    warn "value '$_v' still present in:"
    echo "$_hits" | sed 's/^/    /'
    _FAIL=1
  fi
done

_ipv6_find_args() {
  find "$PAYLOAD" -type f \
    ! -name "*.orig" ! -name "*.orig.stale" ! -name "*.pre-tn*" \
    ! -name "*.gz" ! -name "*.tgz" ! -name "*.tar" \
    ! -name "*.zip" ! -name "*.db" ! -name "*.rrd" \
    ! -name "*.png" ! -name "*.jpg" ! -name "*.gif" \
    ! -path "*/e2guardian/*" ! -path "*/snort/*" \
    2> /dev/null
}

# Check INT_NET6 first (longest string -- if this leaks, INT_IP6 check below
# is redundant but kept for defence in depth)
if [ -n "$D_INT_NET6" ]; then
  case "$D_INT_NET6" in ::1*) : ;; *)
    _hits=$(_ipv6_find_args | xargs grep -lF "$D_INT_NET6" 2> /dev/null \
      | grep -v "\.orig" || true)
    [ -n "$_hits" ] && {
      warn "INT_NET6 '$D_INT_NET6' still in payload"
      _FAIL=1
    }
    ;;
  esac
fi

if [ -n "$D_MONITOR_V6_HOST" ]; then
  case "$D_MONITOR_V6_HOST" in ::1*) : ;; *)
    _hits=$(_ipv6_find_args | xargs grep -lF "$D_MONITOR_V6_HOST" 2> /dev/null \
      | grep -v "\.orig" || true)
    [ -n "$_hits" ] && {
      warn "MONITOR_V6_HOST '$D_MONITOR_V6_HOST' still in payload"
      _FAIL=1
    }
    ;;
  esac
fi

if [ -n "$D_INT_IP6" ]; then
  case "$D_INT_IP6" in ::1*) : ;; *)
    _hits=$(_ipv6_find_args | xargs grep -lF "$D_INT_IP6" 2> /dev/null \
      | grep -v "\.orig" || true)
    [ -n "$_hits" ] && {
      warn "INT_IP6 '$D_INT_IP6' still in payload"
      _FAIL=1
    }
    ;;
  esac
fi

# -- 2. Zero raw RFC1918 or ULA addresses in payload --------------------------
_ADDR_PAT='172\.1[6-9]\.\|172\.2[0-9]\.\|172\.3[01]\.\|10\.[0-9][0-9]*\.[0-9][0-9]*\.\|192\.168\.\|fd[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f][0-9a-f][0-9a-f]:'

_ADDR_HITS=$(find "$PAYLOAD" -type f \
  ! -name "*.orig" ! -name "*.orig.stale" ! -name "*.pre-tn*" \
  ! -name "*.gz" ! -name "*.tgz" ! -name "*.tar" \
  ! -name "*.zip" ! -name "*.db" ! -name "*.rrd" \
  ! -name "*.png" ! -name "*.jpg" ! -name "*.gif" \
  ! -path "*/e2guardian/*" ! -path "*/snort/*" \
  2> /dev/null | while IFS= read -r _af; do
  _hits=$(grep "$_ADDR_PAT" "$_af" 2> /dev/null \
    | grep -v "access-control:" | grep -v "private-address:" \
    | grep -v "socks block" \
    | grep -v "from: 10\." | grep -v "from: 172\." | grep -v "from: 192\." \
    | grep -v "to: 10\." | grep -v "to: 172\." | grep -v "to: 192\." || true)
  [ -n "$_hits" ] && printf "%s\n" "$_af"
done)

if [ -n "$_ADDR_HITS" ]; then
  err "RAW ADDRESS STRINGS REMAIN -- tokenization incomplete:"
  echo "$_ADDR_HITS" | while IFS= read -r _af; do
    err "  ${_af#$PAYLOAD/}:"
    grep -m 5 "$_ADDR_PAT" "$_af" 2> /dev/null | sed 's/^/      /'
  done
  err ""
  err "Recovery:"
  err "  1. Restore originals:"
  err "       find payload/ -name '*.orig' |"
  err "         xargs -I{} sh -c 'mv \"\$1\" \"\${1%.orig}\"' _ {}"
  err "  2. Verify /etc/tn-tokens matches the payload's interface names"
  err "  3. Re-run TN_TOKENIZE.sh"
  _FAIL=1
else
  ok "address invariant: zero raw RFC1918/ULA addresses in payload"
fi

# -- 3. No %%STALE_ADDR%% placeholders should reach commit --------------------
if find "$PAYLOAD" -type f ! -name "*.orig" 2> /dev/null \
  | xargs grep -lF "%%STALE_ADDR%%" 2> /dev/null | grep -qv "\.orig$"; then
  warn "%%STALE_ADDR%% placeholders remain -- audit before committing"
  _FAIL=1
fi

# -- 4. Interface name spot-check on snort-adjacent files ---------------------
for _sf in "$PAYLOAD/etc/rc.local" \
  "$PAYLOAD/usr/local/sbin/service_manager.sh"; do
  [ -f "$_sf" ] || continue
  if grep -qF "$D_INT_IF" "$_sf" 2> /dev/null \
    || grep -qF "$D_EXT_IF" "$_sf" 2> /dev/null; then
    warn "interface name still present in $(basename "$_sf")"
    grep -nF "${D_INT_IF}\|${D_EXT_IF}" "$_sf" | sed 's/^/    /'
    _FAIL=1
  else
    ok "$(basename "$_sf") fully tokenized"
  fi
done

# -- Summary ------------------------------------------------------------------
echo ""
if [ "$_FAIL" -eq 0 ]; then
  ok "Tokenization complete -- payload is clean."
  echo ""
  info "Stages run:"
  info "  Stage 1  canonical templates:  dhcpd, rad, sockd, unbound, pmacct"
  info "  Stage 2  exact substitution:   $_S2_FIXED files"
  info "  Stage 3  stale value sweep:    $_S3_FIXED files"
  info "  Stage 4  dhcpd.conf check:     passed"
  echo ""
  info "Tokens resolved by TN_SUBSTITUTE.sh on the target:"
  info "  %%INT_NET4_ADDR%%     bare network address  (e.g. 172.16.25.0)"
  info "  %%INT_BROADCAST4%%    broadcast address     (e.g. 172.16.25.255)"
  info "  %%INT_MASK4%%         subnet mask           (e.g. 255.255.255.0)"
  info "  %%DHCP_RANGE_START%%  first DHCP address    (e.g. 172.16.25.10)"
  info "  %%DHCP_RANGE_END%%    last DHCP address     (e.g. 172.16.25.245)"
  info "  %%MONITOR_V6_HOST%%   LAN ::254 host        (e.g. fdac:1019::254)"
  echo ""
  info "Original files backed up as .orig"
  info "Next: commit payload/, then run TN_SUBSTITUTE.sh on the target"
else
  warn "Tokenization incomplete -- review warnings above before committing"
  exit 1
fi

exit 0
