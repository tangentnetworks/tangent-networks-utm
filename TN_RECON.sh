#!/bin/ksh
# =============================================================================
# TN_RECON.sh -- Tangent Networks Lab Reconnaissance
# =============================================================================
# Run ONCE on a fully-configured, fully-working lab machine.
#
# What it does:
#   1. Ingests tn-interfaces if present, using it as authoritative ground
#      truth for topology (bridge/vether/wireless roles, interface names).
#   2. Discovers hardware/virt properties, MTU, capabilities using the
#      SAME logic as TN_NET_SET.sh -- but correctly handles bridge+vether
#      topologies where the LAN IP lives on a vether anchor, not a NIC.
#   3. Derives ALL tokens needed by TN_TOKENIZE.sh.
#   4. Writes /etc/tn-tokens -- pure KEY="value", ZERO embedded shell logic.
#
# Bridge/vether topology handled:
#   - LAN IP lives on vether0 (anchor), not bridge0 or em1/athn0 members.
#   - list_interfaces() previously excluded vether* -- fixed.
#   - Stage 3 now consults INT_IF and INT_IS_BRIDGE from tn-interfaces first,
#     falling back to live discovery that understands vether anchors.
#
# Usage: doas ksh TN_RECON.sh [--dry-run] [--force] [--no-mtu-probe]
#   --dry-run       Print what would be written; do not touch /etc/tn-tokens
#   --force         Overwrite an existing /etc/tn-tokens without prompting
#   --no-mtu-probe  Skip the 30-second WAN path-MTU probe (use 1500)
#
# VERSION : 3.0.0
# =============================================================================

set -e
umask 022

VERSION="3.0.0"
TN_TOKENS="/etc/tn-tokens"
TN_INTERFACES="/etc/tn-interfaces"
LOG_DIR="/var/log/tn"
LOG_FILE="${LOG_DIR}/recon.log"
MSS_SAFETY_MARGIN=40

PROBE_IPV4_1="1.1.1.1"; PROBE_IPV4_2="8.8.8.8"; PROBE_IPV4_3="9.9.9.9"
PROBE_IPV6_1="2606:4700:4700::1111"
PROBE_IPV6_2="2001:4860:4860::8888"
PROBE_IPV6_3="2620:fe::fe"

# =============================================================================
# ARGUMENT PARSING
# =============================================================================
DRY_RUN=0; FORCE=0; NO_MTU_PROBE=0
for _arg in "$@"; do
    case "$_arg" in
        --dry-run)      DRY_RUN=1      ;;
        --force)        FORCE=1        ;;
        --no-mtu-probe) NO_MTU_PROBE=1 ;;
        --help|-h)
            echo "Usage: $0 [--dry-run] [--force] [--no-mtu-probe]"
            exit 0 ;;
    esac
done

# =============================================================================
# TERMINAL / LOGGING
# =============================================================================
mkdir -p "$LOG_DIR"
if [ -t 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; NC=''
fi
_log() { printf "[%s] [%-4s] %s\n" "$(date '+%Y-%m-%d %H:%M:%S')" "$1" "$2" \
         >> "$LOG_FILE" 2>/dev/null || true; }
ok()   { printf "  ${GREEN}[OK]${NC}   %s\n" "$1"; _log "OK"   "$1"; }
err()  { printf "  ${RED}[ERR]${NC}  %s\n" "$1"; _log "ERR"  "$1"; }
warn() { printf "  ${YELLOW}[WARN]${NC} %s\n" "$1"; _log "WARN" "$1"; }
info() { printf "  ${CYAN}[INFO]${NC} %s\n" "$1"; _log "INFO" "$1"; }
print_header() {
    echo ""; echo "============================================================"
    echo "  $1"; echo "============================================================"
    _log "INFO" "=== $1 ==="
}
printf "\n=== TN_RECON v%s  %s ===\n" "$VERSION" \
    "$(date '+%Y-%m-%d %H:%M:%S')" >> "$LOG_FILE" 2>/dev/null || true

# =============================================================================
# PRE-FLIGHT
# =============================================================================
print_header "TN Reconnaissance v${VERSION}"
[ "$(id -u)" -ne 0 ]            && { err "Must run as root: doas ksh $0"; exit 1; }
[ "$(uname -s)" != "OpenBSD" ]  && { err "OpenBSD only"; exit 1; }

if [ -f "$TN_TOKENS" ] && [ "$FORCE" -eq 0 ] && [ "$DRY_RUN" -eq 0 ]; then
    warn "Existing $TN_TOKENS found."
    printf "  Overwrite? [y/N]: "; read _ow </dev/tty
    case "$_ow" in [Yy]*) info "Overwriting" ;; *) info "Aborted"; exit 0 ;; esac
fi

# =============================================================================
# STAGE -1: INGEST tn-interfaces (authoritative topology source)
# If present we use its values for interface roles, bridge membership, and
# pre-computed hardware flags.  Live discovery fills the rest or overrides
# stale values where needed (IP addresses, MTU).
# =============================================================================
print_header "Stage -1: Ingest tn-interfaces"

TIF_INT_IF=""; TIF_INT_IS_BRIDGE=0; TIF_INT_BRIDGE_IF=""
TIF_INT_BRIDGE_MEMBERS=""; TIF_INT_IF_BUNDLE=""
TIF_EXT_IF=""; TIF_INT_IFS=""
TIF_RAM_GB=""; TIF_CPU_CORES=""; TIF_CPU_ARCH=""; TIF_AES_NI=""
TIF_HAS_TCP4=""; TIF_HAS_UDP4=""; TIF_HAS_DIVERT=""
TIF_HAS_INET6=""; TIF_HAS_BRIDGE=""
TIF_WIFI_LAN_IF=""; TIF_INT_IS_WIRELESS=0
TIF_ATHN0_WIFI_SSID=""; TIF_ATHN0_WIFI_SECURITY=""
TIF_ATHN0_WIFI_BAND=""; TIF_ATHN0_WIFI_CHANNEL=0
TIF_MBUF_NMBCLUSTERS=""
TIF_JUMBO_MTU_SUPPORTED=""

_tif_get() { grep "^${1}=" "$TN_INTERFACES" 2>/dev/null | \
             cut -d'"' -f2 | head -1 || true; }

if [ -f "$TN_INTERFACES" ]; then
    info "Found $TN_INTERFACES -- loading topology"
    TIF_EXT_IF=$(           _tif_get EXT_IF)
    TIF_INT_IF=$(           _tif_get INT_IF)
    TIF_INT_IFS=$(          _tif_get INT_IFS)
    TIF_INT_IF_BUNDLE=$(    _tif_get INT_IF_BUNDLE)
    TIF_INT_IS_BRIDGE=$(    _tif_get INT_IS_BRIDGE)
    TIF_INT_BRIDGE_IF=$(    _tif_get INT_BRIDGE_IF)
    TIF_INT_BRIDGE_MEMBERS=$(_tif_get INT_BRIDGE_MEMBERS)
    TIF_INT_IS_WIRELESS=$(  _tif_get INT_IS_WIRELESS)
    TIF_WIFI_LAN_IF=$(      _tif_get WIFI_LAN_IF)
    TIF_ATHN0_WIFI_SSID=$(  _tif_get ATHN0_WIFI_SSID)
    TIF_ATHN0_WIFI_SECURITY=$(_tif_get ATHN0_WIFI_SECURITY)
    TIF_ATHN0_WIFI_BAND=$(  _tif_get ATHN0_WIFI_BAND)
    TIF_ATHN0_WIFI_CHANNEL=$(_tif_get ATHN0_WIFI_CHANNEL)
    TIF_RAM_GB=$(           _tif_get RAM_GB)
    TIF_CPU_CORES=$(        _tif_get CPU_CORES)
    TIF_CPU_ARCH=$(         _tif_get CPU_ARCH)
    TIF_AES_NI=$(           _tif_get AES_NI)
    TIF_HAS_TCP4=$(         _tif_get HAS_TCP4)
    TIF_HAS_UDP4=$(         _tif_get HAS_UDP4)
    TIF_HAS_DIVERT=$(       _tif_get HAS_DIVERT)
    TIF_HAS_INET6=$(        _tif_get HAS_INET6)
    TIF_HAS_BRIDGE=$(       _tif_get HAS_BRIDGE)
    TIF_MBUF_NMBCLUSTERS=$( _tif_get MBUF_NMBCLUSTERS)
    TIF_JUMBO_MTU_SUPPORTED=$(_tif_get JUMBO_MTU_SUPPORTED)
    [ -z "$TIF_INT_IS_BRIDGE"    ] && TIF_INT_IS_BRIDGE=0
    [ -z "$TIF_INT_IS_WIRELESS"  ] && TIF_INT_IS_WIRELESS=0
    [ -z "$TIF_ATHN0_WIFI_CHANNEL" ] && TIF_ATHN0_WIFI_CHANNEL=0
    ok "EXT_IF=${TIF_EXT_IF}  INT_IF=${TIF_INT_IF}  BRIDGE=${TIF_INT_IS_BRIDGE}"
    ok "INT_IFS=${TIF_INT_IFS}"
else
    warn "$TN_INTERFACES not found -- full live discovery mode"
fi

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

get_ip4()  { ifconfig "$1" 2>/dev/null | awk '/inet [0-9]/{print $2; exit}'; }
get_mask4() {
    _raw=$(ifconfig "$1" 2>/dev/null | awk '/inet [0-9]/{print $4; exit}')
    case "$_raw" in
        0x*)
            _h="${_raw#0x}"
            printf "%d.%d.%d.%d" \
                $(( (0x$_h >> 24) & 255 )) $(( (0x$_h >> 16) & 255 )) \
                $(( (0x$_h >>  8) & 255 )) $((  0x$_h         & 255 ))
            ;;
        [0-9]*.[0-9]*) echo "$_raw" ;;
        *) echo "255.255.255.0" ;;
    esac
}
mask4_to_cidr() {
    _cidr=0
    for _o in $(echo "$1" | tr '.' ' '); do
        case "$_o" in
            255) _cidr=$((_cidr+8)) ;; 254) _cidr=$((_cidr+7)) ;;
            252) _cidr=$((_cidr+6)) ;; 248) _cidr=$((_cidr+5)) ;;
            240) _cidr=$((_cidr+4)) ;; 224) _cidr=$((_cidr+3)) ;;
            192) _cidr=$((_cidr+2)) ;; 128) _cidr=$((_cidr+1)) ;;
            0)   ;;
        esac
    done
    echo "$_cidr"
}
ip4_network() {
    _a=$(echo "$1"|cut -d. -f1); _e=$(echo "$2"|cut -d. -f1)
    _b=$(echo "$1"|cut -d. -f2); _f=$(echo "$2"|cut -d. -f2)
    _c=$(echo "$1"|cut -d. -f3); _g=$(echo "$2"|cut -d. -f3)
    _d=$(echo "$1"|cut -d. -f4); _h=$(echo "$2"|cut -d. -f4)
    printf "%d.%d.%d.%d" \
        "$((_a&_e))" "$((_b&_f))" "$((_c&_g))" "$((_d&_h))"
}
ip4_broadcast() {
    _na=$(echo "$1"|cut -d. -f1); _ma=$(echo "$2"|cut -d. -f1)
    _nb=$(echo "$1"|cut -d. -f2); _mb=$(echo "$2"|cut -d. -f2)
    _nc=$(echo "$1"|cut -d. -f3); _mc=$(echo "$2"|cut -d. -f3)
    _nd=$(echo "$1"|cut -d. -f4); _md=$(echo "$2"|cut -d. -f4)
    printf "%d.%d.%d.%d" \
        "$((_na|(255-_ma)))" "$((_nb|(255-_mb)))" \
        "$((_nc|(255-_mc)))" "$((_nd|(255-_md)))"
}
get_ip6() {
    ifconfig "$1" 2>/dev/null | \
        awk '/inet6/ && !/fe80/ && !/autoconf temporary/ \
             {sub(/%.*$/,"",$2); print $2; exit}'
}
get_gw4()       { route -n show -inet  2>/dev/null | awk '/^default/{print $2; exit}'; }
get_gw6_clean() { route -n show -inet6 2>/dev/null | \
                  awk '/^default/{gsub(/%[a-z0-9]*/,"",$2); print $2; exit}'; }

is_pppoe()    { ifconfig "$1" 2>/dev/null | grep -q "pppoe"; }
is_wireless() { ifconfig "$1" 2>/dev/null | grep -q "ieee80211"; }
is_bridge()   { ifconfig "$1" 2>/dev/null | grep -q "^[[:space:]]*member:"; }
is_vether()   { case "$1" in vether*) return 0 ;; *) return 1 ;; esac; }
# trunk(4): trunkport lines look like "        trunkport em1 active ..."
is_trunk()    { ifconfig "$1" 2>/dev/null | grep -q "^[[:space:]]*trunkport"; }

# list_interfaces: return all candidate physical/virtual interfaces.
# CRITICAL FIX v3: vether* is no longer excluded here.
# vether is the correct IP anchor for bridge topologies and MUST be seen
# by the LAN discovery logic in Stage 3.
# lo, pflog, enc are still excluded (never carry user traffic).
list_interfaces() {
    ifconfig -a 2>/dev/null | awk -F: \
        '/^[a-z0-9]+:/{if ($1 !~ /^(lo|pflog|enc)/) print $1}'
}

classify_ip4() {
    case "$1" in
        100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*) echo "cgnat" ;;
        10.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|192.168.*) echo "private" ;;
        "") echo "none" ;;
        *) echo "public" ;;
    esac
}
classify_ip6() {
    case "$1" in
        fe80*) echo "linklocal" ;; fc*|fd*) echo "ula" ;;
        2*|3*) echo "gua" ;;     "") echo "none" ;;
        *) echo "none" ;;
    esac
}

ipv4_to_ula_prefix() {
    _o1=$(echo "$1"|cut -d. -f1); _o2=$(echo "$1"|cut -d. -f2); _o3=$(echo "$1"|cut -d. -f3)
    printf "fd%02x:%02x%02x::/64" "$_o1" "$_o2" "$_o3"
}
ipv4_to_ula_host() {
    _o1=$(echo "$1"|cut -d. -f1); _o2=$(echo "$1"|cut -d. -f2); _o3=$(echo "$1"|cut -d. -f3)
    printf "fd%02x:%02x%02x::1" "$_o1" "$_o2" "$_o3"
}
nat64_of_ip4() {
    _o1=$(echo "$1"|cut -d. -f1); _o2=$(echo "$1"|cut -d. -f2)
    _o3=$(echo "$1"|cut -d. -f3); _o4=$(echo "$1"|cut -d. -f4)
    printf "64:ff9b::%02x%02x:%02x%02x" "$_o1" "$_o2" "$_o3" "$_o4"
}

get_link_speed() {
    _s=$(ifconfig "$1" 2>/dev/null | grep "media:" | grep -oE "[0-9]+baseT" \
         | head -1 | sed 's/baseT//')
    [ -z "$_s" ] && _s=$(ifconfig "$1" 2>/dev/null | grep "media:" \
         | grep -oE "[0-9]+G" | head -1 | sed 's/G/000/')
    echo "${_s:-unknown}"
}
get_duplex() {
    ifconfig "$1" 2>/dev/null | grep -q "full-duplex" && echo "full" && return
    ifconfig "$1" 2>/dev/null | grep -q "half-duplex" && echo "half" && return
    echo "unknown"
}
get_offload_caps() {
    _c=""
    ifconfig "$1" 2>/dev/null | grep -q "tso4"      && _c="${_c}tso4,"
    ifconfig "$1" 2>/dev/null | grep -q "tso6"      && _c="${_c}tso6,"
    ifconfig "$1" 2>/dev/null | grep -q "csum"      && _c="${_c}csum,"
    ifconfig "$1" 2>/dev/null | grep -q "vlanhwtag" && _c="${_c}vlan,"
    echo "${_c%,}"
}
get_vlan_support() { ifconfig "$1" 2>/dev/null | grep -q "vlan" && echo "yes" || echo "no"; }
_has_cap()         { ifconfig "$1" 2>/dev/null | grep -q "$2" && echo "1" || echo "0"; }

# For a vether or bridge interface, report capabilities of its first physical
# member (the NIC that actually does DMA offload) rather than the virtual
# interface itself (which always reports no HW caps).
_real_if_for_caps() {
    _if="$1"
    # bridge: probe first physical member
    if is_bridge "$_if"; then
        _m=$(ifconfig "$_if" 2>/dev/null | awk '/member:/{print $2; exit}')
        [ -n "$_m" ] && { echo "$_m"; return; }
    fi
    # trunk(4) / bond: probe first active trunkport
    if is_trunk "$_if"; then
        _m=$(ifconfig "$_if" 2>/dev/null | awk '/trunkport/{print $2; exit}')
        [ -n "$_m" ] && { echo "$_m"; return; }
    fi
    # vether anchor: use known bridge members, or scan for the owning bridge
    if is_vether "$_if"; then
        if [ -n "$TIF_INT_BRIDGE_MEMBERS" ]; then
            echo "$TIF_INT_BRIDGE_MEMBERS" | awk '{print $1}'
            return
        fi
        if [ -n "$R_INT_BRIDGE_IF" ]; then
            _m=$(ifconfig "$R_INT_BRIDGE_IF" 2>/dev/null | \
                 awk '/member:/{print $2; exit}')
            [ -n "$_m" ] && { echo "$_m"; return; }
        fi
    fi
    echo "$_if"
}

detect_virt() {
    _v="bare-metal"; _cloud="none"; _region="unknown"
    if   dmesg 2>/dev/null | grep -qi "vmware\|vmxnet";    then _v="vmware"
    elif dmesg 2>/dev/null | grep -qi "virtio\|QEMU\|KVM"; then _v="kvm"
    elif dmesg 2>/dev/null | grep -qi "Hyper-V\|hvn[0-9]"; then _v="hyperv"
    elif dmesg 2>/dev/null | grep -qi "VirtualBox\|vbox";  then _v="virtualbox"
    elif dmesg 2>/dev/null | grep -qi "Xen";               then _v="xen"
    fi
    if dmesg 2>/dev/null | grep -qi "ec2\|amazon"; then
        _cloud="aws"
        _region=$(ftp -o - -S dont \
            "http://169.254.169.254/latest/meta-data/placement/region" \
            2>/dev/null | head -1 || true)
        _region="${_region:-unknown}"
    elif dmesg 2>/dev/null | grep -qi "google\|gce"; then _cloud="gcp"
    elif dmesg 2>/dev/null | grep -qi "azure\|hv";   then _cloud="azure"
    fi
    echo "$_v $_cloud ${_region:-unknown}"
}

_test_mtu4() {
    _p=$(($1-28))
    for _t in "$PROBE_IPV4_1" "$PROBE_IPV4_2" "$PROBE_IPV4_3"; do
        ping -D -c 2 -s "$_p" -w 3 "$_t" >/dev/null 2>&1 && return 0
    done; return 1
}
_test_mtu6() {
    _p=$(($1-48))
    for _t in "$PROBE_IPV6_1" "$PROBE_IPV6_2" "$PROBE_IPV6_3"; do
        ping6 -c 2 -s "$_p" -w 3 "$_t" >/dev/null 2>&1 && return 0
    done; return 1
}
probe_wan_mtu() {
    [ "$NO_MTU_PROBE" -eq 1 ] && { echo "1500"; return; }
    [ "$2" -eq 1 ]            && { echo "1492"; return; }
    [ -n "$3" ] && for _m in 1500 1492 1480 1472 1460 1440 1420 1400; do
        _test_mtu6 "$_m" && echo "$_m" && return
    done
    for _m in 1500 1492 1480 1472 1460 1440 1420 1400; do
        _test_mtu4 "$_m" && echo "$_m" && return
    done
    echo "1400"
}

# =============================================================================
# STAGE 0 -- HARDWARE ABSTRACTION LAYER
# Prefer tn-interfaces values where already computed; live-probe as fallback.
# =============================================================================
print_header "Stage 0: Hardware Abstraction"

_is_functional() {
    _v=$(sysctl -n "$1" 2>/dev/null || true)
    case "$_v" in [1-9]*) echo "1" ;; *) echo "0" ;; esac
}

# HAS_* flags: prefer tn-interfaces (already audited by TN_NET_SET.sh)
if [ -n "$TIF_HAS_TCP4" ]; then
    R_HAS_TCP4="$TIF_HAS_TCP4"; R_HAS_UDP4="$TIF_HAS_UDP4"
    R_HAS_DIVERT="$TIF_HAS_DIVERT"; R_HAS_INET6="$TIF_HAS_INET6"
    R_HAS_BRIDGE="$TIF_HAS_BRIDGE"
else
    R_HAS_TCP4=$(   _is_functional "net.inet.tcp.mssdflt")
    R_HAS_UDP4=$(   _is_functional "net.inet.udp.recvspace")
    R_HAS_DIVERT=$( _is_functional "net.inet.divert.recvspace")
    R_HAS_INET6=0;  sysctl net 2>/dev/null | grep -q "net.inet6"  && R_HAS_INET6=1
    R_HAS_BRIDGE=0; sysctl net 2>/dev/null | grep -q "net.bridge" && R_HAS_BRIDGE=1
fi

[ "$R_HAS_DIVERT" -eq 0 ] && {
    err "No divert(4) -- payload requires a GENERIC kernel"; exit 1; }

# RAM / CPU: prefer tn-interfaces, live-probe as fallback
if [ -n "$TIF_RAM_GB" ] && [ "$TIF_RAM_GB" -gt 0 ] 2>/dev/null; then
    R_RAM_GB="$TIF_RAM_GB"
else
    # Add 512 MiB rounding offset to account for firmware reservation
    _physmem=$(sysctl -n hw.physmem 2>/dev/null || echo 0)
    R_RAM_GB=$(((_physmem + 536870912) / 1073741824))
    [ "$R_RAM_GB" -eq 0 ] && R_RAM_GB=1
fi

if [ -n "$TIF_CPU_CORES" ] && [ "$TIF_CPU_CORES" -gt 0 ] 2>/dev/null; then
    R_CPU_CORES="$TIF_CPU_CORES"
else
    R_CPU_CORES=$(sysctl -n hw.ncpuonline 2>/dev/null || \
                  sysctl -n hw.ncpu 2>/dev/null || echo 1)
fi

if [ -n "$TIF_CPU_ARCH" ]; then
    R_CPU_ARCH="$TIF_CPU_ARCH"
else
    R_CPU_ARCH=$(sysctl -n hw.machine_arch 2>/dev/null || true)
    [ -z "$R_CPU_ARCH" ] && R_CPU_ARCH=$(uname -m 2>/dev/null || true)
    [ -z "$R_CPU_ARCH" ] && R_CPU_ARCH="unknown"
fi

if [ -n "$TIF_AES_NI" ]; then
    R_AES_NI="$TIF_AES_NI"
else
    R_AES_NI=$(sysctl -n hw.aesni 2>/dev/null || true)
    case "$R_AES_NI" in 0|1) ;; *) R_AES_NI="0" ;; esac
fi

if [ -n "$TIF_MBUF_NMBCLUSTERS" ] && [ "$TIF_MBUF_NMBCLUSTERS" -gt 0 ] 2>/dev/null; then
    R_MBUF_NMBCLUSTERS="$TIF_MBUF_NMBCLUSTERS"
else
    _has_10g=0
    dmesg 2>/dev/null | grep -qiE "^(ix|ixl|ixgbe|bxe|cxl)[0-9]" && _has_10g=1
    if   [ "$_has_10g" -eq 1 ] && [ "$R_RAM_GB" -ge 4 ]; then R_MBUF_NMBCLUSTERS=131072
    elif [ "$R_RAM_GB" -ge 8 ]; then R_MBUF_NMBCLUSTERS=65536
    elif [ "$R_RAM_GB" -ge 2 ]; then R_MBUF_NMBCLUSTERS=16384
    else                              R_MBUF_NMBCLUSTERS=8192
    fi
fi

if   [ "$R_RAM_GB" -ge 8 ]; then R_TCP_SENDSPACE=1048576; R_TCP_RECVSPACE=1048576
elif [ "$R_RAM_GB" -ge 4 ]; then R_TCP_SENDSPACE=524288;  R_TCP_RECVSPACE=524288
elif [ "$R_RAM_GB" -ge 2 ]; then R_TCP_SENDSPACE=262144;  R_TCP_RECVSPACE=262144
else                              R_TCP_SENDSPACE=131072;  R_TCP_RECVSPACE=131072
fi
ok "RAM=${R_RAM_GB}GB  CORES=${R_CPU_CORES}  ARCH=${R_CPU_ARCH}  AES_NI=${R_AES_NI}"

# =============================================================================
# STAGE 1 -- WAN INTERFACE
# tn-interfaces is authoritative if populated; route table as fallback.
# =============================================================================
print_header "Stage 1: WAN Interface"

if [ -n "$TIF_EXT_IF" ]; then
    R_EXT_IF="$TIF_EXT_IF"
    info "Using EXT_IF from tn-interfaces: $R_EXT_IF"
else
    R_EXT_IF=$(route -n show -inet 2>/dev/null | \
               awk '/^default/{print $NF; exit}' || true)
    if [ -z "$R_EXT_IF" ]; then
        R_EXT_IF=$(route -n show -inet6 2>/dev/null | \
                   awk '/^default/{gsub(/%[a-z0-9]*/,"",$NF); print $NF; exit}' || true)
    fi
fi
[ -z "$R_EXT_IF" ] && { err "No WAN interface -- configure lab fully first"; exit 1; }
ok "WAN: $R_EXT_IF"

# =============================================================================
# STAGE 2 -- WAN PROPERTIES
# =============================================================================
print_header "Stage 2: WAN Properties"
R_WAN_IS_PPPOE=0; R_WAN_TYPE="ethernet"; R_PPPOE_PARENT=""
if is_pppoe "$R_EXT_IF"; then
    R_WAN_TYPE="pppoe"; R_WAN_IS_PPPOE=1
    R_PPPOE_PARENT=$(ifconfig "$R_EXT_IF" 2>/dev/null | \
                     awk '/^[[:space:]]*dev:/{print $2; exit}')
elif is_wireless "$R_EXT_IF"; then R_WAN_TYPE="wireless"
fi
R_EXT_IP4=$(get_ip4 "$R_EXT_IF")
R_EXT_MASK4=$(get_mask4 "$R_EXT_IF")
R_EXT_GW4=$(get_gw4)
R_EXT_IP6=$(get_ip6 "$R_EXT_IF")
R_EXT_GW6=$(get_gw6_clean)
R_EXT_IP4_CLASS=$(classify_ip4 "$R_EXT_IP4")
R_EXT_IP6_CLASS=$(classify_ip6 "$R_EXT_IP6")
R_WAN_NET6=""
[ -n "$R_EXT_IP6" ] && R_WAN_NET6=$(echo "$R_EXT_IP6" | \
    awk -F: '{printf "%s:%s:%s:%s::/64\n",$1,$2,$3,$4}')
R_WAN_WIFI_SSID=""; R_WAN_WIFI_SECURITY=""
if [ "$R_WAN_TYPE" = "wireless" ]; then
    R_WAN_WIFI_SSID=$(    ifconfig "$R_EXT_IF" 2>/dev/null | awk '/nwid/{print $2; exit}')
    R_WAN_WIFI_SECURITY=$(ifconfig "$R_EXT_IF" 2>/dev/null | awk '/wpaprotos/{print $2; exit}')
fi
info "EXT_IP4=${R_EXT_IP4:-none}  GW4=${R_EXT_GW4:-none}"
info "EXT_IP6=${R_EXT_IP6:-none}  GW6=${R_EXT_GW6:-none}"

# =============================================================================
# STAGE 3 -- LAN INTERFACE (bridge/vether-aware)
#
# Priority order for INT_IF resolution:
#   1. INT_IF from tn-interfaces (most authoritative -- was set by TN_NET_SET.sh)
#   2. Live discovery: find interface carrying the LAN IP.
#      For bridge topologies this is the vether anchor (vether0), NOT bridge0
#      (which has no inet addr) and NOT the physical members.
#
# CRITICAL FIX v3:
#   - list_interfaces() no longer excludes vether* (was the primary crash path)
#   - Bridge member interfaces (em1, athn0) are noted but never promoted to
#     INT_IF; they carry no inet address and pf rules target the vether anchor.
#   - Bridge interface (bridge0) itself has no inet address; also not INT_IF.
# =============================================================================
print_header "Stage 3: LAN Interface"

R_INT_IF=""; R_INT_IFS=""

if [ -n "$TIF_INT_IF" ]; then
    # Validate the tn-interfaces value is actually up
    if ifconfig "$TIF_INT_IF" >/dev/null 2>&1; then
        R_INT_IF="$TIF_INT_IF"
        info "Using INT_IF from tn-interfaces: $R_INT_IF"
    else
        warn "$TIF_INT_IF from tn-interfaces not found in ifconfig -- falling back to discovery"
    fi
fi

if [ -z "$R_INT_IF" ]; then
    # Live discovery: walk all interfaces, skip WAN, skip loopback IP, find inet
    for _if in $(list_interfaces); do
        [ "$_if" = "$R_EXT_IF" ] && continue
        case "$_if" in lo*) continue ;; esac
        # Skip bare bridge interfaces -- they hold no inet address; the vether
        # anchor does.  A bridge with an inet addr is an unusual setup and would
        # still be found by the grep below.
        if is_bridge "$_if"; then
            _bip=$(ifconfig "$_if" 2>/dev/null | awk '/inet [0-9]/{print $2; exit}')
            [ -z "$_bip" ] && continue
        fi
        if ifconfig "$_if" 2>/dev/null | grep -q "inet "; then
            _if_ip=$(ifconfig "$_if" 2>/dev/null | awk '/inet [0-9]/{print $2; exit}')
            case "$_if_ip" in 127.*) continue ;; esac
            [ -z "$R_INT_IF" ] && R_INT_IF="$_if"
            R_INT_IFS="${R_INT_IFS:+$R_INT_IFS }$_if"
        fi
    done
fi

[ -z "$R_INT_IF" ] && {
    err "No LAN interface found."
    err "Expected a vether or physical interface with a non-loopback inet addr."
    err "Ensure TN_NET_SET.sh has run and tn-interfaces is present."
    exit 1
}

# INT_IFS: prefer tn-interfaces (it has the full bundle: bridge0 em1 athn0 vether0)
if [ -n "$TIF_INT_IFS" ]; then
    R_INT_IFS="$TIF_INT_IFS"
    info "INT_IFS from tn-interfaces: $R_INT_IFS"
elif [ -z "$R_INT_IFS" ]; then
    R_INT_IFS="$R_INT_IF"
fi
ok "LAN anchor: $R_INT_IF  (full bundle: $R_INT_IFS)"

# Bridge topology metadata
R_INT_IS_BRIDGE=${TIF_INT_IS_BRIDGE:-0}
R_INT_BRIDGE_IF="${TIF_INT_BRIDGE_IF:-}"
R_INT_IF_BUNDLE="${TIF_INT_IF_BUNDLE:-$R_INT_IF}"

# If bridge info wasn't in tn-interfaces, detect live.
# Three cases:
#   (a) INT_IF is itself a bridge (unusual but valid).
#   (b) INT_IF is a vether anchor -- the bridge is a sibling interface whose
#       member list includes INT_IF.  is_bridge(vether0) returns false so we
#       must scan bridge* interfaces explicitly.
#   (c) No bridge at all -- flat topology, INT_IS_BRIDGE stays 0.
if [ "$R_INT_IS_BRIDGE" -eq 0 ]; then
    if [ -n "$TIF_INT_BRIDGE_IF" ] && is_bridge "$TIF_INT_BRIDGE_IF"; then
        # tn-interfaces named a bridge but INT_IS_BRIDGE wasn't set
        R_INT_IS_BRIDGE=1
    elif is_bridge "$R_INT_IF"; then
        # INT_IF is itself the bridge
        R_INT_IS_BRIDGE=1; R_INT_BRIDGE_IF="$R_INT_IF"
    elif is_vether "$R_INT_IF"; then
        # INT_IF is a vether anchor -- scan for the bridge that owns it
        for _br in $(ifconfig -a 2>/dev/null | awk -F: '/^bridge[0-9]+:/{print $1}'); do
            if ifconfig "$_br" 2>/dev/null | grep -q "member: ${R_INT_IF}"; then
                R_INT_IS_BRIDGE=1; R_INT_BRIDGE_IF="$_br"
                break
            fi
        done
    fi
fi

R_INT_BRIDGE_MEMBERS="${TIF_INT_BRIDGE_MEMBERS:-}"
if [ -z "$R_INT_BRIDGE_MEMBERS" ] && [ "$R_INT_IS_BRIDGE" -eq 1 ] && \
   [ -n "$R_INT_BRIDGE_IF" ]; then
    R_INT_BRIDGE_MEMBERS=$(ifconfig "$R_INT_BRIDGE_IF" 2>/dev/null | \
        awk '/member:/{print $2}' | tr '\n' ' ' | sed 's/ $//')
fi

ok "IS_BRIDGE=$R_INT_IS_BRIDGE  BRIDGE_IF=${R_INT_BRIDGE_IF:-n/a}  MEMBERS=${R_INT_BRIDGE_MEMBERS:-n/a}"

# Trunk/bond topology detection (trunk(4) -- LACP, failover, roundrobin modes)
# In a trunk topology INT_IF=trunk0 directly carries the inet address;
# the physical trunkports (em1, em2) are subordinate and carry no inet addr.
R_INT_IS_TRUNK=0
R_INT_TRUNK_MEMBERS=""
if [ "$R_INT_IS_BRIDGE" -eq 0 ]; then
    if is_trunk "$R_INT_IF"; then
        R_INT_IS_TRUNK=1
        R_INT_TRUNK_MEMBERS=$(ifconfig "$R_INT_IF" 2>/dev/null | \
            awk '/trunkport/{print $2}' | tr '\n' ' ' | awk '{$1=$1; print}')
    fi
fi
ok "IS_TRUNK=$R_INT_IS_TRUNK  MEMBERS=${R_INT_TRUNK_MEMBERS:-n/a}"

# Wireless metadata (from tn-interfaces, no need to re-probe athn0)
R_INT_IS_WIRELESS=${TIF_INT_IS_WIRELESS:-0}
R_INT_WIFI_SSID="${TIF_ATHN0_WIFI_SSID:-}"
R_INT_WIFI_SECURITY="${TIF_ATHN0_WIFI_SECURITY:-}"
R_INT_WIFI_BAND="${TIF_ATHN0_WIFI_BAND:-}"
R_INT_WIFI_CHANNEL="${TIF_ATHN0_WIFI_CHANNEL:-0}"
R_WIFI_LAN_IF="${TIF_WIFI_LAN_IF:-}"

# If tn-interfaces had nothing, fall back to live probe on INT_IF
if [ "$R_INT_IS_WIRELESS" -eq 0 ] && is_wireless "$R_INT_IF"; then
    R_INT_IS_WIRELESS=1
    R_INT_WIFI_SSID=$(   ifconfig "$R_INT_IF" 2>/dev/null | awk '/nwid/{print $2; exit}')
    R_INT_WIFI_CHANNEL=$(ifconfig "$R_INT_IF" 2>/dev/null | awk '/chan/{print $4; exit}')
    R_INT_WIFI_BAND="2.4ghz"
    [ "${R_INT_WIFI_CHANNEL:-0}" -ge 36 ] && R_INT_WIFI_BAND="5ghz"
fi

# =============================================================================
# STAGE 4 -- LAN ADDRESSES AND ALL DERIVED TOKENS
# =============================================================================
print_header "Stage 4: LAN Addresses and Derived Tokens"

R_INT_IP4=$(get_ip4 "$R_INT_IF")
[ -z "$R_INT_IP4" ] && { err "$R_INT_IF has no IPv4 address"; exit 1; }
case "$R_INT_IP4" in
    127.*)
        err "INT_IP4 resolved to loopback ($R_INT_IP4) -- wrong interface."
        exit 1
        ;;
esac

R_INT_MASK4=$(get_mask4 "$R_INT_IF")
R_INT_CIDR4=$(mask4_to_cidr "$R_INT_MASK4")
R_INT_NET4_ADDR=$(ip4_network "$R_INT_IP4" "$R_INT_MASK4")
R_INT_NET4="${R_INT_NET4_ADDR}/${R_INT_CIDR4}"
R_INT_BROADCAST4=$(ip4_broadcast "$R_INT_NET4_ADDR" "$R_INT_MASK4")

# DHCP range: .10 to .245 within the subnet.
# Use the network address prefix, not the host IP prefix, to handle any
# host address within the subnet correctly (e.g. .1, .2, .254 all work).
_pfx3=$(echo "$R_INT_NET4_ADDR" | cut -d. -f1-3)
R_DHCP_RANGE_START="${_pfx3}.10"
R_DHCP_RANGE_END="${_pfx3}.245"

R_HOSTNAME_EXT="hostname.${R_EXT_IF}"
R_HOSTNAME_INT="hostname.${R_INT_IF}"

R_INT_IP6=$(get_ip6 "$R_INT_IF")
R_INT_CIDR6="64"
R_INT_NET6=""
if [ -n "$R_INT_IP6" ]; then
    # Derive /64 network from the interface IPv6 address.
    # Cannot use %%::* parameter expansion: it silently produces a wrong
    # result for fully-expanded addresses that contain no '::'.
    # awk splits on ':' and reassembles the first 4 groups, which are the
    # /64 network bits for any GUA or ULA assigned to a LAN interface.
    # Works on both compressed (fd10:203::1) and full (2001:db8:0:1::1) forms.
    R_INT_NET6=$(echo "$R_INT_IP6" | awk -F: '{printf "%s:%s:%s:%s::/64\n",$1,$2,$3,$4}')
else
    R_INT_IP6=$(ipv4_to_ula_host "$R_INT_IP4")
    R_INT_NET6=$(ipv4_to_ula_prefix "$R_INT_IP4")
    warn "No IPv6 on $R_INT_IF -- ULA derived from IPv4: $R_INT_IP6"
fi

_net6_pfx="${R_INT_NET6%::/64}"
R_MONITOR_V6_HOST="${_net6_pfx}::254"
R_NAT64_INT_IP4=$(nat64_of_ip4 "$R_INT_IP4")

ok "INT_IP4=$R_INT_IP4  MASK=$R_INT_MASK4  CIDR=$R_INT_CIDR4"
ok "INT_NET4=$R_INT_NET4  NET4_ADDR=$R_INT_NET4_ADDR  BCAST=$R_INT_BROADCAST4"
ok "DHCP=$R_DHCP_RANGE_START .. $R_DHCP_RANGE_END"
ok "INT_IP6=$R_INT_IP6  NET6=$R_INT_NET6"
ok "MONITOR_V6_HOST=$R_MONITOR_V6_HOST  NAT64=$R_NAT64_INT_IP4"

# =============================================================================
# STAGE 5 -- DEPLOYMENT CLASSIFICATION
# =============================================================================
print_header "Stage 5: Classification"
case "$R_EXT_IP4_CLASS" in
    cgnat|private) R_DEPLOY_MODE="cgnat_home" ;;
    public)        R_DEPLOY_MODE="dedicated"  ;;
    none) [ -n "$R_EXT_IP6" ] && R_DEPLOY_MODE="ipv6_only" || R_DEPLOY_MODE="unknown" ;;
    *)    R_DEPLOY_MODE="unknown" ;;
esac
case "$R_EXT_IP6_CLASS" in
    gua)  R_IPV6_MODE="native" ;;
    ula)  R_IPV6_MODE="nat66"  ;;
    none) [ "$R_DEPLOY_MODE" != "ipv6_only" ] && R_IPV6_MODE="nat64" || R_IPV6_MODE="none" ;;
    *)    R_IPV6_MODE="none" ;;
esac
ok "DEPLOY=$R_DEPLOY_MODE  IPV6=$R_IPV6_MODE"

# =============================================================================
# STAGE 6 -- MTU / MSS
# =============================================================================
print_header "Stage 6: MTU/MSS"
if [ "$NO_MTU_PROBE" -eq 1 ]; then
    info "MTU probe skipped (--no-mtu-probe)"
else
    info "Probing WAN path MTU (up to 30 sec)..."
fi
R_WAN_MTU=$(probe_wan_mtu "$R_EXT_IF" "$R_WAN_IS_PPPOE" "$R_EXT_GW6")
R_LAN_MTU="1500"
R_WAN_MSS4=$((R_WAN_MTU - 40 - MSS_SAFETY_MARGIN))
R_WAN_MSS6=$((R_WAN_MTU - 60 - MSS_SAFETY_MARGIN))
R_LAN_MSS4=$((1500     - 40 - MSS_SAFETY_MARGIN))
R_LAN_MSS6=$((1500     - 60 - MSS_SAFETY_MARGIN))
ok "WAN_MTU=$R_WAN_MTU  WAN_MSS4=$R_WAN_MSS4  WAN_MSS6=$R_WAN_MSS6"

# =============================================================================
# STAGE 7 -- NIC CAPABILITIES
# For bridge/vether topologies we probe the underlying physical member NIC
# for hardware offload capabilities, not the virtual interface itself.
# =============================================================================
print_header "Stage 7: NIC Capabilities"
R_WAN_SPEED=$(get_link_speed "$R_EXT_IF"); R_WAN_DUPLEX=$(get_duplex "$R_EXT_IF")
R_WAN_OFFLOAD=$(get_offload_caps "$R_EXT_IF"); R_WAN_VLAN=$(get_vlan_support "$R_EXT_IF")

# Resolve the real physical interface backing INT_IF for capability queries
_lan_phys=$(_real_if_for_caps "$R_INT_IF")
info "LAN capability probe target: $_lan_phys (anchor: $R_INT_IF)"
R_LAN_SPEED=$(get_link_speed "$_lan_phys"); R_LAN_DUPLEX=$(get_duplex "$_lan_phys")
R_LAN_OFFLOAD=$(get_offload_caps "$_lan_phys"); R_LAN_VLAN=$(get_vlan_support "$_lan_phys")

R_WAN_HAS_TSO4=$(_has_cap "$R_EXT_IF"  "tso4"); R_WAN_HAS_TSO6=$(_has_cap "$R_EXT_IF"  "tso6")
R_WAN_HAS_LRO=$( _has_cap "$R_EXT_IF"  "lro");  R_WAN_HAS_VLAN_HW=$(_has_cap "$R_EXT_IF" "vlanhwtag")
R_LAN_HAS_TSO4=$(_has_cap "$_lan_phys" "tso4"); R_LAN_HAS_TSO6=$(_has_cap "$_lan_phys" "tso6")
R_LAN_HAS_LRO=$( _has_cap "$_lan_phys" "lro");  R_LAN_HAS_VLAN_HW=$(_has_cap "$_lan_phys" "vlanhwtag")
R_WAN_IS_10G=0; ifconfig "$R_EXT_IF"  2>/dev/null | grep -qi "10Gbase\|10000base" && R_WAN_IS_10G=1
R_LAN_IS_10G=0; ifconfig "$_lan_phys" 2>/dev/null | grep -qi "10Gbase\|10000base" && R_LAN_IS_10G=1

# Jumbo MTU: prefer tn-interfaces value; test on the physical NIC, not vether
if [ -n "$TIF_JUMBO_MTU_SUPPORTED" ]; then
    R_JUMBO_MTU_SUPPORTED="$TIF_JUMBO_MTU_SUPPORTED"
else
    R_JUMBO_MTU_SUPPORTED=0
    _orig_mtu=$(ifconfig "$_lan_phys" 2>/dev/null | awk '/mtu/{print $NF}')
    if ifconfig "$_lan_phys" mtu 9000 >/dev/null 2>&1; then
        R_JUMBO_MTU_SUPPORTED=1
        ifconfig "$_lan_phys" mtu "${_orig_mtu:-1500}" >/dev/null 2>&1
    fi
fi
ok "WAN NIC caps: TSO4=$R_WAN_HAS_TSO4 TSO6=$R_WAN_HAS_TSO6 LRO=$R_WAN_HAS_LRO"
ok "LAN NIC caps: TSO4=$R_LAN_HAS_TSO4 TSO6=$R_LAN_HAS_TSO6 LRO=$R_LAN_HAS_LRO JUMBO=$R_JUMBO_MTU_SUPPORTED"

# =============================================================================
# STAGE 8 -- TOPOLOGY
# =============================================================================
print_header "Stage 8: Topology"
R_WAN_COUNT=0; _wan_list=""
for _wif in $(route -n show -inet 2>/dev/null | awk '/^default/{print $NF}' | sort -u); do
    case "$_wif" in lo*|enc*|pflog*) continue ;; esac
    _wan_list="${_wan_list:+$_wan_list }$_wif"
    R_WAN_COUNT=$((R_WAN_COUNT+1))
done
[ "$R_WAN_COUNT" -eq 0 ] && R_WAN_COUNT=1
R_MULTI_WAN_DETECTED=0; R_DUAL_ISP=0; R_EXT_IF_SECONDARY=""; R_DUAL_ISP_MODE=""
if [ "$R_WAN_COUNT" -ge 2 ]; then
    R_MULTI_WAN_DETECTED=1; R_DUAL_ISP=1; R_DUAL_ISP_MODE="failover"
    for _wif in $_wan_list; do
        [ "$_wif" = "$R_EXT_IF" ] && continue
        R_EXT_IF_SECONDARY="${R_EXT_IF_SECONDARY:+$R_EXT_IF_SECONDARY }$_wif"
    done
fi

# LAN count: count distinct inet-bearing non-WAN interfaces.
# vether, bridge members, physical LAN NICs all counted correctly now.
R_LAN_COUNT=0
for _lif in $(list_interfaces); do
    [ "$_lif" = "$R_EXT_IF" ] && continue
    # Don't double-count bridge members: if a bridge is present, count only
    # the vether anchor (the bridge itself has no inet addr and members are
    # subordinate)
    if [ "$R_INT_IS_BRIDGE" -eq 1 ] && [ -n "$R_INT_BRIDGE_MEMBERS" ]; then
        _is_member=0
        for _m in $R_INT_BRIDGE_MEMBERS; do
            [ "$_lif" = "$_m" ] && _is_member=1 && break
        done
        [ "$_is_member" -eq 1 ] && continue
        [ "$_lif" = "$R_INT_BRIDGE_IF" ] && continue
    fi
    # Skip trunk members -- they carry no inet addr themselves but appear in
    # list_interfaces; counting them would inflate LAN_COUNT incorrectly
    if [ "$R_INT_IS_TRUNK" -eq 1 ] && [ -n "$R_INT_TRUNK_MEMBERS" ]; then
        _is_trunkport=0
        for _m in $R_INT_TRUNK_MEMBERS; do
            [ "$_lif" = "$_m" ] && _is_trunkport=1 && break
        done
        [ "$_is_trunkport" -eq 1 ] && continue
    fi
    ifconfig "$_lif" 2>/dev/null | grep -q "inet " && R_LAN_COUNT=$((R_LAN_COUNT+1))
done
[ "$R_LAN_COUNT" -eq 0 ] && R_LAN_COUNT=1
ok "WAN_COUNT=$R_WAN_COUNT  LAN_COUNT=$R_LAN_COUNT  MULTI_WAN=$R_MULTI_WAN_DETECTED"

# =============================================================================
# STAGE 9 -- VIRTUAL INFRASTRUCTURE
# =============================================================================
print_header "Stage 9: Virtual Infrastructure"
_virt=$(detect_virt)
R_VIRT_ENV=$(echo "$_virt" | awk '{print $1}')
R_CLOUD_PROVIDER=$(echo "$_virt" | awk '{print $2}')
R_CLOUD_REGION=$(echo "$_virt" | awk '{print $3}')
ok "VIRT=$R_VIRT_ENV  CLOUD=$R_CLOUD_PROVIDER  REGION=$R_CLOUD_REGION"

# =============================================================================
# STAGE 10 -- WRITE /etc/tn-tokens
# CONTRACT: . /etc/tn-tokens must behave like reading a key-value store.
# All variables fully resolved above. No shell logic in the output file.
# =============================================================================
print_header "Stage 10: Writing $TN_TOKENS"

if [ "$DRY_RUN" -eq 1 ]; then
    info "DRY RUN -- would write $TN_TOKENS with discovered values"
    info "EXT_IF=$R_EXT_IF  INT_IF=$R_INT_IF"
    info "INT_IFS=$R_INT_IFS"
    info "INT_IS_BRIDGE=$R_INT_IS_BRIDGE  BRIDGE_IF=${R_INT_BRIDGE_IF:-n/a}"
    info "INT_BRIDGE_MEMBERS=${R_INT_BRIDGE_MEMBERS:-n/a}"
    info "INT_IP4=$R_INT_IP4  INT_NET4=$R_INT_NET4"
    info "INT_IP6=$R_INT_IP6  INT_NET6=$R_INT_NET6"
    exit 0
fi

{
printf '# /etc/tn-tokens -- Tangent Networks Token Map\n'
printf '# Written by TN_RECON.sh v%s on %s\n' "$VERSION" "$(date)"
printf '# Source: %s / %s\n' "$(hostname)" "$(uname -m)"
printf '#\n'
printf '# CONTRACT: Only KEY="value" assignments. No if/for/while/case.\n'
printf '# =============================================================================\n'
printf '\n'
printf 'EXT_IF="%s"\n'               "$R_EXT_IF"
printf 'INT_IF="%s"\n'               "$R_INT_IF"
printf 'INT_IFS="%s"\n'              "$R_INT_IFS"
printf 'INT_IF_BUNDLE="%s"\n'        "$R_INT_IF_BUNDLE"
printf 'INT_IS_BRIDGE="%s"\n'        "$R_INT_IS_BRIDGE"
printf 'INT_BRIDGE_IF="%s"\n'        "$R_INT_BRIDGE_IF"
printf 'INT_BRIDGE_MEMBERS="%s"\n'   "$R_INT_BRIDGE_MEMBERS"
printf 'INT_IS_TRUNK="%s"\n'         "$R_INT_IS_TRUNK"
printf 'INT_TRUNK_MEMBERS="%s"\n'    "$R_INT_TRUNK_MEMBERS"
printf 'HOSTNAME_EXT="%s"\n'         "$R_HOSTNAME_EXT"
printf 'HOSTNAME_INT="%s"\n'         "$R_HOSTNAME_INT"
printf 'WAN_TYPE="%s"\n'             "$R_WAN_TYPE"
printf 'WAN_IS_PPPOE="%s"\n'         "$R_WAN_IS_PPPOE"
printf 'PPPOE_PARENT="%s"\n'         "$R_PPPOE_PARENT"
printf 'WAN_WIFI_SSID="%s"\n'        "$R_WAN_WIFI_SSID"
printf 'WAN_WIFI_SECURITY="%s"\n'    "$R_WAN_WIFI_SECURITY"
printf 'EXT_IP4="%s"\n'              "$R_EXT_IP4"
printf 'EXT_MASK4="%s"\n'            "$R_EXT_MASK4"
printf 'EXT_GW4="%s"\n'              "$R_EXT_GW4"
printf 'EXT_IP4_CLASS="%s"\n'        "$R_EXT_IP4_CLASS"
printf 'EXT_IP6="%s"\n'              "$R_EXT_IP6"
printf 'EXT_GW6="%s"\n'              "$R_EXT_GW6"
printf 'EXT_IP6_CLASS="%s"\n'        "$R_EXT_IP6_CLASS"
printf 'WAN_NET6="%s"\n'             "$R_WAN_NET6"
printf 'INT_IP4="%s"\n'              "$R_INT_IP4"
printf 'INT_MASK4="%s"\n'            "$R_INT_MASK4"
printf 'INT_NET4="%s"\n'             "$R_INT_NET4"
printf 'INT_CIDR4="%s"\n'            "$R_INT_CIDR4"
printf 'INT_IP6="%s"\n'              "$R_INT_IP6"
printf 'INT_NET6="%s"\n'             "$R_INT_NET6"
printf 'INT_CIDR6="%s"\n'            "$R_INT_CIDR6"
printf 'INT_NET4_ADDR="%s"\n'        "$R_INT_NET4_ADDR"
printf 'INT_BROADCAST4="%s"\n'       "$R_INT_BROADCAST4"
printf 'DHCP_RANGE_START="%s"\n'     "$R_DHCP_RANGE_START"
printf 'DHCP_RANGE_END="%s"\n'       "$R_DHCP_RANGE_END"
printf 'DHCPD_FQDN="tangent.localdomain"\n'
printf 'INT_IF4="%s"\n'              "$R_INT_IP4"
printf 'DHCPD_SUBNET="%s"\n'         "$R_INT_NET4_ADDR"
printf 'DHCPD_NETMASK="%s"\n'        "$R_INT_MASK4"
printf 'DHCPD_BROADCAST="%s"\n'      "$R_INT_BROADCAST4"
printf 'DHCPD_INT_IF4_START_ADDR="%s"\n' "$R_DHCP_RANGE_START"
printf 'DHCPD_INT_IF4_END_ADDR="%s"\n'   "$R_DHCP_RANGE_END"
printf 'MONITOR_V6_HOST="%s"\n'      "$R_MONITOR_V6_HOST"
printf 'NAT64_INT_IP4="%s"\n'        "$R_NAT64_INT_IP4"
printf 'NAT64_PFX="64:ff9b::/96"\n'
printf 'INT_IS_WIRELESS="%s"\n'      "$R_INT_IS_WIRELESS"
printf 'INT_WIFI_SSID="%s"\n'        "$R_INT_WIFI_SSID"
printf 'INT_WIFI_SECURITY="%s"\n'    "$R_INT_WIFI_SECURITY"
printf 'INT_WIFI_BAND="%s"\n'        "$R_INT_WIFI_BAND"
printf 'INT_WIFI_CHANNEL="%s"\n'     "$R_INT_WIFI_CHANNEL"
printf 'WIFI_LAN_IF="%s"\n'          "$R_WIFI_LAN_IF"
printf 'WAN_MTU="%s"\n'              "$R_WAN_MTU"
printf 'LAN_MTU="%s"\n'              "$R_LAN_MTU"
printf 'WAN_MSS4="%s"\n'             "$R_WAN_MSS4"
printf 'WAN_MSS6="%s"\n'             "$R_WAN_MSS6"
printf 'LAN_MSS4="%s"\n'             "$R_LAN_MSS4"
printf 'LAN_MSS6="%s"\n'             "$R_LAN_MSS6"
printf 'PF_MAX_MSS4_EXT_IF="%s"\n'   "$R_WAN_MSS4"
printf 'PF_MAX_MSS6_EXT_IF="%s"\n'   "$R_WAN_MSS6"
printf 'PF_MAX_MSS4_INT_IF="%s"\n'   "$R_LAN_MSS4"
printf 'PF_MAX_MSS6_INT_IF="%s"\n'   "$R_LAN_MSS6"
printf 'DEPLOY_MODE="%s"\n'          "$R_DEPLOY_MODE"
printf 'IPV6_MODE="%s"\n'            "$R_IPV6_MODE"
printf 'WAN_COUNT="%s"\n'            "$R_WAN_COUNT"
printf 'LAN_COUNT="%s"\n'            "$R_LAN_COUNT"
printf 'MULTI_WAN_DETECTED="%s"\n'   "$R_MULTI_WAN_DETECTED"
printf 'DUAL_ISP="%s"\n'             "$R_DUAL_ISP"
printf 'EXT_IF_SECONDARY="%s"\n'     "$R_EXT_IF_SECONDARY"
printf 'DUAL_ISP_MODE="%s"\n'        "$R_DUAL_ISP_MODE"
printf 'VIRT_ENV="%s"\n'             "$R_VIRT_ENV"
printf 'CLOUD_PROVIDER="%s"\n'       "$R_CLOUD_PROVIDER"
printf 'CLOUD_REGION="%s"\n'         "$R_CLOUD_REGION"
printf 'WAN_SPEED="%s"\n'            "$R_WAN_SPEED"
printf 'WAN_DUPLEX="%s"\n'           "$R_WAN_DUPLEX"
printf 'WAN_OFFLOAD="%s"\n'          "$R_WAN_OFFLOAD"
printf 'WAN_VLAN="%s"\n'             "$R_WAN_VLAN"
printf 'LAN_SPEED="%s"\n'            "$R_LAN_SPEED"
printf 'LAN_DUPLEX="%s"\n'           "$R_LAN_DUPLEX"
printf 'LAN_OFFLOAD="%s"\n'          "$R_LAN_OFFLOAD"
printf 'LAN_VLAN="%s"\n'             "$R_LAN_VLAN"
printf 'HAS_TCP4="%s"\n'             "$R_HAS_TCP4"
printf 'HAS_UDP4="%s"\n'             "$R_HAS_UDP4"
printf 'HAS_DIVERT="%s"\n'           "$R_HAS_DIVERT"
printf 'HAS_INET6="%s"\n'            "$R_HAS_INET6"
printf 'HAS_BRIDGE="%s"\n'           "$R_HAS_BRIDGE"
printf 'RAM_GB="%s"\n'               "$R_RAM_GB"
printf 'CPU_CORES="%s"\n'            "$R_CPU_CORES"
printf 'CPU_ARCH="%s"\n'             "$R_CPU_ARCH"
printf 'AES_NI="%s"\n'               "$R_AES_NI"
printf 'MBUF_NMBCLUSTERS="%s"\n'     "$R_MBUF_NMBCLUSTERS"
printf 'TCP_SENDSPACE="%s"\n'        "$R_TCP_SENDSPACE"
printf 'TCP_RECVSPACE="%s"\n'        "$R_TCP_RECVSPACE"
printf 'WAN_HAS_TSO4="%s"\n'         "$R_WAN_HAS_TSO4"
printf 'WAN_HAS_TSO6="%s"\n'         "$R_WAN_HAS_TSO6"
printf 'WAN_HAS_LRO="%s"\n'          "$R_WAN_HAS_LRO"
printf 'WAN_HAS_VLAN_HW="%s"\n'      "$R_WAN_HAS_VLAN_HW"
printf 'WAN_IS_10G="%s"\n'           "$R_WAN_IS_10G"
printf 'LAN_HAS_TSO4="%s"\n'         "$R_LAN_HAS_TSO4"
printf 'LAN_HAS_TSO6="%s"\n'         "$R_LAN_HAS_TSO6"
printf 'LAN_HAS_LRO="%s"\n'          "$R_LAN_HAS_LRO"
printf 'LAN_HAS_VLAN_HW="%s"\n'      "$R_LAN_HAS_VLAN_HW"
printf 'LAN_IS_10G="%s"\n'           "$R_LAN_IS_10G"
printf 'JUMBO_MTU_SUPPORTED="%s"\n'  "$R_JUMBO_MTU_SUPPORTED"
printf 'CERT_ORG=""\n'
printf 'CERT_OU=""\n'
printf 'CERT_CN=""\n'
printf 'CERT_COUNTRY=""\n'
printf 'CERT_STATE=""\n'
printf 'CERT_CITY=""\n'
printf 'CERT_EMAIL=""\n'
printf 'TLS_CERT=""\n'
printf 'TLS_KEY=""\n'
printf 'RULES_TYPE=""\n'
printf 'OINK_CODE=""\n'
printf 'OINK_URL=""\n'
printf 'PUBLIC_DOMAIN=""\n'
} > "$TN_TOKENS"

chmod 640 "$TN_TOKENS"
chown root:wheel "$TN_TOKENS"
ok "Written: $TN_TOKENS"

# =============================================================================
# VERIFICATION
# =============================================================================
print_header "Verification"

_missing=0
for _tok in EXT_IF INT_IF INT_IP4 INT_NET4 INT_MASK4 INT_NET4_ADDR \
            INT_BROADCAST4 INT_IP6 INT_NET6 \
            MONITOR_V6_HOST NAT64_INT_IP4 WAN_MTU DEPLOY_MODE; do
    _val=$(grep "^${_tok}=" "$TN_TOKENS" | cut -d'"' -f2)
    if [ -z "$_val" ]; then
        warn "Token $_tok is empty -- check interface configuration"
        _missing=$((_missing+1))
    fi
done

info "Tallying service config tokens..."
for _tok in \
    DHCPD_FQDN INT_IF4 DHCPD_SUBNET DHCPD_NETMASK DHCPD_BROADCAST \
    DHCPD_INT_IF4_START_ADDR DHCPD_INT_IF4_END_ADDR \
    DHCP_RANGE_START DHCP_RANGE_END \
    CPU_CORES INT_IS_BRIDGE INT_BRIDGE_MEMBERS; do
    _val=$(grep "^${_tok}=" "$TN_TOKENS" | cut -d'"' -f2)
    if [ -z "$_val" ] && [ "$_tok" != "INT_BRIDGE_MEMBERS" ]; then
        warn "Service token $_tok is empty"
        _missing=$((_missing+1))
    else
        ok "  ${_tok}=\"${_val}\""
    fi
done

if grep -qE "^[[:space:]]*(if|for|while|case)[[:space:]]" "$TN_TOKENS"; then
    err "FATAL: Shell control flow found in $TN_TOKENS -- file is corrupt"
    grep -nE "^[[:space:]]*(if|for|while|case)[[:space:]]" "$TN_TOKENS"
    exit 1
fi
ok "File format verified -- pure KEY=value, no embedded logic"

echo ""
if [ "$_missing" -eq 0 ]; then
    ok "All critical tokens resolved."
    echo ""
    info "Next steps:"
    printf "    1. Fill in CERT_*, TLS_*, RULES_TYPE, OINK_*, PUBLIC_DOMAIN\n"
    printf "       in %s\n" "$TN_TOKENS"
    printf "    2. Restore any previously-tokenized payload .orig files:\n"
    printf "       find payload/ -name '*.orig' | "
    printf "xargs -I{} sh -c 'mv \"\$1\" \"\${1%%.orig}\"' _ {}\n"
    printf "    3. ksh TN_TOKENIZE.sh\n"
    printf "    4. grep -r '172\\.16\\.' payload/   # must be zero matches\n"
    printf "    5. Commit payload/ to repo\n"
    printf "    6. On target: ksh TN_NET_SET.sh && ksh TN_SUBSTITUTE.sh\n"
else
    warn "$_missing critical token(s) empty -- review before tokenizing."
fi

exit 0
