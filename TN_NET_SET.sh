#!/bin/ksh
# =============================================================================
# TN_NET_SET.sh -- Tangent Networks UTM Network Configuration
# =============================================================================
# VERSION: 5.0.2-dual-lan
#
# Execution order on target:
#   1. TN_NET_SET.sh   -> /etc/tn-interfaces + payload/ appends + new files
#   2. TN_SUBSTITUTE.sh -> payload/ token expansion (%%TOKEN%% -> values)
#   3. TN_PKG_INSTALL.sh -> deploy payload/ to /etc/ and /usr/local/etc/
#   4. TN_CHROOT_SETUP.sh -> configure chroot for httpd
#
# Stages:
#   Stage 1    HAL probe: kernel caps, RAM, CPU, AES-NI, mbufs, sysctl
#   Stage 2    Firmware update (fw_update -v)
#   Stage 3    Hostname + WAN interface selection
#   Stage 4    Multi-WAN topology (dormant -- gated for 8.0)
#   Stage 5    WAN type: ethernet / PPPoE / wireless
#   Stage 6    Wireless WAN credentials (if WAN is wireless)
#   Stage 7    WAN address detection
#   Stage 8    Deployment classification
#   Stage 9    Virtualisation detection
#   Stage 10   VLAN + trunk (dormant -- gated for 8.0)
#   Stage 11   Primary LAN interface selection
#   Stage 12   Primary LAN wireless AP configuration (if wireless NIC)
#   Stage 13   Additional physical LAN interfaces (dormant -- gated for 8.0)
#   Stage 14   LAN subnet assignment
#   Stage 15   HA: CARP + pfsync (dormant -- gated for post-8.0)
#   Stage 16   Hardware offload audit (TSO/LRO disabled for divert safety)
#   Stage 17   Write hostname.INT_IF and hostname.pflog1
#   Stage 18   Bring interfaces up, DAD wait, ULA purge, mygate write
#   Stage 19   Path MTU discovery (IPv6-first, IPv4 fallback)
#   Stage 20   Write /etc/tn-interfaces
#   Stage 21   Connectivity test
#   Stage 22   Payload config extension
#   Stage 23   SSL CA + server certificate generation
#   Stage 24   Final connectivity retest
#
# WIRELESS HOSTNAME FILES:
#   OpenBSD man hostname.if(5) canonical AP form is used verbatim:
#     mediaopt hostap
#     chan <N>
#     nwid <ssid>
#     wpakey <pass>
#     inet <ip4> <mask4>
#     inet6 <ip6> 64
#     -powersave
#     up
#   No explicit mode pin. OpenBSD negotiates the best stable mode at
#   bring-up time. -powersave is mandatory to prevent USB power throttling
#   and ACPI PCI power management from suspending the radio.
#   Band and mode are detected from driver capability via get_wifi_modes
#   (ifconfig <if> media) and stored in tn-interfaces for inventory only.
#
# TOPOLOGY (this release):
#   ONE WAN + ONE LAN. Bridge, VLAN, multi-WAN, N+1 LAN gated for 8.0.
#   Bridge prompt removed entirely -- presenting options the code cannot
#   honour is a defect, not a feature.
#
# SENSITIVE DATA:
#   Credentials read via _read_secret (stty -echo, sub-shell trap).
#   Written only to hostname files (chmod 640). Never to tn-interfaces.
#   tn-interfaces stores "(stored in hostname file)" for such fields.
# =============================================================================

set -e
umask 022

VERSION="6.0.0-dual-lan"

# =============================================================================
# PATHS
# =============================================================================
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOG_DIR="${SCRIPT_DIR}/logs"
LOG_FILE="${LOG_DIR}/network-setup.log"
TN_INTERFACES="/etc/tn-interfaces"
STATUS_OK="/etc/tn-network-setup.status"
STATUS_FAIL="/etc/tn-network-fail.status"
INSTALL_DB="/var/db/tn_install.db"
PAYLOAD_DIR="${SCRIPT_DIR}/payload"
PAYLOAD_ETC="${PAYLOAD_DIR}/etc"

SSL_DIR="/etc/ssl"
SSL_PRIVATE_DIR="/etc/ssl/private"
TN_CA_KEY="${SSL_PRIVATE_DIR}/tn-ca.key"
TN_CA_CERT="${SSL_DIR}/tn-ca.crt"
TN_CA_SERIAL="${SSL_DIR}/tn-ca.serial"

PAYLOAD_DHCPD="${PAYLOAD_ETC}/dhcpd.conf"
PAYLOAD_RAD="${PAYLOAD_ETC}/rad.conf"
PAYLOAD_SOCKD="${PAYLOAD_ETC}/sockd.conf"
PAYLOAD_UNBOUND="${PAYLOAD_DIR}/var/unbound/etc/unbound.conf"
PAYLOAD_PFCONF="${PAYLOAD_ETC}/pf.conf"
PAYLOAD_RCCONF="${PAYLOAD_ETC}/rc.conf.local"
PAYLOAD_SYSCTL="${PAYLOAD_ETC}/sysctl.conf"

mkdir -p "$LOG_DIR"

# =============================================================================
# CONSTANTS
# =============================================================================
PPPOE_WAN_MTU="1492"
DEFAULT_WAN_MTU=1400
MSS_SAFETY_MARGIN=40
WIFI_AP_CCMP_OVERHEAD=60
WIFI_AP_OPEN_OVERHEAD=40
WIFI_CLIENT_MSS4=1440
WIFI_CLIENT_MSS6=1420

TARGET_IPV4_PRIMARY="1.1.1.1"
TARGET_IPV4_SECONDARY="8.8.8.8"
TARGET_IPV4_TERTIARY="9.9.9.9"
TARGET_IPV6_PRIMARY="2606:4700:4700::1111"
TARGET_IPV6_SECONDARY="2001:4860:4860::8888"
TARGET_IPV6_TERTIARY="2620:fe::fe"

# =============================================================================
# TERMINAL COLOURS
# =============================================================================
if [ -t 1 ]; then
  RED='\033[0;31m'
  GREEN='\033[0;32m'
  YELLOW='\033[1;33m'
  CYAN='\033[0;36m'
  BOLD='\033[1m'
  MAGENTA='\033[0;35m'
  NC='\033[0m'
else
  RED=''
  GREEN=''
  YELLOW=''
  CYAN=''
  BOLD=''
  MAGENTA=''
  NC=''
fi

ERRORS=0

# =============================================================================
# LOGGING
# =============================================================================
_log() { printf "[%s] [%-4s] %s\n" "$(date '+%Y-%m-%d %H:%M:%S')" "$1" "$2" \
  >> "$LOG_FILE"; }
ok() {
  printf "  ${GREEN}[OK]${NC}   %s\n" "$1"
  _log "OK" "$1"
}
err() {
  printf "  ${RED}[ERR]${NC}  %s\n" "$1"
  _log "ERR" "$1"
  ERRORS=$((ERRORS + 1))
}
warn() {
  printf "  ${YELLOW}[WARN]${NC} %s\n" "$1"
  _log "WARN" "$1"
}
info() {
  printf "  ${CYAN}[INFO]${NC} %s\n" "$1"
  _log "INFO" "$1"
}

print_header() {
  printf "\n============================================================\n"
  printf "  ${BOLD}%s${NC}\n" "$1"
  printf "============================================================\n"
  _log "INFO" "=== $1 ==="
}

printf "\n=== TN_NET_SET.sh v%s  RUN %s ===\n" \
  "$VERSION" "$(date '+%Y-%m-%d %H:%M:%S')" >> "$LOG_FILE"

# =============================================================================
# INPUT VALIDATION
# =============================================================================
validate_hostname() {
  printf "%s" "$1" | grep -qE '^[a-zA-Z0-9][a-zA-Z0-9.-]*$'
}
validate_email() {
  printf "%s" "$1" \
    | grep -qE '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
}
validate_country_code() {
  [ ${#1} -eq 2 ] && printf "%s" "$1" | grep -qE '^[A-Z]{2}$'
}
validate_cidr_subnet() {
  _vs_net=$(printf "%s" "$1" | cut -d/ -f1)
  _vs_pfx=$(printf "%s" "$1" | cut -d/ -f2)
  printf "%s" "$_vs_net" \
    | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' \
    || return 1
  printf "%s" "$_vs_pfx" \
    | grep -qE '^([0-9]|[12][0-9]|3[0-2])$' || return 1
  for _o in $(printf "%s" "$_vs_net" | tr '.' ' '); do
    [ "$_o" -ge 0 ] && [ "$_o" -le 255 ] || return 1
  done
  return 0
}
validate_ip4() {
  printf "%s" "$1" \
    | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' \
    || return 1
  for _o in $(printf "%s" "$1" | tr '.' ' '); do
    [ "$_o" -ge 0 ] && [ "$_o" -le 255 ] || return 1
  done
}
validate_vlan_id() {
  printf "%s" "$1" | grep -qE '^[0-9]+$' || return 1
  [ "$1" -ge 1 ] && [ "$1" -le 4094 ]
}

# _validate_wifi_channel BAND CHANNEL
_validate_wifi_channel() {
  _vwc_band="$1"
  _vwc_ch="$2"
  [ "$_vwc_ch" -eq 0 ] && return 0
  case "$_vwc_band" in
    2.4ghz)
      [ "$_vwc_ch" -ge 1 ] && [ "$_vwc_ch" -le 13 ] && return 0
      return 1
      ;;
    5ghz)
      for _vc in 36 40 44 48 52 56 60 64 \
        100 104 108 112 116 120 124 128 132 136 140 \
        149 153 157 161 165; do
        [ "$_vwc_ch" -eq "$_vc" ] && return 0
      done
      return 1
      ;;
  esac
  return 0
}

# =============================================================================
# SENSITIVE INPUT
# _rs_restore hoisted to top level (ksh88 forbids nested function definitions)
# =============================================================================
_rs_restore() { stty echo 2> /dev/null || true; }

_read_secret() {
  _rs_var="$1"
  _rs_prompt="${2:-Secret: }"
  printf "  ${MAGENTA}%s${NC}" "$_rs_prompt"
  _rs_val=$(
    trap '_rs_restore' EXIT INT TERM HUP
    stty -echo 2> /dev/null || true
    IFS= read -r _rs_line < /dev/tty || true
    _rs_restore
    printf "%s" "$_rs_line"
  )
  printf "\n"
  eval "${_rs_var}=\"\${_rs_val}\""
}

_clear_secret() {
  for _cs_v in "$@"; do eval "${_cs_v}=\"\""; done
}

# =============================================================================
# GENERAL HELPERS
# =============================================================================
iface_prefix() {
  printf "%s" "$1" | tr '[:lower:]' '[:upper:]' \
    | tr -c 'A-Z0-9\n' '_' | tr -d '\n'
}

record_installed() {
  _ri_path="$1"
  [ -e "$_ri_path" ] || return 0
  [ -f "$INSTALL_DB" ] || return 0
  perl 2> /dev/null << PERL || true
use DBI; use File::stat;
my \$dbh = DBI->connect("dbi:SQLite:dbname=${INSTALL_DB}","","",
    {RaiseError=>0,AutoCommit=>1}) or exit;
\$dbh->do("PRAGMA journal_mode=WAL");
my \$st = stat("${_ri_path}");
my \$mode = sprintf('%04o',\$st->mode & 07777);
my \@pw = getpwuid(\$st->uid); my \@gr = getgrgid(\$st->gid);
\$dbh->do(q{INSERT OR IGNORE INTO installed_files
    (path,type,owner,mode,installed_by) VALUES(?,?,?,?,'TN_NET_SET.sh')},
    undef,"${_ri_path}",'file',"\$pw[0]:\$gr[0]",\$mode);
\$dbh->disconnect;
PERL
}

backup_original() {
  _bo_src="$1"
  [ -f "$_bo_src" ] || return 0
  _bo_bak="${_bo_src}.pre-tn-$(date +%Y%m%d)"
  _bo_i=1
  while [ -f "$_bo_bak" ]; do
    _bo_bak="${_bo_src}.pre-tn-$(date +%Y%m%d).${_bo_i}"
    _bo_i=$((_bo_i + 1))
  done
  cp -p "$_bo_src" "$_bo_bak"
  info "Backed up: $_bo_src -> $_bo_bak"
}

sysctl_set() {
  _ss_key="$1"
  _ss_val="$2"
  _ss_file="${3:-}"
  sysctl "${_ss_key}=${_ss_val}" > /dev/null 2>&1 || true
  { [ -z "$_ss_file" ] || [ ! -f "$_ss_file" ]; } && return 0
  if grep -q "^${_ss_key}=" "$_ss_file" 2> /dev/null; then
    _ss_tmp=$(mktemp)
    sed "s|^${_ss_key}=.*|${_ss_key}=${_ss_val}|" "$_ss_file" > "$_ss_tmp"
    mv "$_ss_tmp" "$_ss_file"
  else
    printf "%s=%s\n" "$_ss_key" "$_ss_val" >> "$_ss_file"
  fi
}

# =============================================================================
# INTERFACE DISCOVERY
# =============================================================================
list_interfaces() {
  ifconfig -a 2> /dev/null | awk -F: '
    /^[a-z0-9]+:/ {
      i=$1
      if (i !~ /^(lo|pflog|enc|vether|pfsync|tun|tap|gif|gre|ppp|sl)[0-9]*$/)
        print i
    }'
}

get_ip4() { ifconfig "$1" 2> /dev/null | awk '/inet [0-9]/{print $2;exit}'; }
get_ip6() {
  ifconfig "$1" 2> /dev/null \
    | awk '/inet6/ && !/fe80/ && !/autoconf temporary/ \
           {sub(/%.*$/,"",$2); print $2; exit}'
}
get_gw4() { route -n show -inet 2> /dev/null | awk '/^default/{print $2;exit}'; }
get_mask4() {
  _raw=$(ifconfig "$1" 2> /dev/null | awk '/inet [0-9]/{print $4;exit}')
  case "$_raw" in
    0x*)
      _h=${_raw#0x}
      printf "%d.%d.%d.%d" \
        $((0x$_h >> 24 & 255)) $((0x$_h >> 16 & 255)) \
        $((0x$_h >> 8 & 255)) $((0x$_h & 255))
      ;;
    *) printf "%s" "$_raw" ;;
  esac
}

# get_gw6 -- best IPv6 default gateway
# Priority: link-local > GUA > ULA
get_gw6() {
  route -n show -inet6 2> /dev/null | awk '
    /^default/ {
      gw=$2
      if (gw~/^fe80:/) { ll=gw;  next }
      if (gw~/^[23]/)  { gua=gw; next }
      if (gw~/^f[cd]/) { ula=gw; next }
    }
    END {
      if (ll!="")  { print ll;  exit }
      if (gua!="") { print gua; exit }
      if (ula!="") { print ula; exit }
    }'
}

get_gw6_clean() {
  _raw=$(get_gw6)
  printf "%s" "$_raw" | sed 's/%[a-z0-9]*$//'
}

get_gw6_iface() {
  _raw=$(get_gw6)
  printf "%s" "$_raw" | awk -F'%' '{if(NF>1) print $2}'
}

is_wireless() { ifconfig "$1" 2> /dev/null | grep -q "ieee80211"; }

get_link_speed() {
  _s=$(ifconfig "$1" 2> /dev/null | grep "media:" \
    | grep -oE "[0-9]+base[A-Za-z]" | head -1 | grep -oE "^[0-9]+")
  [ -z "$_s" ] && _s=$(ifconfig "$1" 2> /dev/null | grep "media:" \
    | grep -oE "[0-9]+G" | head -1 | sed 's/G/000/')
  printf "%s" "${_s:-unknown}"
}

get_duplex() {
  ifconfig "$1" 2> /dev/null | grep -q "full-duplex" && printf "full" && return
  ifconfig "$1" 2> /dev/null | grep -q "half-duplex" && printf "half" && return
  printf "unknown"
}

get_offload_caps() {
  _oc=""
  ifconfig "$1" 2> /dev/null | grep -q "tso4" && _oc="${_oc}tso4,"
  ifconfig "$1" 2> /dev/null | grep -q "tso6" && _oc="${_oc}tso6,"
  ifconfig "$1" 2> /dev/null | grep -q "csum" && _oc="${_oc}csum,"
  ifconfig "$1" 2> /dev/null | grep -q "vlanhwtag" && _oc="${_oc}vlan,"
  printf "%s" "${_oc%,}"
}

get_wifi_driver() {
  # Reports bus the interface attaches to.
  # "athn0 at uhub0 port 1 ..." -> usb(uhub0)
  # "iwm0 at pci1 dev 0 ..."    -> pci(pci1)
  _gwd_bus=$(dmesg 2> /dev/null \
    | awk -v pat="^$1 at " '$0~pat{print $3;exit}' | tr -d ':')
  case "$_gwd_bus" in
    uhub*) printf "usb(%s)" "$_gwd_bus" ;;
    pci*) printf "pci(%s)" "$_gwd_bus" ;;
    *) printf "%s" "${_gwd_bus:-unknown}" ;;
  esac
}

get_wifi_modes() {
  # Use "ifconfig <if> media" to get the full supported media list.
  # Without the 'media' subcommand only the active media line is shown.
  # Active line format: "media: IEEE802.11 autoselect mode 11g hostap"
  # Supported lines:    "        media autoselect mode 11n mediaopt hostap"
  # sed extracts the mode token (11b, 11g, 11n, 11a) from each line.
  ifconfig "$1" media 2> /dev/null \
    | sed -n 's/.*mode \(11[a-z]*\).*/\1/p' \
    | sort -u \
    | tr '\n' ' ' \
    | sed 's/ $//' || true
}

classify_ip4() {
  case "$1" in
    100.6[4-9].* | 100.[7-9][0-9].* | 100.1[01][0-9].* | 100.12[0-7]*) printf "cgnat" ;;
    10.* | 172.1[6-9].* | 172.2[0-9].* | 172.3[01].* | 192.168.*) printf "private" ;;
    "") printf "none" ;;
    *) printf "public" ;;
  esac
}

classify_ip6() {
  case "$1" in
    fe80*) printf "linklocal" ;;
    fc* | fd*) printf "ula" ;;
    2* | 3*) printf "gua" ;;
    "") printf "none" ;;
    *) printf "none" ;;
  esac
}

detect_wan_topology() {
  _dwt_ifs=""
  _dwt_n=0
  for _dwt_if in $(route -n show -inet 2> /dev/null \
    | awk '/^default/{print $NF}' | sort -u); do
    case "$_dwt_if" in lo* | enc* | pflog* | pfsync*) continue ;; esac
    _dwt_ifs="${_dwt_ifs:+$_dwt_ifs }$_dwt_if"
    _dwt_n=$((_dwt_n + 1))
  done
  printf "WAN_COUNT=%s\n" "$_dwt_n"
  printf "WAN_INTERFACES=\"%s\"\n" "$_dwt_ifs"
  [ "$_dwt_n" -ge 2 ] && printf "MULTI_WAN_DETECTED=1\n" \
    || printf "MULTI_WAN_DETECTED=0\n"
}

# =============================================================================
# BRIDGE HELPERS
# =============================================================================

# _create_bridge BRIDGE_IF MEMBER_LIST
# Idempotent: creates the bridge if absent, adds any members not yet present.
# Safe to call multiple times (netstart calls this implicitly via hostname.if,
# but having it as a shell function lets Stage 18 call it explicitly if needed).
_create_bridge() {
  _cb_br="$1"
  _cb_members="$2"

  ifconfig "$_cb_br" > /dev/null 2>&1 \
    || ifconfig "$_cb_br" create > /dev/null 2>&1 \
    || {
      err "Cannot create $_cb_br"
      return 1
    }

  for _cb_m in $_cb_members; do
    # Add member only if not already present
    if ! ifconfig "$_cb_br" 2> /dev/null | grep -q "member: $_cb_m "; then
      ifconfig "$_cb_br" add "$_cb_m" > /dev/null 2>&1 \
        || warn "Could not add $_cb_m to $_cb_br"
    fi
  done
  ok "Bridge $_cb_br ready  members: $_cb_members"
}

probe_pppoe() {
  _pp="$1"
  PPPOE_PHYS=""
  PPPOE_LOGICAL=""
  case "$_pp" in
    pppoe[0-9]*)
      PPPOE_LOGICAL="$_pp"
      PPPOE_PHYS=$(ifconfig "$_pp" 2> /dev/null | awk '/dev:/{print $NF;exit}')
      PPPOE_PHYS="${PPPOE_PHYS:-$_pp}"
      return 0
      ;;
  esac
  for _ppc in $(ifconfig -a 2> /dev/null \
    | awk -F: '/^pppoe[0-9]+:/{print $1}'); do
    _ppd=$(ifconfig "$_ppc" 2> /dev/null | awk '/dev:/{print $NF;exit}')
    if [ "$_ppd" = "$_pp" ]; then
      PPPOE_PHYS="$_pp"
      PPPOE_LOGICAL="$_ppc"
      return 0
    fi
  done
  _pp_tmp=$(mktemp)
  tcpdump -ni "$_pp" -c 1 'ether proto 0x8863 or ether proto 0x8864' \
    > "$_pp_tmp" 2> /dev/null &
  _pp_pid=$!
  _pp_w=0
  while [ "$_pp_w" -lt 5 ]; do
    kill -0 "$_pp_pid" 2> /dev/null || break
    sleep 1
    _pp_w=$((_pp_w + 1))
  done
  kill "$_pp_pid" 2> /dev/null
  wait "$_pp_pid" 2> /dev/null
  if [ -s "$_pp_tmp" ]; then
    rm -f "$_pp_tmp"
    PPPOE_PHYS="$_pp"
    return 0
  fi
  rm -f "$_pp_tmp"
  return 1
}

# =============================================================================
# SUBNET / IPv4 MATH
# =============================================================================
cidr_to_mask() {
  case "$1" in
    32) printf "255.255.255.255" ;; 24) printf "255.255.255.0" ;;
    16) printf "255.255.0.0" ;; 8) printf "255.0.0.0" ;;
    0) printf "0.0.0.0" ;;
    *)
      _cm=$((0xffffffff << (32 - $1) & 0xffffffff))
      printf "%d.%d.%d.%d" \
        $((_cm >> 24 & 255)) $((_cm >> 16 & 255)) $((_cm >> 8 & 255)) $((_cm & 255))
      ;;
  esac
}

# derive_subnet_vars PREFIX IP4 MASK4
derive_subnet_vars() {
  _ds_pfx="$1"
  _da=$(printf "%s" "$2" | cut -d. -f1)
  _ma=$(printf "%s" "$3" | cut -d. -f1)
  _db=$(printf "%s" "$2" | cut -d. -f2)
  _mb=$(printf "%s" "$3" | cut -d. -f2)
  _dc=$(printf "%s" "$2" | cut -d. -f3)
  _mc=$(printf "%s" "$3" | cut -d. -f3)
  _dd=$(printf "%s" "$2" | cut -d. -f4)
  _md=$(printf "%s" "$3" | cut -d. -f4)
  _net=$(printf "%d.%d.%d.%d" \
    "$((_da & _ma))" "$((_db & _mb))" "$((_dc & _mc))" "$((_dd & _md))")
  _bcast=$(printf "%d.%d.%d.%d" \
    "$((_da | (255 - _ma)))" "$((_db | (255 - _mb)))" \
    "$((_dc | (255 - _mc)))" "$((_dd | (255 - _md)))")
  _p3=$(printf "%s" "$_net" | cut -d. -f1-3)
  eval "${_ds_pfx}_NET4_ADDR=\"$_net\""
  eval "${_ds_pfx}_BROADCAST4=\"$_bcast\""
  eval "${_ds_pfx}_DHCP_START=\"${_p3}.10\""
  eval "${_ds_pfx}_DHCP_END=\"${_p3}.245\""
}

# derive_mss PREFIX TYPE [MTU]
derive_mss() {
  _dm_pfx="$1"
  _dm_type="$2"
  _dm_mtu="${3:-1500}"
  case "$_dm_type" in
    wifi-ap-ccmp)
      _dm_mss4=$((_dm_mtu - WIFI_AP_CCMP_OVERHEAD - MSS_SAFETY_MARGIN))
      _dm_mss6=$((_dm_mtu - WIFI_AP_CCMP_OVERHEAD - MSS_SAFETY_MARGIN - 20))
      ;;
    wifi-ap-open)
      _dm_mss4=$((_dm_mtu - WIFI_AP_OPEN_OVERHEAD - MSS_SAFETY_MARGIN))
      _dm_mss6=$((_dm_mtu - WIFI_AP_OPEN_OVERHEAD - MSS_SAFETY_MARGIN - 20))
      ;;
    wifi-client)
      _dm_mss4=$WIFI_CLIENT_MSS4
      _dm_mss6=$WIFI_CLIENT_MSS6
      ;;
    pppoe)
      _dm_mtu=$PPPOE_WAN_MTU
      _dm_mss4=$((_dm_mtu - 40 - MSS_SAFETY_MARGIN))
      _dm_mss6=$((_dm_mtu - 60 - MSS_SAFETY_MARGIN))
      ;;
    *)
      _dm_mss4=$((_dm_mtu - 40 - MSS_SAFETY_MARGIN))
      _dm_mss6=$((_dm_mtu - 60 - MSS_SAFETY_MARGIN))
      ;;
  esac
  eval "${_dm_pfx}_MTU=\"$_dm_mtu\""
  eval "${_dm_pfx}_MSS4=\"$_dm_mss4\""
  eval "${_dm_pfx}_MSS6=\"$_dm_mss6\""
}

# =============================================================================
# IPv6 ULA DERIVATION
# =============================================================================
ipv4_to_ipv6_ula() {
  _o1=$(printf "%s" "$1" | cut -d. -f1)
  _o2=$(printf "%s" "$1" | cut -d. -f2)
  _o3=$(printf "%s" "$1" | cut -d. -f3)
  printf "%s:%s::1" "$(printf "fd%02x" "$_o1")" "$(printf "%02x%02x" "$_o2" "$_o3")"
}
ipv4_net_to_ipv6_ula_net() {
  _o1=$(printf "%s" "$1" | cut -d. -f1)
  _o2=$(printf "%s" "$1" | cut -d. -f2)
  _o3=$(printf "%s" "$1" | cut -d. -f3)
  printf "%s:%s::/64" "$(printf "fd%02x" "$_o1")" "$(printf "%02x%02x" "$_o2" "$_o3")"
}

# =============================================================================
# SMART SUBNET SELECTION
# =============================================================================
subnet_in_use() {
  _siu_network=$(printf "%s" "$1" | cut -d/ -f1)
  route -n show -inet 2> /dev/null | grep -q "$_siu_network" && return 0
  ifconfig 2> /dev/null | grep -q "inet .*${_siu_network}" && return 0
  return 1
}

find_available_subnet() {
  _fas_default="10.10.10.0/24"
  if ! subnet_in_use "$_fas_default"; then
    printf "%s" "$_fas_default"
    return 0
  fi
  for _gc_c in 100 150 200 50 250 25 75 125 175 225; do
    _cand="192.168.${_gc_c}.0/24"
    subnet_in_use "$_cand" && continue
    printf "%s" "$_cand"
    return 0
  done
  for _gc_b in 25 20 30 16 18 22; do
    for _gc_c in 100 150 200; do
      _cand="172.${_gc_b}.${_gc_c}.0/24"
      subnet_in_use "$_cand" && continue
      printf "%s" "$_cand"
      return 0
    done
  done
  warn "All probed subnets appear in use -- using fallback 172.25.25.0/24" >&2
  printf "172.25.25.0/24"
}

# prompt_lan_subnet TITLE
# Returns via globals: _SUBNET_RESULT _SUBNET_RESULT_IP _SUBNET_RESULT_CIDR
#                      _SUBNET_RESULT_MASK _SUBNET_RESULT_IP6 _SUBNET_RESULT_NET6
prompt_lan_subnet() {
  _pls_title="${1:-LAN Subnet}"
  _pls_confirmed=0
  while [ "$_pls_confirmed" -eq 0 ]; do
    print_header "$_pls_title"
    _pls_auto=$(find_available_subnet)
    printf "  Suggested available subnet: ${GREEN}%s${NC}\n" "$_pls_auto"
    printf "  ${MAGENTA}Use this subnet? [Y/n]: ${NC}"
    read _pls_ans
    case "$_pls_ans" in
      [Nn]*)
        _pls_ok=0
        while [ "$_pls_ok" -eq 0 ]; do
          printf "  ${MAGENTA}Enter LAN subnet (e.g. 192.168.100.0/24): ${NC}"
          read _pls_user
          if [ -z "$_pls_user" ]; then
            warn "Subnet cannot be empty"
          elif ! validate_cidr_subnet "$_pls_user"; then
            warn "Invalid format: expected x.x.x.x/yy"
          else
            _pls_ok=1
          fi
        done
        _pls_subnet="$_pls_user"
        ;;
      *) _pls_subnet="$_pls_auto" ;;
    esac
    _SUBNET_RESULT="$_pls_subnet"
    _SUBNET_RESULT_CIDR=$(printf "%s" "$_pls_subnet" | cut -d/ -f2)
    _SUBNET_RESULT_MASK=$(cidr_to_mask "$_SUBNET_RESULT_CIDR")
    _SUBNET_RESULT_IP=$(printf "%s" "$_pls_subnet" | sed 's|\.[0-9]*/.*|.1|')
    if [ "${HAS_INET6:-0}" -eq 1 ]; then
      _SUBNET_RESULT_IP6=$(ipv4_to_ipv6_ula "$_SUBNET_RESULT_IP")
      _SUBNET_RESULT_NET6=$(ipv4_net_to_ipv6_ula_net "$_SUBNET_RESULT_IP")
    else
      _SUBNET_RESULT_IP6=""
      _SUBNET_RESULT_NET6=""
    fi
    printf "\n  Network : %s\n" "$_pls_subnet"
    printf "  LAN IP  : %s  Mask: %s\n" "$_SUBNET_RESULT_IP" "$_SUBNET_RESULT_MASK"
    [ -n "$_SUBNET_RESULT_IP6" ] && printf "  LAN IPv6: %s\n" "$_SUBNET_RESULT_IP6"
    printf "  ${MAGENTA}Accept? [Y/n]: ${NC}"
    read _pls_conf
    case "$_pls_conf" in
      [Nn]*) info "Restarting subnet selection..." ;;
      *)
        ok "Subnet confirmed: $_pls_subnet"
        _pls_confirmed=1
        ;;
    esac
  done
}

# =============================================================================
# WIRELESS HOSTNAME FILE WRITER
# _write_wireless_hostname IFNAME ROLE OUTFILE
# ROLE: wan-client | lan-ap | lan-client
#
# Follows OpenBSD man hostname.if(5) canonical AP form:
#   mediaopt hostap
#   chan <N>
#   nwid <ssid>
#   wpakey <pass>     (omitted for open security)
#   inet <ip4> <mask4>
#   inet6 <ip6> 64    (when HAS_INET6=1 and ip6 is set)
#   -powersave
#   up
#
# No explicit mode pin. OpenBSD negotiates best stable mode at bring-up.
# -powersave is mandatory: prevents USB power throttling and ACPI PCI
# power management from suspending the radio between beacon intervals.
# =============================================================================
_write_wireless_hostname() {
  _wwh_if="$1"
  _wwh_role="$2"
  _wwh_out="$3"
  _WP=$(iface_prefix "$_wwh_if")

  eval _ssid="\${${_WP}_WIFI_SSID:-}"
  eval _pass="\${${_WP}_WIFI_PASS:-}"
  eval _sec="\${${_WP}_WIFI_SECURITY:-wpa2}"
  eval _chan="\${${_WP}_WIFI_CHANNEL:-6}"
  eval _ip4="\${${_WP}_IP4:-}"
  eval _mask4="\${${_WP}_MASK4:-}"
  eval _ip6="\${${_WP}_IP6:-}"

  printf '# /etc/hostname.%s -- role: %s -- generated by TN_NET_SET.sh v%s\n' \
    "$_wwh_if" "$_wwh_role" "$VERSION" > "$_wwh_out"

  case "$_wwh_role" in
    lan-ap)
      # Canonical OpenBSD hostname.if(5) AP form.
      # No mode pin -- driver negotiates best stable mode at bring-up.
      # Channel is operator-confirmed and validated against band capability.
      # -powersave mandatory: prevents USB throttle and ACPI PCI suspend.
      printf 'mediaopt hostap\n' >> "$_wwh_out"
      printf 'chan %s\n' "$_chan" >> "$_wwh_out"
      printf 'nwid %s\n' "$_ssid" >> "$_wwh_out"
      [ "$_sec" != "open" ] \
        && printf 'wpakey %s\n' "$_pass" >> "$_wwh_out"
      printf 'inet %s %s\n' "$_ip4" "$_mask4" >> "$_wwh_out"
      if [ "${HAS_INET6:-0}" -eq 1 ] && [ -n "$_ip6" ]; then
        printf 'inet6 %s 64\n' "$_ip6" >> "$_wwh_out"
      fi
      printf -- '-powersave\n' >> "$_wwh_out"
      printf 'up\n' >> "$_wwh_out"
      ;;
    wan-client | lan-client)
      if [ "$_sec" = "open" ]; then
        printf 'nwid %s\n' "$_ssid" >> "$_wwh_out"
      else
        printf 'join %s wpakey %s\n' "$_ssid" "$_pass" >> "$_wwh_out"
      fi
      printf 'inet autoconf\n' >> "$_wwh_out"
      if [ "${HAS_INET6:-0}" -eq 1 ]; then
        printf 'inet6 autoconf -temporary\n' >> "$_wwh_out"
        [ -n "$_ip6" ] \
          && printf '!route add -inet6 64:ff9b::/96 %s\n' "$_ip6" >> "$_wwh_out"
      fi
      printf -- '-powersave\n' >> "$_wwh_out"
      printf 'up\n' >> "$_wwh_out"
      ;;
  esac
  chmod 640 "$_wwh_out"
  chown root:wheel "$_wwh_out"
}

# =============================================================================
# WIRELESS CONFIGURATION PROMPT
# _prompt_wireless_config PREFIX IFNAME LABEL [FORCE_ROLE]
#
# Band and mode are detected from driver capability (get_wifi_modes) and
# stored in tn-interfaces for inventory only. They are NOT written to the
# hostname file. OpenBSD negotiates the best stable mode at bring-up.
#
# For AP role the operator is asked only for:
#   SSID, passphrase, security type, channel, client isolation,
#   hidden SSID, max clients.
# Bridge prompt is intentionally absent -- bridge is dormant in this
# release. Presenting options the code cannot honour is a defect.
# =============================================================================
_prompt_wireless_config() {
  _pwc_pfx="$1"
  _pwc_if="$2"
  _pwc_label="${3:-}"
  _pwc_force_role="${4:-}"

  _pwc_driver=$(get_wifi_driver "$_pwc_if")
  _pwc_modes=$(get_wifi_modes "$_pwc_if")

  info "Wireless: $_pwc_if  driver: ${_pwc_driver:-unknown}  modes: ${_pwc_modes:-unknown}"

  if [ -n "$_pwc_force_role" ]; then
    info "Role: $_pwc_force_role (topology-determined)"
    case "$_pwc_force_role" in
      ap) _pwc_role_ans="1" ;;
      client) _pwc_role_ans="2" ;;
      *) _pwc_role_ans="1" ;;
    esac
  else
    printf "\n  Wireless role for %s%s:\n" "$_pwc_if" \
      "${_pwc_label:+ ($_pwc_label)}"
    printf "    1) AP  (mediaopt hostap -- broadcast SSID for LAN clients)\n"
    printf "    2) client (join upstream wireless network)\n"
    printf "  ${MAGENTA}Choice [1]: ${NC}"
    read _pwc_role_ans
  fi

  case "${_pwc_role_ans:-1}" in
    2)
      eval "${_pwc_pfx}_WIFI_ROLE=\"client\""
      eval "${_pwc_pfx}_WIFI_DRIVER=\"${_pwc_driver:-}\""
      _read_secret "_pwc_ssid" "Upstream SSID: "
      eval "${_pwc_pfx}_WIFI_SSID=\"$_pwc_ssid\""
      printf "  ${MAGENTA}Security (wpa2/wpa3/open) [wpa2]: ${NC}"
      read _pwc_sec
      case "${_pwc_sec:-wpa2}" in
        wpa3) _pwc_security="wpa3" ;;
        open) _pwc_security="open" ;;
        *) _pwc_security="wpa2" ;;
      esac
      eval "${_pwc_pfx}_WIFI_SECURITY=\"$_pwc_security\""
      if [ "$_pwc_security" != "open" ]; then
        _read_secret "_pwc_pass" "Upstream passphrase: "
        eval "${_pwc_pfx}_WIFI_PASS=\"$_pwc_pass\""
        _clear_secret _pwc_pass
      else
        eval "${_pwc_pfx}_WIFI_PASS=\"\""
      fi
      eval "${_pwc_pfx}_WIFI_BAND=\"auto\""
      _clear_secret _pwc_ssid
      ok "Wireless client configured: $_pwc_if"
      ;;
    *)
      eval "${_pwc_pfx}_WIFI_ROLE=\"ap\""
      eval "${_pwc_pfx}_WIFI_DRIVER=\"${_pwc_driver:-}\""
      _read_secret "_pwc_ssid" "AP SSID: "
      eval "${_pwc_pfx}_WIFI_SSID=\"$_pwc_ssid\""
      _clear_secret _pwc_ssid
      _read_secret "_pwc_pass" "AP passphrase (min 8 chars): "
      eval "${_pwc_pfx}_WIFI_PASS=\"$_pwc_pass\""
      _clear_secret _pwc_pass
      printf "  ${MAGENTA}Security (wpa2/wpa3/open) [wpa2]: ${NC}"
      read _pwc_sec
      case "${_pwc_sec:-wpa2}" in
        wpa3) _pwc_security="wpa3" ;;
        open) _pwc_security="open" ;;
        *) _pwc_security="wpa2" ;;
      esac
      eval "${_pwc_pfx}_WIFI_SECURITY=\"$_pwc_security\""

      # Derive band and mode from driver capability for inventory only.
      # Mode is intentionally NOT written to the hostname file.
      # OpenBSD "mediaopt hostap" negotiates best stable mode at bring-up.
      # 11a in supported modes means 5GHz capable.
      if printf "%s" "${_pwc_modes:-}" | grep -q "11a"; then
        _pwc_band="5ghz"
        _pwc_hwm="a"
        printf "%s" "${_pwc_modes:-}" | grep -q "11n" && _pwc_hwm="n"
      elif printf "%s" "${_pwc_modes:-}" | grep -q "11n"; then
        _pwc_band="2.4ghz"
        _pwc_hwm="n"
      elif printf "%s" "${_pwc_modes:-}" | grep -q "11g"; then
        _pwc_band="2.4ghz"
        _pwc_hwm="g"
      else
        _pwc_band="2.4ghz"
        _pwc_hwm="b"
      fi
      info "Band: $_pwc_band  highest mode: 802.$_pwc_hwm (inventory only, not pinned)"
      eval "${_pwc_pfx}_WIFI_BAND=\"$_pwc_band\""
      eval "${_pwc_pfx}_WIFI_HW_MODE=\"$_pwc_hwm\""

      # Channel -- validated against detected band
      _pwc_ch_ok=0
      while [ "$_pwc_ch_ok" -eq 0 ]; do
        case "$_pwc_band" in
          2.4ghz) printf "  ${MAGENTA}Channel 1-13 or 0=auto [6]: ${NC}" ;;
          5ghz) printf "  ${MAGENTA}Channel (36/40/44/48/... or 0=auto) [36]: ${NC}" ;;
        esac
        read _pwc_ch
        _pwc_ch="${_pwc_ch:-$([ "$_pwc_band" = "5ghz" ] && echo 36 || echo 6)}"
        _validate_wifi_channel "$_pwc_band" "$_pwc_ch" \
          && _pwc_ch_ok=1 || warn "Channel $_pwc_ch not valid for $_pwc_band"
      done
      eval "${_pwc_pfx}_WIFI_CHANNEL=\"$_pwc_ch\""

      printf "  ${MAGENTA}Client isolation? [y/N]: ${NC}"
      read _pwc_iso
      case "$_pwc_iso" in
        [Yy]*) eval "${_pwc_pfx}_WIFI_ISOLATION=\"1\"" ;;
        *) eval "${_pwc_pfx}_WIFI_ISOLATION=\"0\"" ;;
      esac

      printf "  ${MAGENTA}Hidden SSID? [y/N]: ${NC}"
      read _pwc_hid
      case "$_pwc_hid" in
        [Yy]*) eval "${_pwc_pfx}_WIFI_HIDDEN=\"1\"" ;;
        *) eval "${_pwc_pfx}_WIFI_HIDDEN=\"0\"" ;;
      esac

      printf "  ${MAGENTA}Max clients [50]: ${NC}"
      read _pwc_mc
      eval "${_pwc_pfx}_WIFI_MAX_CLIENTS=\"${_pwc_mc:-50}\""

      # Bridge not available in this release -- no prompt
      eval "${_pwc_pfx}_WIFI_BRIDGE=\"\""

      ok "AP configured: $_pwc_if  band=$_pwc_band  ch=$_pwc_ch  SSID=<hidden>"
      ;;
  esac
}

# =============================================================================
# HARDWARE OFFLOAD AUDIT
# Disables TSO4/TSO6/LRO required for divert(4) inspection chain.
# =============================================================================
audit_offload() {
  _ao_if="$1"
  _ao_label="${2:-$1}"
  _aopfx=$(iface_prefix "$_ao_if")
  _tso4=0
  _tso6=0
  _lro=0
  _aoifc=$(ifconfig "$_ao_if" 2> /dev/null)
  printf "%s" "$_aoifc" | grep -q "tso4" \
    && ifconfig "$_ao_if" -tso4 > /dev/null 2>&1 && _tso4=1 || true
  printf "%s" "$_aoifc" | grep -q "tso6" \
    && ifconfig "$_ao_if" -tso6 > /dev/null 2>&1 && _tso6=1 || true
  printf "%s" "$_aoifc" | grep -q " lro" \
    && ifconfig "$_ao_if" -lro > /dev/null 2>&1 && _lro=1 || true
  eval "${_aopfx}_TSO4_DISABLED=\"$_tso4\""
  eval "${_aopfx}_TSO6_DISABLED=\"$_tso6\""
  eval "${_aopfx}_LRO_DISABLED=\"$_lro\""
  [ "$_tso4" -eq 1 ] && ok "  $_ao_label: -tso4 (divert safety)"
  [ "$_tso6" -eq 1 ] && ok "  $_ao_label: -tso6 (divert safety)"
  [ "$_lro" -eq 1 ] && ok "  $_ao_label: -lro  (divert safety)"
  [ "$_tso4$_tso6$_lro" = "000" ] && info "  $_ao_label: no TSO/LRO caps present"
  _ao_hn="/etc/hostname.${_ao_if}"
  if [ -f "$_ao_hn" ]; then
    _ao_tmp=$(mktemp)
    awk -v t4="$_tso4" -v t6="$_tso6" -v lr="$_lro" '
      /^up$/{if(t4)print "-tso4"; if(t6)print "-tso6"; if(lr)print "-lro"}
      {print}
    ' "$_ao_hn" > "$_ao_tmp"
    mv "$_ao_tmp" "$_ao_hn"
  fi
}

# =============================================================================
# PAYLOAD APPEND HELPERS
# =============================================================================
_payload_exists() { [ -f "$1" ]; }

append_dhcpd_subnet() {
  _pa_if="$1"
  _pa_ip="$2"
  _pa_mask="$3"
  _pa_net="$4"
  _pa_bc="$5"
  _pa_s="$6"
  _pa_e="$7"
  _payload_exists "$PAYLOAD_DHCPD" || return 0
  printf '\n# %s -- appended by TN_NET_SET.sh\n' "$_pa_if" >> "$PAYLOAD_DHCPD"
  printf 'subnet %s netmask %s {\n' "$_pa_net" "$_pa_mask" >> "$PAYLOAD_DHCPD"
  printf '\toption routers             %s;\n' "$_pa_ip" >> "$PAYLOAD_DHCPD"
  printf '\toption domain-name-servers %s;\n' "$_pa_ip" >> "$PAYLOAD_DHCPD"
  printf '\toption broadcast-address   %s;\n' "$_pa_bc" >> "$PAYLOAD_DHCPD"
  printf '\trange %s %s;\n' "$_pa_s" "$_pa_e" >> "$PAYLOAD_DHCPD"
  printf '}\n' >> "$PAYLOAD_DHCPD"
  ok "dhcpd.conf: appended subnet $_pa_net for $_pa_if"
}

append_rad_iface() {
  [ -z "${3:-}" ] && return 0
  _payload_exists "$PAYLOAD_RAD" || return 0
  printf '\n# %s -- appended by TN_NET_SET.sh\n' "$1" >> "$PAYLOAD_RAD"
  printf 'interface %s {\n' "$1" >> "$PAYLOAD_RAD"
  printf '\tdefault router yes\n' >> "$PAYLOAD_RAD"
  printf '\tprefix %s\n' "$3" >> "$PAYLOAD_RAD"
  printf '\tmtu %%LAN_MTU%%\n' >> "$PAYLOAD_RAD"
  printf '\tdns {\n' >> "$PAYLOAD_RAD"
  printf '\t\tlifetime 604800\n' >> "$PAYLOAD_RAD"
  printf '\t\tnameserver %s\n' "$2" >> "$PAYLOAD_RAD"
  printf '\t}\n}\n' >> "$PAYLOAD_RAD"
  ok "rad.conf: appended interface $1"
}

append_sockd_subnet() {
  [ -z "${2:-}" ] && return 0
  _payload_exists "$PAYLOAD_SOCKD" || return 0
  printf '\n# %s -- appended by TN_NET_SET.sh\n' "$1" >> "$PAYLOAD_SOCKD"
  printf 'client pass {\n\tfrom: %s to: 0/0\n' "$2" >> "$PAYLOAD_SOCKD"
  printf '\tlog: connect disconnect error\n}\n' >> "$PAYLOAD_SOCKD"
  printf 'socks pass {\n\tfrom: %s to: 0/0\n' "$2" >> "$PAYLOAD_SOCKD"
  printf '\tcommand: connect\n\tprotocol: tcp\n' >> "$PAYLOAD_SOCKD"
  printf '\tlog: connect disconnect iooperation\n}\n' >> "$PAYLOAD_SOCKD"
  ok "sockd.conf: appended $2 for $1"
}

append_unbound_iface() {
  _payload_exists "$PAYLOAD_UNBOUND" || return 0
  _aui_tmp=$(mktemp)
  awk -v ip4="$1" -v ip6="${2:-}" '
    /interface:.*%%INT_IP/{
      print
      printf "\tinterface: %s\n", ip4
      if (ip6 != "") printf "\tinterface: %s\n", ip6
      next
    }
    {print}
  ' "$PAYLOAD_UNBOUND" > "$_aui_tmp"
  mv "$_aui_tmp" "$PAYLOAD_UNBOUND"
  ok "unbound.conf: added interface $1"
}

# =============================================================================
# STATUS / UNDO / TRAP
# =============================================================================
write_status_ok() {
  printf '# TN_NET_SET.sh v%s completed %s\n' "$VERSION" "$(date)" > "$STATUS_OK"
  printf "EXT_IF=%s\nINT_IF=%s\nWAN_TYPE=%s\nWAN_MTU=%s\n" \
    "${EXT_IF:-}" "${INT_IF:-}" "${WAN_TYPE:-}" "${WAN_MTU:-}" >> "$STATUS_OK"
  printf "INT_NET4=%s\nINT_NET6=%s\nLog=%s\n" \
    "${INT_NET4:-}" "${INT_NET6:-}" "$LOG_FILE" >> "$STATUS_OK"
  ok "Status: $STATUS_OK"
}

write_status_fail() {
  printf '# TN_NET_SET.sh FAILED v%s  %s\n' "$VERSION" "$(date)" > "$STATUS_FAIL"
  printf "Reason=%s\nErrors=%s\nLog=%s\n" "${1:-unknown}" "$ERRORS" "$LOG_FILE" \
    >> "$STATUS_FAIL"
  err "Failure status: $STATUS_FAIL"
}

_undo() {
  _ur="$1"
  warn "Undoing: $_ur"
  _log "WARN" "UNDO: $_ur"
  [ "${_TN_INTERFACES_WRITTEN:-0}" -eq 1 ] && [ -f "$TN_INTERFACES" ] \
    && rm -f "$TN_INTERFACES" && info "Removed: $TN_INTERFACES"
  if [ -n "${INT_IF:-}" ] && [ "${_HOSTNAME_INT_WRITTEN:-0}" -eq 1 ]; then
    _hn="/etc/hostname.${INT_IF}"
    _bk=$(ls -t "${_hn}.pre-tn-"* 2> /dev/null | head -1)
    if [ -n "$_bk" ] && [ -f "$_bk" ]; then
      cp -p "$_bk" "$_hn"
    else rm -f "$_hn"; fi
    info "Restored: $_hn"
  fi
  # Destroy bridge and vether0 created during this session to prevent
  # bridge1, vether1 accumulation on repeated abort/re-run cycles.
  if [ -n "${_BRIDGE_CREATED:-}" ]; then
    ifconfig "$_BRIDGE_CREATED" destroy > /dev/null 2>&1 \
      && info "Destroyed: $_BRIDGE_CREATED" \
      || warn "Could not destroy $_BRIDGE_CREATED -- reboot will clean it up"
    _BRIDGE_CREATED=""
  fi
  if [ -n "${_VETH_CREATED:-}" ]; then
    ifconfig "$_VETH_CREATED" destroy > /dev/null 2>&1 \
      && info "Destroyed: $_VETH_CREATED" \
      || warn "Could not destroy $_VETH_CREATED -- reboot will clean it up"
    _VETH_CREATED=""
  fi
  [ "${_PFLOG1_WRITTEN:-0}" -eq 1 ] && rm -f /etc/hostname.pflog1
  [ "${_MYGATE_WRITTEN:-0}" -eq 1 ] && {
    _bk=$(ls -t /etc/mygate.pre-tn-* 2> /dev/null | head -1)
    if [ -n "$_bk" ] && [ -f "$_bk" ]; then
      cp -p "$_bk" /etc/mygate
    else rm -f /etc/mygate; fi
    info "Restored: /etc/mygate"
  }
  write_status_fail "$_ur"
}

# =============================================================================
# _full_reset
# Called at the start of a re-run when STATUS_OK exists (previous attempt
# left the system in an unknown state). Shows the operator exactly what will
# be removed, asks for confirmation, then wipes everything this script touched
# so Stage 3 onwards starts from a clean slate.
# =============================================================================
_full_reset() {
  print_header "Previous Run Detected -- Reset Required"

  # Inventory what we find
  _rst_bridges=$(ifconfig -a 2> /dev/null \
    | awk -F: '/^bridge[0-9]+:/{print $1}')
  _rst_vethers=$(ifconfig -a 2> /dev/null \
    | awk -F: '/^vether[0-9]+:/{print $1}')
  _rst_hn_files=$(find /etc -maxdepth 1 -name 'hostname.*' \
    ! -name 'hostname.pflog0' 2> /dev/null | sort)
  _rst_has_ti=0
  [ -f "$TN_INTERFACES" ] && _rst_has_ti=1
  _rst_has_mg=0
  [ -f /etc/mygate ] && _rst_has_mg=1

  printf "\n  The following will be removed or restored if you confirm:\n\n"

  if [ -n "$_rst_bridges" ]; then
    for _rb in $_rst_bridges; do
      _rbm=$(ifconfig "$_rb" 2> /dev/null \
        | awk '/member:/{print $2}' | tr '\n' ' ')
      printf "  Bridge:       %s  (members: %s)\n" \
        "$_rb" "${_rbm:-none}"
    done
  else
    printf "  Bridge:       none found\n"
  fi

  if [ -n "$_rst_vethers" ]; then
    for _rv in $_rst_vethers; do
      printf "  Vether:       %s\n" "$_rv"
    done
  else
    printf "  Vether:       none found\n"
  fi

  if [ -n "$_rst_hn_files" ]; then
    for _rh in $_rst_hn_files; do
      printf "  Hostname:     %s\n" "$_rh"
    done
  else
    printf "  Hostname:     none found\n"
  fi

  [ "$_rst_has_ti" -eq 1 ] \
    && printf "  Inventory:    %s\n" "$TN_INTERFACES" \
    || printf "  Inventory:    not present\n"

  [ "$_rst_has_mg" -eq 1 ] \
    && printf "  mygate:       /etc/mygate (will restore from backup if available)\n" \
    || printf "  mygate:       not present\n"

  printf "\n  Backups from the previous run are in: %s\n" \
    "${SCRIPT_DIR}/net-backup"

  printf "\n  ${MAGENTA}Wipe the above and start fresh? [y/N]: ${NC}"
  read _rst_confirm
  case "$_rst_confirm" in
    [Yy]*) : ;;
    *)
      info "Reset declined. Exiting -- fix manually or reboot and re-run."
      trap - EXIT
      exit 0
      ;;
  esac

  # Destroy stale bridge interfaces
  for _rb in $_rst_bridges; do
    ifconfig "$_rb" destroy > /dev/null 2>&1 \
      && ok "Destroyed: $_rb" \
      || warn "Could not destroy $_rb -- may need reboot"
  done

  # Destroy stale vether interfaces
  for _rv in $_rst_vethers; do
    ifconfig "$_rv" destroy > /dev/null 2>&1 \
      && ok "Destroyed: $_rv" \
      || warn "Could not destroy $_rv -- may need reboot"
  done

  # Remove generated hostname files (keep pflog0 which is system-managed)
  for _rh in $_rst_hn_files; do
    rm -f "$_rh" && ok "Removed: $_rh"
  done

  # Remove tn-interfaces
  [ "$_rst_has_ti" -eq 1 ] \
    && rm -f "$TN_INTERFACES" && ok "Removed: $TN_INTERFACES"

  # Restore mygate from backup if available
  if [ "$_rst_has_mg" -eq 1 ]; then
    _mg_bk=$(ls -t /etc/mygate.pre-tn-* 2> /dev/null | head -1)
    if [ -n "$_mg_bk" ] && [ -f "$_mg_bk" ]; then
      cp -p "$_mg_bk" /etc/mygate
      ok "Restored: /etc/mygate from $_mg_bk"
    else
      rm -f /etc/mygate
      ok "Removed: /etc/mygate (no backup found)"
    fi
  fi

  # Flush default routes so Stage 7 detects them fresh
  info "Flushing default routes..."
  _flushed=0
  while route -n show -inet 2> /dev/null | grep -q "^default"; do
    _gw=$(route -n show -inet 2> /dev/null | awk '/^default/{print $2;exit}')
    route delete default "$_gw" > /dev/null 2>&1 || break
    _flushed=$((_flushed + 1))
  done
  while route -n show -inet6 2> /dev/null | grep -q "^default"; do
    _gw6=$(route -n show -inet6 2> /dev/null \
      | awk '/^default/{print $2;exit}')
    route delete -inet6 default "$_gw6" > /dev/null 2>&1 || break
    _flushed=$((_flushed + 1))
  done
  ok "Flushed $_flushed default route(s)"

  # Reset all tracking variables
  _BRIDGE_CREATED=""
  _HOSTNAME_INT_WRITTEN=0
  _TN_INTERFACES_WRITTEN=0
  _PFLOG1_WRITTEN=0
  _MYGATE_WRITTEN=0

  ok "Reset complete -- continuing from Stage 3"
}

_TRAP_ACTIVE=0
_trap_handler() { [ "$_TRAP_ACTIVE" -eq 1 ] && _undo "unexpected exit"; }
trap '_trap_handler' EXIT

# =============================================================================
# SSL HELPERS
# =============================================================================
_write_ca_cnf() {
  printf '[ req ]\ndefault_bits=4096\ndefault_md=sha256\n' > "$1"
  printf 'prompt=no\ndistinguished_name=dn\nx509_extensions=ca_ext\n\n' >> "$1"
  printf '[ dn ]\nC=%s\nO=%s\nOU=%s\n' "$CERT_COUNTRY" "$CERT_ORG" "$CERT_OU" >> "$1"
  [ -n "${CERT_STATE:-}" ] && printf 'ST=%s\n' "$CERT_STATE" >> "$1"
  [ -n "${CERT_CITY:-}" ] && printf 'L=%s\n' "$CERT_CITY" >> "$1"
  printf 'CN=Tangent Networks CA\n\n[ ca_ext ]\n' >> "$1"
  printf 'basicConstraints=critical,CA:true\n' >> "$1"
  printf 'keyUsage=critical,cRLSign,keyCertSign\n' >> "$1"
  printf 'subjectKeyIdentifier=hash\n' >> "$1"
  printf 'authorityKeyIdentifier=keyid:always\n' >> "$1"
}

_write_csr_cnf() {
  printf '[ req ]\ndefault_bits=2048\ndefault_md=sha256\n' > "$1"
  printf 'prompt=no\ndistinguished_name=dn\n\n[ dn ]\n' >> "$1"
  printf 'C=%s\nO=%s\nOU=%s\n' "$CERT_COUNTRY" "$CERT_ORG" "$CERT_OU" >> "$1"
  [ -n "${CERT_STATE:-}" ] && printf 'ST=%s\n' "$CERT_STATE" >> "$1"
  [ -n "${CERT_CITY:-}" ] && printf 'L=%s\n' "$CERT_CITY" >> "$1"
  printf 'CN=%s\n' "$CERT_CN" >> "$1"
}

_write_srv_ext() {
  printf 'basicConstraints=CA:FALSE\n' > "$1"
  printf 'keyUsage=digitalSignature,keyEncipherment\n' >> "$1"
  printf 'extendedKeyUsage=serverAuth\n' >> "$1"
  printf 'subjectAltName=%s\n' "$2" >> "$1"
}

_build_san() {
  _san="IP:${INT_IP4},DNS:${CERT_CN},DNS:tangent.localdomain,IP:127.0.0.1"
  [ "${HAS_INET6:-0}" -eq 1 ] && [ -n "${INT_IP6:-}" ] \
    && _san="${_san},IP:${INT_IP6}"
  [ -n "${WIFI_LAN_IP4:-}" ] && _san="${_san},IP:${WIFI_LAN_IP4}"
  printf "%s" "$_san"
}

# _hc IFNAME CAPABILITY -- hoisted to top level (ksh88: no nested functions)
_hc() { ifconfig "$1" 2> /dev/null | grep -q "$2" && printf "1" || printf "0"; }

# _check_mib MIB
_check_mib() {
  _cmib_v=$(sysctl -n "$1" 2> /dev/null || true)
  [ -n "$_cmib_v" ] && [ "$_cmib_v" != "0" ] && return 0
  return 1
}

# =============================================================================
# STAGE 1 -- HAL PROBE
# =============================================================================
probe_hal() {
  print_header "Stage 1: Hardware Abstraction Layer"

  _check_mib "net.inet.tcp.mssdflt" && HAS_TCP4=1 || HAS_TCP4=0
  _check_mib "net.inet.udp.recvspace" && HAS_UDP4=1 || HAS_UDP4=0
  _check_mib "net.inet.divert.recvspace" && HAS_DIVERT=1 || HAS_DIVERT=0
  _check_mib "net.inet6.ip6.maxfragpackets" && HAS_INET6=1 || HAS_INET6=0
  sysctl net.bridge > /dev/null 2>&1 && HAS_BRIDGE=1 || HAS_BRIDGE=0
  sysctl net.inet.carp > /dev/null 2>&1 && HAS_CARP=1 || HAS_CARP=0
  sysctl net.pfsync > /dev/null 2>&1 && HAS_PFSYNC=1 || HAS_PFSYNC=0

  AES_NI=$(sysctl -n hw.aesni 2> /dev/null || printf "0")
  case "$AES_NI" in 0 | 1) ;; *) AES_NI="0" ;; esac

  [ "$HAS_TCP4" -eq 0 ] && err "No TCP in kernel -- abort" && exit 1
  [ "$HAS_DIVERT" -eq 0 ] && err "No divert(4) support -- check kernel" && exit 1
  [ "$HAS_INET6" -eq 0 ] && warn "No IPv6 detected -- IPv6 features disabled"

  ok "TCP4=$HAS_TCP4 UDP4=$HAS_UDP4 DIVERT=$HAS_DIVERT INET6=$HAS_INET6 CARP=$HAS_CARP"

  _bytes=$(sysctl -n hw.physmem 2> /dev/null || printf "0")
  # Add 512 MiB before dividing to avoid firmware reservations causing
  # truncation to wrong GB bucket (e.g. 4 GB system reporting 3)
  RAM_GB=$(((_bytes + 536870912) / 1024 / 1024 / 1024))
  [ "$RAM_GB" -lt 1 ] && RAM_GB=1

  CPU_CORES=$(sysctl -n hw.ncpuonline 2> /dev/null \
    || sysctl -n hw.ncpu 2> /dev/null || printf "1")
  CPU_ARCH=$(sysctl -n hw.machine_arch 2> /dev/null \
    || uname -m 2> /dev/null || printf "unknown")

  _has10g=0
  dmesg 2> /dev/null | grep -qiE "^(ix|ixl|ixgbe|bxe|oce|cxl)[0-9]" && _has10g=1

  case "$RAM_GB" in
    0 | 1) MBUF_NMBCLUSTERS=8192 ;;
    2 | 3) MBUF_NMBCLUSTERS=16384 ;;
    4 | 5 | 6 | 7) MBUF_NMBCLUSTERS=65536 ;;
    *) MBUF_NMBCLUSTERS=131072 ;;
  esac
  [ "$_has10g" -eq 1 ] && [ "$MBUF_NMBCLUSTERS" -lt 65536 ] \
    && MBUF_NMBCLUSTERS=65536

  if ! _kern_max=$(sysctl -n kern.maxclusters); then
    err "Cannot read kern.maxclusters -- kernel probe failed"
    exit 1
  fi
  if [ "$MBUF_NMBCLUSTERS" -gt "$_kern_max" ]; then
    warn "kern.maxclusters ceiling ${_kern_max} -- capping MBUF from ${MBUF_NMBCLUSTERS}"
    MBUF_NMBCLUSTERS=$_kern_max
  fi

  # pf frags limit: half of cluster count, leaves headroom for TCP reassembly.
  # Written directly into pf.conf -- no token. Value tracks real kernel ceiling.
  PF_FRAGS=$((MBUF_NMBCLUSTERS / 2))
  if [ -f "$PAYLOAD_PFCONF" ]; then
    _pf_tmp=$(mktemp)
    sed "s|^set limit frags.*|set limit frags         ${PF_FRAGS}|" \
      "$PAYLOAD_PFCONF" > "$_pf_tmp"
    mv "$_pf_tmp" "$PAYLOAD_PFCONF"
    ok "pf.conf: set limit frags -> ${PF_FRAGS}"
  else
    warn "payload/etc/pf.conf not found -- frags limit not patched"
  fi

  sysctl_set "net.inet.ip.forwarding" "1" "$PAYLOAD_SYSCTL"
  [ "$HAS_INET6" -eq 1 ] \
    && sysctl_set "net.inet6.ip6.forwarding" "1" "$PAYLOAD_SYSCTL"
  sysctl_set "kern.maxclusters" "$MBUF_NMBCLUSTERS" "$PAYLOAD_SYSCTL"

  ok "RAM=${RAM_GB}GB CPU=${CPU_CORES}x${CPU_ARCH} AES_NI=$AES_NI MBUF=$MBUF_NMBCLUSTERS PF_FRAGS=$PF_FRAGS"

  # APM high-performance mode -- appliance hardening.
  # apmd in automatic mode aggressively suspends USB ports, destabilising
  # USB wireless NICs and USB ethernet dongles mid-session.
  APM_SET_HIGHPERF=0
  if rcctl check apmd > /dev/null 2>&1; then
    info "apmd detected -- switching to high-performance mode"
    apm -H > /dev/null 2>&1 && APM_SET_HIGHPERF=1 || true
    [ "$APM_SET_HIGHPERF" -eq 1 ] \
      && ok "APM: high-performance mode active (USB suspend disabled)" \
      || warn "APM: failed to set high-performance mode"
  else
    info "apmd not running -- USB suspend not a concern"
  fi
  if _payload_exists "$PAYLOAD_RCCONF"; then
    if grep -q "^apmd_flags=" "$PAYLOAD_RCCONF" 2> /dev/null; then
      _apm_tmp=$(mktemp)
      sed 's|^apmd_flags=.*|apmd_flags="-H"|' \
        "$PAYLOAD_RCCONF" > "$_apm_tmp" && mv "$_apm_tmp" "$PAYLOAD_RCCONF" \
        || rm -f "$_apm_tmp"
      ok "rc.conf.local: apmd_flags updated to -H"
    else
      printf '\napmd_flags="-H"\n' >> "$PAYLOAD_RCCONF"
      ok "rc.conf.local: apmd_flags=-H written"
    fi
  fi

  # Wake USB bus before fw_update
  if [ -d /dev/usb ]; then
    info "Waking USB bus..."
    sleep 3
    ok "USB bus ready"
  fi

  # Disable 802.11 power save on all wireless interfaces during install.
  # The persistent -powersave line in hostname files ensures it survives reboot.
  for _wif in $(list_interfaces); do
    is_wireless "$_wif" || continue
    ifconfig "$_wif" -powersave > /dev/null 2>&1 \
      && info "Wireless: $_wif -powersave set (install guard)" \
      || info "Wireless: $_wif -powersave not supported (driver: $(get_wifi_driver "$_wif"))"
  done
}

probe_nic_capabilities() {
  WAN_HAS_TSO4=$(_hc "$EXT_IF" "tso4")
  WAN_HAS_TSO6=$(_hc "$EXT_IF" "tso6")
  WAN_HAS_LRO=$(_hc "$EXT_IF" "lro")
  WAN_HAS_VLAN_HW=$(_hc "$EXT_IF" "vlanhwtag")
  LAN_HAS_TSO4=$(_hc "$INT_IF" "tso4")
  LAN_HAS_TSO6=$(_hc "$INT_IF" "tso6")
  LAN_HAS_LRO=$(_hc "$INT_IF" "lro")
  LAN_HAS_VLAN_HW=$(_hc "$INT_IF" "vlanhwtag")
  WAN_IS_10G=0
  ifconfig "$EXT_IF" 2> /dev/null | grep -qiE "10Gbase|10000base" && WAN_IS_10G=1
  LAN_IS_10G=0
  ifconfig "$INT_IF" 2> /dev/null | grep -qiE "10Gbase|10000base" && LAN_IS_10G=1
  JUMBO_MTU_SUPPORTED=0
  _omtu=$(ifconfig "$INT_IF" 2> /dev/null | awk '/mtu/{print $NF}')
  ifconfig "$INT_IF" mtu 9000 > /dev/null 2>&1 && {
    JUMBO_MTU_SUPPORTED=1
    ifconfig "$INT_IF" mtu "${_omtu:-1500}" > /dev/null 2>&1
  }
  ok "WAN NIC: TSO4=$WAN_HAS_TSO4 TSO6=$WAN_HAS_TSO6 LRO=$WAN_HAS_LRO 10G=$WAN_IS_10G"
  ok "LAN NIC: TSO4=$LAN_HAS_TSO4 TSO6=$LAN_HAS_TSO6 LRO=$LAN_HAS_LRO 10G=$LAN_IS_10G"
}

# =============================================================================
# PRE-FLIGHT
# =============================================================================
print_header "Tangent Networks UTM -- Network Setup v${VERSION}"
info "Log: $LOG_FILE"
[ "$(id -u)" -ne 0 ] && err "Must run as root: ksh $0" && exit 1
[ "$(uname -s)" != "OpenBSD" ] && err "OpenBSD only" && exit 1

probe_hal

if [ -f "$STATUS_OK" ] || [ -f "$STATUS_FAIL" ]; then
  if [ -f "$STATUS_OK" ]; then
    warn "Previous successful run found:"
    cat "$STATUS_OK"
  else
    warn "Previous failed run found:"
    cat "$STATUS_FAIL"
  fi
  rm -f "$STATUS_OK" "$STATUS_FAIL"
  _full_reset
fi

rm -f "$STATUS_FAIL"
_TRAP_ACTIVE=1

# Pre-install backup
_NET_BACKUP="${SCRIPT_DIR}/net-backup"
mkdir -p "$_NET_BACKUP"
for _bf in /etc/fstab /etc/myname /etc/mygate /etc/rc /etc/resolv.conf \
  /etc/rc.conf.local /etc/sysctl.conf /etc/pf.conf \
  $(find /etc -maxdepth 1 -name 'hostname.*' 2> /dev/null); do
  [ -f "$_bf" ] || continue
  _bname=$(basename "$_bf")
  [ ! -f "${_NET_BACKUP}/${_bname}" ] \
    && cp -p "$_bf" "${_NET_BACKUP}/${_bname}" \
    && info "Backup: $_bf -> ${_NET_BACKUP}/${_bname}"
done
warn "DO NOT DELETE ${_NET_BACKUP} -- required for uninstall and restore."

# Initialise all variables
VLAN_COUNT=0
EXTRA_LAN_COUNT=0
HA_ENABLED=0
HA_ROLE="none"
CARP0_VIP_LAN=""
CARP0_VIP_WAN=""
CARP0_VHID="1"
CARP0_ADVSKEW="0"
PFSYNC0_IF=""
PFSYNC0_PEER_IP=""
OFFLOAD_AUDIT_DONE=0
WAN_COUNT=1
WAN_MULTI_MODE="none"
WAN_PRIMARY_IF=""
WAN2_IF=""
WAN2_TYPE=""
WAN2_GW4=""
WAN2_MTU=1500
WAN2_MONITOR_IP=""
WAN2_WEIGHT=1
WAN2_STANDBY_MODE="hot"
WAN3_IF=""
WAN3_TYPE=""
WAN3_GW4=""
WAN3_MTU=1500
WAN3_MONITOR_IP=""
WAN3_WEIGHT=1
LAGG_IF=""
LAGG_MODE=""
LAGG_MEMBERS=""
WIFI_LAN_IF=""
WIFI_LAN_ROLE="none"
WIFI_LAN_IP4=""
WIFI_LAN_NET4=""
WIFI_LAN_MASK4=""
WIFI_LAN_IP6=""
WIFI_LAN_NET6=""
_PFLOG1_WRITTEN=0
_PFLOG1_WRITTEN=0
_LAGG_WRITTEN=0
_PFSYNC_WRITTEN=0
_HOSTNAME_INT_WRITTEN=0
_TN_INTERFACES_WRITTEN=0
_MYGATE_WRITTEN=0
_BRIDGE_CREATED=""
_VETH_CREATED=""
_BRIDGE_IF=""
_AUDITED_IFACES=""
_LAGG_WRITTEN=0
_PFSYNC_WRITTEN=0
_HOSTNAME_INT_WRITTEN=0
_TN_INTERFACES_WRITTEN=0
_MYGATE_WRITTEN=0
_AUDITED_IFACES=""

# =============================================================================
# STAGE 2 -- FIRMWARE UPDATE
# =============================================================================
print_header "Stage 2: Firmware Update"

if ! command -v fw_update > /dev/null 2>&1; then
  warn "fw_update not found -- skipping"
else
  info "Running fw_update -v..."
  _fw_output=$(fw_update -v 2>&1) || true
  printf "%s\n" "$_fw_output" | tee -a "$LOG_FILE" | sed 's/^/  /'
  if printf "%s" "$_fw_output" | grep -q "installed\."; then
    printf "\n  ${BOLD}REBOOT REQUIRED BEFORE SETUP CAN CONTINUE${NC}\n\n"
    printf "  Firmware installed. No configuration written yet.\n"
    printf "  After reboot, re-run TN_NET_SET.sh to continue.\n\n"
    printf "  ${MAGENTA}Reboot now? [Y/n]: ${NC}"
    read _rb_ans
    case "${_rb_ans:-y}" in
      [Nn]*) warn "Reboot declined -- new hardware may not be visible." ;;
      *)
        ok "Rebooting in 5 seconds..."
        sleep 5
        reboot
        ;;
    esac
  else
    ok "No firmware updates needed."
  fi
fi

# =============================================================================
# STAGE 3 -- HOSTNAME + WAN INTERFACE
# =============================================================================
print_header "Stage 3: Hostname and WAN Interface"

MYNAME_FILE="/etc/myname"
CURRENT_HOSTNAME=""
[ -f "$MYNAME_FILE" ] && CURRENT_HOSTNAME=$(tr -d ' \t\n' < "$MYNAME_FILE")

if [ -z "$CURRENT_HOSTNAME" ]; then
  _ho=0
  while [ "$_ho" -eq 0 ]; do
    printf "  ${MAGENTA}Hostname (e.g. gateway-01): ${NC}"
    read _hn
    _hn=$(printf "%s" "$_hn" | tr -d ' \t')
    if validate_hostname "$_hn"; then
      CURRENT_HOSTNAME="$_hn"
      backup_original "$MYNAME_FILE"
      printf "%s\n" "$CURRENT_HOSTNAME" > "$MYNAME_FILE"
      chmod 644 "$MYNAME_FILE"
      chown root:wheel "$MYNAME_FILE"
      hostname "$CURRENT_HOSTNAME"
      ok "Hostname: $CURRENT_HOSTNAME"
      _ho=1
    else warn "Invalid hostname format"; fi
  done
fi

printf "%s" "$CURRENT_HOSTNAME" | grep -q '\.' \
  && DHCPD_FQDN_VAL="$CURRENT_HOSTNAME" \
  || DHCPD_FQDN_VAL="${CURRENT_HOSTNAME}.localdomain"
ok "Hostname: $CURRENT_HOSTNAME  FQDN: $DHCPD_FQDN_VAL"

printf "\n  Available interfaces:\n\n"
for _if in $(list_interfaces); do
  _stat="down"
  ifconfig "$_if" 2> /dev/null | grep -q "status: active" && _stat="active"
  _wl=""
  is_wireless "$_if" && _wl=" [wireless]"
  _ip=$(get_ip4 "$_if")
  printf "  %-12s %-18s [%s]%s\n" "$_if" "${_ip:--}" "$_stat" "$_wl"
done
printf "\n  ${MAGENTA}WAN interface (faces internet): ${NC}"
read EXT_IF
EXT_IF=$(printf "%s" "$EXT_IF" | tr -d ' \t')
[ -z "$EXT_IF" ] && _undo "WAN not provided" && exit 1
ifconfig "$EXT_IF" > /dev/null 2>&1 || case "$EXT_IF" in
  pppoe[0-9]* | bridge[0-9]*) : ;;
  *) _undo "Interface $EXT_IF does not exist" && exit 1 ;;
esac
ok "WAN: $EXT_IF"

# =============================================================================
# STAGE 4 -- MULTI-WAN (dormant -- gated for 8.0)
# =============================================================================
print_header "Stage 4: Multi-WAN Topology"
printf "\n  (!) Dormant in this release. ONE WAN enforced.\n"
printf "      Multi-WAN (failover/load-balance/policy) gated for 8.0.\n\n"
WAN_PRIMARY_IF="$EXT_IF"
WAN_COUNT=1
WAN_MULTI_MODE="none"
WAN2_IF=""
WAN2_TYPE=""
WAN2_GW4=""
WAN2_MONITOR_IP=""
WAN3_IF=""
WAN3_TYPE=""
WAN3_GW4=""
WAN3_MONITOR_IP=""
info "Single WAN enforced: $EXT_IF"

# =============================================================================
# STAGE 5 -- WAN TYPE
# =============================================================================
print_header "Stage 5: WAN Type Detection"

WAN_IS_PPPOE=0
WAN_TYPE="ethernet"
PPPOE_PARENT=""
PPPOE_LOGICAL_IF=""
WAN_WIFI_SSID=""
WAN_WIFI_SECURITY=""

_s2_link=$(ifconfig "$EXT_IF" 2> /dev/null | awk '/status:/{print $2;exit}')

if [ "$_s2_link" = "active" ] && probe_pppoe "$EXT_IF"; then
  WAN_TYPE="pppoe"
  WAN_IS_PPPOE=1
  PPPOE_PARENT="$PPPOE_PHYS"
  PPPOE_LOGICAL_IF="${PPPOE_LOGICAL:-pppoe0}"
  EXT_IF="$PPPOE_LOGICAL_IF"
  ok "WAN: PPPoE  phys=$PPPOE_PARENT  logical=$EXT_IF"
  PPPOE_USER=""
  PPPOE_PASS=""
  printf "  ${MAGENTA}PPPoE username: ${NC}"
  read PPPOE_USER
  _read_secret "PPPOE_PASS" "PPPoE password: "
elif is_wireless "$EXT_IF"; then
  WAN_TYPE="wireless"
  WAN_WIFI_SSID=$(ifconfig "$EXT_IF" 2> /dev/null | awk '/nwid/{print $2;exit}')
  ok "WAN: wireless  SSID=${WAN_WIFI_SSID:-unknown}"
else
  WAN_TYPE="ethernet"
  # Write /etc/hostname.$EXT_IF for wired Ethernet WAN.
  # Guard: if the file already exists and contains an inet or inet6 line,
  # preserve it -- the operator may have customised it (static IP, VLAN, etc).
  # Only write a fresh autoconf skeleton on first-time setup.
  _WAN_HN="/etc/hostname.${EXT_IF}"
  if [ -f "$_WAN_HN" ] && grep -qE '^inet|^inet6' "$_WAN_HN" 2> /dev/null; then
    info "Preserved existing: $_WAN_HN"
  else
    backup_original "$_WAN_HN"
    printf '# /etc/hostname.%s -- wired Ethernet WAN -- TN_NET_SET.sh v%s\n' \
      "$EXT_IF" "$VERSION" > "$_WAN_HN"
    printf 'inet autoconf\n' >> "$_WAN_HN"
    printf 'inet6 autoconf -temporary\n' >> "$_WAN_HN"
    printf 'up\n' >> "$_WAN_HN"
    chmod 640 "$_WAN_HN"
    chown root:wheel "$_WAN_HN"
    record_installed "$_WAN_HN"
    ok "Written: $_WAN_HN"
  fi
  ok "WAN: ethernet"
fi

# =============================================================================
# STAGE 6 -- WIRELESS WAN CREDENTIALS
# =============================================================================
if [ "$WAN_TYPE" = "wireless" ]; then
  print_header "Stage 6: Wireless WAN Credentials"
  _EXT_PFX=$(iface_prefix "$EXT_IF")
  _read_secret "_ws_ssid" "WAN SSID${WAN_WIFI_SSID:+ [${WAN_WIFI_SSID}]}: "
  [ -n "$_ws_ssid" ] && WAN_WIFI_SSID="$_ws_ssid"
  eval "${_EXT_PFX}_WIFI_SSID=\"$WAN_WIFI_SSID\""
  _clear_secret _ws_ssid
  printf "  ${MAGENTA}Security (wpa2/wpa3/open) [wpa2]: ${NC}"
  read _ws_sec
  case "${_ws_sec:-wpa2}" in
    wpa3) WAN_WIFI_SECURITY="wpa3" ;;
    open) WAN_WIFI_SECURITY="open" ;;
    *) WAN_WIFI_SECURITY="wpa2" ;;
  esac
  eval "${_EXT_PFX}_WIFI_SECURITY=\"$WAN_WIFI_SECURITY\""
  _ws_pass=""
  [ "$WAN_WIFI_SECURITY" != "open" ] \
    && _read_secret "_ws_pass" "WAN passphrase: "
  eval "${_EXT_PFX}_WIFI_PASS=\"$_ws_pass\""
  _WAN_HN="/etc/hostname.${EXT_IF}"
  backup_original "$_WAN_HN"
  _write_wireless_hostname "$EXT_IF" "wan-client" "$_WAN_HN"
  ok "Written: $_WAN_HN"
  eval "${_EXT_PFX}_WIFI_PASS=\"(stored in hostname file)\""
  _clear_secret _ws_pass
fi

# PPPoE hostname files
if [ "$WAN_IS_PPPOE" -eq 1 ]; then
  _PPPOE_HN="/etc/hostname.${PPPOE_LOGICAL_IF}"
  backup_original "$_PPPOE_HN"
  printf '# /etc/hostname.%s -- PPPoE WAN -- TN_NET_SET.sh\n' \
    "$PPPOE_LOGICAL_IF" > "$_PPPOE_HN"
  printf 'inet 0.0.0.0 255.255.255.255 0.0.0.0 pppoedev %s \\\n' \
    "$PPPOE_PARENT" >> "$_PPPOE_HN"
  printf '    authproto pap authname %s authkey %s \\\n' \
    "$PPPOE_USER" "$PPPOE_PASS" >> "$_PPPOE_HN"
  printf '    mtu %s autoconn\n' "$PPPOE_WAN_MTU" >> "$_PPPOE_HN"
  printf '!/sbin/route add default -ifp %s 0.0.0.1\n' \
    "$PPPOE_LOGICAL_IF" >> "$_PPPOE_HN"
  chmod 640 "$_PPPOE_HN"
  chown root:wheel "$_PPPOE_HN"
  record_installed "$_PPPOE_HN"
  ok "Written: $_PPPOE_HN"
  _clear_secret PPPOE_PASS
  _PPPOE_PHYS_HN="/etc/hostname.${PPPOE_PARENT}"
  backup_original "$_PPPOE_PHYS_HN"
  [ ! -f "$_PPPOE_PHYS_HN" ] && printf 'up\n' > "$_PPPOE_PHYS_HN" \
    && chmod 640 "$_PPPOE_PHYS_HN" && chown root:wheel "$_PPPOE_PHYS_HN" \
    && record_installed "$_PPPOE_PHYS_HN" \
    && ok "Written: $_PPPOE_PHYS_HN"
fi

# =============================================================================
# STAGE 7 -- WAN ADDRESS DETECTION
# =============================================================================
print_header "Stage 7: WAN Address Detection"
EXT_IP4=$(get_ip4 "$EXT_IF")
EXT_MASK4=$(get_mask4 "$EXT_IF")
EXT_GW4=$(get_gw4)
EXT_IP6=$(get_ip6 "$EXT_IF")
EXT_GW6=$(get_gw6)
EXT_GW6_CLEAN=$(get_gw6_clean)
WAN_NET6=""
[ -n "$EXT_IP6" ] && WAN_NET6=$(printf "%s" "$EXT_IP6" | sed 's/:[^:]*:[^:]*:[^:]*:[^:]*$/::/')::/64
EXT_IP4_CLASS=$(classify_ip4 "$EXT_IP4")
EXT_IP6_CLASS=$(classify_ip6 "$EXT_IP6")
printf "  WAN IPv4: %-20s  GW: %s\n" "${EXT_IP4:-not detected}" "${EXT_GW4:-not detected}"
printf "  WAN IPv6: %-38s  GW: %s\n" "${EXT_IP6:-not detected}" "${EXT_GW6_CLEAN:-not detected}"

# =============================================================================
# STAGE 8 -- DEPLOYMENT CLASSIFICATION
# =============================================================================
print_header "Stage 8: Deployment Classification"
case "$EXT_IP4_CLASS" in
  cgnat | private) DEPLOY_MODE="cgnat_home" ;;
  public) DEPLOY_MODE="dedicated" ;;
  none) [ -n "$EXT_IP6" ] && DEPLOY_MODE="ipv6_only" || DEPLOY_MODE="unknown" ;;
  *) DEPLOY_MODE="unknown" ;;
esac
case "$EXT_IP6_CLASS" in
  gua) IPV6_MODE="native" ;;
  ula) IPV6_MODE="nat66" ;;
  none) [ "$DEPLOY_MODE" != "ipv6_only" ] && IPV6_MODE="nat64" || IPV6_MODE="none" ;;
  *) IPV6_MODE="none" ;;
esac
[ "${HAS_INET6:-0}" -eq 0 ] && IPV6_MODE="none"
ok "DEPLOY=$DEPLOY_MODE  IPv6=$IPV6_MODE"

# =============================================================================
# STAGE 9 -- VIRTUALISATION DETECTION
# =============================================================================
print_header "Stage 9: Virtualisation Detection"
VIRT_ENV="bare-metal"
CLOUD_PROVIDER="none"
CLOUD_REGION="unknown"
dmesg 2> /dev/null | grep -qi "vmware\|vmxnet" && VIRT_ENV="vmware"
dmesg 2> /dev/null | grep -qi "virtio\|QEMU\|KVM" && VIRT_ENV="kvm"
dmesg 2> /dev/null | grep -qi "Hyper-V\|hvn[0-9]" && VIRT_ENV="hyperv"
dmesg 2> /dev/null | grep -qi "VirtualBox\|vbox" && VIRT_ENV="virtualbox"
dmesg 2> /dev/null | grep -qi "Xen" && VIRT_ENV="xen"
_VIRT_NO_WIFI=0
case "$VIRT_ENV" in bare-metal) : ;; *) _VIRT_NO_WIFI=1 ;; esac
ok "Virtualisation: $VIRT_ENV"

# =============================================================================
# STAGE 10 -- VLAN / TRUNK (dormant -- gated for 8.0)
# =============================================================================
print_header "Stage 10: VLAN and Trunk Configuration"
printf "\n  (!) Dormant in this release. Defaulting to 0 VLANs.\n\n"
VLAN_COUNT=0
LAGG_IF=""
LAGG_MODE=""
LAGG_MEMBERS=""
info "Stage 10 skipped -- Dual-LAN enforcement active"

# =============================================================================
# STAGE 11 -- PRIMARY LAN INTERFACE
# =============================================================================
#
# Probes all physical interfaces that are not the WAN, classifies each one
# (wired / wireless), and presents the findings to the operator before asking
# any questions. The operator never needs to know that bridge0 does not exist
# yet -- the script makes the decision to create it based on what it found.
#
# Decision tree:
#   0 spare interfaces -> abort (no LAN possible)
#   1 spare interface  -> select it automatically, no bridge possible
#   2+ spare interfaces -> ask: single LAN or bridge?
#     bridge -> auto-create bridge0, offer all spares as candidates,
#               operator picks members by NUMBER from a displayed list
#     single -> operator picks interface by NUMBER from displayed list
#
# A numbered menu is used throughout so the operator never types interface
# names. Mistyping an interface name was the failure mode of the old design.
# =============================================================================
print_header "Stage 11: Primary LAN Interface"

# Collect spare interfaces
_spare_ifs=""
_spare_count=0
for _if in $(list_interfaces); do
  [ "$_if" = "$EXT_IF" ] && continue
  case "$_if" in
    bridge* | vlan* | tun* | tap* | enc* | pflog* | pfsync* | lo*) continue ;;
  esac
  ifconfig "$_if" > /dev/null 2>&1 || continue
  _spare_ifs="${_spare_ifs:+$_spare_ifs }$_if"
  _spare_count=$((_spare_count + 1))
done

if [ "$_spare_count" -eq 0 ]; then
  _undo "No LAN interfaces available after excluding WAN ($EXT_IF)"
  exit 1
fi

# Display findings with improved alignment
printf "\n  %-25s : %s\n" "WAN Interface" "$EXT_IF"
printf "  %-25s : %d found\n" "Available Interfaces" "$_spare_count"
printf "\n  %s\n" "--- Interface List ---"
_idx=0
for _if in $_spare_ifs; do
  _idx=$((_idx + 1))
  _stat="down"
  ifconfig "$_if" 2> /dev/null | grep -q "status: active" && _stat="active"
  _type="wired"
  is_wireless "$_if" && _type="wireless ($(get_wifi_driver "$_if"))"
  printf "  [%d] %-12s | Status: %-8s | Type: %s\n" "$_idx" "$_if" "$_stat" "$_type"
done
printf "\n"

# Initialise LAN variables before selection logic.
# set -u is active -- every variable referenced later must be set here
# regardless of which branch (single/bridge, wired/wireless) is taken.
INT_IF=""
INT_IFS=""
INT_IS_WIRELESS=0
INT_IS_BRIDGE=0
INT_BRIDGE_MEMBERS=""

# Logic for selection
if [ "$_spare_count" -eq 1 ]; then
  INT_IF="$_spare_ifs"
  is_wireless "$INT_IF" && INT_IS_WIRELESS=1
  INT_IFS="$INT_IF"
  ok "Single interface detected: $INT_IF (Selected automatically)"
else
  printf "  %s\n" "Please choose a configuration mode:"
  printf "  [A] Single Interface : Use one specific port/device for LAN.\n"
  printf "  [B] Bridge LAN       : Combine multiple ports into one segment.\n"
  printf "\n  ${MAGENTA}Enter choice [A/B] (Default: A): ${NC}"
  read _lan_mode
  _lan_mode=$(printf "%s" "${_lan_mode:-a}" | tr 'A-Z' 'a-z' | tr -d ' \t')

  case "$_lan_mode" in
    b)
      # Bridge LAN
      # Auto-select next available bridge number
      _br_n=0
      while ifconfig "bridge${_br_n}" > /dev/null 2>&1; do
        _br_n=$((_br_n + 1))
      done
      INT_IF="bridge${_br_n}"
      ifconfig "$INT_IF" create > /dev/null 2>&1 \
        || {
          _undo "Could not create $INT_IF"
          exit 1
        }
      ok "Created: $INT_IF"
      _BRIDGE_CREATED="$INT_IF"
      INT_IS_BRIDGE=1
      INT_IS_WIRELESS=0

      printf "\n  %s\n" "--- Bridge Member Selection ---"
      printf "  Enter the numbers (e.g., 1) one by one. Press Enter on a blank line to finish.\n"
      printf "  Each interface is identified by number in the list above.\n\n"
      _bm_list=""
      _bm_count=0
      while true; do
        # Show running list of already-selected members
        if [ -n "$_bm_list" ]; then
          printf "  Current members: ${GREEN}%s${NC}\n" "$_bm_list"
        fi
        printf "  ${MAGENTA}Add interface number: ${NC}"
        read _bm_n
        _bm_n=$(printf "%s" "$_bm_n" | tr -d ' \t')
        [ -z "$_bm_n" ] && break

        # Validate numeric input
        case "$_bm_n" in
          '' | *[!0-9]*)
            warn "  Enter a number from the list above"
            continue
            ;;
        esac
        if [ "$_bm_n" -lt 1 ] || [ "$_bm_n" -gt "$_spare_count" ]; then
          warn "  Number out of range (1-$_spare_count)"
          continue
        fi

        # Resolve number to interface name
        _bm_input=$(printf "%s" "$_spare_ifs" \
          | tr ' ' '\n' | sed -n "${_bm_n}p")
        [ -z "$_bm_input" ] && warn "  Could not resolve selection" && continue

        # Reject duplicates
        _dup=0
        for _existing in $_bm_list; do
          [ "$_existing" = "$_bm_input" ] && _dup=1 && break
        done
        if [ "$_dup" -eq 1 ]; then
          warn "  $_bm_input already added"
          continue
        fi

        _bm_list="${_bm_list:+$_bm_list }$_bm_input"
        _bm_count=$((_bm_count + 1))
        ok "Added: $_bm_input"
      done

      if [ -z "$_bm_list" ]; then
        _undo "Bridge $INT_IF has no members -- cannot continue"
        exit 1
      fi

      INT_BRIDGE_MEMBERS="$_bm_list"
      INT_IFS="$INT_IF $INT_BRIDGE_MEMBERS"
      for _bm in $INT_BRIDGE_MEMBERS; do
        is_wireless "$_bm" && INT_IS_WIRELESS=1 && break
      done
      printf "\n"
      ok "Bridge LAN: $INT_IF  ($_bm_count member(s): $INT_BRIDGE_MEMBERS)"
      ;;

    *)
      # Single interface -- pick by number
      if [ "$_spare_count" -eq 1 ]; then
        INT_IF="$_spare_ifs"
      else
        _pick_ok=0
        printf "\n  %s\n" "--- Manual Selection ---"
        printf "  Each interface is identified by number in the list above.\n\n"
        while [ "$_pick_ok" -eq 0 ]; do
          printf "  ${MAGENTA}Select interface number [1]: ${NC}"
          read _pick_n
          _pick_n="${_pick_n:-1}"
          case "$_pick_n" in
            '' | *[!0-9]*)
              warn "  Enter a number from the list above"
              continue
              ;;
          esac
          if [ "$_pick_n" -lt 1 ] || [ "$_pick_n" -gt "$_spare_count" ]; then
            warn "  Number out of range (1-$_spare_count)"
            continue
          fi
          INT_IF=$(printf "%s" "$_spare_ifs" \
            | tr ' ' '\n' | sed -n "${_pick_n}p")
          [ -n "$INT_IF" ] && _pick_ok=1 || warn "  Could not resolve selection"
        done
      fi
      is_wireless "$INT_IF" && INT_IS_WIRELESS=1
      INT_IFS="$INT_IF"
      ok "Primary LAN: $INT_IF"
      ;;
  esac
fi

_claimed="${EXT_IF} ${INT_IF}"

# =============================================================================
# STAGE 12 -- PRIMARY LAN WIRELESS CONFIGURATION (AP)
#
# Role is architecturally determined in dual-NIC topology:
#   Wired WAN + wireless LAN -> AP forced.
#   The wired interface provides upstream; wireless serves LAN clients.
#   A single radio cannot simultaneously be WAN client and LAN AP.
#
# _prompt_wireless_config called with force-role "ap" -- no role question.
# Band detected from driver capability (get_wifi_modes); inventory only.
# No mode pin in hostname file. OpenBSD negotiates at bring-up.
# =============================================================================
WIFI_LAN_IF=""
WIFI_LAN_ROLE="none"
WIFI_IS_BRIDGE_MEMBER=0

if [ "${INT_IS_BRIDGE:-0}" -eq 1 ] && [ -n "$INT_BRIDGE_MEMBERS" ]; then
  # Bridge LAN: check if any member is wireless.
  # If so, configure it as an AP now. The IP will be assigned to bridge0,
  # not to the wireless interface -- WIFI_IS_BRIDGE_MEMBER suppresses the
  # inet lines in the member hostname file (written in Stage 17).
  print_header "Stage 12: Bridge Member Wireless Configuration"
  for _bm in $INT_BRIDGE_MEMBERS; do
    if is_wireless "$_bm" && [ "$_VIRT_NO_WIFI" -eq 0 ]; then
      _bm_pfx=$(iface_prefix "$_bm")
      info "Bridge member $_bm is wireless -- configuring as AP (IP stays on $INT_IF)"
      eval "${_bm_pfx}_WIFI_ROLE=\"ap\""
      WIFI_LAN_ROLE="ap"
      WIFI_LAN_IF="${WIFI_LAN_IF:+$WIFI_LAN_IF }$_bm"
      WIFI_IS_BRIDGE_MEMBER=1
      _prompt_wireless_config "$_bm_pfx" "$_bm" "bridge member AP" "ap"
    elif is_wireless "$_bm" && [ "$_VIRT_NO_WIFI" -eq 1 ]; then
      warn "Virtual machine detected -- wireless member $_bm skipped"
    fi
  done
elif [ "$INT_IS_WIRELESS" -eq 1 ] && [ "$_VIRT_NO_WIFI" -eq 0 ]; then
  # Non-bridge: wireless is the primary LAN interface, AP role forced.
  print_header "Stage 12: Primary LAN Wireless Configuration (AP)"
  _INT_PFX=$(iface_prefix "$INT_IF")
  info "WAN is wired ($EXT_IF) -- LAN wireless ($INT_IF) role: AP (topology-determined)"
  eval "${_INT_PFX}_WIFI_ROLE=\"ap\""
  WIFI_LAN_ROLE="ap"
  WIFI_LAN_IF="$INT_IF"
  _prompt_wireless_config "$_INT_PFX" "$INT_IF" "primary LAN" "ap"
elif [ "$INT_IS_WIRELESS" -eq 1 ] && [ "$_VIRT_NO_WIFI" -eq 1 ]; then
  warn "Virtual machine detected -- wireless not available"
fi

# =============================================================================
# STAGE 13 -- ADDITIONAL PHYSICAL LAN (dormant -- gated for 8.0)
# =============================================================================
print_header "Stage 13: Additional Physical LAN Interfaces"
EXTRA_LAN_COUNT=0
printf "\n  (!) Dormant in this release. N+1 LAN scaling gated for 8.0.\n\n"
info "Stage 13 skipped -- Dual-LAN enforcement active"

# =============================================================================
# STAGE 14 -- LAN SUBNET ASSIGNMENT
# =============================================================================
print_header "Stage 14: LAN Subnet Assignment"

prompt_lan_subnet "Primary LAN (${INT_IF}) Subnet"
INT_IP4="$_SUBNET_RESULT_IP"
INT_MASK4="$_SUBNET_RESULT_MASK"
INT_NET4="$_SUBNET_RESULT"
INT_CIDR4="$_SUBNET_RESULT_CIDR"
INT_IP6="${_SUBNET_RESULT_IP6:-}"
INT_NET6="${_SUBNET_RESULT_NET6:-}"
INT_CIDR6="64"

_INT_PFX=$(iface_prefix "$INT_IF")
derive_subnet_vars "INT" "$INT_IP4" "$INT_MASK4"

# Populate prefix-keyed vars so _write_wireless_hostname (Stage 17) finds them.
# Stage 12 sets WIFI_* vars under the prefix but not _IP4/_MASK4/_IP6.
# Without these three lines the AP hostname file gets blank inet addresses.
eval "${_INT_PFX}_IP4=\"${INT_IP4}\""
eval "${_INT_PFX}_MASK4=\"${INT_MASK4}\""
eval "${_INT_PFX}_IP6=\"${INT_IP6:-}\""

_int_mss_type="ethernet"
if [ "$INT_IS_WIRELESS" -eq 1 ]; then
  eval _int_wfr="\${${_INT_PFX}_WIFI_ROLE:-none}"
  eval _int_wsec="\${${_INT_PFX}_WIFI_SECURITY:-wpa2}"
  case "$_int_wfr" in
    ap) [ "$_int_wsec" = "open" ] \
      && _int_mss_type="wifi-ap-open" \
      || _int_mss_type="wifi-ap-ccmp" ;;
    client) _int_mss_type="wifi-client" ;;
  esac
fi
derive_mss "INT" "$_int_mss_type" 1500
ok "Primary LAN: $INT_IP4/$INT_CIDR4  MSS4=$INT_MSS4  MSS6=$INT_MSS6"

# Wireless AP mirrors primary LAN subnet
WIFI_LAN_IP4=""
WIFI_LAN_NET4=""
WIFI_LAN_MASK4=""
WIFI_LAN_IP6=""
WIFI_LAN_NET6=""
WIFI_LAN_CIDR4=""
WIFI_LAN_CIDR6="64"
if [ "$WIFI_LAN_ROLE" = "ap" ] && [ -n "$WIFI_LAN_IF" ]; then
  WIFI_LAN_IP4="$INT_IP4"
  WIFI_LAN_NET4="$INT_NET4"
  WIFI_LAN_MASK4="$INT_MASK4"
  WIFI_LAN_CIDR4="$INT_CIDR4"
  WIFI_LAN_IP6="$INT_IP6"
  WIFI_LAN_NET6="$INT_NET6"
fi

# =============================================================================
# STAGE 15 -- HA: CARP + pfsync (dormant -- gated for post-8.0)
# =============================================================================
print_header "Stage 15: High Availability (CARP)"
printf "\n  (!) Dormant. This is a single-node UTM release.\n"
printf "      CARP would provide IP mobility only -- active proxy sessions\n"
printf "      drop on failover without cluster-aware proxy redesign.\n\n"
HA_ENABLED=0
HA_ROLE="none"
CARP0_VIP_LAN=""
CARP0_VIP_WAN=""
CARP0_VHID="1"
CARP0_ADVSKEW="0"
PFSYNC0_IF=""
PFSYNC0_PEER_IP=""
info "Stage 15 skipped -- Single-node UTM"

# =============================================================================
# STAGE 16 -- HARDWARE OFFLOAD AUDIT
# =============================================================================
print_header "Stage 16: Hardware Offload Audit"

_audit_once() {
  _ao_if="$1"
  _ao_label="$2"
  _already=0
  for _aif in $_AUDITED_IFACES; do
    [ "$_aif" = "$_ao_if" ] && _already=1 && break
  done
  [ "$_already" -eq 1 ] && return 0
  audit_offload "$_ao_if" "$_ao_label"
  _AUDITED_IFACES="$_AUDITED_IFACES $_ao_if"
}

_audit_once "$EXT_IF" "WAN ($EXT_IF)"

if [ "${INT_IS_BRIDGE:-0}" -eq 1 ] && [ -n "$INT_BRIDGE_MEMBERS" ]; then
  # Bridge: audit each physical member, not the bridge pseudo-interface.
  # TSO/LRO live on the real NICs; ifconfig on bridge0 sees none of them.
  # The bridge interface itself has no offload caps to disable.
  for _bm in $INT_BRIDGE_MEMBERS; do
    _audit_once "$_bm" "LAN bridge member ($_bm)"
  done
  info "Bridge pseudo-interface $INT_IF skipped (no offload caps)"
else
  _audit_once "$INT_IF" "LAN ($INT_IF)"
fi

OFFLOAD_AUDIT_DONE=1
ok "Offload audit complete"

# =============================================================================
# STAGE 17 -- WRITE hostname.INT_IF AND hostname.pflog1
# =============================================================================
print_header "Stage 17: Interface Hostname Files"

# HOSTNAME_INT_FILE, backup_original, and _INT_PFX are set inside each
# branch below.  In bridge mode INT_IF is remapped bridge0->vether0 before
# those are set, so they must not be computed before the branch is entered.

if [ "${INT_IS_BRIDGE:-0}" -eq 1 ]; then
  # -------------------------------------------------------------------------
  # Bridge LAN topology (OpenBSD UTM canonical form):
  #
  #   em1, em2, athn0  -->  bridge0 (L2 forwarder, no IP)
  #                              |
  #                          vether0  (holds LAN IP -- INT_IF for pf/divert)
  #
  # vether0 is a virtual Ethernet pair whose one end lives inside bridge0.
  # All pf rules, divert sockets, dhcpd, rad, and unbound bind to vether0,
  # not to bridge0 or the physical members.  This is mandatory for the UTM
  # inspection pipeline: divert(4) rules keyed on a bridge pseudo-interface
  # do not match traffic arriving on its physical ports.
  #
  # hostname.bridge0  -- "add em1 / add athn0 / add vether0 / up"  (no IP)
  # hostname.vether0  -- "inet / inet6 / up"                        (LAN IP)
  # hostname.emN      -- offload flags + "up"                       (no IP)
  # hostname.athn0    -- mediaopt hostap + chan + nwid + up         (no IP)
  # -------------------------------------------------------------------------

  # Create vether0 now so Stage 18 can bring it up.
  _VETH_IF="vether0"
  ifconfig "$_VETH_IF" > /dev/null 2>&1 \
    || ifconfig "$_VETH_IF" create > /dev/null 2>&1 \
    || {
      _undo "Cannot create $_VETH_IF"
      exit 1
    }
  _VETH_CREATED="$_VETH_IF"
  ok "Created: $_VETH_IF"

  # Remap INT_IF -> vether0 for all downstream stages (Stage 18 onward,
  # tn-interfaces, SSL SAN, dhcpd, rad, unbound, pf).
  # Save the bridge name so we can write its hostname file below.
  _BRIDGE_IF="$INT_IF"
  INT_IF="$_VETH_IF"
  INT_IFS="$_BRIDGE_IF $INT_BRIDGE_MEMBERS $INT_IF"

  # Update HOSTNAME_INT_FILE to point at vether0.
  HOSTNAME_INT_FILE="/etc/hostname.${INT_IF}"
  backup_original "$HOSTNAME_INT_FILE"
  _INT_PFX=$(iface_prefix "$INT_IF")

  # hostname.vether0 -- LAN IP lives here.
  printf '# /etc/hostname.%s -- bridge LAN anchor -- TN_NET_SET.sh v%s\n' \
    "$INT_IF" "$VERSION" > "$HOSTNAME_INT_FILE"
  printf 'inet %s %s\n' "$INT_IP4" "$INT_MASK4" >> "$HOSTNAME_INT_FILE"
  if [ "${HAS_INET6:-0}" -eq 1 ] && [ -n "$INT_IP6" ]; then
    printf 'inet6 %s %s\n' "$INT_IP6" "$INT_CIDR6" >> "$HOSTNAME_INT_FILE"
    printf '!route add -inet6 64:ff9b::/96 %s\n' "$INT_IP6" >> "$HOSTNAME_INT_FILE"
  fi
  printf 'up\n' >> "$HOSTNAME_INT_FILE"
  chmod 640 "$HOSTNAME_INT_FILE"
  chown root:wheel "$HOSTNAME_INT_FILE"
  ok "Written: $HOSTNAME_INT_FILE"

  # hostname.bridge0 -- L2 forwarder only; no IP.
  # Members: all physical ports + vether0.
  _BRIDGE_HN="/etc/hostname.${_BRIDGE_IF}"
  backup_original "$_BRIDGE_HN"
  printf '# /etc/hostname.%s -- bridge forwarder -- TN_NET_SET.sh v%s\n' \
    "$_BRIDGE_IF" "$VERSION" > "$_BRIDGE_HN"
  for _bm in $INT_BRIDGE_MEMBERS; do
    printf 'add %s\n' "$_bm" >> "$_BRIDGE_HN"
  done
  printf 'add %s\n' "$INT_IF" >> "$_BRIDGE_HN" # vether0 is the IP anchor
  printf 'up\n' >> "$_BRIDGE_HN"
  chmod 640 "$_BRIDGE_HN"
  chown root:wheel "$_BRIDGE_HN"
  record_installed "$_BRIDGE_HN"
  ok "Written: $_BRIDGE_HN"

  # hostname.emN / hostname.athn0 -- members get no IP, just up + offload flags.
  # Written to /etc/ directly; Stage 18 brings them up bare before the bridge.
  for _bm in $INT_BRIDGE_MEMBERS; do
    _bm_hn="/etc/hostname.${_bm}"
    backup_original "$_bm_hn"
    _bm_pfx=$(iface_prefix "$_bm")
    if is_wireless "$_bm"; then
      # Wireless bridge member: hostap mode, no inet/inet6.
      # The radio operates at L2 inside the bridge; IP lives on vether0.
      eval _bm_ssid="\${${_bm_pfx}_WIFI_SSID:-}"
      eval _bm_pass="\${${_bm_pfx}_WIFI_PASS:-}"
      eval _bm_sec="\${${_bm_pfx}_WIFI_SECURITY:-wpa2}"
      eval _bm_chan="\${${_bm_pfx}_WIFI_CHANNEL:-6}"
      printf '# /etc/hostname.%s -- wireless bridge member -- TN_NET_SET.sh v%s\n' \
        "$_bm" "$VERSION" > "$_bm_hn"
      printf 'mediaopt hostap\n' >> "$_bm_hn"
      printf 'chan %s\n' "$_bm_chan" >> "$_bm_hn"
      printf 'nwid %s\n' "$_bm_ssid" >> "$_bm_hn"
      [ "$_bm_sec" != "open" ] \
        && printf 'wpakey %s\n' "$_bm_pass" >> "$_bm_hn"
      printf -- '-powersave\n' >> "$_bm_hn"
      printf 'up\n' >> "$_bm_hn"
      eval "${_bm_pfx}_WIFI_PASS=\"(stored in hostname file)\""
    else
      # Wired bridge member: offload flags + up, no IP.
      _bm_pfx2=$(iface_prefix "$_bm")
      eval _bmt4v="\${${_bm_pfx2}_TSO4_DISABLED:-0}"
      eval _bmt6v="\${${_bm_pfx2}_TSO6_DISABLED:-0}"
      eval _bmlrv="\${${_bm_pfx2}_LRO_DISABLED:-0}"
      printf '# /etc/hostname.%s -- wired bridge member -- TN_NET_SET.sh v%s\n' \
        "$_bm" "$VERSION" > "$_bm_hn"
      [ "$_bmt4v" -eq 1 ] && printf -- '-tso4\n' >> "$_bm_hn"
      [ "$_bmt6v" -eq 1 ] && printf -- '-tso6\n' >> "$_bm_hn"
      [ "$_bmlrv" -eq 1 ] && printf -- '-lro\n' >> "$_bm_hn"
      printf 'up\n' >> "$_bm_hn"
    fi
    chmod 640 "$_bm_hn"
    chown root:wheel "$_bm_hn"
    record_installed "$_bm_hn"
    ok "Written: $_bm_hn"
  done

elif [ "$INT_IS_WIRELESS" -eq 1 ] && [ "$WIFI_LAN_ROLE" != "none" ]; then
  # Wireless primary LAN (not a bridge member) -- canonical AP form.
  HOSTNAME_INT_FILE="/etc/hostname.${INT_IF}"
  backup_original "$HOSTNAME_INT_FILE"
  _INT_PFX=$(iface_prefix "$INT_IF")
  _write_wireless_hostname "$INT_IF" "lan-${WIFI_LAN_ROLE}" "$HOSTNAME_INT_FILE"
  eval "${_INT_PFX}_WIFI_PASS=\"(stored in hostname file)\""

else
  # Wired primary LAN (no bridge)
  HOSTNAME_INT_FILE="/etc/hostname.${INT_IF}"
  backup_original "$HOSTNAME_INT_FILE"
  _INT_PFX=$(iface_prefix "$INT_IF")
  printf '# /etc/hostname.%s -- primary LAN -- TN_NET_SET.sh v%s\n' \
    "$INT_IF" "$VERSION" > "$HOSTNAME_INT_FILE"
  printf 'inet %s %s\n' "$INT_IP4" "$INT_MASK4" >> "$HOSTNAME_INT_FILE"
  if [ "${HAS_INET6:-0}" -eq 1 ] && [ -n "$INT_IP6" ]; then
    printf 'inet6 %s %s\n' "$INT_IP6" "$INT_CIDR6" >> "$HOSTNAME_INT_FILE"
    printf '!route add -inet6 64:ff9b::/96 %s\n' "$INT_IP6" >> "$HOSTNAME_INT_FILE"
  fi
  printf 'mtu 1500\nup\n' >> "$HOSTNAME_INT_FILE"
  chmod 640 "$HOSTNAME_INT_FILE"
  chown root:wheel "$HOSTNAME_INT_FILE"
fi

_HOSTNAME_INT_WRITTEN=1
record_installed "$HOSTNAME_INT_FILE"
ok "Written: $HOSTNAME_INT_FILE"

# pflog1 -- sovereign all-traffic log interface for UTM pipeline.
# Brought up by this file during netstart; not managed by pflogd.
# The match log (to pflog1) rule in pf.conf directs copies of all
# packets on real interfaces here. Loopback is excluded.
if [ ! -f /etc/hostname.pflog1 ]; then
  printf 'up\n' > /etc/hostname.pflog1
  chmod 640 /etc/hostname.pflog1
  chown root:wheel /etc/hostname.pflog1
  _PFLOG1_WRITTEN=1
  record_installed /etc/hostname.pflog1
  ok "Written: /etc/hostname.pflog1"
else
  info "Exists: /etc/hostname.pflog1"
fi

# =============================================================================
# STAGE 18 -- BRING INTERFACES UP
# =============================================================================
print_header "Stage 18: Bringing Interfaces Up"

# Tear down INT_IF (vether0 in bridge mode, physical NIC otherwise) before
# reconfiguring. Old ULA and IPv4 addresses persist alongside new ones
# without this, confusing DAD, DHCP, unbound, and rad.
info "Tearing down $INT_IF before reconfiguration..."
ifconfig "$INT_IF" down > /dev/null 2>&1 || true
sleep 1

ifconfig "$INT_IF" 2> /dev/null | awk '/inet / {print $2}' \
  | while IFS= read -r _a4; do
    ifconfig "$INT_IF" inet "$_a4" delete > /dev/null 2>&1 || true
  done

ifconfig "$INT_IF" 2> /dev/null | awk '/inet6 / {print $2}' \
  | while IFS= read -r _a6; do
    _a6b=$(printf "%s" "$_a6" | cut -d% -f1)
    ifconfig "$INT_IF" inet6 "$_a6b" delete > /dev/null 2>&1 || true
  done
ok "$INT_IF cleared"

# In bridge mode, also tear down the bridge and its physical members so
# Stage 11's live ifconfig bridge0 create + the address-strip above
# leave us in a clean known state before we re-sequence bring-up.
if [ "${INT_IS_BRIDGE:-0}" -eq 1 ]; then
  info "Tearing down bridge ${_BRIDGE_IF} and members before reconfiguration..."
  ifconfig "$_BRIDGE_IF" down > /dev/null 2>&1 || true
  for _tbm in $INT_BRIDGE_MEMBERS; do
    ifconfig "$_tbm" down > /dev/null 2>&1 || true
  done
  sleep 1
fi

if [ "${INT_IS_BRIDGE:-0}" -eq 1 ]; then
  # Bridge bring-up sequence (order is mandatory):
  #
  #   Step 1: Bring each physical member up bare with ifconfig.
  #           Do NOT use netstart here -- the member hostname files
  #           now live in /etc/ but we must not assign any IP to a
  #           member; ifconfig up is sufficient and safe.
  #
  #   Step 2: netstart vether0 -- assigns the LAN IP.
  #           vether0 must be up before the bridge enslaves it so that
  #           the bridge inherits a valid MAC from it.
  #
  #   Step 3: netstart bridge0 -- reads hostname.bridge0, issues
  #           "ifconfig bridge0 add emN / add vether0", brings bridge up.
  #           Members and vether0 must be up before this step.
  #
  # netstart is NOT called on individual members because their hostname
  # files contain only "up" (plus optional offload flags) and we have
  # already stripped addresses above.  Calling netstart on a member
  # whose hostname file has no inet line is harmless, but calling it
  # before the bridge exists risks leaving stale kernel state.

  for _bm in $INT_BRIDGE_MEMBERS; do
    info "Preparing bridge member (bare up): $_bm"
    ifconfig "$_bm" down > /dev/null 2>&1 || true
    sleep 1
    # Strip any stale addresses.
    ifconfig "$_bm" 2> /dev/null | awk '/inet / {print $2}' \
      | while IFS= read -r _bma4; do
        ifconfig "$_bm" inet "$_bma4" delete > /dev/null 2>&1 || true
      done
    ifconfig "$_bm" 2> /dev/null | awk '/inet6 / {print $2}' \
      | while IFS= read -r _bma6; do
        _bma6b=$(printf "%s" "$_bma6" | cut -d% -f1)
        ifconfig "$_bm" inet6 "$_bma6b" delete > /dev/null 2>&1 || true
      done
    # Apply offload flags from the member hostname file if present,
    # then bring the interface up bare (no IP).
    sh /etc/netstart "$_bm" > /dev/null 2>&1 || true
    ok "Member up: $_bm"
  done

  # Step 2: bring vether0 up with the LAN IP.
  info "Bringing up $_VETH_IF (LAN anchor)..."
  ifconfig "$_VETH_IF" down > /dev/null 2>&1 || true
  sleep 1
  ifconfig "$_VETH_IF" 2> /dev/null | awk '/inet / {print $2}' \
    | while IFS= read -r _va4; do
      ifconfig "$_VETH_IF" inet "$_va4" delete > /dev/null 2>&1 || true
    done
  sh /etc/netstart "$_VETH_IF" > /dev/null 2>&1
  ok "$_VETH_IF up: $INT_IP4"

  # Step 3: bring bridge0 up -- enslaves members + vether0.
  info "Bringing up bridge: $_BRIDGE_IF..."
  ifconfig "$_BRIDGE_IF" down > /dev/null 2>&1 || true
  sleep 1
  sh /etc/netstart "$_BRIDGE_IF" > /dev/null 2>&1
  ok "$_BRIDGE_IF up"
fi

# Non-bridge path (INT_IF is the wired or wireless LAN interface directly).
# Bridge path already called netstart for vether0 above; skip for bridge.
[ "${INT_IS_BRIDGE:-0}" -eq 0 ] && sh /etc/netstart "$INT_IF" > /dev/null 2>&1
sleep 2

# IPv6 DAD wait on primary LAN
if [ "${HAS_INET6:-0}" -eq 1 ] && [ -n "$INT_IP6" ]; then
  _di=0
  while [ "$_di" -lt 10 ]; do
    ifconfig "$INT_IF" 2> /dev/null | grep -q "tentative" || break
    sleep 1
    _di=$((_di + 1))
  done
  ok "IPv6 DAD settled on $INT_IF"
fi

ifconfig pflog1 create up > /dev/null 2>&1 && ok "Up: pflog1" || true

# Tear down EXT_IF -- strip stale addresses before reconfiguring
info "Tearing down $EXT_IF before reconfiguration..."
ifconfig "$EXT_IF" down > /dev/null 2>&1 || true
sleep 1
ifconfig "$EXT_IF" 2> /dev/null | awk '/inet / {print $2}' \
  | while IFS= read -r _wa4; do
    ifconfig "$EXT_IF" inet "$_wa4" delete > /dev/null 2>&1 || true
  done
ifconfig "$EXT_IF" 2> /dev/null | awk '/inet6 / {print $2}' \
  | while IFS= read -r _wa6; do
    _wa6b=$(printf "%s" "$_wa6" | cut -d% -f1)
    ifconfig "$EXT_IF" inet6 "$_wa6b" delete > /dev/null 2>&1 || true
  done
ok "$EXT_IF cleared"

[ "$WAN_IS_PPPOE" -eq 1 ] && [ -n "$PPPOE_PARENT" ] \
  && ifconfig "$PPPOE_PARENT" up > /dev/null 2>&1
ifconfig "$EXT_IF" up > /dev/null 2>&1

EXT_IP4=$(get_ip4 "$EXT_IF")
EXT_GW4=$(get_gw4)
if [ -z "$EXT_IP4" ]; then
  dhclient "$EXT_IF" > /dev/null 2>&1 &
  sleep 5
  EXT_IP4=$(get_ip4 "$EXT_IF")
  EXT_GW4=$(get_gw4)
fi
[ -z "$EXT_IP6" ] && EXT_IP6=$(get_ip6 "$EXT_IF")

# IPv6 gateway re-detect BEFORE writing /etc/mygate.
# SLAAC/DHCPv6 gateways only appear after interface bring-up.
if [ "${HAS_INET6:-0}" -eq 1 ]; then
  _gi=0
  while [ "$_gi" -lt 10 ]; do
    _tg=$(get_gw6)
    if [ -n "$_tg" ]; then
      EXT_GW6="$_tg"
      EXT_GW6_CLEAN=$(get_gw6_clean)
      ok "IPv6 GW: $EXT_GW6_CLEAN"
      break
    fi
    sleep 1
    _gi=$((_gi + 1))
  done

  # Purge ULA (fd::/fc::) default routes installed by SLAAC.
  # These answer ping6 locally but cannot route to the public internet,
  # silently breaking IPv6 for all clients behind this gateway.
  _ula_purged=0
  while true; do
    _ula_gw=$(route -n show -inet6 2> /dev/null \
      | awk '/^default/ && $2~/^f[cd]/{print $2;exit}')
    [ -z "$_ula_gw" ] && break
    route delete -inet6 default "$_ula_gw" > /dev/null 2>&1 || break
    warn "Removed ULA default route: $_ula_gw (non-routable)"
    _ula_purged=$((_ula_purged + 1))
  done
  if [ "$_ula_purged" -gt 0 ]; then
    ok "Purged $_ula_purged ULA default route(s) -- link-local gateway retained"
    ifconfig "$EXT_IF" -autoconf6 > /dev/null 2>&1 \
      && ok "Disabled IPv6 autoconf on $EXT_IF (ULA suppression)" \
      || warn "Could not disable autoconf6 on $EXT_IF -- ULA routes may recur"
    _whn="/etc/hostname.${EXT_IF}"
    if [ -f "$_whn" ] && ! grep -q "^-autoconf6" "$_whn"; then
      _whn_tmp=$(mktemp)
      awk '/^up$/{print "-autoconf6"}{print}' "$_whn" > "$_whn_tmp"
      mv "$_whn_tmp" "$_whn"
      ok "Persisted -autoconf6 in hostname.$EXT_IF"
    fi
  fi
  EXT_GW6=$(get_gw6)
  EXT_GW6_CLEAN=$(get_gw6_clean)
  [ -n "$EXT_GW6_CLEAN" ] && ok "Effective IPv6 GW: $EXT_GW6_CLEAN"
fi

# /etc/mygate -- written after IPv6 re-detect so both gateways are current.
if [ -n "$EXT_GW4" ] || [ -n "${EXT_GW6:-}" ]; then
  backup_original /etc/mygate
  > /etc/mygate
  [ -n "$EXT_GW4" ] && [ "$WAN_TYPE" != "pppoe" ] \
    && printf "%s\n" "$EXT_GW4" >> /etc/mygate
  [ -n "${EXT_GW6:-}" ] && printf "%s\n" "$EXT_GW6" >> /etc/mygate
  chmod 640 /etc/mygate
  chown root:wheel /etc/mygate
  _MYGATE_WRITTEN=1
  record_installed /etc/mygate
  ok "Written: /etc/mygate"
fi
ok "Interfaces up"

# =============================================================================
# STAGE 19 -- PATH MTU DISCOVERY
# =============================================================================
print_header "Stage 19: Path MTU Discovery"

# OpenBSD ping(8): no -w; use -c count only.
# OpenBSD ping6(8): -w seconds supported.
_test_mtu6() { ping6 -c 2 -s $(($1 - 48)) -w 3 "$2" > /dev/null 2>&1; }
_test_mtu4() { ping -c 3 -s $(($1 - 28)) "$2" > /dev/null 2>&1; }

_find_mtu6() {
  for _t in "$TARGET_IPV6_PRIMARY" "$TARGET_IPV6_SECONDARY" "$TARGET_IPV6_TERTIARY"; do
    ping6 -c 1 -w 3 "$_t" > /dev/null 2>&1 || continue
    for _m in 1500 1492 1480 1472 1460 1452 1440 1428 1420 1400 1384 1372; do
      _test_mtu6 "$_m" "$_t" && printf "%s" "$_m" && return 0
    done
  done
  printf "%s" "$DEFAULT_WAN_MTU"
}
_find_mtu4() {
  for _t in "$TARGET_IPV4_PRIMARY" "$TARGET_IPV4_SECONDARY" "$TARGET_IPV4_TERTIARY"; do
    ping -c 1 "$_t" > /dev/null 2>&1 || continue
    for _m in 1500 1492 1480 1472 1460 1452 1440 1428 1420 1400 1384 1372; do
      _test_mtu4 "$_m" "$_t" && printf "%s" "$_m" && return 0
    done
  done
  printf "%s" "$DEFAULT_WAN_MTU"
}

if [ "$WAN_IS_PPPOE" -eq 1 ]; then
  WAN_MTU="$PPPOE_WAN_MTU"
  ok "PPPoE: MTU fixed at $WAN_MTU"
else
  WAN_MTU=""
  if [ "${HAS_INET6:-0}" -eq 1 ] && [ -n "${EXT_GW6:-}" ]; then
    if ping6 -c 1 -w 3 "$EXT_GW6" > /dev/null 2>&1; then
      WAN_MTU=$(_find_mtu6)
      ok "IPv6 path MTU: $WAN_MTU"
    fi
  fi
  if [ -z "$WAN_MTU" ] && [ -n "${EXT_GW4:-}" ]; then
    if ping -c 2 "$EXT_GW4" > /dev/null 2>&1; then
      WAN_MTU=$(_find_mtu4)
      ok "IPv4 path MTU: $WAN_MTU"
    fi
  fi
  if [ -z "$WAN_MTU" ]; then
    warn "MTU probe failed -- using conservative default $DEFAULT_WAN_MTU"
    WAN_MTU="$DEFAULT_WAN_MTU"
  fi
fi

_wan_mss_type="ethernet"
[ "$WAN_IS_PPPOE" -eq 1 ] && _wan_mss_type="pppoe"
derive_mss "WAN" "$_wan_mss_type" "$WAN_MTU"
derive_mss "INT" "$_int_mss_type" 1500

PF_MAX_MSS4_EXT_IF="$WAN_MSS4"
PF_MAX_MSS6_EXT_IF="$WAN_MSS6"
PF_MAX_MSS4_INT_IF="$INT_MSS4"
PF_MAX_MSS6_INT_IF="$INT_MSS6"
ok "WAN MTU=$WAN_MTU  MSS4=$WAN_MSS4  MSS6=$WAN_MSS6"
ok "LAN MSS4=$INT_MSS4  MSS6=$INT_MSS6"

# Persist MTU in WAN hostname file
_whn_file="/etc/hostname.${EXT_IF}"
if [ -f "$_whn_file" ] && ! grep -q "^mtu " "$_whn_file"; then
  _whn_tmp=$(mktemp)
  awk -v m="$WAN_MTU" '/^up$/{printf "mtu %s\n",m}{print}' \
    "$_whn_file" > "$_whn_tmp"
  mv "$_whn_tmp" "$_whn_file"
  ok "Set MTU=$WAN_MTU in hostname.$EXT_IF"
fi

probe_nic_capabilities

# =============================================================================
# STAGE 20 -- WRITE /etc/tn-interfaces
# =============================================================================
print_header "Stage 20: Writing /etc/tn-interfaces"

# NAT64 mapped address for INT_IP4
if [ "${HAS_INET6:-0}" -eq 1 ] && [ -n "$INT_IP4" ]; then
  _n1=$(printf "%s" "$INT_IP4" | cut -d. -f1)
  _n2=$(printf "%s" "$INT_IP4" | cut -d. -f2)
  _n3=$(printf "%s" "$INT_IP4" | cut -d. -f3)
  _n4=$(printf "%s" "$INT_IP4" | cut -d. -f4)
  NAT64_INT_IP4=$(printf "64:ff9b::%02x%02x:%02x%02x" \
    "$_n1" "$_n2" "$_n3" "$_n4")
else
  NAT64_INT_IP4=""
fi

# IPv6 monitor host (::254 in LAN prefix)
MONITOR_V6_HOST=""
if [ "${HAS_INET6:-0}" -eq 1 ] && [ -n "$INT_NET6" ]; then
  _mp=$(printf "%s" "$INT_NET6" | sed 's|::/64||')
  MONITOR_V6_HOST="${_mp}::254"
fi

INT_IF_BUNDLE="$INT_IF"
EXT_IF_BUNDLE="$EXT_IF"

{
  printf '# /etc/tn-interfaces -- Tangent Networks UTM\n'
  printf '# Generated by TN_NET_SET.sh v%s on %s\n' "$VERSION" "$(date)"
  printf '# DO NOT EDIT MANUALLY -- re-run TN_NET_SET.sh to regenerate\n\n'

  printf '# ----------------------------------------------------------------------------\n'
  printf '# INTERFACE NAMES\n'
  printf '# ----------------------------------------------------------------------------\n'
  printf 'EXT_IF="%s"\n' "$EXT_IF"
  printf 'INT_IF="%s"\n' "$INT_IF"
  printf 'INT_IFS="%s"\n' "$INT_IFS"
  printf 'INT_IF_BUNDLE="%s"\n' "$INT_IF_BUNDLE"
  printf 'EXT_IF_BUNDLE="%s"\n' "$EXT_IF_BUNDLE"
  printf 'WAN_TYPE="%s"\n' "$WAN_TYPE"
  printf 'INT_IS_WIRELESS="%s"\n' "$INT_IS_WIRELESS"
  printf 'INT_IS_BRIDGE="%s"\n' "${INT_IS_BRIDGE:-0}"
  printf 'INT_BRIDGE_IF="%s"\n' "${_BRIDGE_IF:-}"
  printf 'INT_BRIDGE_MEMBERS="%s"\n' "${INT_BRIDGE_MEMBERS:-}"
  printf 'WIFI_IS_BRIDGE_MEMBER="%s"\n' "${WIFI_IS_BRIDGE_MEMBER:-0}"

  printf '\n# ----------------------------------------------------------------------------\n'
  printf '# WAN ADDRESSES\n'
  printf '# ----------------------------------------------------------------------------\n'
  printf 'EXT_IP4="%s"\n' "${EXT_IP4:-}"
  printf 'EXT_MASK4="%s"\n' "${EXT_MASK4:-}"
  printf 'EXT_GW4="%s"\n' "${EXT_GW4:-}"
  printf 'EXT_IP4_CLASS="%s"\n' "${EXT_IP4_CLASS:-none}"
  printf 'EXT_IP6="%s"\n' "${EXT_IP6:-}"
  printf 'EXT_GW6="%s"\n' "${EXT_GW6_CLEAN:-}"
  printf 'EXT_IP6_CLASS="%s"\n' "${EXT_IP6_CLASS:-none}"
  printf 'WAN_NET6="%s"\n' "${WAN_NET6:-}"
  printf 'PPPOE_PARENT="%s"\n' "${PPPOE_PARENT:-}"
  printf 'PPPOE_USER="%s"\n' "${PPPOE_USER:-}"

  printf '\n# ----------------------------------------------------------------------------\n'
  printf '# LAN ADDRESSES\n'
  printf '# ----------------------------------------------------------------------------\n'
  printf 'INT_IP4="%s"\n' "$INT_IP4"
  printf 'INT_IF4="%s"\n' "$INT_IP4"
  printf 'INT_MASK4="%s"\n' "$INT_MASK4"
  printf 'INT_NET4="%s"\n' "$INT_NET4"
  printf 'INT_CIDR4="%s"\n' "$INT_CIDR4"
  printf 'INT_NET4_ADDR="%s"\n' "$INT_NET4_ADDR"
  printf 'INT_BROADCAST4="%s"\n' "$INT_BROADCAST4"
  printf 'INT_DHCP_START="%s"\n' "$INT_DHCP_START"
  printf 'INT_DHCP_END="%s"\n' "$INT_DHCP_END"
  printf 'INT_IP6="%s"\n' "${INT_IP6:-}"
  printf 'INT_NET6="%s"\n' "${INT_NET6:-}"
  printf 'INT_CIDR6="%s"\n' "$INT_CIDR6"

  printf '\n# ----------------------------------------------------------------------------\n'
  printf '# DHCPD TOKENS (consumed by TN_SUBSTITUTE.sh)\n'
  printf '# ----------------------------------------------------------------------------\n'
  printf 'DHCPD_FQDN="%s"\n' "$DHCPD_FQDN_VAL"
  printf 'DHCPD_SUBNET="%s"\n' "$INT_NET4_ADDR"
  printf 'DHCPD_NETMASK="%s"\n' "$INT_MASK4"
  printf 'DHCPD_BROADCAST="%s"\n' "$INT_BROADCAST4"
  printf 'DHCPD_INT_IF4_START_ADDR="%s"\n' "$INT_DHCP_START"
  printf 'DHCPD_INT_IF4_END_ADDR="%s"\n' "$INT_DHCP_END"

  printf '\n# ----------------------------------------------------------------------------\n'
  printf '# MTU / MSS PER INTERFACE\n'
  printf '# ----------------------------------------------------------------------------\n'
  printf 'WAN_MTU="%s"\n' "$WAN_MTU"
  printf 'WAN_MSS4="%s"\n' "$WAN_MSS4"
  printf 'WAN_MSS6="%s"\n' "$WAN_MSS6"
  printf 'INT_MTU="%s"\n' "${INT_MTU:-1500}"
  printf 'INT_MSS4="%s"\n' "$INT_MSS4"
  printf 'INT_MSS6="%s"\n' "$INT_MSS6"
  printf 'LAN_MTU="%s"\n' "${INT_MTU:-1500}"
  printf '# Backward-compat aliases for pf.conf template\n'
  printf 'PF_MAX_MSS4_EXT_IF="%s"\n' "$PF_MAX_MSS4_EXT_IF"
  printf 'PF_MAX_MSS6_EXT_IF="%s"\n' "$PF_MAX_MSS6_EXT_IF"
  printf 'PF_MAX_MSS4_INT_IF="%s"\n' "$PF_MAX_MSS4_INT_IF"
  printf 'PF_MAX_MSS6_INT_IF="%s"\n' "$PF_MAX_MSS6_INT_IF"

  printf '\n# ----------------------------------------------------------------------------\n'
  printf '# DEPLOYMENT CLASSIFICATION\n'
  printf '# ----------------------------------------------------------------------------\n'
  printf 'DEPLOY_MODE="%s"\n' "$DEPLOY_MODE"
  printf 'IPV6_MODE="%s"\n' "$IPV6_MODE"
  printf 'WAN_IS_PPPOE="%s"\n' "$WAN_IS_PPPOE"
  printf 'VIRT_ENV="%s"\n' "$VIRT_ENV"
  printf 'CLOUD_PROVIDER="%s"\n' "${CLOUD_PROVIDER:-none}"
  printf 'CLOUD_REGION="%s"\n' "${CLOUD_REGION:-unknown}"
  printf 'NAT64_PFX="64:ff9b::/96"\n'
  printf 'NAT64_INT_IP4="%s"\n' "${NAT64_INT_IP4:-}"
  printf 'MONITOR_V6_HOST="%s"\n' "${MONITOR_V6_HOST:-}"

  printf '\n# ----------------------------------------------------------------------------\n'
  printf '# MULTI-WAN\n'
  printf '# ----------------------------------------------------------------------------\n'
  printf 'WAN_COUNT="%s"\n' "$WAN_COUNT"
  printf 'WAN_PRIMARY_IF="%s"\n' "$WAN_PRIMARY_IF"
  printf 'WAN_MULTI_MODE="%s"\n' "$WAN_MULTI_MODE"
  printf 'WAN2_IF="%s"\n' "${WAN2_IF:-}"
  printf 'WAN2_TYPE="%s"\n' "${WAN2_TYPE:-}"
  printf 'WAN2_GW4="%s"\n' "${WAN2_GW4:-}"
  printf 'WAN2_MTU="%s"\n' "${WAN2_MTU:-1500}"
  printf 'WAN2_MONITOR_IP="%s"\n' "${WAN2_MONITOR_IP:-}"
  printf 'WAN2_WEIGHT="%s"\n' "${WAN2_WEIGHT:-1}"
  printf 'WAN2_STANDBY_MODE="%s"\n' "${WAN2_STANDBY_MODE:-hot}"
  printf 'WAN3_IF="%s"\n' "${WAN3_IF:-}"
  printf 'WAN3_TYPE="%s"\n' "${WAN3_TYPE:-}"
  printf 'WAN3_GW4="%s"\n' "${WAN3_GW4:-}"
  printf 'WAN3_MONITOR_IP="%s"\n' "${WAN3_MONITOR_IP:-}"

  printf '\n# ----------------------------------------------------------------------------\n'
  printf '# VLAN MAP (dormant -- gated for 8.0)\n'
  printf '# ----------------------------------------------------------------------------\n'
  printf 'VLAN_COUNT="%s"\n' "$VLAN_COUNT"

  printf '\n# ----------------------------------------------------------------------------\n'
  printf '# TRUNK / LAGG (dormant -- gated for 8.0)\n'
  printf '# ----------------------------------------------------------------------------\n'
  printf 'LAGG_IF="%s"\n' "${LAGG_IF:-}"
  printf 'LAGG_MODE="%s"\n' "${LAGG_MODE:-}"
  printf 'LAGG_MEMBERS="%s"\n' "${LAGG_MEMBERS:-}"

  printf '\n# ----------------------------------------------------------------------------\n'
  printf '# ADDITIONAL PHYSICAL LAN INTERFACES (dormant -- gated for 8.0)\n'
  printf '# ----------------------------------------------------------------------------\n'
  printf 'EXTRA_LAN_COUNT="%s"\n' "$EXTRA_LAN_COUNT"

  printf '\n# ----------------------------------------------------------------------------\n'
  printf '# WIRELESS LAN (primary LAN if wireless)\n'
  printf '# ----------------------------------------------------------------------------\n'
  printf 'WIFI_LAN_ROLE="%s"\n' "${WIFI_LAN_ROLE:-none}"
  printf 'WIFI_LAN_IF="%s"\n' "${WIFI_LAN_IF:-}"
  printf 'WIFI_LAN_IP4="%s"\n' "${WIFI_LAN_IP4:-}"
  printf 'WIFI_LAN_NET4="%s"\n' "${WIFI_LAN_NET4:-}"
  printf 'WIFI_LAN_MASK4="%s"\n' "${WIFI_LAN_MASK4:-}"
  printf 'WIFI_LAN_IP6="%s"\n' "${WIFI_LAN_IP6:-}"
  printf 'WIFI_LAN_NET6="%s"\n' "${WIFI_LAN_NET6:-}"
  if [ -n "$WIFI_LAN_IF" ]; then
    for _wfi in $WIFI_LAN_IF; do
      _WFP=$(iface_prefix "$_wfi")
      for _wft in WIFI_ROLE WIFI_SSID WIFI_BAND WIFI_CHANNEL WIFI_HW_MODE \
        WIFI_ISOLATION WIFI_HIDDEN WIFI_MAX_CLIENTS WIFI_DRIVER WIFI_SECURITY; do
        eval _wfv="\${${_WFP}_${_wft}:-}"
        printf '%s_%s="%s"\n' "$_WFP" "$_wft" "$_wfv"
      done
      printf '%s_WIFI_BRIDGE=""\n' "$_WFP"
      printf '%s_WIFI_PASS="(stored in hostname file)"\n' "$_WFP"
    done
  fi

  printf '\n# ----------------------------------------------------------------------------\n'
  printf '# HIGH AVAILABILITY (dormant -- gated for post-8.0)\n'
  printf '# ----------------------------------------------------------------------------\n'
  printf 'HA_ENABLED="%s"\n' "$HA_ENABLED"
  printf 'HA_ROLE="%s"\n' "$HA_ROLE"
  printf 'CARP0_VIP_LAN="%s"\n' "${CARP0_VIP_LAN:-}"
  printf 'CARP0_VIP_WAN="%s"\n' "${CARP0_VIP_WAN:-}"
  printf 'CARP0_VHID="%s"\n' "$CARP0_VHID"
  printf 'CARP0_ADVSKEW="%s"\n' "$CARP0_ADVSKEW"
  printf 'PFSYNC0_IF="%s"\n' "${PFSYNC0_IF:-}"
  printf 'PFSYNC0_PEER_IP="%s"\n' "${PFSYNC0_PEER_IP:-}"

  printf '\n# ----------------------------------------------------------------------------\n'
  printf '# HARDWARE OFFLOAD DECISIONS\n'
  printf '# ----------------------------------------------------------------------------\n'
  printf 'OFFLOAD_AUDIT_DONE="%s"\n' "$OFFLOAD_AUDIT_DONE"
  # Offload audit results -- WAN, primary LAN, and any bridge members
  _tni_oif_list="$EXT_IF $INT_IF"
  for _bm in ${INT_BRIDGE_MEMBERS:-}; do
    _tni_oif_list="$_tni_oif_list $_bm"
  done
  for _oif in $_tni_oif_list; do
    _opfx=$(iface_prefix "$_oif")
    eval _ot4="\${${_opfx}_TSO4_DISABLED:-0}"
    eval _ot6="\${${_opfx}_TSO6_DISABLED:-0}"
    eval _olr="\${${_opfx}_LRO_DISABLED:-0}"
    printf '%s_TSO4_DISABLED="%s"\n' "$_opfx" "$_ot4"
    printf '%s_TSO6_DISABLED="%s"\n' "$_opfx" "$_ot6"
    printf '%s_LRO_DISABLED="%s"\n' "$_opfx" "$_olr"
  done

  printf '\n# ----------------------------------------------------------------------------\n'
  printf '# HARDWARE SIZING\n'
  printf '# ----------------------------------------------------------------------------\n'
  printf 'RAM_GB="%s"\n' "$RAM_GB"
  printf 'CPU_CORES="%s"\n' "$CPU_CORES"
  printf 'CPU_ARCH="%s"\n' "$CPU_ARCH"
  printf 'AES_NI="%s"\n' "${AES_NI:-0}"
  printf 'MBUF_NMBCLUSTERS="%s"\n' "$MBUF_NMBCLUSTERS"
  printf 'JUMBO_MTU_SUPPORTED="%s"\n' "${JUMBO_MTU_SUPPORTED:-0}"

  printf '\n# ----------------------------------------------------------------------------\n'
  printf '# KERNEL CAPABILITY FLAGS\n'
  printf '# ----------------------------------------------------------------------------\n'
  printf 'HAS_TCP4="%s"\n' "$HAS_TCP4"
  printf 'HAS_UDP4="%s"\n' "$HAS_UDP4"
  printf 'HAS_DIVERT="%s"\n' "$HAS_DIVERT"
  printf 'HAS_INET6="%s"\n' "$HAS_INET6"
  printf 'HAS_BRIDGE="%s"\n' "$HAS_BRIDGE"
  printf 'HAS_CARP="%s"\n' "$HAS_CARP"
  printf 'HAS_PFSYNC="%s"\n' "$HAS_PFSYNC"
  printf 'WAN_HAS_TSO4="%s"\n' "${WAN_HAS_TSO4:-0}"
  printf 'WAN_HAS_TSO6="%s"\n' "${WAN_HAS_TSO6:-0}"
  printf 'WAN_HAS_LRO="%s"\n' "${WAN_HAS_LRO:-0}"
  printf 'WAN_HAS_VLAN_HW="%s"\n' "${WAN_HAS_VLAN_HW:-0}"
  printf 'WAN_IS_10G="%s"\n' "${WAN_IS_10G:-0}"
  printf 'LAN_HAS_TSO4="%s"\n' "${LAN_HAS_TSO4:-0}"
  printf 'LAN_HAS_TSO6="%s"\n' "${LAN_HAS_TSO6:-0}"
  printf 'LAN_HAS_LRO="%s"\n' "${LAN_HAS_LRO:-0}"
  printf 'LAN_HAS_VLAN_HW="%s"\n' "${LAN_HAS_VLAN_HW:-0}"
  printf 'LAN_IS_10G="%s"\n' "${LAN_IS_10G:-0}"

  printf '\n# ----------------------------------------------------------------------------\n'
  printf '# SSL (stubs -- populated by Stage 23)\n'
  printf '# ----------------------------------------------------------------------------\n'
  printf 'CERT_ORG=""\nCERT_OU=""\nCERT_CN=""\nCERT_COUNTRY=""\n'
  printf 'CERT_STATE=""\nCERT_CITY=""\nCERT_EMAIL=""\n'
  printf 'TN_CA_CERT=""\nTN_CA_KEY=""\nTLS_CERT=""\nTLS_KEY=""\n'

  printf '\n# ----------------------------------------------------------------------------\n'
  printf '# SNORT / RULES (populated by DEPLOY_CONFIGS.sh)\n'
  printf '# ----------------------------------------------------------------------------\n'
  printf 'RULES_TYPE=""\nOINK_CODE=""\nOINK_URL=""\n'
  printf 'PUBLIC_DOMAIN="%s"\n' "${PUBLIC_DOMAIN:-}"
  printf 'HOSTNAME="%s"\n' "$CURRENT_HOSTNAME"
  printf 'DHCPD_FQDN_VAL="%s"\n' "$DHCPD_FQDN_VAL"

} > "$TN_INTERFACES"

chmod 640 "$TN_INTERFACES"
chown root:wheel "$TN_INTERFACES"
_TN_INTERFACES_WRITTEN=1
record_installed "$TN_INTERFACES"
ok "Written: $TN_INTERFACES"

# =============================================================================
# STAGE 21 -- CONNECTIVITY TEST
# =============================================================================
print_header "Stage 21: Connectivity Test"
_cfail=0

if [ -n "${EXT_GW4:-}" ]; then
  printf "  IPv4 gateway (%s) ... " "$EXT_GW4"
  ping -c 2 "$EXT_GW4" > /dev/null 2>&1 \
    && printf "${GREEN}OK${NC}\n" || {
    printf "${RED}FAIL${NC}\n"
    _cfail=1
  }
fi

printf "  IPv4 internet (1.1.1.1) ... "
ping -c 2 1.1.1.1 > /dev/null 2>&1 \
  && printf "${GREEN}OK${NC}\n" || {
  printf "${RED}FAIL${NC}\n"
  _cfail=1
}

if [ "${HAS_INET6:-0}" -eq 1 ]; then
  # Final ULA purge guard
  while true; do
    _ula=$(route -n show -inet6 2> /dev/null \
      | awk '/^default/ && $2~/^f[cd]/{print $2;exit}')
    [ -z "$_ula" ] && break
    route delete -inet6 default "$_ula" > /dev/null 2>&1 || break
    warn "Purged ULA default route: $_ula"
  done
  case "$IPV6_MODE" in
    native | nat66)
      if [ -n "${EXT_GW6:-}" ]; then
        printf "  IPv6 gateway (%s) ... " "$EXT_GW6_CLEAN"
        ping6 -c 2 -w 3 "$EXT_GW6" > /dev/null 2>&1 \
          && printf "${GREEN}OK${NC}\n" \
          || printf "${YELLOW}UNREACHABLE${NC} (gateway may not respond to ping)\n"
      fi
      printf "  IPv6 internet (2606:4700:4700::1111) ... "
      ping6 -c 2 -w 3 2606:4700:4700::1111 > /dev/null 2>&1 \
        && printf "${GREEN}OK${NC}\n" \
        || {
          printf "${RED}FAIL${NC}\n"
          _cfail=1
        }
      ;;
    nat64)
      printf "  DNS64 (AAAA for ipv4.google.com) ... "
      drill ipv4.google.com AAAA 2> /dev/null | grep -q "64:ff9b::" \
        && printf "${GREEN}OK${NC}\n" \
        || {
          printf "${RED}FAIL${NC}\n"
          _cfail=1
        }
      ;;
    none) printf "  IPv6 ... ${YELLOW}SKIP${NC} (disabled)\n" ;;
  esac
else
  printf "  IPv6 ... ${YELLOW}SKIP${NC} (kernel lacks IPv6)\n"
fi

if [ "$_cfail" -eq 1 ]; then
  warn "Some connectivity tests failed"
  printf "  ${MAGENTA}Continue anyway? [y/N]: ${NC}"
  read _fc
  case "$_fc" in
    [Yy]*) warn "Continuing despite failures" ;;
    *)
      _undo "connectivity test failed"
      exit 1
      ;;
  esac
else
  ok "Connectivity verified"
fi

# =============================================================================
# STAGE 22 -- PAYLOAD CONFIG EXTENSION
# =============================================================================
print_header "Stage 22: Payload Config Extension"

# Production bogon safety gate.
# Payload pf.conf ships without RFC1918 ranges to allow lab WAN topologies.
# A public WAN must have these ranges present in the bogon block.
if [ "${EXT_IP4_CLASS:-none}" = "public" ] \
  && _payload_exists "$PAYLOAD_PFCONF"; then
  if ! grep -q '10\.0\.0\.0/8' "$PAYLOAD_PFCONF" 2> /dev/null; then
    info "Production WAN (public) -- patching bogon block with RFC1918 ranges"
    _bogon_tmp=$(mktemp)
    sed \
      -e 's|0\.0\.0\.0/8, 100\.64\.0\.0/10,|0.0.0.0/8, 100.64.0.0/10, 10.0.0.0/8,|' \
      -e 's|127\.0\.0\.0/8, 169\.254\.0\.0/16,|127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16,|' \
      -e 's|::1\/128, ::\/128,|::1\/128, ::\/128, fc00::\/7,|' \
      "$PAYLOAD_PFCONF" > "$_bogon_tmp" \
      && mv "$_bogon_tmp" "$PAYLOAD_PFCONF" \
      || {
        err "Failed to patch bogon block"
        rm -f "$_bogon_tmp"
      }
    ok "pf.conf bogon block: RFC1918 and fc00::/7 added"
    warn "Review payload/etc/pf.conf [I] bogon block before loading rules"
  fi
else
  info "Non-public WAN -- lab bogon exemptions retained"
fi

ok "Stage 22 complete"

# =============================================================================
# STAGE 23 -- SSL CA + SERVER CERTIFICATE
# CA:     4096-bit RSA, 3650 days, CA:TRUE, cRLSign+keyCertSign
# Server: 2048-bit RSA, 825 days (Apple/Chrome/Firefox max for trusted certs;
#         values above 825 days cause ERR_CERT_VALIDITY_TOO_LONG)
# =============================================================================
print_header "Stage 23: SSL Certificate Generation"

_cert_ok=0
while [ "$_cert_ok" -eq 0 ]; do
  printf "  ${MAGENTA}Organisation [Local Security Gateway]: ${NC}"
  read CERT_ORG
  CERT_ORG="${CERT_ORG:-Local Security Gateway}"
  printf "  ${MAGENTA}Organisational Unit [IT Department]: ${NC}"
  read CERT_OU
  CERT_OU="${CERT_OU:-IT Department}"
  _cn_ok=0
  while [ "$_cn_ok" -eq 0 ]; do
    printf "  ${MAGENTA}Common Name / FQDN [firewall.local]: ${NC}"
    read CERT_CN
    CERT_CN="${CERT_CN:-firewall.local}"
    validate_hostname "$CERT_CN" && _cn_ok=1 || warn "Invalid hostname"
  done
  _cc_ok=0
  while [ "$_cc_ok" -eq 0 ]; do
    printf "  ${MAGENTA}Country code (2 letters) [US]: ${NC}"
    read CERT_COUNTRY
    CERT_COUNTRY=$(printf "%s" "${CERT_COUNTRY:-US}" | tr '[:lower:]' '[:upper:]')
    validate_country_code "$CERT_COUNTRY" && _cc_ok=1 \
      || warn "Must be 2 uppercase letters"
  done
  printf "  ${MAGENTA}State/Province (optional): ${NC}"
  read CERT_STATE
  printf "  ${MAGENTA}City/Locality (optional): ${NC}"
  read CERT_CITY
  _em_ok=0
  while [ "$_em_ok" -eq 0 ]; do
    _read_secret CERT_EMAIL "Email [admin@${CERT_CN}]: "
    CERT_EMAIL="${CERT_EMAIL:-admin@${CERT_CN}}"
    validate_email "$CERT_EMAIL" && _em_ok=1 || warn "Invalid email"
  done
  _cert_display=$(printf '%s' "$CERT_EMAIL" | sed 's/^\([^@]\{1,3\}\)[^@]*@/\1***@/')
  printf "\n  Org: %s  CN: %s  Country: %s  Email: %s\n" \
    "$CERT_ORG" "$CERT_CN" "$CERT_COUNTRY" "$_cert_display"
  printf "  ${MAGENTA}Accept? [Y/n]: ${NC}"
  read _ca
  case "$_ca" in [Nn]*) : ;; *) _cert_ok=1 ;; esac
done

TLS_CERT="${SSL_DIR}/${CERT_CN}.crt"
TLS_KEY="${SSL_PRIVATE_DIR}/${CERT_CN}.key"

# Stage 23a: CA (4096-bit, 3650 days)
print_header "Stage 23a: Certificate Authority (4096-bit, 3650 days)"
mkdir -p "$SSL_PRIVATE_DIR"
chmod 700 "$SSL_PRIVATE_DIR"

_ca_valid=0
if [ -f "$TN_CA_KEY" ] && [ -f "$TN_CA_CERT" ]; then
  _ca_bc=$(openssl x509 -noout -text -in "$TN_CA_CERT" 2> /dev/null \
    | grep -A1 "Basic Constraints" | grep -c "CA:TRUE" || true)
  _ca_ku=$(openssl x509 -noout -text -in "$TN_CA_CERT" 2> /dev/null \
    | grep -A1 "Key Usage" | grep -c "Certificate Sign" || true)
  if [ "${_ca_bc:-0}" -ge 1 ] && [ "${_ca_ku:-0}" -ge 1 ]; then
    _ca_valid=1
    warn "Existing CA found and validated -- skipping (delete $TN_CA_KEY to regenerate)"
  else
    warn "Existing CA missing required extensions -- removing and regenerating"
    rm -f "$TN_CA_KEY" "$TN_CA_CERT" "$TN_CA_SERIAL"
  fi
fi
if [ "$_ca_valid" -eq 0 ]; then
  rm -f "$TN_CA_KEY" "$TN_CA_CERT" "$TN_CA_SERIAL"
  _cacnf=$(mktemp /tmp/tn-ca.XXXXXX)
  _write_ca_cnf "$_cacnf"
  info "Generating 4096-bit CA key..."
  openssl genrsa -out "$TN_CA_KEY" 4096 2> /dev/null \
    || {
      rm -f "$_cacnf"
      _undo "CA keygen failed"
      exit 1
    }
  chmod 600 "$TN_CA_KEY"
  chown root:wheel "$TN_CA_KEY"
  info "Signing CA certificate (3650 days)..."
  openssl req -new -x509 -config "$_cacnf" -key "$TN_CA_KEY" \
    -out "$TN_CA_CERT" -days 3650 2> /dev/null \
    || {
      rm -f "$_cacnf"
      _undo "CA cert failed"
      exit 1
    }
  rm -f "$_cacnf"
  chmod 644 "$TN_CA_CERT"
  chown root:wheel "$TN_CA_CERT"
  record_installed "$TN_CA_KEY"
  record_installed "$TN_CA_CERT"
  ok "CA: $TN_CA_CERT"
fi

# Stage 23b: Server certificate (2048-bit, 825 days)
# 825 days is the maximum for server certs trusted by Apple, Chrome, Firefox.
# Longer validity causes ERR_CERT_VALIDITY_TOO_LONG in modern browsers.
print_header "Stage 23b: Server Certificate (2048-bit, 825 days)"

if [ -f "$TLS_KEY" ] && [ -f "$TLS_CERT" ]; then
  warn "Existing server cert found -- skipping (delete $TLS_KEY to regenerate)"
else
  rm -f "$TLS_KEY" "$TLS_CERT"
  _csrcnf=$(mktemp /tmp/tn-csr.XXXXXX)
  _csrtmp=$(mktemp /tmp/tn-csr-req.XXXXXX)
  _exttmp=$(mktemp /tmp/tn-srv-ext.XXXXXX)
  _write_csr_cnf "$_csrcnf"
  _SAN=$(_build_san)
  info "SAN: $_SAN"
  _write_srv_ext "$_exttmp" "$_SAN"
  info "Generating 2048-bit server key..."
  openssl genrsa -out "$TLS_KEY" 2048 2> /dev/null \
    || {
      rm -f "$_csrcnf" "$_csrtmp" "$_exttmp"
      _undo "server keygen failed"
      exit 1
    }
  chmod 600 "$TLS_KEY"
  chown root:wheel "$TLS_KEY"
  openssl req -new -config "$_csrcnf" -key "$TLS_KEY" -out "$_csrtmp" 2> /dev/null \
    || {
      rm -f "$_csrcnf" "$_csrtmp" "$_exttmp"
      _undo "CSR failed"
      exit 1
    }
  rm -f "$_csrcnf"
  info "Signing server certificate (825 days)..."
  openssl x509 -req -in "$_csrtmp" -CA "$TN_CA_CERT" -CAkey "$TN_CA_KEY" \
    -CAcreateserial -CAserial "$TN_CA_SERIAL" \
    -out "$TLS_CERT" -days 825 -extfile "$_exttmp" 2> /dev/null \
    || {
      rm -f "$_csrtmp" "$_exttmp"
      _undo "cert sign failed"
      exit 1
    }
  rm -f "$_csrtmp" "$_exttmp"
  chmod 644 "$TLS_CERT"
  chown root:wheel "$TLS_CERT"
  record_installed "$TLS_KEY"
  record_installed "$TLS_CERT"
  openssl verify -CAfile "$TN_CA_CERT" "$TLS_CERT" > /dev/null 2>&1 \
    && ok "Chain verified" || err "Chain verify FAILED"
  ok "Server cert: $TLS_CERT"
fi

# Stage 23b-i: SSLproxy CA placement
# SSLproxy uses the TN CA to forge leaf certificates during TLS interception.
# Both CA cert and CA key go to the SSLproxy payload directory so
# TN_PKG_INSTALL.sh deploys them under /usr/local/etc/sslproxy/.
print_header "Stage 23b-i: SSLproxy Certificate Placement"
_SSLPROXY_PAYLOAD="${SCRIPT_DIR}/payload/usr/local/etc/sslproxy"
mkdir -p "$_SSLPROXY_PAYLOAD"
cp "$TN_CA_CERT" "${_SSLPROXY_PAYLOAD}/ca.crt" \
  || {
    _undo "Failed to copy CA cert to sslproxy payload"
    exit 1
  }
chmod 644 "${_SSLPROXY_PAYLOAD}/ca.crt"
chown root:wheel "${_SSLPROXY_PAYLOAD}/ca.crt"
cp "$TN_CA_KEY" "${_SSLPROXY_PAYLOAD}/ca.key" \
  || {
    _undo "Failed to copy CA key to sslproxy payload"
    exit 1
  }
chmod 600 "${_SSLPROXY_PAYLOAD}/ca.key"
chown root:wheel "${_SSLPROXY_PAYLOAD}/ca.key"
record_installed "${_SSLPROXY_PAYLOAD}/ca.crt"
record_installed "${_SSLPROXY_PAYLOAD}/ca.key"
ok "SSLproxy CA -> ${_SSLPROXY_PAYLOAD}/"

# Stage 23b-ii: CA cert for client download
# ONLY the CA cert goes to the webroot -- never the CA key, never the server cert.
# Served over plain HTTP so clients can download before installing the CA cert.
# httpd is fully chrooted so we use cp (not ln -sf) -- symlinks from outside
# the chroot dangle and httpd cannot resolve them.
print_header "Stage 23b-ii: CA Cert for Client Download"
_WEBCERTS_PAYLOAD="${SCRIPT_DIR}/payload/var/www/htdocs/tn/certs"
mkdir -p "$_WEBCERTS_PAYLOAD"
cp "$TN_CA_CERT" "${_WEBCERTS_PAYLOAD}/tangent-ca.crt" \
  || {
    _undo "Failed to copy CA cert to webroot payload"
    exit 1
  }
chmod 644 "${_WEBCERTS_PAYLOAD}/tangent-ca.crt"
chown root:wheel "${_WEBCERTS_PAYLOAD}/tangent-ca.crt"
record_installed "${_WEBCERTS_PAYLOAD}/tangent-ca.crt"
ok "CA cert for client download -> ${_WEBCERTS_PAYLOAD}/tangent-ca.crt"
info "Download URL: http://${INT_IP4:-<LAN_IP>}/certs/tangent-ca.crt"
info "CA SHA256 fingerprint:"
openssl x509 -noout -fingerprint -sha256 -in "$TN_CA_CERT" | sed 's/^/    /'

# Patch SSL stubs in tn-interfaces
_tni_tmp=$(mktemp)
sed \
  -e "s|^CERT_ORG=\"\"$|CERT_ORG=\"${CERT_ORG}\"|" \
  -e "s|^CERT_OU=\"\"$|CERT_OU=\"${CERT_OU}\"|" \
  -e "s|^CERT_CN=\"\"$|CERT_CN=\"${CERT_CN}\"|" \
  -e "s|^CERT_COUNTRY=\"\"$|CERT_COUNTRY=\"${CERT_COUNTRY}\"|" \
  -e "s|^CERT_STATE=\"\"$|CERT_STATE=\"${CERT_STATE:-}\"|" \
  -e "s|^CERT_CITY=\"\"$|CERT_CITY=\"${CERT_CITY:-}\"|" \
  -e "s|^CERT_EMAIL=\"\"$|CERT_EMAIL=\"${CERT_EMAIL}\"|" \
  -e "s|^TN_CA_CERT=\"\"$|TN_CA_CERT=\"${TN_CA_CERT}\"|" \
  -e "s|^TN_CA_KEY=\"\"$|TN_CA_KEY=\"${TN_CA_KEY}\"|" \
  -e "s|^TLS_CERT=\"\"$|TLS_CERT=\"${TLS_CERT}\"|" \
  -e "s|^TLS_KEY=\"\"$|TLS_KEY=\"${TLS_KEY}\"|" \
  "$TN_INTERFACES" > "$_tni_tmp"
mv "$_tni_tmp" "$TN_INTERFACES"
chmod 640 "$TN_INTERFACES"
chown root:wheel "$TN_INTERFACES"
ok "SSL tokens patched into $TN_INTERFACES"

# =============================================================================
# STAGE 23c -- SNORT OINKCODE CONFIGURATION
# =============================================================================
print_header "Stage 23c: Snort Oinkcode Configuration"

_OINK_CONF="${PAYLOAD_ETC}/oinkmaster.conf"
_OINK_URL_BASE="https://www.snort.org/reg-rules/snortrules-snapshot-29200.tar.gz"
_OINK_FILE="${SCRIPT_DIR}/oinkcode"
_PLACEHOLDER="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
OINK_CODE=""
OINK_URL=""
RULES_TYPE=""
_oink_kept=0

_oink_format_ok() { printf '%s' "$1" | grep -qE '^[0-9a-f]{40}$'; }
_oink_mask() { printf '%s' "$1" | sed 's/.\{34\}/***********************************/'; }

# Step 1: detect existing oinkcode in oinkmaster.conf
_oink_existing=""
if [ -f "$_OINK_CONF" ]; then
  _oink_existing=$(awk '
    /^url =.*snortrules-snapshot-29200/ {
      match($0, /[0-9a-f]{40}/)
      if (RLENGTH == 40) { print substr($0, RSTART, RLENGTH); exit }
    }' "$_OINK_CONF")
fi

if [ -n "$_oink_existing" ]; then
  ok "Existing oinkcode detected: $(_oink_mask "$_oink_existing")"
  printf "  ${MAGENTA}Keep existing oinkcode? [Y/n]: ${NC}"
  read _oink_keep
  case "${_oink_keep:-Y}" in
    [Nn]*) info "Replacing existing oinkcode." ;;
    *)
      OINK_CODE="$_oink_existing"
      OINK_URL="${_OINK_URL_BASE}/${OINK_CODE}"
      RULES_TYPE="registered"
      _oink_kept=1
      ok "Existing oinkcode retained."
      ;;
  esac
fi

# Step 2: acquire oinkcode (file-first, keyboard fallback)
if [ -z "$OINK_CODE" ]; then
  _oink_input=""
  if [ -f "$_OINK_FILE" ]; then
    _oink_raw=$(grep -m1 -iE '^(oinkcode|OINKCODE)\s*=' "$_OINK_FILE" \
      | sed 's/^[^=]*=//;s/[[:space:]"'"'"']//g' | tr '[:upper:]' '[:lower:]')
    [ -z "$_oink_raw" ] && _oink_raw=$(grep -m1 -E '^[0-9a-fA-F]+$' \
      "$_OINK_FILE" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')
    if [ -n "$_oink_raw" ] && [ "$_oink_raw" != "$_PLACEHOLDER" ]; then
      if _oink_format_ok "$_oink_raw"; then
        _oink_input="$_oink_raw"
        info "Oinkcode loaded from file: $(_oink_mask "$_oink_input")"
      else
        err "oinkcode file: invalid format (expected 40 hex chars)"
        exit 1
      fi
    fi
  fi

  if [ -z "$_oink_input" ]; then
    info "Register free at: https://snort.org/users/register"
    info "Tip: echo 'oinkcode=\"<code>\"' > ${SCRIPT_DIR}/oinkcode"
    while true; do
      _read_secret "_oink_input" "Oinkcode (40 hex chars): "
      _oink_input=$(printf '%s' "$_oink_input" \
        | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')
      [ -z "$_oink_input" ] \
        && err "Oinkcode required. Ctrl-C to exit." && continue
      _oink_format_ok "$_oink_input" \
        && ok "Oinkcode accepted: $(_oink_mask "$_oink_input")" && break \
        || err "Invalid format: need 40 hex characters."
    done
  fi

  OINK_CODE="$_oink_input"
  OINK_URL="${_OINK_URL_BASE}/${OINK_CODE}"
  RULES_TYPE="registered"
fi

# Step 3: patch oinkmaster.conf
if [ -f "$_OINK_CONF" ] && [ "$_oink_kept" -eq 0 ]; then
  _oink_url_line="url = ${_OINK_URL_BASE}/${OINK_CODE}"
  _oink_tmp=$(mktemp /tmp/tn_oink.XXXXXX)
  if grep -q "^url =.*snortrules-snapshot-29200" "$_OINK_CONF"; then
    awk -v url="$_oink_url_line" '
      /^url =.*snortrules-snapshot-29200/ && !done {print url; done=1; next}
      {print}' "$_OINK_CONF" > "$_oink_tmp" \
      && mv "$_oink_tmp" "$_OINK_CONF" \
      || {
        err "Failed to patch oinkmaster.conf"
        rm -f "$_oink_tmp"
      }
    ok "oinkmaster.conf: url updated"
  else
    awk -v url="$_oink_url_line" '
      /^# Snort site in your registered user profile\.$/ && !done {
        print; print url; done=1; next}
      {print}' "$_OINK_CONF" > "$_oink_tmp" \
      && mv "$_oink_tmp" "$_OINK_CONF" \
      || {
        err "Failed to insert url in oinkmaster.conf"
        rm -f "$_oink_tmp"
      }
    ok "oinkmaster.conf: url inserted"
  fi
fi

# Patch tn-interfaces with oinkcode
_tni_oink_tmp=$(mktemp)
sed \
  -e "s|^RULES_TYPE=\"\"$|RULES_TYPE=\"${RULES_TYPE}\"|" \
  -e "s|^OINK_CODE=\"\"$|OINK_CODE=\"${OINK_CODE}\"|" \
  -e "s|^OINK_URL=\"\"$|OINK_URL=\"${OINK_URL}\"|" \
  "$TN_INTERFACES" > "$_tni_oink_tmp" \
  && mv "$_tni_oink_tmp" "$TN_INTERFACES" \
  || {
    err "Failed to patch tn-interfaces with oinkcode"
    rm -f "$_tni_oink_tmp"
  }
chmod 640 "$TN_INTERFACES"
chown root:wheel "$TN_INTERFACES"
ok "OINK_CODE written to $TN_INTERFACES"

# Activate oinkmaster cron job if present as comment
if [ -f "${PAYLOAD_ETC}/crontab" ]; then
  _oink_cron_tmp=$(mktemp /tmp/tn_cron_oink.XXXXXX)
  sed 's|^#\(.*oinkmaster_update_snortinline\.sh.*\)$|\1|' \
    "${PAYLOAD_ETC}/crontab" > "$_oink_cron_tmp" \
    && mv "$_oink_cron_tmp" "${PAYLOAD_ETC}/crontab" \
    || rm -f "$_oink_cron_tmp"
  ok "Oinkmaster cron job activated"
fi

# =============================================================================
# STAGE 24 -- FINAL CONNECTIVITY CHECK
# =============================================================================
print_header "Stage 24: Final Connectivity Check"
_cfail=0

printf "  IPv4 internet (1.1.1.1) ... "
ping -c 2 1.1.1.1 > /dev/null 2>&1 \
  && printf "${GREEN}OK${NC}\n" || {
  printf "${RED}FAIL${NC}\n"
  _cfail=1
}

if [ "${HAS_INET6:-0}" -eq 1 ]; then
  # Final ULA purge
  while true; do
    _ula=$(route -n show -inet6 2> /dev/null \
      | awk '/^default/ && $2~/^f[cd]/{print $2;exit}')
    [ -z "$_ula" ] && break
    route delete -inet6 default "$_ula" > /dev/null 2>&1 || break
    warn "Purged ULA default route: $_ula"
  done
  case "$IPV6_MODE" in
    native | nat66)
      printf "  IPv6 internet (2606:4700:4700::1111) ... "
      ping6 -c 2 -w 3 2606:4700:4700::1111 > /dev/null 2>&1 \
        && printf "${GREEN}OK${NC}\n" \
        || {
          printf "${RED}FAIL${NC}\n"
          _cfail=1
        }
      ;;
    nat64)
      printf "  DNS64 (AAAA for ipv4.google.com) ... "
      _dns64_test=$(drill ipv4.google.com AAAA 2> /dev/null \
        | grep "64:ff9b::" | head -1)
      [ -n "$_dns64_test" ] \
        && printf "${GREEN}OK${NC} (%s)\n" \
          "$(printf '%s' "$_dns64_test" | awk '{print $5}')" \
        || {
          printf "${RED}FAIL${NC}\n"
          _cfail=1
        }
      printf "  NAT64 route (64:ff9b::/96) ... "
      route -n show -inet6 2> /dev/null | grep -q "64:ff9b::" \
        && printf "${GREEN}OK${NC}\n" \
        || {
          printf "${RED}FAIL${NC} (missing -- check hostname.$INT_IF)\n"
          _cfail=1
        }
      ;;
    none) printf "  IPv6 ... ${YELLOW}SKIP${NC} (disabled)\n" ;;
  esac
fi

if [ "$_cfail" -eq 1 ]; then
  warn "Final connectivity FAILED"
  printf "  ${MAGENTA}Continue anyway? [y/N]: ${NC}"
  read _fc
  case "$_fc" in
    [Yy]*) warn "Continuing -- risk of incomplete setup" ;;
    *)
      _undo "final connectivity test failed"
      exit 1
      ;;
  esac
else
  ok "Final connectivity verified"
fi

# =============================================================================
# SUMMARY
# =============================================================================
print_header "Setup Complete"
printf "\n"
printf "  %-28s %s\n" "WAN:" "$EXT_IF ($WAN_TYPE, MTU=$WAN_MTU)"
printf "  %-28s %s\n" "Primary LAN:" "$INT_IF  $INT_IP4/$INT_CIDR4  MSS4=$INT_MSS4"
[ -n "$INT_IP6" ] \
  && printf "  %-28s %s\n" "  IPv6:" "$INT_IP6/$INT_CIDR6"
[ "$INT_IS_WIRELESS" -eq 1 ] && {
  _prefix=$(iface_prefix "$INT_IF")
  eval "_chan=\${${_prefix}_WIFI_CHANNEL:-?}"
  printf "  %-28s %s\n" "  Wireless:" "AP  channel=$_chan  -powersave"
}
printf "\n"
printf "  %-28s %s\n" "Deploy mode:" "$DEPLOY_MODE"
printf "  %-28s %s\n" "IPv6 mode:" "$IPV6_MODE"
printf "  %-28s %s\n" "Offload audit:" "done (TSO/LRO disabled on WAN+LAN)"
printf "  %-28s %s\n" "CA cert:" "$TN_CA_CERT"
printf "  %-28s %s\n" "Server cert:" "$TLS_CERT"
printf "  %-28s %s\n" "Inventory:" "$TN_INTERFACES"
printf "  %-28s %s\n" "Log:" "$LOG_FILE"
printf "\n"

printf "  ============================================================\n"
printf "  CA Certificate -- Client Trust Installation\n"
printf "  ============================================================\n"
printf "\n"
printf "  Download from:\n"
printf "    http://%s/certs/tangent-ca.crt\n" "${INT_IP4:-<LAN_IP>}"
printf "\n"
printf "  Android: Settings > Security > Install from storage\n"
printf "  iOS:     Settings > Profile Downloaded > Install (then trust in\n"
printf "           Settings > General > About > Certificate Trust Settings)\n"
printf "  Windows: certmgr.msc > Trusted Root Certification Authorities\n"
printf "  macOS:   Keychain Access > System > Trust > Always Trust\n"
printf "  Linux:   update-ca-certificates or trust anchor\n"
printf "\n"
printf "  Chrome and Firefox on mobile require OS-level trust store\n"
printf "  installation, not browser-level. Use the steps above.\n"
printf "  On managed networks, deploy via GPO or MDM.\n"
printf "  ============================================================\n"
printf "\n"

_TRAP_ACTIVE=0
write_status_ok
trap - EXIT
exit 0
