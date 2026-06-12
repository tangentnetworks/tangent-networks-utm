#!/bin/ksh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

set -euo pipefail

# ===================================================================================================
# CONFIGURATION
# ===================================================================================================
LOG_DIR="/var/www/htdocs/tn/data/logs/bootlog"
MANAGER_LOG="${LOG_DIR}/manager_$(date '+%Y-%m-%d').log"
DEBUG_LOG="/tmp/service_manager.log"

# Ensure log directory exists
install -d -o root -g wheel -m 755 "$LOG_DIR"

# ===================================================================================================
# LOGGING
# NOTE: Implemented against set -euo pipefail.
# tee can fail with SIGPIPE when stdout is a closed pipe (queue_processor capture).
# suppressing that with || true so set -e never fires inside log().
# ===================================================================================================
log() {
  local level="$1"
  local message="$2"
  local timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
  local logline="[$timestamp] MANAGER: [$level] $message"

  # Write to main log
  printf "%s\n" "$logline" | tee -a "$MANAGER_LOG" || true

  # Write to debug log with additional context
  printf "[%s] PID=%s ACTION=%s SERVICE=%s [%s] %s\n" \
    "$timestamp" "$$" "${ACTION:-?}" "${SERVICE:-?}" "$level" "$message" \
    >> "$DEBUG_LOG" 2> /dev/null || true
}

# Check if process is running by PID file
is_running() {
  local pidfile="$1"
  if [ -f "$pidfile" ]; then
    local pid=$(cat "$pidfile" 2> /dev/null)
    if [ -n "$pid" ] && kill -0 "$pid" 2> /dev/null; then
      return 0
    fi
  fi
  return 1
}

# Check if process is running by name
is_running_by_name() {
  local process_name="$1"
  pgrep -f "$process_name" > /dev/null 2>&1
}

# Check if service is rc-controlled
is_rc_service() {
  local service="$1"
  case "$service" in
    cron | dhcpd | ftpproxy | ftpproxy6 | httpd | ntpd | rad | slaacd | slowcgi | smtpd | syslogd | unbound)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

# Fast restart for logger pipeline services (skip graceful shutdown)
restart_fast() {
  local service="$1"

  case "$service" in
    snort)
      log "INFO" "Fast-restarting Snort IDS (force-kill old, start new)"

      # pkill exits 1 when nothing matched -- guard so set -e doesn't abort
      pkill -9 -f "snort.*-i %%INT_IF%%.*snort.conf" 2> /dev/null || true
      pkill -9 -f "logger -t snort_ids" 2> /dev/null || true
      rm -f /var/www/htdocs/tn/data/run/snort/snort_%%INT_IF%%.pid
      rm -f /var/www/htdocs/tn/data/run/snort/snort_%%INT_IF%%.launching
      sleep 1

      start_service "$service"
      return 0
      ;;

    snortinline)
      log "INFO" "Fast-restarting Snort IPS (force-kill old, start new)"

      pkill -9 -f "snort.*-Q.*snortinline.conf" 2> /dev/null || true
      pkill -9 -f "logger -t snort_ips" 2> /dev/null || true
      rm -f /var/www/htdocs/tn/data/run/snort/snort_.pid
      rm -f /var/www/htdocs/tn/data/run/snort/snort_.launching
      sleep 1

      start_service "$service"
      return 0
      ;;

    pmacct)
      log "INFO" "Fast-restarting pmacct (force-kill old, start new)"

      pkill -9 -f "pmacctd" 2> /dev/null || true
      pkill -9 -f "find.*pmacct.*chmod" 2> /dev/null || true
      pkill -9 -f "sleep 8" 2> /dev/null || true
      rm -f /var/www/htdocs/tn/data/run/pmacct/*.pid
      sleep 2

      start_service "$service"
      return 0
      ;;

    *)
      # Not a pipeline service -- use normal restart
      log "ERROR" "restart_fast called for non-pipeline service: $service"
      return 1
      ;;
  esac
}

# ===================================================================================================
# STOP SERVICE
# ===================================================================================================
stop_service() {
  local service="$1"
  log "INFO" "Stopping $service..."

  # Handle rc-controlled services
  if is_rc_service "$service"; then
    if rcctl check "$service" > /dev/null 2>&1; then
      rcctl stop "$service" 2>&1 | while read line; do log "INFO" "$line"; done
      log "INFO" "$service stopped (via rcctl)"
    else
      log "WARN" "$service not running (rcctl)"
    fi
    return 0
  fi

  # Handle custom rc.local services
  case "$service" in
    snort)
      local pidfile="/var/www/htdocs/tn/data/run/snort/snort_%%INT_IF%%.pid"

      # Always remove launching sentinel on stop -- prevents stale "launching" state
      rm -f /var/www/htdocs/tn/data/run/snort/snort_%%INT_IF%%.launching

      if [ -f "$pidfile" ]; then
        local pid=$(cat "$pidfile" 2> /dev/null)
        if [ -n "$pid" ] && kill -0 "$pid" 2> /dev/null; then
          log "INFO" "Stopping Snort IDS (PID: $pid)"

          # Send TERM signal
          if kill "$pid" 2> /dev/null; then
            # Wait for clean shutdown (up to 10 seconds)
            local i=1
            while [ $i -le 10 ]; do
              if ! kill -0 "$pid" 2> /dev/null; then
                log "INFO" "Snort IDS stopped cleanly"
                rm -f "$pidfile"

                # Kill logger process if it exists
                local logger_pid=$(pgrep -f "logger -t snort_ids" 2> /dev/null)
                if [ -n "$logger_pid" ]; then
                  kill "$logger_pid" 2> /dev/null
                  log "INFO" "Stopped logger process (PID: $logger_pid)"
                fi
                return 0
              fi
              sleep 1
              i=$((i + 1))
            done

            # Force kill if still running
            if kill -0 "$pid" 2> /dev/null; then
              log "WARN" "Snort IDS did not stop gracefully, forcing shutdown"
              kill -9 "$pid" 2> /dev/null
              sleep 1
              rm -f "$pidfile"
              log "INFO" "Snort IDS force-stopped"
            fi
          else
            log "ERROR" "Failed to send TERM signal to Snort IDS (PID: $pid)"
            return 1
          fi

          # Cleanup logger
          local logger_pid=$(pgrep -f "logger -t snort_ids" 2> /dev/null)
          if [ -n "$logger_pid" ]; then
            kill "$logger_pid" 2> /dev/null
            log "INFO" "Stopped logger process (PID: $logger_pid)"
          fi
          return 0
        else
          log "WARN" "Snort IDS PID file exists but process not running"
          rm -f "$pidfile"
        fi
      else
        log "INFO" "Snort IDS not running (no PID file)"
      fi

      # Check for orphaned processes
      local orphan_snort=$(pgrep -f "snort.*-i %%INT_IF%%.*snort.conf" 2> /dev/null)
      if [ -n "$orphan_snort" ]; then
        log "WARN" "Found orphaned Snort IDS process (PID: $orphan_snort), cleaning up"
        kill "$orphan_snort" 2> /dev/null
        sleep 1
        if kill -0 "$orphan_snort" 2> /dev/null; then
          kill -9 "$orphan_snort" 2> /dev/null
          log "WARN" "Force-killed orphaned Snort IDS"
        fi
      fi

      local orphan_logger=$(pgrep -f "logger -t snort_ids" 2> /dev/null)
      if [ -n "$orphan_logger" ]; then
        log "WARN" "Found orphaned logger process (PID: $orphan_logger), cleaning up"
        kill "$orphan_logger" 2> /dev/null
      fi
      ;;

    snortinline)
      local pidfile="/var/www/htdocs/tn/data/run/snort/snort_.pid"

      rm -f /var/www/htdocs/tn/data/run/snort/snort_.launching

      if [ -f "$pidfile" ]; then
        local pid=$(cat "$pidfile" 2> /dev/null)
        if [ -n "$pid" ] && kill -0 "$pid" 2> /dev/null; then
          log "INFO" "Stopping Snort IPS (PID: $pid)"

          # Send TERM signal
          if kill "$pid" 2> /dev/null; then
            # Wait for clean shutdown (up to 10 seconds)
            local i=1
            while [ $i -le 10 ]; do
              if ! kill -0 "$pid" 2> /dev/null; then
                log "INFO" "Snort IPS stopped cleanly"
                rm -f "$pidfile"

                # Kill logger process if it exists
                local logger_pid=$(pgrep -f "logger -t snort_ips" 2> /dev/null)
                if [ -n "$logger_pid" ]; then
                  kill "$logger_pid" 2> /dev/null
                  log "INFO" "Stopped logger process (PID: $logger_pid)"
                fi
                return 0
              fi
              sleep 1
              i=$((i + 1))
            done

            # Force kill if still running
            if kill -0 "$pid" 2> /dev/null; then
              log "WARN" "Snort IPS did not stop gracefully, forcing shutdown"
              kill -9 "$pid" 2> /dev/null
              sleep 1
              rm -f "$pidfile"
              log "INFO" "Snort IPS force-stopped"
            fi
          else
            log "ERROR" "Failed to send TERM signal to Snort IPS (PID: $pid)"
            return 1
          fi

          # Cleanup logger
          local logger_pid=$(pgrep -f "logger -t snort_ips" 2> /dev/null)
          if [ -n "$logger_pid" ]; then
            kill "$logger_pid" 2> /dev/null
            log "INFO" "Stopped logger process (PID: $logger_pid)"
          fi
          return 0
        else
          log "WARN" "Snort IPS PID file exists but process not running"
          rm -f "$pidfile"
        fi
      else
        log "INFO" "Snort IPS not running (no PID file)"
      fi

      # Check for orphaned processes
      local orphan_snort=$(pgrep -f "snort.*-Q.*snortinline.conf" 2> /dev/null)
      if [ -n "$orphan_snort" ]; then
        log "WARN" "Found orphaned Snort IPS process (PID: $orphan_snort), cleaning up"
        kill "$orphan_snort" 2> /dev/null
        sleep 1
        if kill -0 "$orphan_snort" 2> /dev/null; then
          kill -9 "$orphan_snort" 2> /dev/null
          log "WARN" "Force-killed orphaned Snort IPS"
        fi
      fi

      local orphan_logger=$(pgrep -f "logger -t snort_ips" 2> /dev/null)
      if [ -n "$orphan_logger" ]; then
        log "WARN" "Found orphaned logger process (PID: $orphan_logger), cleaning up"
        kill "$orphan_logger" 2> /dev/null
      fi
      ;;

    snortsentry)
      if pkill -f "^/usr/local/sbin/snortsentry" 2> /dev/null; then
        sleep 1
        log "INFO" "SnortSentry stopped"
      else
        log "WARN" "SnortSentry not running"
      fi
      rm -f /var/www/htdocs/tn/data/run/snortsentry/snortsentry.pid
      ;;

    e2guardian)
      if pkill -f "^/usr/local/sbin/e2guardian" 2> /dev/null; then
        sleep 2
        log "INFO" "E2Guardian stopped"
      else
        log "WARN" "E2Guardian not running"
      fi
      rm -f /var/www/htdocs/tn/data/run/e2guardian/e2guardian.pid
      ;;

    collectd)
      if pkill -f "^/usr/local/sbin/collectd" 2> /dev/null; then
        sleep 1
        log "INFO" "Collectd stopped"
      else
        log "WARN" "Collectd not running"
      fi
      rm -f /var/www/htdocs/tn/data/sockets/collectd/collectd.sock 2> /dev/null
      rm -f /var/www/htdocs/tn/data/run/collectd/*.pid
      ;;

    p3scan)
      local pidfile="/var/www/htdocs/tn/data/run/p3scan/p3scan.pid"
      if is_running "$pidfile"; then
        if kill $(cat "$pidfile") 2> /dev/null; then
          sleep 1
          log "INFO" "P3Scan stopped"
        else
          log "WARN" "P3Scan kill failed"
        fi
      else
        log "WARN" "P3Scan not running"
      fi
      rm -f "$pidfile"
      ;;

    clamd)
      local pidfile="/var/www/htdocs/tn/data/run/clamav/clamd.pid"
      if is_running "$pidfile"; then
        if kill $(cat "$pidfile") 2> /dev/null; then
          sleep 2
          log "INFO" "ClamAV stopped"
        else
          log "WARN" "ClamAV kill failed"
        fi
      else
        log "WARN" "ClamAV not running"
      fi
      rm -f /var/www/htdocs/tn/data/run/clamav/clamd.pid
      ;;

    freshclam)
      if pkill -f "^/usr/local/bin/freshclam" 2> /dev/null; then
        sleep 1
        log "INFO" "FreshClam stopped"
      else
        log "WARN" "FreshClam not running"
      fi
      rm -f /var/www/htdocs/tn/data/run/clamav/freshclam.pid
      ;;

    pmacct)
      if pkill -f "^/usr/local/sbin/pmacctd" 2> /dev/null; then
        sleep 2
        log "INFO" "pmacct instances stopped"
      else
        log "WARN" "pmacct not running"
      fi

      pkill -f "find.*pmacct.*chmod" 2> /dev/null
      pkill -f "sleep 8" 2> /dev/null

      log "INFO" "pmacct stopped (all instances and background jobs)"
      rm -f /var/www/htdocs/tn/data/run/pmacct/*.pid
      ;;

    sockd)
      local pidfile="/var/www/htdocs/tn/data/run/sockd/sockd.pid"
      if is_running "$pidfile"; then
        if kill $(cat "$pidfile") 2> /dev/null; then
          sleep 1
          log "INFO" "Dante (sockd) stopped"
        else
          log "WARN" "Dante (sockd) kill failed"
        fi
      else
        log "WARN" "Dante (sockd) not running"
      fi
      rm -f "$pidfile"
      ;;

    spamd)
      local pidfile="/var/www/htdocs/tn/data/run/spamd/spamd.pid"
      if is_running "$pidfile"; then
        if kill $(cat "$pidfile") 2> /dev/null; then
          sleep 1
          log "INFO" "spamd stopped"
        else
          log "WARN" "spamd kill failed"
        fi
      else
        log "WARN" "spamd not running"
      fi
      rm -f "$pidfile"
      ;;

    smtp-gated)
      if pkill -f "^/usr/local/sbin/smtp-gated" 2> /dev/null; then
        sleep 1
        log "INFO" "SMTP-gated stopped"
      else
        log "WARN" "SMTP-gated not running"
      fi
      rm -f /var/www/htdocs/tn/data/run/smtp-gated/smtp-gated.pid
      ;;

    sslproxy)
      if pkill -f "^/usr/local/bin/sslproxy" 2> /dev/null; then
        sleep 1
        log "INFO" "SSLproxy stopped"
      else
        log "WARN" "SSLproxy not running"
      fi
      rm -f /var/www/htdocs/tn/data/run/sslproxy/sslproxy.pid
      ;;

    imspector)
      if pkill -f "^/usr/local/sbin/imspector" 2> /dev/null; then
        sleep 1
        log "INFO" "IMSpector stopped"
      else
        log "WARN" "IMSpector not running"
      fi
      rm -f /var/www/htdocs/tn/data/run/imspector/*.pid 2> /dev/null
      ;;

    tcpdump)
      # Stop the runner first (prevents immediate restart)
      local runner_pid="/var/www/htdocs/tn/data/run/webui/pflog_maint.pid"
      if is_running "$runner_pid"; then
        kill $(cat "$runner_pid") 2> /dev/null
        sleep 1
        log "INFO" "pf_tcpdump_runner stopped"
      else
        log "WARN" "pf_tcpdump_runner not running"
      fi
      rm -f "$runner_pid"
      # Kill bare tcpdump process if present (orphan cleanup)
      pkill -f "tcpdump -n -e -ttt -i %%INT_IF%%" 2> /dev/null
      sleep 1
      log "INFO" "tcpdump (%%INT_IF%%) stopped"
      ;;

    *)
      log "ERROR" "Unknown service: $service"
      return 1
      ;;
  esac
  return 0
}

# ===================================================================================================
# START SERVICE
# ===================================================================================================
start_service() {
  local service="$1"
  log "INFO" "Starting $service..."

  # Handle rc-controlled services
  if is_rc_service "$service"; then
    if rcctl check "$service" > /dev/null 2>&1; then
      log "WARN" "$service already running (rcctl)"
    else
      rcctl start "$service" 2>&1 | while read line; do log "INFO" "$line"; done
      log "INFO" "$service started (via rcctl)"
    fi
    return 0
  fi

  # Handle custom rc.local services
  case "$service" in
    snort)
      if [ ! -x /usr/local/bin/snort ]; then
        log "ERROR" "Snort binary not found at /usr/local/bin/snort"
        return 1
      fi

      # Ensure directories exist with correct permissions
      mkdir -p /var/www/htdocs/tn/data/run/snort
      mkdir -p /var/www/htdocs/tn/data/logs/snort
      chown _snort:wheel /var/www/htdocs/tn/data/run/snort
      chmod 0755 /var/www/htdocs/tn/data/run/snort

      # Check config file
      if [ ! -f /etc/snort/snort.conf ]; then
        log "ERROR" "Config file /etc/snort/snort.conf not found"
        return 1
      fi

      # Check if already running
      if [ -f /var/www/htdocs/tn/data/run/snort/snort_%%INT_IF%%.pid ]; then
        local old_pid=$(cat /var/www/htdocs/tn/data/run/snort/snort_%%INT_IF%%.pid 2> /dev/null)
        if [ -n "$old_pid" ] && kill -0 "$old_pid" 2> /dev/null; then
          log "WARN" "Snort IDS already running (PID: $old_pid)"
          return 0
        else
          rm -f /var/www/htdocs/tn/data/run/snort/snort_%%INT_IF%%.pid
        fi
      fi

      log "INFO" "Starting Network Intrusion Detection System"

      # Write launching sentinel -- status_service returns "launching" until PID confirmed
      touch /var/www/htdocs/tn/data/run/snort/snort_%%INT_IF%%.launching
      chmod 0644 /var/www/htdocs/tn/data/run/snort/snort_%%INT_IF%%.launching 2> /dev/null || true

      {
        umask 0022
        /usr/local/bin/snort -i %%INT_IF%% -d -c /etc/snort/snort.conf \
          -u _snort -g _snort -b -l /var/www/htdocs/tn/data/logs/snort \
          --pid-path /var/www/htdocs/tn/data/run/snort \
          2>&1 | logger -t snort_ids -p daemon.info
      } &

      # Detached subshell watcher -- uses ( ) not { } so 'local' is never needed
      # and exit only affects this subshell, not the parent script.
      (
        _w=0
        while [ $_w -lt 45 ]; do
          if [ -f /var/www/htdocs/tn/data/run/snort/snort_%%INT_IF%%.pid ]; then
            _wpid=$(cat /var/www/htdocs/tn/data/run/snort/snort_%%INT_IF%%.pid 2> /dev/null)
            if [ -n "$_wpid" ] && kill -0 "$_wpid" 2> /dev/null; then
              chmod 0644 /var/www/htdocs/tn/data/run/snort/snort_%%INT_IF%%.pid 2> /dev/null || true
              rm -f /var/www/htdocs/tn/data/run/snort/snort_%%INT_IF%%.launching
              log "INFO" "Snort IDS confirmed running (PID: $_wpid)"
              exit 0
            fi
          fi
          sleep 1
          _w=$((_w + 1))
        done
        rm -f /var/www/htdocs/tn/data/run/snort/snort_%%INT_IF%%.launching
        log "ERROR" "Snort IDS watcher timed out -- PID file never appeared"
      ) &

      log "INFO" "Snort IDS launched (background watcher monitoring startup)"
      ;;

    snortinline)
      if [ ! -x /usr/local/bin/snort ]; then
        log "ERROR" "Snort binary not found at /usr/local/bin/snort"
        return 1
      fi

      # Ensure directories exist with correct permissions
      mkdir -p /var/www/htdocs/tn/data/run/snort
      mkdir -p /var/www/htdocs/tn/data/logs/snort
      chown _snort:wheel /var/www/htdocs/tn/data/run/snort
      chmod 0755 /var/www/htdocs/tn/data/run/snort

      # Check config file
      if [ ! -f /etc/snort/snortinline.conf ]; then
        log "ERROR" "Config file /etc/snort/snortinline.conf not found"
        return 1
      fi

      # Check if already running
      if [ -f /var/www/htdocs/tn/data/run/snort/snort_.pid ]; then
        local old_pid=$(cat /var/www/htdocs/tn/data/run/snort/snort_.pid 2> /dev/null)
        if [ -n "$old_pid" ] && kill -0 "$old_pid" 2> /dev/null; then
          log "WARN" "Snort IPS already running (PID: $old_pid)"
          return 0
        else
          rm -f /var/www/htdocs/tn/data/run/snort/snort_.pid
        fi
      fi

      log "INFO" "Starting Network Intrusion Prevention System"

      touch /var/www/htdocs/tn/data/run/snort/snort_.launching
      chmod 0644 /var/www/htdocs/tn/data/run/snort/snort_.launching 2> /dev/null || true

      {
        umask 0022
        /usr/local/bin/snort -d -Q -c /etc/snort/snortinline.conf \
          -u _snort -g _snort -b -l /var/www/htdocs/tn/data/logs/snort \
          --pid-path /var/www/htdocs/tn/data/run/snort \
          2>&1 | logger -t snort_ips -p daemon.info
      } &

      (
        _w=0
        while [ $_w -lt 45 ]; do
          if [ -f /var/www/htdocs/tn/data/run/snort/snort_.pid ]; then
            _wpid=$(cat /var/www/htdocs/tn/data/run/snort/snort_.pid 2> /dev/null)
            if [ -n "$_wpid" ] && kill -0 "$_wpid" 2> /dev/null; then
              chmod 0644 /var/www/htdocs/tn/data/run/snort/snort_.pid 2> /dev/null || true
              rm -f /var/www/htdocs/tn/data/run/snort/snort_.launching
              log "INFO" "Snort IPS confirmed running (PID: $_wpid)"
              exit 0
            fi
          fi
          sleep 1
          _w=$((_w + 1))
        done
        rm -f /var/www/htdocs/tn/data/run/snort/snort_.launching
        log "ERROR" "Snort IPS watcher timed out -- PID file never appeared"
      ) &

      log "INFO" "Snort IPS launched (background watcher monitoring startup)"
      ;;

    snortsentry)
      if [ ! -x /usr/local/sbin/snortsentry ]; then
        log "ERROR" "SnortSentry binary not found"
        return 1
      fi
      /usr/local/sbin/snortsentry -f /etc/snort/snortsentry.conf > /dev/null 2>&1 &
      log "INFO" "SnortSentry started"
      ;;

    e2guardian)
      if [ ! -x /usr/local/sbin/e2guardian ]; then
        log "ERROR" "E2Guardian binary not found"
        return 1
      fi
      [[ ! -d /var/www/htdocs/tn/data/tmp/e2guardian ]] && mkdir -p /var/www/htdocs/tn/data/tmp/e2guardian
      chown -R _e2guardian:_clamav /var/www/htdocs/tn/data/tmp/e2guardian
      /usr/local/sbin/e2guardian > /dev/null 2>&1 &
      log "INFO" "E2Guardian started"
      ;;

    collectd)
      if [ ! -x /usr/local/sbin/collectd ]; then
        log "ERROR" "Collectd binary not found"
        return 1
      fi
      rm -f /var/www/htdocs/tn/data/sockets/collectd/collectd.sock 2> /dev/null
      /usr/local/sbin/collectd -C /etc/collectd.conf > /dev/null 2>&1 &
      sleep 2
      log "INFO" "Collectd started"
      ;;

    p3scan)
      if [ ! -x /usr/local/sbin/p3scan ]; then
        log "ERROR" "P3Scan binary not found"
        return 1
      fi
      [[ ! -d /var/www/htdocs/tn/data/run/p3scan ]] && mkdir -p /var/www/htdocs/tn/data/run/p3scan
      chown _p3scan:wheel /var/www/htdocs/tn/data/run/p3scan
      rm -f /var/www/htdocs/tn/data/run/p3scan/p3scan.pid 2> /dev/null
      /usr/local/sbin/p3scan -f /etc/p3scan/p3scan.conf > /dev/null 2>&1 &
      log "INFO" "P3Scan started"
      ;;

    clamd)
      if [ ! -x /usr/local/sbin/clamd ]; then
        log "ERROR" "ClamAV binary not found"
        return 1
      fi
      local CLAMRUN="/var/www/htdocs/tn/data/run/clamav"
      local CLAMTMP="/var/www/htdocs/tn/data/tmp/clamav"
      for dir in "$CLAMRUN" "$CLAMTMP"; do
        [ -d "$dir" ] || mkdir -p "$dir"
      done
      chown _clamav:_clamav "$CLAMRUN"
      chown _clamav:wheel "$CLAMTMP"
      /usr/local/sbin/clamd -c /etc/clamd.conf > /dev/null 2>&1 &

      # Wait for socket
      local SOCKET="/var/www/htdocs/tn/data/tmp/clamav/clamd.socket"
      local SECS=0
      local MAX_WAIT=90
      while [ $SECS -lt $MAX_WAIT ]; do
        if [ -S "$SOCKET" ]; then
          log "INFO" "ClamAV started and socket ready"
          return 0
        fi
        SECS=$((SECS + 1))
        sleep 1
      done
      log "ERROR" "ClamAV socket not ready after $MAX_WAIT seconds"
      return 1
      ;;

    freshclam)
      if [ ! -x /usr/local/bin/freshclam ]; then
        log "ERROR" "FreshClam binary not found"
        return 1
      fi
      /usr/local/bin/freshclam -d > /dev/null 2>&1 &
      log "INFO" "FreshClam started"
      ;;

    pmacct)
      if [ ! -x /usr/local/sbin/pmacctd ]; then
        log "ERROR" "pmacctd binary not found"
        return 1
      fi

      local PMACCT_LOG_DIR="/var/www/htdocs/tn/data/logs/pmacct"
      local PMACCT_STATUS_LOG_DIR="/var/www/htdocs/tn/data/services/pmacct"
      local PMACCT_EXT_IF_DIR="/var/www/htdocs/tn/data/network/pmacct/ext"
      local PMACCT_MFS_DIR="/var/www/htdocs/tn/data/pipes/pmacct"

      # Ensure directories exist
      for dir in "$PMACCT_LOG_DIR" "$PMACCT_STATUS_LOG_DIR" "$PMACCT_MFS_DIR" "$PMACCT_EXT_IF_DIR"; do
        if [ ! -d "$dir" ]; then
          mkdir -p "$dir"
          if [ $? -ne 0 ]; then
            log "ERROR" "Failed to create directory: $dir"
            return 1
          fi
        fi
      done

      # Pre-create MFS log files with good permissions
      local PMACCT_MFS_EXT_JSON="$PMACCT_MFS_DIR/ext_if_json.log"
      local PMACCT_MFS_INT_JSON="$PMACCT_MFS_DIR/int_if_json.log"
      touch "$PMACCT_MFS_EXT_JSON" "$PMACCT_MFS_INT_JSON"
      chmod 644 "$PMACCT_MFS_EXT_JSON" "$PMACCT_MFS_INT_JSON"

      # Start MFS-based instances (immediate start)
      /usr/local/sbin/pmacctd -f /etc/pmacct/ext_if_json_mfs.conf > /dev/null 2>&1 &
      /usr/local/sbin/pmacctd -f /etc/pmacct/int_if_json_mfs.conf > /dev/null 2>&1 &

      # Background job: find and fix MFS log permissions every 8 seconds
      {
        while true; do
          find "$PMACCT_MFS_DIR" -type f -name "*.log" -exec chmod 644 {} \; 2> /dev/null
          sleep 8
        done
      } &

      # Start log-to-disk instance (waits for 15-min boundary)
      {
        /usr/local/sbin/pmacctd -f /etc/pmacct/ext_if_json_log.conf 2>&1 | logger -t pmacct_ext -p daemon.info
      } &

      # Wait for 3 PIDs to confirm startup
      local MAX_WAIT=10
      local SECS=0
      while [ $SECS -lt $MAX_WAIT ]; do
        local PMACCT_PIDS=$(pgrep -f pmacctd | wc -l)
        if [ "$PMACCT_PIDS" -ge 3 ]; then
          log "INFO" "pmacct started successfully ($PMACCT_PIDS instances)"
          return 0
        fi
        sleep 1
        SECS=$((SECS + 1))
      done

      log "ERROR" "pmacct failed to start - expected 3+ instances, found $(pgrep -f pmacctd | wc -l)"
      return 1
      ;;

    sockd)
      if [ ! -x /usr/local/sbin/sockd ]; then
        log "ERROR" "Dante (sockd) binary not found"
        return 1
      fi
      /usr/local/sbin/sockd -D -p /var/www/htdocs/tn/data/run/sockd/sockd.pid > /dev/null 2>&1 &
      log "INFO" "Dante (sockd) started"
      ;;

    spamd)
      if [ ! -x /usr/local/bin/spamd ]; then
        log "ERROR" "spamd binary not found"
        return 1
      fi
      /usr/local/bin/spamd -L -d -x -u _spamdaemon -r /var/www/htdocs/tn/data/run/spamd/spamd.pid > /dev/null 2>&1 &
      log "INFO" "spamd started"
      ;;

    smtp-gated)
      if [ ! -x /usr/local/sbin/smtp-gated ]; then
        log "ERROR" "SMTP-gated binary not found"
        return 1
      fi
      /usr/local/sbin/smtp-gated /usr/local/etc/smtp-gated/smtp-gated.conf > /dev/null 2>&1 &
      log "INFO" "SMTP-gated started"
      ;;

    sslproxy)
      if [ ! -x /usr/local/bin/sslproxy ]; then
        log "ERROR" "SSLproxy binary not found"
        return 1
      fi
      /usr/local/bin/sslproxy -f /usr/local/etc/sslproxy/sslproxy.conf > /dev/null 2>&1 &
      log "INFO" "SSLproxy started"
      ;;

    imspector)
      if [ ! -x /usr/local/sbin/imspector ]; then
        log "ERROR" "IMSpector binary not found"
        return 1
      fi
      [[ ! -d /tmp/imspector ]] && mkdir -p /tmp/imspector
      chown -R _imspector:_imspector /tmp/imspector
      /usr/local/sbin/imspector -c /usr/local/etc/imspector/imspector.conf > /dev/null 2>&1 &
      log "INFO" "IMSpector started"
      ;;

    tcpdump)
      if [ ! -x /usr/local/sbin/pf_tcpdump_runner.sh ]; then
        log "ERROR" "pf_tcpdump_runner.sh not found or not executable"
        return 1
      fi

      if ! ifconfig %%INT_IF%% > /dev/null 2>&1; then
        log "ERROR" "%%INT_IF%% interface not found"
        return 1
      fi

      local runner_pid="/var/www/htdocs/tn/data/run/webui/pflog_maint.pid"
      if is_running "$runner_pid"; then
        log "WARN" "pf_tcpdump_runner already running (PID: $(cat $runner_pid))"
        return 0
      fi

      /usr/local/sbin/pf_tcpdump_runner.sh < /dev/null > /dev/null 2>&1 &
      sleep 1
      if is_running "$runner_pid"; then
        log "INFO" "pf_tcpdump_runner started (PID: $(cat $runner_pid))"
      else
        log "ERROR" "pf_tcpdump_runner failed to start"
        return 1
      fi
      ;;

    *)
      log "ERROR" "Unknown service: $service"
      return 1
      ;;
  esac
  return 0
}

# ===================================================================================================
# GET SERVICE STATUS
# ===================================================================================================
status_service() {
  local service="$1"

  # Handle rc-controlled services
  if is_rc_service "$service"; then
    if rcctl check "$service" > /dev/null 2>&1; then
      local pid=$(pgrep -x "$service" 2> /dev/null | head -1)
      if [ -n "$pid" ]; then
        echo "$service:running:$pid"
      else
        echo "$service:running:0"
      fi
    else
      echo "$service:stopped"
    fi
    return 0
  fi

  # Handle custom rc.local services
  case "$service" in
    snort)
      local pidfile="/var/www/htdocs/tn/data/run/snort/snort_%%INT_IF%%.pid"
      local sentinel="/var/www/htdocs/tn/data/run/snort/snort_%%INT_IF%%.launching"
      if is_running "$pidfile"; then
        echo "snort:running:$(cat $pidfile)"
      elif [ -f "$sentinel" ]; then
        echo "snort:launching"
      else
        echo "snort:stopped"
      fi
      ;;

    snortinline)
      local pidfile="/var/www/htdocs/tn/data/run/snort/snort_.pid"
      local sentinel="/var/www/htdocs/tn/data/run/snort/snort_.launching"
      if is_running "$pidfile"; then
        echo "snortinline:running:$(cat $pidfile)"
      elif [ -f "$sentinel" ]; then
        echo "snortinline:launching"
      else
        echo "snortinline:stopped"
      fi
      ;;

    snortsentry)
      if is_running_by_name "snortsentry"; then
        echo "snortsentry:running:$(pgrep -f snortsentry)"
      else
        echo "snortsentry:stopped"
      fi
      ;;

    e2guardian)
      if is_running_by_name "e2guardian"; then
        echo "e2guardian:running:$(pgrep -f e2guardian)"
      else
        echo "e2guardian:stopped"
      fi
      ;;

    collectd)
      if is_running_by_name "collectd"; then
        echo "collectd:running:$(pgrep -f collectd)"
      else
        echo "collectd:stopped"
      fi
      ;;

    p3scan)
      local pidfile="/var/www/htdocs/tn/data/run/p3scan/p3scan.pid"
      if is_running "$pidfile"; then
        echo "p3scan:running:$(cat $pidfile)"
      else
        echo "p3scan:stopped"
      fi
      ;;

    clamd)
      local pidfile="/var/www/htdocs/tn/data/run/clamav/clamd.pid"
      if is_running "$pidfile"; then
        echo "clamd:running:$(cat $pidfile)"
      else
        echo "clamd:stopped"
      fi
      ;;

    freshclam)
      if is_running_by_name "freshclam"; then
        echo "freshclam:running:$(pgrep -f freshclam)"
      else
        echo "freshclam:stopped"
      fi
      ;;

    pmacct)
      if is_running_by_name "pmacctd"; then
        echo "pmacct:running:$(pgrep -f pmacctd | head -1)"
      else
        echo "pmacct:stopped"
      fi
      ;;

    sockd)
      local pidfile="/var/www/htdocs/tn/data/run/sockd/sockd.pid"
      if is_running "$pidfile"; then
        echo "sockd:running:$(cat $pidfile)"
      else
        echo "sockd:stopped"
      fi
      ;;

    spamd)
      local pidfile="/var/www/htdocs/tn/data/run/spamd/spamd.pid"
      if is_running "$pidfile"; then
        echo "spamd:running:$(cat $pidfile)"
      else
        echo "spamd:stopped"
      fi
      ;;

    smtp-gated)
      if is_running_by_name "smtp-gated"; then
        echo "smtp-gated:running:$(pgrep -f smtp-gated)"
      else
        echo "smtp-gated:stopped"
      fi
      ;;

    sslproxy)
      if is_running_by_name "sslproxy"; then
        echo "sslproxy:running:$(pgrep -f sslproxy)"
      else
        echo "sslproxy:stopped"
      fi
      ;;

    imspector)
      if is_running_by_name "imspector"; then
        echo "imspector:running:$(pgrep -f imspector)"
      else
        echo "imspector:stopped"
      fi
      ;;

    tcpdump)
      local runner_pid="/var/www/htdocs/tn/data/run/webui/pflog_maint.pid"
      if is_running "$runner_pid"; then
        echo "tcpdump:running:$(cat $runner_pid)"
      else
        echo "tcpdump:stopped"
      fi
      ;;

    *)
      echo "$service:unknown"
      ;;
  esac
}

# ===================================================================================================
# LIST SERVICES
# ===================================================================================================
list_services() {
  cat << EOF
snort
snortinline
snortsentry
e2guardian
collectd
p3scan
clamd
freshclam
pmacct
sockd
spamd
smtp-gated
sslproxy
imspector
tcpdump
cron
dhcpd
ftpproxy
ftpproxy6
httpd
ntpd
rad
slaacd
slowcgi
smtpd
syslogd
unbound
EOF
}

# ===================================================================================================
# USAGE
# ===================================================================================================
_usage() {
  cat << EOF
Usage: $0 <action> [service]

Actions:
  start   <service>   Start a service
  stop    <service>   Stop a service
  restart <service>   Restart a service (fast-restart for snort, snortinline, pmacct)
  status  <service>   Show service status
  list                List all managed services
  --help              Show this help

Services (rc.d):
  cron dhcpd ftpproxy ftpproxy6 httpd ntpd rad slaacd slowcgi smtpd syslogd unbound

Services (local):
  snort snortinline snortsentry e2guardian collectd p3scan clamd freshclam
  pmacct sockd spamd smtp-gated sslproxy imspector tcpdump

Examples:
  $0 start snort
  $0 restart pmacct
  $0 status clamd
  $0 list
EOF
}

# ===================================================================================================
# MAIN
# ===================================================================================================

ACTION="${1:-}"
SERVICE="${2:-}"

case "$ACTION" in
  start)
    if [ -z "$SERVICE" ]; then
      log "ERROR" "Service name required for start action"
      exit 1
    fi
    start_service "$SERVICE"
    ;;

  stop)
    if [ -z "$SERVICE" ]; then
      log "ERROR" "Service name required for stop action"
      exit 1
    fi
    stop_service "$SERVICE"
    ;;

  restart)
    if [ -z "$SERVICE" ]; then
      log "ERROR" "Service name required for restart action"
      exit 1
    fi

    # Use fast-restart for logger pipeline services
    case "$SERVICE" in
      snort | snortinline | pmacct)
        restart_fast "$SERVICE"
        ;;
      *)
        # Normal restart for other services
        set +e
        stop_service "$SERVICE"
        set -e
        sleep 2
        start_service "$SERVICE"
        ;;
    esac
    ;;

  status)
    if [ -z "$SERVICE" ]; then
      log "ERROR" "Service name required for status action"
      exit 1
    fi
    status_service "$SERVICE"
    ;;

  list)
    list_services
    ;;

  --help | -h)
    _usage
    exit 0
    ;;

  *)
    log "ERROR" "Invalid action: $ACTION"
    exit 1
    ;;
esac

exit 0
