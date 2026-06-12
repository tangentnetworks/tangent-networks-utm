package TNWatchParser;

# TNWatch - Log Parsing Engine
# /etc/TNWatch/TNWatchParser.pm
#
# Parsers for each OpenBSD log source.
# Each parser returns an arrayref of event hashrefs
# ready for TNWatchDatabase::insert_events_bulk().

use strict;
use warnings;
use DBI;
use JSON::PP;
use POSIX qw(strftime mktime);

#===================================
# LOG SOURCE PATHS
#===================================

my %LOG_PATHS = (
    tnaudit        => '/var/www/htdocs/tn/data/db/TNAudit.db',
    httpd          => '/var/www/htdocs/tn/data/logs/httpd/httpd_error.log',
    tnwaf_access   => '/var/www/htdocs/tn/data/logs/waf/access.log',
    tnwaf_security => '/var/www/htdocs/tn/data/logs/waf/security.log',
    tnwaf_error    => '/var/www/htdocs/tn/data/logs/waf/error.log',
    snort          => '/var/www/htdocs/tn/data/logs/snort/alert.log',
    e2guardian     => '/var/www/htdocs/tn/data/logs/e2guardian/access.log',
    unbound        => '/var/www/htdocs/tn/data/logs/unbound/unbound.log',
    syslog         => '/var/www/htdocs/tn/data/logs/system/messages',
    daemon         => '/var/www/htdocs/tn/data/logs/system/daemon',
    authlog        => '/var/log/authlog',
    services       => '/var/www/htdocs/tn/data/logs/bootlog/services.json',

    # pf => uses pfctl commands, not a log file
);

#===================================
# CONSTRUCTOR
#===================================

sub new {
    my ( $class, %opts ) = @_;
    return bless {
        paths   => { %LOG_PATHS, %{ $opts{paths} // {} } },
        verbose => $opts{verbose} // 0,
    }, $class;
}

#===================================
# PARSE DISPATCHER
#===================================

sub parse {
    my ( $self, $source, $state ) = @_;
    $state //= { last_pos => 0, last_ts => 0 };

    my %dispatch = (
        tnaudit        => \&parse_tnaudit,
        pf             => \&parse_pf_counters,
        httpd          => \&parse_httpd_log,
        tnwaf_access   => \&parse_tnwaf_access,
        tnwaf_security => \&parse_tnwaf_security,
        tnwaf_error    => \&parse_tnwaf_error,
        snort          => \&parse_snort_alert,
        e2guardian     => \&parse_e2guardian,
        unbound        => \&parse_unbound,
        syslog         => \&parse_syslog,
        daemon         => \&parse_daemon,
        authlog        => \&parse_authlog,
        services       => \&parse_services,
    );

    my $fn = $dispatch{$source} or die "Unknown source: $source\n";
    return $self->$fn($state);
}

sub parse_all {
    my ( $self, $states ) = @_;
    $states //= {};
    my %results;

    for my $source ( keys(%LOG_PATHS), 'pf' ) {
        eval {
            my $state = $states->{$source} // { last_pos => 0, last_ts => 0 };
            my ( $events, $new_state ) = $self->parse( $source, $state );
            $results{$source} = {
                events    => $events,
                new_state => $new_state,
                count     => scalar(@$events),
                error     => undef,
            };
        };
        if ($@) {
            my $err = $@;
            $err =~ s/\n$//;
            $results{$source} = { events => [], count => 0, error => $err };
            warn "TNWatchParser: $source failed: $err\n" if $self->{verbose};
        }
    }

    return \%results;
}

#===================================
# TNAUDIT PARSER
#===================================
# Reads TNAudit.db directly via SQLite.
# Extracts files with status != 'ok' or recently changed.

sub parse_tnaudit {
    my ( $self, $state ) = @_;
    my $db_path = $self->{paths}{tnaudit};

    die "TNAudit database not found: $db_path\n" unless -f $db_path;

    my $dbh =
      DBI->connect( "dbi:SQLite:dbname=$db_path", '', '',
        { RaiseError => 1, AutoCommit => 1, sqlite_unicode => 1 } )
      or die "Cannot open TNAudit.db: $DBI::errstr\n";

    my @events;
    my $last_ts = $state->{last_ts} // 0;

    # -- Discover TNAudit schema dynamically (column names vary by version)
    my %cols;
    eval {
        my $pragma = $dbh->prepare("PRAGMA table_info(files)");
        $pragma->execute;
        while ( my $r = $pragma->fetchrow_hashref ) { $cols{ $r->{name} } = 1 }
    };

    my $path_col =
        exists $cols{filepath}  ? 'filepath'
      : exists $cols{file_path} ? 'file_path'
      : exists $cols{filename}  ? 'filename'
      : exists $cols{path}      ? 'path'
      :                           'rowid';

    my $sha_col =
        exists $cols{sha256}         ? 'sha256'
      : exists $cols{file_sha256}    ? 'file_sha256'
      : exists $cols{current_sha256} ? 'current_sha256'
      :                                undef;

    my $base_sha =
        exists $cols{baseline_sha256} ? 'baseline_sha256'
      : exists $cols{base_sha256}     ? 'base_sha256'
      :                                 undef;

    # -- Query files with non-ok status.
    # 'baseline' is the post-acceptance state from --update-baseline and is
    # treated as clean. 'ok' and 'verified' are the normal clean states.
    # We only emit file_change events for rows whose last_checked timestamp
    # is newer than last_ts — this prevents a file sitting in 'modified'
    # state from generating a duplicate event on every 5-minute parse cycle.
    eval {
        my @sc = ( 'status', $path_col, 'id' );
        push @sc, $sha_col       if $sha_col;
        push @sc, $base_sha      if $base_sha;
        push @sc, 'last_checked' if exists $cols{last_checked};
        push @sc, 'file_size'    if exists $cols{file_size};
        push @sc, 'file_mtime'   if exists $cols{file_mtime};

        my $clean = "'ok', 'verified', 'baseline'";
        my $sql =
            "SELECT "
          . join( ", ", @sc )
          . " FROM files WHERE status NOT IN ($clean)";

        # Gate on last_ts so already-reported changes are not re-emitted.
        # On the first run last_ts is 0 so all current issues are captured.
        if ( $last_ts > 0 && exists $cols{last_checked} ) {
            $sql .= " AND last_checked > $last_ts";
        }

        my $sth = $dbh->prepare($sql);
        $sth->execute;

        while ( my $row = $sth->fetchrow_hashref ) {
            my $fpath = $row->{$path_col} // '?';
            push @events,
              {
                source     => 'tnaudit',
                event_type => 'file_change',
                severity   => _tnaudit_severity( $row->{status} ),
                timestamp  => $row->{last_checked} // time(),
                message    =>
                  sprintf( "TNAudit: %s -- %s", uc( $row->{status} ), $fpath ),
                details => encode_json(
                    {
                        status       => $row->{status},
                        old_sha256   => $base_sha ? $row->{$base_sha} : undef,
                        new_sha256   => $sha_col  ? $row->{$sha_col}  : undef,
                        file_size    => $row->{file_size},
                        file_mtime   => $row->{file_mtime},
                        last_checked => $row->{last_checked},
                    }
                ),
                src_ip => undef,
              };
        }
    };
    warn "TNAudit file query failed: $@\n" if $@;

    # ── Get overall integrity summary ──────────────────────────
    my %summary;
    eval {
        my $sth = $dbh->prepare(
            q{
            SELECT status, COUNT(*) as cnt FROM files GROUP BY status
        }
        );
        $sth->execute;
        while ( my $row = $sth->fetchrow_hashref ) {
            $summary{ $row->{status} } = $row->{cnt};
        }
    };

    # Always emit a summary event for the digest
    my $total = 0;
    $total += $_ for values %summary;
    my $ok      = ( $summary{ok} // 0 ) + ( $summary{verified} // 0 );
    my $changed = $total - $ok;

    push @events,
      {
        source     => 'tnaudit',
        event_type => 'integrity_check',
        severity   => ( $changed > 0 ? 'critical' : 'info' ),
        timestamp  => time(),
        message    => sprintf(
            "TNAudit integrity check: %d total, %d ok, %d issues",
            $total, $ok, $changed
        ),
        details => encode_json(
            {
                summary => \%summary,
                total   => $total,
                changed => $changed,
            }
        ),
      };

    $dbh->disconnect;

    my $new_state = { last_ts => time(), last_pos => 0 };
    return ( \@events, $new_state );
}

sub _tnaudit_severity {
    my ($status) = @_;
    return 'critical' if $status =~ /^(modified|missing|corrupted)$/i;
    return 'warning'  if $status =~ /^new$/i;
    return 'info';
}

#===================================
# PF COUNTER PARSER  (replaces pflog file parsing)
#===================================
# %%INT_IF%%.log is already displayed live in the Firewall
# UI view — parsing it in TNWatch would be redundant,
# slow on high-traffic networks, and give incomplete data.
#
# Instead we call pfctl which reads kernel counters
# directly: exact totals, near-zero cost (~2ms), no
# file I/O, no tcpdump process spawning.
#
# Two pfctl calls:
#   pfctl -s info     -> packet/block/pass counters + state table
#   pfctl -s Tables   -> active table names (for blocklist counts)

sub parse_pf_counters {
    my ( $self, $state ) = @_;
    my @events;
    my $now = time();
    my %m;

    # Read directly from pfctl -si — same approach as the existing cron script.
    # We do not depend on pf_stats.json so TNWatch is self-contained.
    open( my $fh, '-|', '/sbin/pfctl', '-si' )
      or do { warn "TNWatch: cannot run pfctl -si: $!\n" };
    if ($fh) {
        while (<$fh>) {
            if (/current entries\s+(\d+)/) { $m{current}  = int($1) }
            if (/searches\s+(\d+)/)        { $m{searches} = int($1) }
            if (/inserts\s+(\d+)/)         { $m{inserts}  = int($1) }
            if (/removals\s+(\d+)/)        { $m{removals} = int($1) }
        }
        close $fh;
    }

    # pfctl -s info for status line (Enabled/Disabled)
    open( my $ih, '-|', '/sbin/pfctl', '-s', 'info' )
      or do { warn "TNWatch: cannot run pfctl -s info: $!\n" };
    if ($ih) {
        while (<$ih>) {
            if (/Status:\s+(\S+)/) { $m{status} = $1 }
            if (/Since:\s+(.+)/)   { $m{since}  = $1; $m{since} =~ s/\s+$// }
        }
        close $ih;
    }
    $m{status} //= 'unknown';
    $m{since}  //= '';

    # Delta inserts vs last run for churn rate
    my $prev    = $state->{pf_counters} // {};
    my $elapsed = $now - ( $state->{last_ts} // $now );
    $elapsed = 300 if $elapsed < 1;

    my $d_ins =
      ( $m{inserts} // 0 ) - ( $prev->{inserts} // ( $m{inserts} // 0 ) );
    my $d_rem =
      ( $m{removals} // 0 ) - ( $prev->{removals} // ( $m{removals} // 0 ) );
    $d_ins = 0 if $d_ins < 0;
    $d_rem = 0 if $d_rem < 0;

    my $ins_ps = int( $d_ins / $elapsed );
    my $rem_ps = int( $d_rem / $elapsed );
    my $churn  = $ins_ps - $rem_ps;

    push @events,
      {
        source     => 'pf',
        event_type => 'pf_summary',
        severity   => 'info',
        timestamp  => $now,
        message    => sprintf(
            "PF: %s, %d states, +%d/-%d/s",
            $m{status}, $m{current} // 0,
            $ins_ps,    $rem_ps
        ),
        details => encode_json(
            {
                pf_status   => $m{status},
                pf_since    => $m{since},
                states      => $m{current}  // 0,
                searches    => $m{searches} // 0,
                inserts     => $m{inserts}  // 0,
                removals    => $m{removals} // 0,
                inserts_ps  => $ins_ps,
                removals_ps => $rem_ps,
                churn       => $churn,
            }
        ),
      };

    if ( $d_ins > 500 ) {
        push @events,
          {
            source     => 'pf',
            event_type => 'block_spike',
            severity   => 'warning',
            timestamp  => $now,
            message    =>
              "PF: State insert spike -- $d_ins new states in last interval",
            details => encode_json( { delta_inserts => $d_ins } ),
          };
    }

    return (
        \@events,
        {
            last_ts     => $now,
            last_pos    => 0,
            pf_counters => {
                inserts  => $m{inserts}  // 0,
                removals => $m{removals} // 0,
                searches => $m{searches} // 0,
            },
        }
    );
}

#===================================
# HTTPD LOG PARSER
#===================================
# OpenBSD httpd combined log format:
# IP - - [date] "METHOD URI HTTP/V" STATUS SIZE "ref" "UA"

sub parse_httpd_log {
    my ( $self, $state ) = @_;
    my $logfile = $self->{paths}{httpd};
    my @events;

    die "httpd log not found: $logfile\n" unless -f $logfile;

    open( my $fh, '<', $logfile ) or die "Cannot open $logfile: $!\n";

    # Seek to last position for incremental parsing
    if ( $state->{last_pos} > 0 && $state->{last_pos} <= -s $logfile ) {
        seek( $fh, $state->{last_pos}, 0 );
    }

    while ( my $line = <$fh> ) {
        chomp $line;

# Combined log format
# 203.0.113.1 - - [18/Feb/2026:07:45:23 +0000] "GET /admin HTTP/1.1" 404 512 "-" "curl/7.x"
        next
          unless $line =~
/^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\w+)\s+(\S+)\s+HTTP\/[\d.]+"\s+(\d+)\s+(\d+)/;

        my ( $ip, $date, $method, $uri, $status, $size ) =
          ( $1, $2, $3, $4, $5, $6 );
        my $ts  = _parse_httpd_date($date);
        my $sev = _http_severity($status);
        my $etype =
            $status >= 500 ? '5xx_error'
          : $status >= 400 ? '4xx_error'
          :                  'request';

        next if $etype eq 'request';    # Skip normal traffic

        # Flag suspicious URIs
        my $suspicious = 0;
        $suspicious = 1
          if $uri =~
          m{/(admin|wp-admin|phpmyadmin|\.env|shell|backdoor|eval|base64)}i;
        $sev = 'warning' if $suspicious && $sev eq 'info';

        push @events,
          {
            source     => 'httpd',
            event_type => $etype,
            severity   => $sev,
            timestamp  => $ts,
            src_ip     => $ip,
            message    => "httpd $status: $method $uri from $ip",
            details    => encode_json(
                {
                    method     => $method,
                    uri        => $uri,
                    status     => $status,
                    size       => $size,
                    suspicious => $suspicious,
                }
            ),
          };
    }

    my $new_pos = tell($fh);
    close($fh);

    my $new_state = { last_pos => $new_pos, last_ts => time() };
    return ( \@events, $new_state );
}

sub _http_severity {
    my ($code) = @_;
    return 'critical' if $code >= 500;
    return 'warning'  if $code >= 400;
    return 'info';
}

sub _parse_httpd_date {
    my ($date) = @_;

    # 18/Feb/2026:07:45:23 +0000
    my %months = (
        Jan => 1,
        Feb => 2,
        Mar => 3,
        Apr => 4,
        May => 5,
        Jun => 6,
        Jul => 7,
        Aug => 8,
        Sep => 9,
        Oct => 10,
        Nov => 11,
        Dec => 12
    );
    if ( $date =~ /(\d+)\/(\w+)\/(\d+):(\d+):(\d+):(\d+)/ ) {
        my ( $d, $m, $y, $H, $M, $S ) = ( $1, $2, $3, $4, $5, $6 );
        return mktime( $S, $M, $H, $d, ( $months{$m} // 1 ) - 1, $y - 1900 );
    }
    return time();
}

#===================================
# TNWAF ACCESS LOG PARSER
#===================================
# Format: [timestamp] IP METHOD URI "UA"

sub parse_tnwaf_access {
    my ( $self, $state ) = @_;
    my $logfile = $self->{paths}{tnwaf_access};
    my @events;

    die "TNWAF access log not found: $logfile\n" unless -f $logfile;

    open( my $fh, '<', $logfile ) or die "Cannot open $logfile: $!\n";
    seek( $fh, $state->{last_pos}, 0 )
      if $state->{last_pos} > 0 && $state->{last_pos} <= -s $logfile;

    while ( my $line = <$fh> ) {
        chomp $line;

        # [2026-02-18 07:45:23] 203.0.113.1 GET /path "Mozilla/5.0..."
        next
          unless $line =~ /^\[([^\]]+)\]\s+(\S+)\s+(\w+)\s+(\S+)\s+"([^"]*)"/;
        my ( $ts_str, $ip, $method, $uri, $ua ) = ( $1, $2, $3, $4, $5 );

        my $ts    = _parse_iso_timestamp($ts_str);
        my $sev   = 'info';
        my $etype = 'request';

        # Flag suspicious patterns
        if ( $uri =~
m{<script|javascript:|union\s+select|\.\.\/|/etc/passwd|cmd=|eval\(}i
          )
        {
            $sev   = 'warning';
            $etype = 'suspicious_request';
        }

        push @events,
          {
            source     => 'tnwaf',
            event_type => $etype,
            severity   => $sev,
            timestamp  => $ts,
            src_ip     => $ip,
            message    => "TNWAF: $method $uri from $ip",
            details    =>
              encode_json( { method => $method, uri => $uri, ua => $ua } ),
          };
    }

    my $new_pos = tell($fh);
    close($fh);
    return ( \@events, { last_pos => $new_pos, last_ts => time() } );
}

#===================================
# TNWAF SECURITY LOG PARSER
#===================================

sub parse_tnwaf_security {
    my ( $self, $state ) = @_;
    my $logfile = $self->{paths}{tnwaf_security};
    my @events;

    die "TNWAF security log not found: $logfile\n" unless -f $logfile;

    open( my $fh, '<', $logfile ) or die "Cannot open $logfile: $!\n";
    seek( $fh, $state->{last_pos}, 0 )
      if $state->{last_pos} > 0 && $state->{last_pos} <= -s $logfile;

    while ( my $line = <$fh> ) {
        chomp $line;
        my $ts  = time();
        my $sev = 'warning';
        my $etype;

        if ( $line =~ /rate.?limit/i ) {
            $etype = 'rate_limit';
            $sev   = 'warning';
        }
        elsif ( $line =~ /block/i ) {
            $etype = 'pattern_block';
            $sev   = 'warning';
        }
        elsif ( $line =~ /xss/i ) {
            $etype = 'xss_attempt';
            $sev   = 'critical';
        }
        elsif ( $line =~ /sqli|sql.injection/i ) {
            $etype = 'sqli_attempt';
            $sev   = 'critical';
        }
        else {
            $etype = 'security_event';
        }

        my $src_ip = extract_ip($line);

        push @events,
          {
            source     => 'tnwaf',
            event_type => $etype,
            severity   => $sev,
            timestamp  => $ts,
            src_ip     => $src_ip,
            message    => "TNWAF security: $line",
          };
    }

    my $new_pos = tell($fh);
    close($fh);
    return ( \@events, { last_pos => $new_pos, last_ts => time() } );
}

#===================================
# TNWAF ERROR LOG PARSER
#===================================
# Reads waf/error.log — dedicated WAF error stream written by
# TNWAF.pm error_response() dual logging (separate from httpd_error.log
# which is kept for the UI log viewer).
#
# Format: [timestamp] HTTP CODE STATUS - IP=x.x.x.x URI=/path
# Example: [Mon Feb 24 14:10:57 2026] HTTP 429 Too Many Requests - IP=1.2.3.4 URI=/admin

sub parse_tnwaf_error {
    my ( $self, $state ) = @_;
    my $logfile = $self->{paths}{tnwaf_error};
    my @events;

    die "TNWAF error log not found: $logfile\n" unless -f $logfile;

    open( my $fh, '<', $logfile ) or die "Cannot open $logfile: $!\n";
    seek( $fh, $state->{last_pos}, 0 )
      if $state->{last_pos} > 0 && $state->{last_pos} <= -s $logfile;

    while ( my $line = <$fh> ) {
        chomp $line;

        # [timestamp] HTTP CODE STATUS - IP=x.x.x.x URI=/path
        next
          unless $line =~
          /\[([^\]]+)\]\s+HTTP\s+(\d+)\s+(.*?)\s+-\s+IP=(\S+)\s+URI=(\S+)/;
        my ( $ts_str, $code, $status_text, $ip, $uri ) = ( $1, $2, $3, $4, $5 );

        my $ts = _parse_ctime($ts_str);
        my $etype;
        my $sev;

        if ( $code == 429 ) {
            $etype = 'rate_limit';
            $sev   = 'warning';
        }
        elsif ( $code == 400 ) {
            $etype = 'bad_request';
            $sev   = 'warning';
        }
        elsif ( $code == 403 ) {
            $etype = 'forbidden';
            $sev   = 'warning';
        }
        elsif ( $code == 404 ) {
            $etype = '4xx_error';
            $sev   = 'info';

            # 404s are high volume — skip unless suspicious URI
            next unless $uri =~ m{/admin|\.php|\.env|wp-|shell|eval|passwd}i;
            $sev = 'warning';
        }
        elsif ( $code >= 500 ) {
            $etype = '5xx_error';
            $sev   = 'critical';
        }
        else {
            next;    # Skip other codes (shouldn't appear in error log)
        }

        push @events,
          {
            source     => 'tnwaf',
            event_type => $etype,
            severity   => $sev,
            timestamp  => $ts,
            src_ip     => $ip,
            message    => sprintf(
                "TNWAF %d %s: %s from %s",
                $code, $status_text, $uri, $ip
            ),
            details => encode_json(
                {
                    code   => $code,
                    status => $status_text,
                    uri    => $uri,
                }
            ),
          };
    }

    my $new_pos = tell($fh);
    close($fh);
    return ( \@events, { last_pos => $new_pos, last_ts => time() } );
}

# Parse ctime-style timestamp: Mon Feb 24 14:10:57 2026
sub _parse_ctime {
    my ($ts) = @_;
    my %months = (
        Jan => 1,
        Feb => 2,
        Mar => 3,
        Apr => 4,
        May => 5,
        Jun => 6,
        Jul => 7,
        Aug => 8,
        Sep => 9,
        Oct => 10,
        Nov => 11,
        Dec => 12
    );
    if ( $ts =~ /\w+\s+(\w+)\s+(\d+)\s+(\d+):(\d+):(\d+)\s+(\d+)/ ) {
        my ( $mon, $day, $H, $M, $S, $year ) = ( $1, $2, $3, $4, $5, $6 );
        return mktime( $S, $M, $H, $day, ( $months{$mon} // 1 ) - 1,
            $year - 1900 );
    }
    return time();
}

#===================================
# DAEMON LOG PARSER
#===================================
# Reads /var/www/htdocs/tn/data/logs/system/daemon
# OpenBSD syslog daemon facility — background service messages.
# Disjoint from messages log via syslog.conf:
#   *.notice;daemon,auth,authpriv,cron,ftp,kern,lpr,mail,user.none  messages
# This means daemon facility goes only to daemon log, no overlap.
#
# Signal patterns worth catching:
#   smtpd    — delivery failures, TLS errors, queue problems
#   ntpd     — clock drift, peer unreachable, lost sync
#   dhcpd    — lease exhaustion, interface errors
#   unbound  — upstream SERVFAIL, resolver unreachable
#   pflogd   — lost pflog interface
#   collectd — plugin load errors
#
# Noise suppressed:
#   Normal operational lines (connected, starting, reloading etc.)
#   ntpd routine peer adjustments
#   smtpd normal delivery confirmations

sub parse_daemon {
    my ( $self, $state ) = @_;
    my $logfile = $self->{paths}{daemon};
    my @events;

    die "Daemon log not found: $logfile\n" unless -f $logfile;

    open( my $fh, '<', $logfile ) or die "Cannot open $logfile: $!\n";
    seek( $fh, $state->{last_pos}, 0 )
      if $state->{last_pos} > 0 && $state->{last_pos} <= -s $logfile;

    while ( my $line = <$fh> ) {
        chomp $line;

        # Only process lines with error/failure signal words
        next
          unless $line =~
          /\b(error|err|crit|emerg|alert|panic|fail|failed|failure|
                                  lost\s+sync|unreachable|exhausted|refused|timeout|
                                  cannot|unable|no\s+route|servfail|nxdomain\s+flood)\b/xi;

        # ── Noise suppression ──────────────────────────────────────
        # ntpd routine peer status (very chatty, not actionable)
        next
          if $line =~ /ntpd.*peer\s+\S+\s+(now\s+invalid|constraint|offset)/i;
        next if $line =~ /ntpd.*adjusting/i;

        # smtpd normal delivery (contains word "failed" in bounce reports)
        next if $line =~ /smtpd.*delivery\s+ok/i;
        next if $line =~ /smtpd.*accepted/i;

        # collectd routine plugin stats
        next if $line =~ /collectd.*values?\s+for/i;

        # unbound startup verbosity
        next if $line =~ /unbound.*start/i;

        # dhcpd normal lease activity
        next if $line =~ /dhcpd.*DHCPACK|dhcpd.*DHCPOFFER|dhcpd.*DHCPREQUEST/i;

        my $ts     = _parse_syslog_date($line);
        my $src_ip = extract_ip($line);

        # Severity classification
        my $sev =
          $line =~ /\b(crit|emerg|alert|panic|lost\s+sync)\b/i
          ? 'critical'
          : $line =~ /\b(error|err|fail|failed|failure|unreachable|
                               exhausted|servfail|cannot|unable)\b/xi
          ? 'warning'
          : 'info';

        # Event type by daemon
        my $etype = 'daemon_error';
        $etype = 'smtp_error'     if $line =~ /smtpd/i;
        $etype = 'ntp_error'      if $line =~ /ntpd/i;
        $etype = 'dhcp_error'     if $line =~ /dhcpd/i;
        $etype = 'dns_error'      if $line =~ /unbound/i;
        $etype = 'pflog_error'    if $line =~ /pflogd/i;
        $etype = 'collectd_error' if $line =~ /collectd/i;

        push @events,
          {
            source     => 'daemon',
            event_type => $etype,
            severity   => $sev,
            timestamp  => $ts,
            src_ip     => $src_ip,
            message    => $line,
          };
    }

    my $new_pos = tell($fh);
    close($fh);
    return ( \@events, { last_pos => $new_pos, last_ts => time() } );
}

#===================================
# SERVICES STATUS PARSER
#===================================
# Reads services.json — live status of all monitored services,
# updated every 15 seconds by process_monitor.pl.
#
# Two service types in the JSON:
#   type: standalone  — single process, flat fields
#   type: aggregated  — parent entry (pmacct) with aggregated_metrics
#                       and a subprocesses array
#
# Events emitted:
#   service_down      — critical: standalone not running, OR aggregated
#                       all_running=false and running_count=0
#   service_degraded  — warning:  aggregated all_running=false but
#                       running_count > 0 (partial outage)
#   service_high_mem  — warning:  mem% > MEM_THRESHOLD (default 10%)
#                       Uses total_mem for aggregated services.
#   services_summary  — one per parse cycle (digest + alert engine)
#
# parse_state: services.json is not a sequential log — no byte offset.
# mtime is used as last_ts so an unchanged file on a quiet system does
# not generate duplicate events. On RPi 5 (slow storage) this matters.

use constant MEM_THRESHOLD => 10;    # percent

sub parse_services {
    my ( $self, $state ) = @_;
    my $jsonfile = $self->{paths}{services};
    my @events;

    die "Services JSON not found: $jsonfile\n" unless -f $jsonfile;

    # Skip if file has not changed since last parse
    my $mtime = ( stat($jsonfile) )[9] // 0;
    if ( $state->{last_ts} && $mtime <= $state->{last_ts} ) {
        return ( [], { last_pos => 0, last_ts => $state->{last_ts} } );
    }

    open( my $fh, '<', $jsonfile ) or die "Cannot open $jsonfile: $!\n";
    my $raw = do { local $/; <$fh> };
    close($fh);

    my $data = eval { decode_json($raw) };
    die "Failed to parse services.json: $@\n" if $@;

    my $services = $data->{services} // {};
    my $now      = time();

    my ( @down, @degraded, @high_mem );
    my $total         = 0;
    my $running_count = 0;

    for my $svc_name ( sort keys %$services ) {
        my $svc     = $services->{$svc_name};
        my $type    = lc( $svc->{type}   // 'standalone' );
        my $status  = lc( $svc->{status} // 'unknown' );
        my $display = $svc->{display_name} // $svc_name;

        $total++;

        # ── AGGREGATED service (pmacct etc.) ─────────────────────
        if ( $type eq 'aggregated' ) {
            my $agg   = $svc->{aggregated_metrics} // {};
            my $r_cnt = $agg->{running_count}      // 0;
            my $t_cnt = $agg->{total_count}        // 0;
            my $all   = $agg->{all_running}        // 1;
            my $tmem  = $agg->{total_mem}          // 0;

            if ($all) {
                $running_count++;
            }
            elsif ( $r_cnt == 0 ) {
                push @down, $svc_name;
                push @events,
                  {
                    source     => 'services',
                    event_type => 'service_down',
                    severity   => 'critical',
                    timestamp  => $now,
                    message    =>
                      "Service $display: ALL DOWN ($r_cnt/$t_cnt running)",
                    details => encode_json(
                        {
                            service       => $svc_name,
                            display       => $display,
                            type          => 'aggregated',
                            running_count => $r_cnt,
                            total_count   => $t_cnt,
                            total_mem     => $tmem,
                            total_rss     => $agg->{total_rss} // 0,
                        }
                    ),
                  };
            }
            else {
                # Partial — some subprocesses down
                push @degraded, $svc_name;
                my @failed = grep { lc( $_->{status} // '' ) ne 'running' }
                  @{ $svc->{subprocesses} // [] };
                my @failed_names =
                  map { $_->{display_name} // $_->{key} } @failed;
                push @events,
                  {
                    source     => 'services',
                    event_type => 'service_degraded',
                    severity   => 'warning',
                    timestamp  => $now,
                    message    => sprintf(
                        "Service %s: DEGRADED (%d/%d running) -- down: %s",
                        $display, $r_cnt,
                        $t_cnt,   join( ', ', @failed_names )
                    ),
                    details => encode_json(
                        {
                            service       => $svc_name,
                            display       => $display,
                            type          => 'aggregated',
                            running_count => $r_cnt,
                            total_count   => $t_cnt,
                            failed        => \@failed_names,
                            total_mem     => $tmem,
                            total_rss     => $agg->{total_rss} // 0,
                        }
                    ),
                  };
            }

            # Memory check on aggregate total
            if ( $tmem >= MEM_THRESHOLD ) {
                push @high_mem,
                  { name => $svc_name, display => $display, mem => $tmem };
                push @events,
                  {
                    source     => 'services',
                    event_type => 'service_high_mem',
                    severity   => 'warning',
                    timestamp  => $now,
                    message    => sprintf(
                        "Service %s: high memory %.1f%% (aggregated)",
                        $display, $tmem
                    ),
                    details => encode_json(
                        {
                            service   => $svc_name,
                            display   => $display,
                            mem_pct   => $tmem,
                            total_rss => $agg->{total_rss} // 0,
                            total_vsz => $agg->{total_vsz} // 0,
                        }
                    ),
                  };
            }

            next;
        }

        # ── STANDALONE service ────────────────────────────────────
        my $mem     = $svc->{mem}     // 0;
        my $cpu     = $svc->{cpu}     // '0.0';
        my $pid     = $svc->{pid}     // '-';
        my $rss     = $svc->{rss}     // 0;
        my $vsz     = $svc->{vsz}     // 0;
        my $user    = $svc->{user}    // '?';
        my $command = $svc->{command} // '?';

        if ( $status eq 'running' ) {
            $running_count++;
        }
        else {
            push @down, $svc_name;
            push @events,
              {
                source     => 'services',
                event_type => 'service_down',
                severity   => 'critical',
                timestamp  => $now,
                message    => "Service $display: " . uc($status),
                details    => encode_json(
                    {
                        service => $svc_name,
                        display => $display,
                        status  => $status,
                        pid     => $pid,
                        command => $command,
                        mem_pct => $mem,
                        cpu_pct => $cpu,
                        rss     => $rss,
                        vsz     => $vsz,
                        user    => $user,
                    }
                ),
              };
        }

        # Memory check — standalone
        if ( $mem >= MEM_THRESHOLD ) {
            push @high_mem,
              { name => $svc_name, display => $display, mem => $mem };
            push @events,
              {
                source     => 'services',
                event_type => 'service_high_mem',
                severity   => 'warning',
                timestamp  => $now,
                message    => sprintf(
                    "Service %s: high memory %.1f%% (RSS %s KB)",
                    $display, $mem, $rss
                ),
                details => encode_json(
                    {
                        service => $svc_name,
                        display => $display,
                        mem_pct => $mem,
                        rss     => $rss,
                        vsz     => $vsz,
                        pid     => $pid,
                        user    => $user,
                    }
                ),
              };
        }
    }

    # ── Single summary event per parse cycle ─────────────────────
    # Kept minimal for RPi 5 storage — one row covers the full picture.
    my $down_count     = scalar @down;
    my $degraded_count = scalar @degraded;
    my $summary_sev =
        $down_count     ? 'critical'
      : $degraded_count ? 'warning'
      :                   'info';

    push @events,
      {
        source     => 'services',
        event_type => 'services_summary',
        severity   => $summary_sev,
        timestamp  => $now,
        message    => sprintf(
            "Services: %d/%d running, %d down, %d degraded",
            $running_count, $total, $down_count, $degraded_count
        ),
        details => encode_json(
            {
                total         => $total,
                running       => $running_count,
                down          => $down_count,
                degraded      => $degraded_count,
                down_list     => \@down,
                degraded_list => \@degraded,
                high_mem      => \@high_mem,
            }
        ),
      };

    return ( \@events, { last_pos => 0, last_ts => $mtime } );
}

#===================================
# SNORT ALERT PARSER
#===================================
# Snort fast alert format:
# [**] [1:1000001:1] ET SCAN Possible Nmap SYN Scan [**]
# [Priority: 2]
# 02/18-07:45:23.123456 203.0.113.45:4321 -> 192.168.1.1:22
# TCP TTL:128 TOS:0x0 ID:12345 IpLen:20 DgmLen:44 DF
# ******S* Seq: 0x...  Ack: 0x0  Win: 0x...

sub parse_snort_alert {
    my ( $self, $state ) = @_;
    my $logfile = $self->{paths}{snort};
    my @events;

    die "Snort alert log not found: $logfile\n" unless -f $logfile;

    open( my $fh, '<', $logfile ) or die "Cannot open $logfile: $!\n";
    seek( $fh, $state->{last_pos}, 0 )
      if $state->{last_pos} > 0 && $state->{last_pos} <= -s $logfile;

    my ( $rule_msg, $priority, $src_ip, $dst_ip, $src_port, $dst_port, $proto );
    my $ts = time();

    while ( my $line = <$fh> ) {
        chomp $line;

        if ( $line =~ /\[\*\*\]\s+\[(\d+:\d+:\d+)\]\s+(.*?)\s+\[\*\*\]/ ) {

            # Flush previous alert if any
            if ($rule_msg) {
                push @events,
                  _make_snort_event(
                    $rule_msg, $priority, $src_ip, $dst_ip,
                    $src_port, $dst_port, $proto,  $ts
                  );
            }
            $rule_msg = $2;
            ( $src_ip, $dst_ip, $src_port, $dst_port, $proto, $priority ) =
              (undef) x 6;
            $ts = time();
        }
        elsif ( $line =~ /\[Priority:\s*(\d+)\]/ ) {
            $priority = $1;
        }
        elsif ( $line =~ /^(\d+\/\d+-\d+:\d+:\d+\.\d+)\s+(\S+)\s+->\s+(\S+)/ ) {

            # Parse timestamp and IPs
            ( $src_ip, $src_port ) = _split_ip_port($2);
            ( $dst_ip, $dst_port ) = _split_ip_port($3);
            $ts = _parse_snort_timestamp($1);
        }
        elsif ( $line =~ /^(TCP|UDP|ICMP)\s/ ) {
            $proto = lc $1;
        }
    }

    # Flush last alert
    if ($rule_msg) {
        push @events,
          _make_snort_event(
            $rule_msg, $priority, $src_ip, $dst_ip,
            $src_port, $dst_port, $proto,  $ts
          );
    }

    my $new_pos = tell($fh);
    close($fh);
    return ( \@events, { last_pos => $new_pos, last_ts => time() } );
}

sub _make_snort_event {
    my ( $msg, $priority, $src_ip, $dst_ip, $src_port, $dst_port, $proto, $ts )
      = @_;
    $priority //= 3;

    my $sev =
        $priority == 1 ? 'critical'
      : $priority == 2 ? 'warning'
      :                  'info';

    my $etype =
        $priority == 1 ? 'alert_critical'
      : $priority == 2 ? 'alert_high'
      :                  'alert_low';

    return {
        source     => 'snort',
        event_type => $etype,
        severity   => $sev,
        timestamp  => $ts // time(),
        src_ip     => $src_ip,
        dst_ip     => $dst_ip,
        port       => $dst_port,
        protocol   => $proto,
        message    => "Snort [$sev]: $msg",
        details    => encode_json(
            {
                msg      => $msg,
                priority => $priority,
                src_port => $src_port,
            }
        ),
    };
}

sub _split_ip_port {
    my ($addr) = @_;
    if ( $addr =~ /^([\d.]+):(\d+)$/ ) { return ( $1, $2 ) }
    return ( $addr, undef );
}

sub _parse_snort_timestamp {
    my ($ts_str) = @_;

    # 02/18-07:45:23.123456
    if ( $ts_str =~ /(\d+)\/(\d+)-(\d+):(\d+):(\d+)/ ) {
        my ( $mon, $day, $H, $M, $S ) = ( $1, $2, $3, $4, $5 );
        my $year = (localtime)[5] + 1900;
        return mktime( $S, $M, $H, $day, $mon - 1, $year - 1900 );
    }
    return time();
}

#===================================
# E2GUARDIAN PARSER
#===================================

sub parse_e2guardian {
    my ( $self, $state ) = @_;
    my $logfile = $self->{paths}{e2guardian};
    my @events;

    die "E2Guardian log not found: $logfile\n" unless -f $logfile;

    open( my $fh, '<', $logfile ) or die "Cannot open $logfile: $!\n";
    seek( $fh, $state->{last_pos}, 0 )
      if $state->{last_pos} > 0 && $state->{last_pos} <= -s $logfile;

    while ( my $line = <$fh> ) {
        chomp $line;

     # E2Guardian access log: date time IP URL status category
     # 2026.02.18 07:45:23 192.168.1.5 http://malware.example.com DENIED malware
        next unless $line =~ /^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\w+)\s*(.*)$/;
        my ( $date, $time_str, $ip, $url, $action, $category ) =
          ( $1, $2, $3, $4, $5, $6 );

        next unless $action =~ /DENIED|BLOCKED/i;

        my $ts = _parse_e2guardian_date( $date, $time_str );
        my $sev =
          ( $category =~ /malware|phish|virus/i ) ? 'critical' : 'warning';

        push @events,
          {
            source     => 'e2guardian',
            event_type => 'blocked_domain',
            severity   => $sev,
            timestamp  => $ts,
            src_ip     => $ip,
            message    => "E2Guardian blocked $ip -> $url ($category)",
            details    => encode_json(
                { url => $url, category => $category, action => $action }
            ),
          };
    }

    my $new_pos = tell($fh);
    close($fh);
    return ( \@events, { last_pos => $new_pos, last_ts => time() } );
}

sub _parse_e2guardian_date {
    my ( $date, $time_str ) = @_;

    # 2026.02.18 07:45:23
    if (   $date =~ /(\d{4})\.(\d{2})\.(\d{2})/
        && $time_str =~ /(\d{2}):(\d{2}):(\d{2})/ )
    {
        return mktime( $6, $5, $4, $3, $2 - 1, $1 - 1900 );
    }
    return time();
}

#===================================
# UNBOUND PARSER
#===================================

sub parse_unbound {
    my ( $self, $state ) = @_;
    my $logfile = $self->{paths}{unbound};
    my @events;

    die "Unbound log not found: $logfile\n" unless -f $logfile;

    open( my $fh, '<', $logfile ) or die "Cannot open $logfile: $!\n";
    seek( $fh, $state->{last_pos}, 0 )
      if $state->{last_pos} > 0 && $state->{last_pos} <= -s $logfile;

    while ( my $line = <$fh> ) {
        chomp $line;

      # unbound[pid:0] info: 192.168.1.5 malware.example.com. NOERROR 1.234 0 84
      # We care about NXDOMAIN and info-level queries to suspicious domains
        next unless $line =~ /NXDOMAIN|REFUSED|error/i;

        my $ts     = time();
        my $sev    = 'info';
        my $etype  = 'nxdomain';
        my $src_ip = extract_ip($line);
        my $domain;

        if ( $line =~ /(\S+)\.\s+(?:NXDOMAIN|REFUSED)/ ) {
            $domain = $1;
        }

        $sev   = 'warning'     if $line =~ /REFUSED/i;
        $etype = 'dns_refused' if $line =~ /REFUSED/i;

        push @events,
          {
            source     => 'unbound',
            event_type => $etype,
            severity   => $sev,
            timestamp  => $ts,
            src_ip     => $src_ip,
            message    => "Unbound: $line",
            details    => encode_json( { domain => $domain } ),
          };
    }

    my $new_pos = tell($fh);
    close($fh);
    return ( \@events, { last_pos => $new_pos, last_ts => time() } );
}

#===================================
# SYSLOG PARSER
#===================================

sub parse_syslog {
    my ( $self, $state ) = @_;
    my $logfile = $self->{paths}{syslog};
    my @events;

    die "Syslog not found: $logfile\n" unless -f $logfile;

    open( my $fh, '<', $logfile ) or die "Cannot open $logfile: $!\n";
    seek( $fh, $state->{last_pos}, 0 )
      if $state->{last_pos} > 0 && $state->{last_pos} <= -s $logfile;

    while ( my $line = <$fh> ) {
        chomp $line;

        # Feb 18 07:45:23 hostname daemon[pid]: message
        next unless $line =~ /\b(error|crit|emerg|alert|panic|fail)\b/i;

        # Skip known noisy/harmless patterns.
        # NOTE: the original pattern had a trailing | which created an empty
        # alternation matching every line — fixed here.
        next if $line =~ /motd|prelogin/i;

        # Skip integrity runner housekeeping lines. These appear in syslog
        # if integrity_check.sh or TNAudit.pl use logger(1), and they contain
        # words like 'error' or 'fail' in normal operational messages
        # (e.g. "No requests - exit", "TNAudit.pl exit code: 0").
        next if $line =~ /integrity.runner/i;
        next if $line =~ /TNAudit\.pl/i;
        next if $line =~ /integrity_check\.sh/i;
        next if $line =~ /Processing:\s+request-/i;
        next if $line =~ /Found\s+\d+\s+request/i;
        next if $line =~ /Action=(?:verify|baseline|update)/i;
        next if $line =~ /SUCCESS:\s+Created\s+out-/i;
        next if $line =~ /Removed\s+request\s+file/i;
        next if $line =~ /Integrity\s+runner\s+(?:started|completed)/i;

        my $ts = _parse_syslog_date($line);
        my $sev =
            $line =~ /\b(crit|emerg|alert|panic)\b/i ? 'critical'
          : $line =~ /\berror\b/i                    ? 'warning'
          :                                            'info';

        my $src_ip = extract_ip($line);

        push @events,
          {
            source     => 'syslog',
            event_type => 'daemon_error',
            severity   => $sev,
            timestamp  => $ts,
            src_ip     => $src_ip,
            message    => $line,
          };
    }

    my $new_pos = tell($fh);
    close($fh);
    return ( \@events, { last_pos => $new_pos, last_ts => time() } );
}

#===================================
# AUTHLOG PARSER
#===================================

sub parse_authlog {
    my ( $self, $state ) = @_;
    my $logfile = $self->{paths}{authlog};
    my @events;

    die "authlog not found: $logfile\n" unless -f $logfile;

    open( my $fh, '<', $logfile ) or die "Cannot open $logfile: $!\n";
    seek( $fh, $state->{last_pos}, 0 )
      if $state->{last_pos} > 0 && $state->{last_pos} <= -s $logfile;

    while ( my $line = <$fh> ) {
        chomp $line;
        my $ts     = _parse_syslog_date($line);
        my $src_ip = extract_ip($line);
        my ( $etype, $sev, $msg );

        # SSH failures
        if ( $line =~ /Failed password for (\S+) from (\S+)/ ) {
            my ( $user, $ip ) = ( $1, $2 );
            $etype  = 'auth_failure';
            $sev    = 'warning';
            $src_ip = $ip;
            $msg    = "SSH auth failure: user '$user' from $ip";
        }

        # Invalid user
        elsif ( $line =~ /Invalid user (\S+) from (\S+)/ ) {
            my ( $user, $ip ) = ( $1, $2 );
            $etype  = 'auth_failure';
            $sev    = 'warning';
            $src_ip = $ip;
            $msg    = "SSH invalid user '$user' from $ip";
        }

        # Root login attempt
        elsif ( $line =~ /ROOT LOGIN REFUSED|login_refused.*root/i ) {
            $etype = 'root_login_attempt';
            $sev   = 'critical';
            $msg   = "Root login refused: $line";
        }

        # Doas usage
        elsif ( $line =~ /doas:\s+(\S+)\s+ran\s+(.+)\s+as\s+(\S+)/ ) {
            my ( $user, $cmd, $as ) = ( $1, $2, $3 );
            $etype = 'doas_exec';
            $sev   = 'info';
            $msg   = "doas: $user ran '$cmd' as $as";
        }

        # Accepted auth
        elsif ( $line =~ /Accepted (password|publickey) for (\S+) from (\S+)/ )
        {
            my ( $method, $user, $ip ) = ( $1, $2, $3 );
            $etype  = 'auth_success';
            $sev    = 'info';
            $src_ip = $ip;
            $msg    = "SSH login: $user from $ip via $method";
        }

        # Disconnected
        elsif ( $line =~ /Disconnected from|Connection closed/ ) {
            next;    # Too noisy, skip
        }
        else {
            next;    # Skip unrecognized auth lines
        }

        push @events,
          {
            source     => 'authlog',
            event_type => $etype,
            severity   => $sev,
            timestamp  => $ts,
            src_ip     => $src_ip,
            message    => $msg // $line,
          };
    }

    my $new_pos = tell($fh);
    close($fh);
    return ( \@events, { last_pos => $new_pos, last_ts => time() } );
}

#===================================
# SHARED HELPERS
#===================================

sub classify_severity {
    my ( $source, $event_type, $count, $threshold ) = @_;
    return 'critical' if $count >= $threshold * 3;
    return 'warning'  if $count >= $threshold;
    return 'info';
}

sub extract_ip {
    my ($text) = @_;
    return $1 if $text =~ /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/;
    return undef;
}

sub extract_ips {
    my ($text) = @_;
    my @ips = ( $text =~ /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g );
    return @ips;
}

sub _parse_syslog_date {
    my ($line) = @_;

    # Feb 18 07:45:23
    my %months = (
        Jan => 1,
        Feb => 2,
        Mar => 3,
        Apr => 4,
        May => 5,
        Jun => 6,
        Jul => 7,
        Aug => 8,
        Sep => 9,
        Oct => 10,
        Nov => 11,
        Dec => 12
    );
    if ( $line =~ /^(\w{3})\s+(\d+)\s+(\d+):(\d+):(\d+)/ ) {
        my ( $mon, $day, $H, $M, $S ) = ( $1, $2, $3, $4, $5 );
        my $year  = (localtime)[5] + 1900;
        my $mon_n = ( $months{$mon} // 1 ) - 1;
        return mktime( $S, $M, $H, $day, $mon_n, $year - 1900 );
    }
    return time();
}

sub _parse_iso_timestamp {
    my ($ts_str) = @_;

    # 2026-02-18 07:45:23
    if ( $ts_str =~ /(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})/ ) {
        return mktime( $6, $5, $4, $3, $2 - 1, $1 - 1900 );
    }
    return time();
}

1;

__END__

=head1 NAME

TNWatchParser - Log parsing engine for TNWatch

=head1 SYNOPSIS

    use TNWatchParser;

    my $parser = TNWatchParser->new(verbose => 1);

    # Parse single source, incrementally
    my $state = $db->get_parse_state('authlog');
    my ($events, $new_state) = $parser->parse('authlog', $state);
    $db->insert_events_bulk(@$events);
    $db->update_parse_state('authlog', %$new_state);

    # Parse everything
    my $results = $parser->parse_all(\%states);

=head1 SUPPORTED SOURCES

tnaudit, pf, httpd, tnwaf_access, tnwaf_security, tnwaf_error,
snort, e2guardian, unbound, syslog, daemon, authlog, services

=head1 RETENTION

RPi 5 deployment: purge events older than 7 days.
Cron entry in TNWatch.pl should read:
  0  2  *  *  *  root  TNWatch.pl --purge --days 7

=cut
