#!/usr/bin/perl -T

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

use strict;
use warnings;
use FindBin qw($RealBin);
use File::Spec;

BEGIN {
    my $lib_path =
      File::Spec->catdir( $RealBin, File::Spec->updir, 'data', 'lib' );

    unless ( File::Spec->file_name_is_absolute($lib_path) ) {
        $lib_path = File::Spec->rel2abs($lib_path);
    }

    if ( $lib_path =~ m{^([-/\w.]+)$} ) {
        unshift @INC, $1;
    }
    else {
        die "FATAL: Invalid lib path\n";
    }
}

use TNEnv;
use TNSecurityCheck;

# Security check
my $session = security_check('standard');

# Now load other modules
use CGI;
use JSON;
use POSIX qw(strftime mktime);
use File::Basename;
use Fcntl qw(:flock);

# Clean environment (TNEnv does this, but keeping for safety)
$ENV{'PATH'} = '/bin:/usr/bin:/usr/local/bin';
delete @ENV{qw(IFS CDPATH ENV BASH_ENV)};

# Script directory -- dirname(__FILE__) is safe and chroot-compatible.
# abs_path() is intentionally avoided here: it calls realpath(2) which
# can return undef inside a chroot when the real-root path is invisible.
# Other CGI scripts in this suite use the same pattern.
my $script_dir = dirname(__FILE__);
if ( $script_dir =~ m{^([-/\w.]+)$} ) {
    $script_dir = $1;
}
else {
    die "FATAL: Invalid script_dir\n";
}

# Base log directory -- relative path with '..' as in all other CGI scripts.
my $LOG_BASE_DIR = File::Spec->catfile( $script_dir, '..', 'data', 'logs' );
my $ROTATION_STAMP =
  File::Spec->catfile( $LOG_BASE_DIR, 'bootlog', '.rotation_stamp' );
my $ROTATION_META = File::Spec->catfile( $LOG_BASE_DIR, '.rotation_meta' );

# Untaint constructed paths -- only literal segments were used, no user input.
for ( $LOG_BASE_DIR, $ROTATION_STAMP, $ROTATION_META ) {
    if (m{^([-/\w.]+)$}) { $_ = $1 }
    else                 { die "FATAL: Invalid log path\n" }
}

# Debug log -- date-stamped, one file per day, written to /tmp
# (which is /tmp inside the httpd chroot).
my $LOG_DATE = strftime( "%Y-%m-%d", localtime );
my $LOG_FILE = "/tmp/log_ui-${LOG_DATE}.log";

# ============================================================================
# LOG SOURCE CONFIGURATION
# ============================================================================

my %LOG_CONFIG = (
    'system/messages' => {
        live_path       => File::Spec->catfile( 'system', 'messages' ),
        archive_pattern =>
          File::Spec->catfile( 'system', 'messages_{date}.log' ),
        type            => 'live',
        limit           => 100,
        default_filter  => 'all',
        filter_flowbits => 1
    },
    'system/daemon' => {
        live_path       => File::Spec->catfile( 'system', 'daemon' ),
        archive_pattern => File::Spec->catfile( 'system', 'daemon_{date}.log' ),
        type            => 'live',
        limit           => 100,
        default_filter  => 'all',
        filter_flowbits => 1
    },
    'bootlog/rc.local.log' => {
        live_path       => File::Spec->catfile( 'bootlog', 'rc.local.log' ),
        archive_pattern =>
          File::Spec->catfile( 'bootlog', 'rc.local_{date}.log' ),
        type           => 'boot',
        limit          => 0,
        default_filter => 'all'
    },
    'doas/doas.log' => {
        live_path       => File::Spec->catfile( 'doas', 'doas.log' ),
        archive_pattern => File::Spec->catfile( 'doas', 'doas_{date}.log' ),
        type            => 'live',
        limit           => 100,
        default_filter  => 'all'
    },
    'dhcpd/dhcpd.log' => {
        live_path       => File::Spec->catfile( 'dhcpd', 'dhcpd.log' ),
        archive_pattern => File::Spec->catfile( 'dhcpd', 'dhcpd_{date}.log' ),
        type            => 'live',
        limit           => 100,
        default_filter  => 'all'
    },
    'unbound/unbound.log' => {
        live_path       => File::Spec->catfile( 'unbound', 'unbound.log' ),
        archive_pattern =>
          File::Spec->catfile( 'unbound', 'unbound_{date}.log' ),
        type           => 'live',
        limit          => 100,
        default_filter => 'all'
    },
    'rad/rad.log' => {
        live_path       => File::Spec->catfile( 'rad', 'rad.log' ),
        archive_pattern => File::Spec->catfile( 'rad', 'rad_{date}.log' ),
        type            => 'live',
        limit           => 100,
        default_filter  => 'all'
    },
    'collectd/collectd.log' => {
        live_path       => File::Spec->catfile( 'collectd', 'collectd.log' ),
        archive_pattern =>
          File::Spec->catfile( 'collectd', 'collectd_{date}.log' ),
        type           => 'live',
        limit          => 100,
        default_filter => 'all'
    },
    'sslproxy/sslproxy.log' => {
        live_path       => File::Spec->catfile( 'sslproxy', 'sslproxy.log' ),
        archive_pattern =>
          File::Spec->catfile( 'sslproxy', 'sslproxy_{date}.log' ),
        type           => 'live',
        limit          => 100,
        default_filter => 'all'
    },
    'sslproxy/sslproxy_connect.log' => {
        live_path => File::Spec->catfile( 'sslproxy', 'sslproxy_connect.log' ),
        archive_pattern =>
          File::Spec->catfile( 'sslproxy', 'sslproxy_connect_{date}.log' ),
        type           => 'live',
        limit          => 100,
        default_filter => 'all'
    },
    'sockd/sockd.log' => {
        live_path       => File::Spec->catfile( 'sockd', 'sockd.log' ),
        archive_pattern => File::Spec->catfile( 'sockd', 'sockd_{date}.log' ),
        type            => 'live',
        limit           => 100,
        default_filter  => 'all'
    },
    'p3scan/p3scan.log' => {
        live_path       => File::Spec->catfile( 'p3scan', 'p3scan.log' ),
        archive_pattern => File::Spec->catfile( 'p3scan', 'p3scan_{date}.log' ),
        type            => 'live',
        limit           => 100,
        default_filter  => 'all'
    },
    'smtp-gated/smtp-gated.log' => {
        live_path => File::Spec->catfile( 'smtp-gated', 'smtp-gated.log' ),
        archive_pattern =>
          File::Spec->catfile( 'smtp-gated', 'smtp-gated_{date}.log' ),
        type           => 'live',
        limit          => 100,
        default_filter => 'all'
    },
    'spamd/spamd.log' => {
        live_path       => File::Spec->catfile( 'spamd', 'spamd.log' ),
        archive_pattern => File::Spec->catfile( 'spamd', 'spamd_{date}.log' ),
        type            => 'live',
        limit           => 100,
        default_filter  => 'all'
    },
    'snort/alert.log' => {
        live_path       => File::Spec->catfile( 'snort', 'alert.log' ),
        archive_pattern => File::Spec->catfile( 'snort', 'alert_{date}.log' ),
        type            => 'live',
        limit           => 100,
        default_filter  => 'all'
    },
    'snort/snort.log' => {
        live_path       => File::Spec->catfile( 'snort', 'snort.log' ),
        archive_pattern => File::Spec->catfile( 'snort', 'snort_{date}.log' ),
        type            => 'live',
        limit           => 100,
        default_filter  => 'all',
        filter_flowbits => 1
    },
    'snort/snortinline.log' => {
        live_path       => File::Spec->catfile( 'snort', 'snortinline.log' ),
        archive_pattern =>
          File::Spec->catfile( 'snort', 'snortinline_{date}.log' ),
        type            => 'live',
        limit           => 100,
        default_filter  => 'all',
        filter_flowbits => 1
    },
    'snortsentry/snortsentry.log' => {
        live_path => File::Spec->catfile( 'snortsentry', 'snortsentry.log' ),
        archive_pattern =>
          File::Spec->catfile( 'snortsentry', 'snortsentry_{date}.log' ),
        type           => 'live',
        limit          => 100,
        default_filter => 'all'
    },
    'e2guardian/access.log' => {
        live_path       => File::Spec->catfile( 'e2guardian', 'access.log' ),
        archive_pattern =>
          File::Spec->catfile( 'e2guardian', 'access_{date}.log' ),
        type           => 'live',
        limit          => 100,
        default_filter => 'all'
    },
    'e2guardian/e2guardian.log' => {
        live_path => File::Spec->catfile( 'e2guardian', 'e2guardian.log' ),
        archive_pattern =>
          File::Spec->catfile( 'e2guardian', 'e2guardian_{date}.log' ),
        type           => 'live',
        limit          => 100,
        default_filter => 'all'
    },
    'httpd/httpd_access.log' => {
        live_path       => File::Spec->catfile( 'httpd', 'httpd_access.log' ),
        archive_pattern =>
          File::Spec->catfile( 'httpd', 'httpd_access_{date}.log' ),
        type           => 'live',
        limit          => 100,
        default_filter => 'all'
    },
    'httpd/httpd_error.log' => {
        live_path       => File::Spec->catfile( 'httpd', 'httpd_error.log' ),
        archive_pattern =>
          File::Spec->catfile( 'httpd', 'httpd_error_{date}.log' ),
        type           => 'live',
        limit          => 100,
        default_filter => 'all'
    },
    'imspector/imspector.log' => {
        live_path       => File::Spec->catfile( 'imspector', 'imspector.log' ),
        archive_pattern =>
          File::Spec->catfile( 'imspector', 'imspector_{date}.log' ),
        type           => 'live',
        limit          => 100,
        default_filter => 'all'
    },
    'ftp-proxy/ftp-proxy.log' => {
        live_path       => File::Spec->catfile( 'ftp-proxy', 'ftp-proxy.log' ),
        archive_pattern =>
          File::Spec->catfile( 'ftp-proxy', 'ftp-proxy_{date}.log' ),
        type           => 'live',
        limit          => 100,
        default_filter => 'all'
    },
);

# ============================================================================
# CGI HEADER -- emitted before pledge so stdio is established
# ============================================================================

my $q = CGI->new;
print $q->header( '-type' => 'application/json', '-charset' => 'utf-8' );

# ============================================================================
# PLEDGE / UNVEIL
# Plain Perl open() throughout -- no fork, no exec, no external processes.
# stdio : JSON response output
# rpath : log files, config, keys, db (session check via TNSecurityCheck)
# wpath + cpath + flock : debug log in /tmp
# ============================================================================
{
    my $app_root = $script_dir;
    $app_root =~ s{/cgi-bin$}{};
    $app_root =~ s{^/var/www}{};

    eval {
        if ( eval { require OpenBSD::Unveil; 1 } ) {
            OpenBSD::Unveil::unveil( "$app_root/data/lib", "r" )
              or die "unveil data/lib: $!";
            OpenBSD::Unveil::unveil( "$app_root/data/config", "r" )
              or die "unveil data/config: $!";
            OpenBSD::Unveil::unveil( "$app_root/data/keys", "r" )
              or die "unveil data/keys: $!";
            OpenBSD::Unveil::unveil( "$app_root/data/db", "r" )
              or die "unveil data/db: $!";
            OpenBSD::Unveil::unveil( "$app_root/data/logs", "r" )
              or die "unveil data/logs: $!";
            OpenBSD::Unveil::unveil( "/tmp", "rwc" ) or die "unveil tmp: $!";
            OpenBSD::Unveil::unveil()                or die "unveil lock: $!";
        }
        if ( eval { require OpenBSD::Pledge; 1 } ) {
            OpenBSD::Pledge::pledge("stdio rpath wpath cpath flock")
              or die "pledge: $!";
        }
    };
    if ($@) {
        write_log( 'ERROR', "sandbox_init_failed: $@" );
        print encode_json(
            { success => 0, message => "sandbox_init_failed", detail => "$@" }
        );
        exit;
    }
}

# ============================================================================
# ROUTER
# ============================================================================

my $action = $q->param('action') || 'fetch';
$action = ( $action =~ /^(available_dates|fetch)$/ ) ? $1 : '';

if ( $action eq 'available_dates' ) {
    handle_available_dates();
}
elsif ( $action eq 'fetch' ) {
    handle_fetch_logs();
}
else {
    error_exit("Unknown action");
}

# ============================================================================
# LOGGING HELPER  (mirrors firewall.pl write_log pattern)
# ============================================================================
sub write_log {
    my ( $level, $msg ) = @_;
    my $timestamp = strftime( "%Y-%m-%d %H:%M:%S", localtime );
    if ( open( my $fh, '>>', $LOG_FILE ) ) {
        flock( $fh, LOCK_EX );
        print $fh "[$timestamp] [$level] $msg\n";
        close $fh;
    }
}

# ============================================================================
# ENDPOINT: Available Dates
# Returns list of dates with archives (7 days), rotation metadata, gaps.
# The 'date' field in each entry is a YYYY-MM-DD string -- this is what the
# JS stores in option.value and sends back as the 'date' CGI parameter.
# ============================================================================
sub handle_available_dates {
    my $raw_source = $q->param('source') || 'system/messages';
    my $source;

    if ( exists $LOG_CONFIG{$raw_source} ) {
        $source = $raw_source;
    }
    else {
        write_log( 'WARN', "available_dates: unknown source '$raw_source'" );
        error_exit("Log source not in inventory");
    }

    my $config        = $LOG_CONFIG{$source};
    my @available     = ();
    my @gaps          = ();
    my %meta          = ();
    my $last_rotation = undef;

    # Read rotation metadata
    if ( -f $ROTATION_META ) {
        %meta          = read_metadata();
        $last_rotation = $meta{LAST_ROTATION} || undef;
    }

    # Fallback: stamp file
    if ( !defined $last_rotation && -f $ROTATION_STAMP ) {
        if ( open( my $fh, '<', $ROTATION_STAMP ) ) {
            $last_rotation = <$fh>;
            chomp($last_rotation) if defined $last_rotation;
            close($fh);
        }
    }

    # Scan last 7 completed days (days_ago 1..7).
    # Day 0 (today) is excluded: today's archive is never complete until
    # rotation runs tonight, so it would always appear as a gap.
    # Live logs cover today's data via the 'live' option.
    my $now = time;
    for ( my $days_ago = 1 ; $days_ago <= 7 ; $days_ago++ ) {
        my $target_time = $now - ( $days_ago * 86400 );
        my $date_str    = strftime( "%Y-%m-%d", localtime($target_time) );

        my $archive_path = $config->{archive_pattern};
        $archive_path =~ s/\{date\}/$date_str/g;
        my $full_path = File::Spec->catfile( $LOG_BASE_DIR, $archive_path );

        if ( -f $full_path ) {
            my $size = -s $full_path;
            push @available,
              {
                date   => $date_str,
                size   => $size,
                exists => 1
              };
        }
        else {
            # Classify the gap reason
            my $reason = 'missing_archive';

            if ( defined $last_rotation && $date_str gt $last_rotation ) {
                $reason = 'system_offline';
            }
            elsif ( check_skipped_empty( $source, $date_str, \%meta ) ) {
                $reason = 'empty_not_rotated';
            }

            push @gaps,
              {
                date   => $date_str,
                reason => $reason
              };
        }
    }

    my @consolidated_gaps = consolidate_gaps( \@gaps );
    my $live_path = File::Spec->catfile( $LOG_BASE_DIR, $config->{live_path} );

    write_log( 'DEBUG',
            "available_dates: source=$source found="
          . scalar(@available)
          . " gaps="
          . scalar(@gaps) );

    print encode_json(
        {
            success         => 1,
            source          => $source,
            available_dates => \@available,
            gaps            => \@gaps,
            gap_ranges      => \@consolidated_gaps,
            last_rotation   => $last_rotation,
            metadata        => \%meta,
            live_available  => ( -f $live_path ) ? 1 : 0
        }
    );
    exit;
}

# ============================================================================
# ENDPOINT: Fetch Logs
# Pure Perl open() -- no backticks, no external processes.
# 'date' param is either the string 'live' or a YYYY-MM-DD date string.
# ============================================================================
sub handle_fetch_logs {
    my $raw_source = $q->param('source') || 'system/messages';
    my $source;
    if ( exists $LOG_CONFIG{$raw_source} ) {
        $source = $raw_source;
    }
    else {
        write_log( 'WARN', "fetch: unknown source '$raw_source'" );
        error_exit("Log source not in inventory");
    }

    # --- Date parameter ---
    # Accepted values:
    #   'live'        -- read the live (current) log file
    #   'YYYY-MM-DD'  -- read the rotated archive for that date
    # Using defined + length guards avoids the Perl falsy-zero trap that
    # affected the old numeric-offset design.
    my $raw_date = $q->param('date');
    my $date;
    if ( !defined $raw_date || !length($raw_date) || $raw_date eq 'live' ) {
        $date = 'live';
    }
    elsif ( $raw_date =~ /^(\d{4}-\d{2}-\d{2})$/ ) {
        $date = $1;    # untainted YYYY-MM-DD
    }
    else {
        write_log( 'WARN', "fetch: invalid date param '$raw_date'" );
        error_exit("Invalid date parameter");
    }

    # --- Filter parameter ---
    my $config     = $LOG_CONFIG{$source};
    my $raw_filter = $q->param('filter');
    my $filter;
    if (   !defined $raw_filter
        || !length($raw_filter)
        || $raw_filter eq 'default' )
    {
        $filter = $config->{default_filter} || 'all';
    }
    elsif ( $raw_filter =~ /^(all|error|warning|auth|connection|blocked)$/ ) {
        $filter = $1;
    }
    else {
        $filter = 'all';
    }

    # --- Resolve file path ---
    my $file_path;

    if ( $date eq 'live' ) {
        $file_path = File::Spec->catfile( $LOG_BASE_DIR, $config->{live_path} );
    }
    else {
        # Validate the date is not in the future
        my ( $y, $m, $d ) = split( /-/, $date );
        my $requested_epoch = mktime( 0, 0, 0, $d, $m - 1, $y - 1900 );
        my $today_epoch     = do {
            my @t = localtime;
            mktime( 0, 0, 0, $t[3], $t[4], $t[5] );
        };
        if ( $requested_epoch > $today_epoch ) {
            write_log( 'WARN', "fetch: future date requested '$date'" );
            print encode_json(
                {
                    success    => 0,
                    error_type => 'future_date',
                    message    => "Cannot access logs from a future date",
                    details    => { requested_date => $date },
                    meta       => { source => $source, type => $config->{type} }
                }
            );
            exit;
        }

        my $archive_path = $config->{archive_pattern};
        $archive_path =~ s/\{date\}/$date/g;
        $file_path = File::Spec->catfile( $LOG_BASE_DIR, $archive_path );
    }

    # Untaint the resolved path -- it is constructed entirely from validated
    # segments so this is a formality for taint mode, not a security gate.
    if ( $file_path =~ m{^([-/\w.]+)$} ) {
        $file_path = $1;
    }
    else {
        write_log( 'ERROR',
            "fetch: path contains unexpected characters: $file_path" );
        error_exit("Internal path error");
    }

    write_log( 'DEBUG',
        "fetch: source=$source date=$date file=$file_path filter=$filter" );

    # --- File existence ---
    if ( !-e $file_path ) {
        write_log( 'DEBUG', "fetch: file not found: $file_path" );
        return smart_error_response( $source, $date, $config, $file_path );
    }

    # --- Empty file ---
    my $file_size = -s $file_path;
    if ( $file_size == 0 ) {
        write_log( 'DEBUG', "fetch: file is empty: $file_path" );
        print encode_json(
            {
                success    => 1,
                logs       => [],
                empty_file => 1,
                message    => "Log file is empty (0 bytes)",
                meta       => {
                    source     => $source,
                    type       => $config->{type},
                    file       => basename($file_path),
                    count      => 0,
                    size       => 0,
                    quiet_mode => $config->{quiet_mode},
                    filter     => $filter
                }
            }
        );
        exit;
    }

 # --- Read file with pure Perl open() ---
 # Live logs  : read all lines, then keep the last $line_limit (tail behaviour).
 # Archive logs: read all lines, keep the first $line_limit (head behaviour —
 #               rotation reverses the file so newest lines are at the top).
 # Boot logs (limit 0): keep all lines.
 #
 # Using open() instead of backtick tail/head/cat:
 #   - No exec pledge required
 #   - No shell metacharacter risk
 #   - Works identically regardless of which binaries are in the chroot
    my $line_limit = $config->{limit};    # 0 means unlimited
    my $log_type   = $config->{type};

    my @raw_lines;
    if ( open( my $fh, '<', $file_path ) ) {
        @raw_lines = <$fh>;
        close($fh);
    }
    else {
        write_log( 'ERROR', "fetch: cannot open '$file_path': $!" );
        error_exit("Cannot open log file");
    }

    my $total_lines = scalar(@raw_lines);

    # Apply line limit
    if ( $line_limit > 0 ) {
        if ( $date eq 'live' ) {

            # Live: newest at bottom -- take last N
            if ( $total_lines > $line_limit ) {
                @raw_lines = @raw_lines[ ( $total_lines - $line_limit )
                  .. ( $total_lines - 1 ) ];
            }
        }
        else {
            # Archive: newest at top after rotation -- take first N
            if ( $total_lines > $line_limit ) {
                @raw_lines = @raw_lines[ 0 .. ( $line_limit - 1 ) ];
            }
        }
    }

    # --- Process lines ---
    my @logs;
    foreach my $line_text (@raw_lines) {
        chomp($line_text);
        next if $line_text =~ /^\s*$/;

        # Filter snort flowbits noise
        if ( $config->{filter_flowbits} ) {
            next if $line_text =~ /flowbits key/i;
            next if $line_text =~ /WARNING.*flowbits/i;
            next if $line_text =~ /\bsnort\[\d+\]:/;
        }

        # Server-side filter (reduces payload for mobile clients)
        if ( $filter eq 'error' ) {
            next unless $line_text =~ /error|fail|denied|critical/i;
        }
        elsif ( $filter eq 'warning' ) {
            next unless $line_text =~ /warn|error|fail|denied|critical/i;
        }
        elsif ( $filter eq 'auth' ) {
            next unless $line_text =~ /login|auth|session|password|doas/i;
        }
        elsif ( $filter eq 'blocked' ) {
            next unless $line_text =~ /block|deny|reject/i;
        }
        elsif ( $filter eq 'connection' ) {
            next unless $line_text =~ /connect|accept|established/i;
        }

        # Timestamp extraction
        my ( $timestamp, $service ) = ( '', '' );

        if ( $line_text =~
            /^\[(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\]\s+([A-Z\-]+):/ )
        {
            # Format 1: [YYYY-MM-DD HH:MM:SS] SERVICE:
            $timestamp = $1;
            $service   = $2;
        }
        elsif ( $line_text =~ /^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})/ ) {

            # Format 2: Standard syslog (Mon DD HH:MM:SS)
            $timestamp = $1;
        }
        elsif ( $line_text =~
            /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2})/ )
        {
            # Format 3: ISO 8601 with timezone
            $timestamp = $1;
        }

        # Log level classification
        my $level = 'info';
        if ( $line_text =~ /\[ERROR\]|error|fail|critical|denied/i ) {
            $level = 'error';
        }
        elsif ( $line_text =~ /\[WARN\]|warn/i ) {
            $level = 'warning';
        }

        push @logs,
          {
            text      => $line_text,
            timestamp => $timestamp,
            service   => $service,
            level     => $level
          };
    }

    write_log( 'DEBUG',
        "fetch: returned " . scalar(@logs) . " lines from $file_path" );

    print encode_json(
        {
            success => 1,
            logs    => \@logs,
            meta    => {
                source         => $source,
                type           => $log_type,
                file           => basename($file_path),
                count          => scalar(@logs),
                total_lines    => $total_lines,
                limit          => $line_limit,
                size           => $file_size,
                filter         => $filter,
                filter_applied => ( $filter ne 'all' ) ? 1 : 0
            }
        }
    );
}

# ============================================================================
# Helper: Smart Error Response
# ============================================================================
sub smart_error_response {
    my ( $source, $date, $config, $file_path ) = @_;

    my $error_type    = 'file_not_found';
    my $error_message = "Log file not found";
    my $error_details = {};
    my %meta          = read_metadata();

    if ( $date ne 'live' ) {
        my $last_rotation = $meta{LAST_ROTATION};
        my $today_str     = strftime( "%Y-%m-%d", localtime );

        if ( defined $last_rotation && $date gt $last_rotation ) {
            $error_type    = 'system_offline';
            $error_message = "System was offline or not logging on this date";
            $error_details = {
                requested_date => $date,
                last_rotation  => $last_rotation,
                reason         =>
"Log rotation did not occur -- system may have been powered off"
            };
        }
        elsif ( check_skipped_empty( $source, $date, \%meta ) ) {
            $error_type = 'empty_not_rotated';
            $error_message =
              "Log file was empty on this date (service running but silent)";
            $error_details = {
                requested_date => $date,
                reason         =>
                  "0-byte file not rotated (normal for quiet-mode services)"
            };
        }
        else {
            $error_type = 'missing_archive';
            $error_message =
              "Archive file missing (possible corruption or manual deletion)";
            $error_details = {
                requested_date => $date,
                expected_file  => basename($file_path),
                last_rotation  => $last_rotation
            };
        }
    }
    else {
        $error_type = 'live_not_found';
        $error_message =
          "Live log file not found -- service may not be running";
        $error_details = { expected_file => basename($file_path) };
    }

    write_log( 'DEBUG',
        "smart_error: source=$source date=$date type=$error_type" );

    print encode_json(
        {
            success    => 0,
            error_type => $error_type,
            message    => $error_message,
            details    => $error_details,
            meta       => {
                source => $source,
                type   => $config->{type},
                file   => basename($file_path)
            }
        }
    );
    exit;
}

# ============================================================================
# Helper: Read Rotation Metadata File
# ============================================================================
sub read_metadata {
    my %meta = ();
    if ( open( my $fh, '<', $ROTATION_META ) ) {
        while ( my $line = <$fh> ) {
            chomp($line);
            next if $line =~ /^\s*$/;
            if ( $line =~ /^(\w+)=(.*)$/ ) {
                $meta{$1} = $2;
            }
        }
        close($fh);
    }
    return %meta;
}

# ============================================================================
# Helper: Check if Source Was Skipped Due to Empty File
# ============================================================================
sub check_skipped_empty {
    my ( $source, $date, $meta_ref ) = @_;
    my $skipped_empty = $meta_ref->{SKIPPED_EMPTY} || '';
    my $basename      = ( split( '/', $source ) )[-1];
    $basename =~ s/\.log$//;
    return ( $skipped_empty =~ /\b\Q$basename\E\b/ );
}

# ============================================================================
# Helper: Consolidate Consecutive Gaps into Ranges
# ============================================================================
sub consolidate_gaps {
    my ($gaps_ref) = @_;
    my @gaps       = @$gaps_ref;
    my @ranges     = ();
    return @ranges unless @gaps;

    @gaps = sort { $a->{date} cmp $b->{date} } @gaps;

    my $current = {
        start  => $gaps[0]{date},
        end    => $gaps[0]{date},
        reason => $gaps[0]{reason},
        count  => 1
    };

    for ( my $i = 1 ; $i < @gaps ; $i++ ) {
        my $prev_epoch = date_to_epoch( $gaps[ $i - 1 ]{date} );
        my $curr_epoch = date_to_epoch( $gaps[$i]{date} );
        my $diff_days  = int( ( $curr_epoch - $prev_epoch ) / 86400 );

        if ( $diff_days == 1 && $gaps[$i]{reason} eq $current->{reason} ) {
            $current->{end} = $gaps[$i]{date};
            $current->{count}++;
        }
        else {
            push @ranges, $current;
            $current = {
                start  => $gaps[$i]{date},
                end    => $gaps[$i]{date},
                reason => $gaps[$i]{reason},
                count  => 1
            };
        }
    }
    push @ranges, $current;
    return @ranges;
}

# ============================================================================
# Helper: Convert YYYY-MM-DD to epoch
# ============================================================================
sub date_to_epoch {
    my ($date_str) = @_;
    if ( $date_str =~ /^(\d{4})-(\d{2})-(\d{2})$/ ) {
        return mktime( 0, 0, 0, $3, $2 - 1, $1 - 1900 );
    }
    return 0;
}

# ============================================================================
# Helper: Error exit
# ============================================================================
sub error_exit {
    my $msg = shift;
    print encode_json( { success => 0, message => $msg } );
    exit;
}
