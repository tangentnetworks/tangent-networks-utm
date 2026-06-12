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
use JSON::PP;
use CGI;
use POSIX          qw(:sys_wait_h strftime);
use File::Basename qw(dirname);
use Time::Local;
use Fcntl qw(:flock);

# --- Configuration ---
my $script_dir = dirname(__FILE__);

# Untaint $script_dir -- strict charset, rejects shell metacharacters
if ( $script_dir =~ m{^([-/\w.]+)$} ) {
    $script_dir = $1;
}
else {
    die "FATAL: Invalid script_dir\n";
}

# Dedicated error log -- date-stamped, one file per day
my $LOG_DATE = strftime( "%Y-%m-%d", localtime );
my $LOG_FILE = "/tmp/firewall-${LOG_DATE}.log";

my $PFLOG_LIVE =
  File::Spec->catfile( $script_dir, '..', 'data', 'logs', 'pf', 'pflog1.log' );
my $ARCHIVE_DIR =
  File::Spec->catdir( $script_dir, '..', 'data', 'archive', 'logs', 'system' );

# Untaint paths -- strict charset (rejects shell metacharacters).
# Paths are code-constructed from $script_dir + literal segments; no user input reaches them.
for ( $PFLOG_LIVE, $ARCHIVE_DIR ) {
    if (m{^([-/\w.]+)$}) { $_ = $1 }
    else                 { die "FATAL: Invalid log path\n" }
}

# --- Signal Handling ---
$SIG{CHLD} = 'IGNORE';

# --- Untaint $ENV{PATH} ---
$ENV{PATH} = '/usr/bin:/bin:/usr/sbin:/sbin';

my $query = CGI->new;
print $query->header('application/json');

# --- Error Logging ---
sub write_log {
    my ( $level, $msg ) = @_;
    my $timestamp = strftime( "%Y-%m-%d %H:%M:%S", localtime );
    if ( open( my $fh, '>>', $LOG_FILE ) ) {
        flock( $fh, LOCK_EX );
        print $fh "[$timestamp] [$level] $msg\n";
        close $fh;
    }
}

# --- Parameters (Untaint and Validate) ---
my $mode    = $query->param('mode')    || 'live';
my $limit   = $query->param('limit')   || 50;
my $offset  = $query->param('offset')  || 0;
my $family  = $query->param('family')  || '';
my $proto   = $query->param('proto')   || '';
my $port    = $query->param('port')    || '';
my $blocked = $query->param('blocked') || 0;
my $debug   = $query->param('debug')   || 0;
my $date    = $query->param('date')    || '';

# Untaint and validate numeric parameters
$limit   = ( $limit   =~ /^(\d+)$/ )  ? $1 : 50;
$offset  = ( $offset  =~ /^(\d+)$/ )  ? $1 : 0;
$port    = ( $port    =~ /^(\d+)$/ )  ? $1 : '';
$blocked = ( $blocked =~ /^([01])$/ ) ? $1 : 0;
$debug   = ( $debug   =~ /^([01])$/ ) ? $1 : 0;

# Untaint and validate mode
$mode = ( $mode =~ /^(live|archive)$/ ) ? $1 : 'live';

# Untaint and validate family
$family = ( $family =~ /^(IPv4|IPv6)?$/ ) ? $1 : '';

# Untaint and validate proto
$proto = ( $proto =~ /^(tcp|udp|icmp|icmp6)?$/ ) ? $1 : '';

# Untaint and validate date (YYYY-MM-DD format)
$date = ( $date =~ /^(\d{4}-\d{2}-\d{2})$/ ) ? $1 : '';

# --- Get Current Year for Date Parsing ---
my $current_year = (localtime)[5] + 1900;

# Check if we're looking for today's logs
my @t        = localtime();
my $today    = sprintf( "%04d-%02d-%02d", $t[5] + 1900, $t[4] + 1, $t[3] );
my $is_today = ( $date eq $today );

my $log_file = File::Spec->catfile( $ARCHIVE_DIR, "pflog_${date}.log" );

# Untaint: $date already validated as /^\d{4}-\d{2}-\d{2}$/ -- no user-controlled characters.
if ( $log_file =~ m{^([-/\w.]+)$} ) { $log_file = $1 }
else                                { die "FATAL: Invalid log_file path\n" }

# If looking for today and archive doesn't exist, fall back to live log
my $target_log;
if ( $is_today && !-r $log_file && -r $PFLOG_LIVE ) {
    $target_log = $PFLOG_LIVE;
    write_log( 'DEBUG', "Using live log for today: $PFLOG_LIVE" ) if $debug;
}
elsif ( -r $log_file ) {
    $target_log = $log_file;
    write_log( 'DEBUG', "Using archive file: $log_file" ) if $debug;
}
else {
    # Try to list what files ARE there
    my @available_files = glob("$ARCHIVE_DIR/pflog_*.log");
    my $available_list  = join( ", ", map { s/.*\///; $_ } @available_files );

    print encode_json(
        {
            error      => "Log file not found: pflog_${date}.log",
            debug_info => {
                looking_for     => $log_file,
                archive_dir     => $ARCHIVE_DIR,
                available_files => $available_list || "none found",
                date_received   => $date,
                is_today        => $is_today ? "yes" : "no",
                live_log        => $PFLOG_LIVE,
                live_exists     => -r $PFLOG_LIVE ? "yes" : "no",
            },
            html_logs       => '',
            html_pagination => '',
            total           => 0,
            ipv4            => 0,
            ipv6            => 0,
            blocked         => 0,
            offset          => 0,
            limit           => $limit,
        }
    );
    exit;
}

# --- OpenBSD pledge + unveil ---
# Plain Perl open() -- no fork, no exec, no external process.
# stdio: response output   rpath: log file, config, keys, db (session check)
# Wrapped in eval: a failing unveil returns JSON error instead of silent empty body.
{
    my $app_root = $script_dir;
    $app_root =~ s{/cgi-bin$}{};
    $app_root =~ s{^/var/www}{};
    my $pledge_err = '';
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
            OpenBSD::Unveil::unveil( "$app_root/data/logs/pf", "r" )
              or die "unveil data/logs/pf: $!";
            OpenBSD::Unveil::unveil( "$app_root/data/archive/logs/system", "r" )
              or die "unveil data/archive: $!";
            OpenBSD::Unveil::unveil( "/tmp", "rwc" ) or die "unveil tmp: $!";
            OpenBSD::Unveil::unveil( "/bin", "rx" )  or die "unveil /bin: $!";
            OpenBSD::Unveil::unveil( "/usr/bin", "rx" )
              or die "unveil /usr/bin: $!";
            OpenBSD::Unveil::unveil() or die "unveil lock: $!";
        }
        if ( eval { require OpenBSD::Pledge; 1 } ) {

            # Plain file read only -- no fork, no exec.
            OpenBSD::Pledge::pledge("stdio rpath wpath cpath flock")
              or die "pledge: $!";
        }
    };
    if ($@) {
        write_log( 'ERROR', "sandbox_init_failed: $@" );
        print encode_json(
            {
                error    => "sandbox_init_failed",
                detail   => "$@",
                app_root => $app_root
            }
        );
        exit;
    }
}

my %month_map = (
    'Jan' => 0,
    'Feb' => 1,
    'Mar' => 2,
    'Apr' => 3,
    'May' => 4,
    'Jun' => 5,
    'Jul' => 6,
    'Aug' => 7,
    'Sep' => 8,
    'Oct' => 9,
    'Nov' => 10,
    'Dec' => 11
);

sub parse_timestamp {
    my ($ts) = @_;

    # Parse: Dec 23 05:35:01.801331
    if ( $ts =~ /^(\w+)\s+(\d+)\s+([\d:.]+)$/ ) {
        my ( $mon, $day, $time ) = ( $1, $2, $3 );

        # Extract time components
        my ( $hour, $min, $sec ) = split( /:/, $time );
        $sec =~ s/\..*//;

        my $mon_num = $month_map{$mon};
        return 0 unless defined $mon_num;

        # Use Time::Local to create epoch timestamp
        eval {
            return timelocal( $sec, $min, $hour, $day, $mon_num,
                $current_year );
        };
        return 0 if $@;
    }
    return 0;
}

# --- Execution & Parsing ---
my @results;

# Direct Perl file read -- no fork, no exec, no /bin/cat.
# Log files are plain text; open() is sufficient and tighter than open3.
# Pledge can now be "stdio rpath" only.
open( my $log_fh, '<', $target_log ) or do {
    write_log( 'ERROR', "Cannot open pf log file '$target_log': $!" );
    print encode_json(
        {
            error           => "Cannot open log file: $!",
            html_logs       => '',
            html_pagination => '',
            total           => 0,
            ipv4            => 0,
            ipv6            => 0,
            blocked         => 0,
            offset          => 0,
            limit           => $limit,
        }
    );
    exit;
};

while ( my $line = <$log_fh> ) {
    chomp($line);

    # Skip tcpdump header lines
    next if $line =~ /^tcpdump:/;
    next if $line =~ /listening on/;
    next if $line =~ /packets (received|dropped)/;

    if ( $debug && $line =~ /(error|permission|denied|failed)/i ) {
        push @results,
          {
            time    => "SYSTEM",
            payload => "Error: $line",
            action  => "error",
            epoch   => 0
          };
        next;
    }

# Parse log line: Dec 23 05:35:01.801331 rule 0/(match) match in on %%EXT_IF%%: ...
    if ( $line =~
/^(\w+\s+\d+\s+[\d:.]+)\s+rule\s+(\d+)\/\(([^)]+)\)\s+(\w+)\s+(\w+)\s+on\s+(\w+):\s+(.*)$/
      )
    {
        my ( $ts, $rule, $reason, $action, $dir, $iface, $payload ) =
          ( $1, $2, $3, $4, $5, $6, $7 );

        # Filter by blocked if requested
        next if ( $blocked && $action ne 'block' );

        # Parse timestamp for sorting
        my $epoch = parse_timestamp($ts);

        # Extract IP addresses and ports from payload
        my ( $src, $dst, $src_port, $dst_port ) = ( "", "", "", "" );

      # Parse src and dst address+port from the payload.
      #
      # pflog always delimits the port with a trailing dot regardless of family:
      #   IPv4: 192.168.1.1.46370 > 192.168.1.2.443: ...
      #   IPv6: 2620:fe::fe.443   > fdac:1005::1.8443: ...
      #   no-port: fe80::1 > ff02::1: ICMP6 ...
      #
      # A single greedy regex cannot handle both families because IPv4 addresses
      # also contain dots. parse_pflog_side() handles each side by family:
      #   IPv6 side (contains ':'): strip trailing .digits for port
      #   IPv4 side: must match d.d.d.d exactly before a 5th dot port component

        if ( $payload =~ /^(.+?)\s+>\s+(.+?)(?::\s|$)/ ) {
            my ( $src_part, $dst_part ) = ( $1, $2 );

            ( $src, $src_port ) = _parse_pflog_side($src_part);
            ( $dst, $dst_port ) = _parse_pflog_side($dst_part);

            # Determine IP family from src address
            my $curr_family = ( $src =~ /:/ ) ? "IPv6" : "IPv4";
            next if ( $family && $curr_family ne $family );

            # Filter by port
            if ($port) {
                next
                  unless ( ( $src_port eq $port ) || ( $dst_port eq $port ) );
            }
        }

        # Detect protocol from payload
        my $detected_proto = "unknown";
        if ( $payload =~ /\b(tcp|udp|icmp|icmp6)\b/i ) {
            $detected_proto = lc($1);
        }
        elsif ( $payload =~ /: S \d+:\d+/ ) {
            $detected_proto = "tcp";
        }
        elsif ( $payload =~ /echo request|echo reply/ ) {
            $detected_proto = ( $src =~ /:/ ) ? "icmp6" : "icmp";
        }

        # Filter by protocol if specified
        if ($proto) {
            next unless ( $detected_proto eq $proto );
        }

        push @results,
          {
            time    => $ts,
            epoch   => $epoch,
            rule    => $rule,
            reason  => "($reason)",
            action  => $action,
            dir     => $dir,
            iface   => $iface,
            src     => $src      || "N/A",
            dst     => $dst      || "N/A",
            port    => $dst_port || $src_port || "N/A",
            proto   => $detected_proto,
            payload => $payload
          };
    }
}

close($log_fh);

# --- Sort by timestamp (newest first) ---
@results = sort { $b->{epoch} <=> $a->{epoch} } @results;

# --- Calculate Statistics ---
my $total         = scalar @results;
my $blocked_count = scalar grep { $_->{action} eq 'block' } @results;

# FIXED: Calculate IPv4 and IPv6 counts
my $ipv4_count = 0;
my $ipv6_count = 0;
foreach my $log (@results) {

    # Check if source or destination contains ':' (IPv6 indicator)
    if ( $log->{src} =~ /:/ || $log->{dst} =~ /:/ ) {
        $ipv6_count++;
    }
    else {
        $ipv4_count++;
    }
}

# --- Pagination ---
my @paged = splice( @results, $offset, $limit );

# --- Helper: parse one side of a pflog payload address.port token ---
# pflog format: address.port (port appended after the last dot).
# IPv6 addresses contain colons so must be handled separately from IPv4
# where the address itself contains dots.
sub _parse_pflog_side {
    my ($part) = @_;
    if ( $part =~ /:/ ) {

        # IPv6: trailing .digits = port; no trailing digits = no port
        if ( $part =~ /^([0-9a-fA-F:]+)\.(\d+)$/ ) {
            return ( $1, $2 );
        }
        return ( $part, '' );
    }
    else {
        # IPv4: exactly d.d.d.d followed by optional .port
        if ( $part =~ /^(\d+\.\d+\.\d+\.\d+)\.(\d+)$/ ) {
            return ( $1, $2 );
        }
        return ( $part, '' );
    }
}

# --- Helper function to escape HTML ---
sub escape_html {
    my ($text) = @_;
    return '' unless defined $text;
    $text =~ s/&/&amp;/g;
    $text =~ s/</&lt;/g;
    $text =~ s/>/&gt;/g;
    $text =~ s/"/&quot;/g;
    $text =~ s/'/&#39;/g;
    return $text;
}

# --- Generate HTML for Logs ---
my $html_logs = '';
if (@paged) {
    foreach my $log (@paged) {
        my $action_class =
          $log->{action} eq 'block'
          ? 'border-red-500 text-red-500 bg-red-500/5'
          : $log->{action} eq 'match'
          ? 'border-blue-500 text-blue-500 bg-blue-500/5'
          : 'border-green-500 text-green-500 bg-green-500/5';

      # Escape all data attributes (SSR approach - no JSON parsing needed in JS)
        my $attr_time    = escape_html( $log->{time}    || 'N/A' );
        my $attr_rule    = escape_html( $log->{rule}    || 'N/A' );
        my $attr_reason  = escape_html( $log->{reason}  || 'N/A' );
        my $attr_action  = escape_html( $log->{action}  || 'N/A' );
        my $attr_dir     = escape_html( $log->{dir}     || 'N/A' );
        my $attr_iface   = escape_html( $log->{iface}   || 'N/A' );
        my $attr_src     = escape_html( $log->{src}     || 'N/A' );
        my $attr_dst     = escape_html( $log->{dst}     || 'N/A' );
        my $attr_port    = escape_html( $log->{port}    || 'N/A' );
        my $attr_proto   = escape_html( $log->{proto}   || 'N/A' );
        my $attr_payload = escape_html( $log->{payload} || 'N/A' );

        # For JSON copy - properly escaped
        my $json_str = encode_json($log);
        $json_str = escape_html($json_str);

        $html_logs .= qq|
            <li class="group cursor-pointer p-3 transition-colors hover:bg-blue-50/30 dark:hover:bg-blue-900/10"
                data-time="$attr_time"
                data-rule="$attr_rule"
                data-reason="$attr_reason"
                data-action="$attr_action"
                data-dir="$attr_dir"
                data-iface="$attr_iface"
                data-src="$attr_src"
                data-dst="$attr_dst"
                data-port="$attr_port"
                data-proto="$attr_proto"
                data-payload="$attr_payload"
                data-json="$json_str">
                <div class="flex flex-col gap-1">
                    <div class="mb-1 flex items-center justify-between">
                        <span class="font-bold text-blue-600 dark:text-blue-400 font-mono text-xs">
                            $attr_time
                        </span>
                        <span class="border $action_class px-1.5 py-0.5 text-[9px] font-black tracking-tighter uppercase font-sans">
                            $attr_action
                        </span>
                    </div>
                    <div class="leading-relaxed break-all text-gray-700 opacity-90 group-hover:opacity-100 dark:text-gray-300 font-mono text-xs">
                        $attr_payload
                    </div>
                </div>
            </li>
        |;
    }
}
else {
    $html_logs = qq|
        <li class="p-8 text-center">
            <div class="card bg-gray-50 dark:bg-gray-800 p-6">
                <p class="text-gray-600 dark:text-gray-400 font-bold">NO LOGS FOUND</p>
                <p class="text-sm mt-2 text-gray-500">Try adjusting your filters</p>
            </div>
        </li>
    |;
}

# --- Generate HTML for Pagination ---
my $total_pages     = $total > 0 ? int( ( $total + $limit - 1 ) / $limit ) : 1;
my $current_page    = int( $offset / $limit );
my $html_pagination = '';

# Previous button
my $prev_disabled =
  $current_page == 0
  ? 'disabled opacity-30 cursor-not-allowed'
  : 'bg-white dark:bg-gray-800 hover:bg-gray-100';
my $prev_page = $current_page > 0 ? $current_page - 1 : 0;

$html_pagination .= qq|
    <button class="$prev_disabled border px-2 py-1.5 text-[10px] font-bold transition-all border-gray-200 dark:border-gray-700" data-page="$prev_page">
        <svg class="w-3 h-3" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
            <path d="M15 19l-7-7 7-7"></path>
        </svg>
    </button>
|;

# Page buttons (show 5 pages max)
my $start_page = $current_page - 2 > 0         ? $current_page - 2 : 0;
my $end_page = $start_page + 5 <= $total_pages ? $start_page + 5 : $total_pages;

for my $i ( $start_page .. $end_page - 1 ) {
    my $active_class =
      $i == $current_page
      ? 'bg-blue-700 text-white border-blue-700 z-10'
      : 'bg-white dark:bg-gray-800 text-gray-600 dark:text-gray-400 border-gray-200 dark:border-gray-700 hover:bg-gray-100';

    $html_pagination .= qq|
        <button data-page="$i"
            class="$active_class border px-3 py-1.5 text-[10px] font-bold transition-all active:scale-90">
            @{[$i + 1]}
        </button>
    |;
}

# Next button
my $next_disabled =
  $current_page >= $total_pages - 1
  ? 'disabled opacity-30 cursor-not-allowed'
  : 'bg-white dark:bg-gray-800 hover:bg-gray-100';
my $next_page =
  $current_page < $total_pages - 1 ? $current_page + 1 : $current_page;

$html_pagination .= qq|
    <button class="$next_disabled border px-2 py-1.5 text-[10px] font-bold transition-all border-gray-200 dark:border-gray-700" data-page="$next_page">
        <svg class="w-3 h-3" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
            <path d="M9 5l7 7-7 7"></path>
        </svg>
    </button>
|;

# --- JSON Response (FIXED: Now includes ipv4 and ipv6) ---
print encode_json(
    {
        html_logs       => $html_logs,
        html_pagination => $html_pagination,
        total           => $total,
        ipv4            => $ipv4_count,
        ipv6            => $ipv6_count,
        blocked         => $blocked_count,
        offset          => $offset,
        limit           => $limit,
        meta            => {
            date    => $date,
            storage => "ARCHIVE",
            year    => $current_year,
        }
    }
);
