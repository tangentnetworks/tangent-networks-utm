#!/usr/bin/perl -T

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# collectd_exporter.pl - Modular collectd JSON exporter for OpenBSD unixsock
# David Peter, TANGENT NETWORKS
# Environment: Perl, JSON::XS, IO::Socket::UNIX
# Features: Full metrics registry, safe CGI/CLI, per-plugin or aggregate output,
#           automatic RRD fallback, IEC unit conversion, display-ready output

use strict;
use warnings;
use IO::Socket::UNIX;
use JSON::XS;
use File::Path qw(make_path);
use POSIX      qw(isnan);
use lib '/etc';
use collectd_rrd_exporter qw(fetch_from_rrd);

# Untaint environment for secure execution under -T
$ENV{PATH} = '/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin';
delete @ENV{ 'IFS', 'CDPATH', 'ENV', 'BASH_ENV' };

# ---------- CONFIGURATION ----------
my $SOCK             = '/var/www/htdocs/tn/data/sockets/collectd/collectd.sock';
my $HOST             = 'tangent';
my $OUTPUT_BASE      = '/var/www/htdocs/tn/data/stats/collectd';
my $AGGREGATE_FILE   = '/var/www/htdocs/tn/data/stats/collectd_exporter.json';
my $CURRENT_TIME     = time;
my $USE_RRD_FALLBACK = 1;    # Enable automatic RRD fallback
my $LOG_FILE         = '/var/www/htdocs/tn/data/logs/collectd/exporter.log';

# IEC unit conversion factors (base 1024)
my %IEC_UNITS = (
    1024               => 'KiB',
    1024 * 1024        => 'MiB',
    1024 * 1024 * 1024 => 'GiB',
);

# ---------- HELPER SUBROUTINES ----------

# Logging function - writes to file only
sub log_msg {
    my ($msg) = @_;
    my $timestamp = scalar localtime;

    if ( open( my $fh, '>>', $LOG_FILE ) ) {
        print $fh "[$timestamp] $msg\n";
        close($fh);
    }
}

# Untaint user input - only allows safe characters
sub untaint {
    my ($v) = @_;
    $v =~ /^([\w.\-\/]+)$/ or die "Tainted value rejected: $v";
    return $1;
}

# Convert bytes to IEC units with display string
sub bytes_to_iec {
    my ($bytes) = @_;

    return {
        display => sprintf( "%.0f B", $bytes ),
        value   => $bytes,
        unit    => 'B',
        raw     => $bytes,
        status  => 'ok'
      }
      if $bytes < 1024;

    for my $divisor ( sort { $b <=> $a } keys %IEC_UNITS ) {
        if ( $bytes >= $divisor ) {
            my $converted = $bytes / $divisor;
            return {
                display =>
                  sprintf( "%.2f %s", $converted, $IEC_UNITS{$divisor} ),
                value  => sprintf( "%.2f", $converted ),
                unit   => $IEC_UNITS{$divisor},
                raw    => $bytes,
                status => 'ok'
            };
        }
    }

    return {
        display => sprintf( "%.0f B", $bytes ),
        value   => $bytes,
        unit    => 'B',
        raw     => $bytes,
        status  => 'ok'
    };
}

# Format metric value based on type with display string
sub format_metric {
    my ( $value, $id ) = @_;

   # Apply IEC conversion for memory, disk, swap, network octets, process memory
    if ( $id =~
/memory|swap|disk_octets|if_octets|df_complex|ps_rss|ps_vm|ps_data|ps_code|ps_stacksize/
      )
    {
        if ( $value >= 1024 ) {
            return bytes_to_iec($value);
        }
        else {
            return {
                display => sprintf( "%.0f B", $value ),
                value   => $value,
                unit    => 'B',
                raw     => $value,
                status  => 'ok'
            };
        }
    }

    # CPU percentages
    if ( $id =~ /cpu/ && $id !~ /ps_cputime/ ) {
        return {
            display => sprintf( "%.1f%%", $value ),
            value   => sprintf( "%.1f",   $value ),
            unit    => '%',
            status  => 'ok'
        };
    }

    # Process count
    if ( $id =~ /ps_count/ ) {
        return {
            display => sprintf( "%.0f", $value ),
            value   => int($value),
            status  => 'ok'
        };
    }

    # CPU time (microseconds to seconds)
    if ( $id =~ /ps_cputime/ ) {
        my $seconds = $value / 1000000;
        return {
            display => sprintf( "%.2f s", $seconds ),
            value   => sprintf( "%.2f",   $seconds ),
            unit    => 's',
            raw     => $value,
            status  => 'ok'
        };
    }

    # Page faults
    if ( $id =~ /ps_pagefaults/ ) {
        return {
            display => sprintf( "%.0f", $value ),
            value   => int($value),
            status  => 'ok'
        };
    }

    # Load average
    if ( $id =~ /load/ ) {
        return {
            display => sprintf( "%.2f", $value ),
            value   => sprintf( "%.2f", $value ),
            status  => 'ok'
        };
    }

    # Ping latency
    if ( $id =~ /ping/ && $id !~ /droprate|stddev/ ) {
        return {
            display => sprintf( "%.2f ms", $value ),
            value   => sprintf( "%.2f",    $value ),
            unit    => 'ms',
            status  => 'ok'
        };
    }

    # Ping droprate
    if ( $id =~ /ping_droprate/ ) {
        return {
            display => sprintf( "%.1f%%", $value ),
            value   => sprintf( "%.1f",   $value ),
            unit    => '%',
            status  => 'ok'
        };
    }

    # Ping stddev
    if ( $id =~ /ping_stddev/ ) {
        return {
            display => sprintf( "%.2f ms", $value ),
            value   => sprintf( "%.2f",    $value ),
            unit    => 'ms',
            status  => 'ok'
        };
    }

    # Network packets/errors
    if ( $id =~ /if_packets|if_errors/ ) {
        return {
            display => sprintf( "%.0f", $value ),
            value   => int($value),
            status  => 'ok'
        };
    }

    # PF counters
    if ( $id =~ /pf_counters|pf_state|pf_source|pf_limits|pf_states/ ) {
        return {
            display => sprintf( "%.0f", $value ),
            value   => int($value),
            status  => 'ok'
        };
    }

    # Users
    if ( $id =~ /users/ ) {
        return {
            display => sprintf( "%.0f", $value ),
            value   => int($value),
            status  => 'ok'
        };
    }

    # Uptime (seconds to days/hours)
    if ( $id =~ /uptime/ ) {
        my $days  = int( $value / 86400 );
        my $hours = int( ( $value % 86400 ) / 3600 );
        return {
            display => sprintf( "%dd %dh", $days, $hours ),
            value   => $value,
            unit    => 's',
            raw     => $value,
            status  => 'ok'
        };
    }

    # Default: plain number
    return {
        display => sprintf( "%.2f", $value ),
        value   => sprintf( "%.2f", $value ),
        status  => 'ok'
    };
}

# Check if socket exists and is accessible
sub socket_exists {
    return -S $SOCK;
}

# Connect to collectd unix socket and send a command
sub collectd_cmd {
    my ($cmd) = @_;

    my $sock = IO::Socket::UNIX->new(
        Type    => SOCK_STREAM,
        Peer    => $SOCK,
        Timeout => 3
    ) or return ();    # Return empty on connection failure

    print $sock "$cmd\n";
    $sock->flush();

    my @resp;
    my $value_count  = 0;
    my $values_found = 0;
    my $got_error    = 0;

    while ( my $line = <$sock> ) {
        $line =~ s/\r//g;
        chomp $line;

        # Check for error responses
        if ( $line =~ /^<?-\s*\d+\s+(No such value|is unknown|not found)/i ) {
            $got_error = 1;
            push @resp, $line;
            last;
        }

        # Parse the initial response line with count
        if ( $line =~ /^<?-?\s*(\d+)\s+Values?\s+found/i ) {
            $value_count = $1;
            next;
        }

        # Skip other status lines
        if ( $line =~ /^<?-?\s*\d+\s+[A-Z]/ && $line !~ /=/ ) {
            next;
        }

        # Collect value lines (format: key=value)
        if ( $line =~ /^([\w\-\+]+)=(.+)$/ ) {
            push @resp, $line;
            $values_found++;
        }

        # Exit once we've collected all expected values
        if ( $value_count > 0 && $values_found >= $value_count ) {
            last;
        }
    }

    close $sock;
    return @resp;
}

# Parse GETVAL response and return structured data with formatting
sub get_values {
    my ($id) = @_;

    my @raw = collectd_cmd("GETVAL $id");

    # Check if socket query failed - try RRD fallback
    if ( @raw == 0 || grep { /No such value|is unknown|not found/i } @raw ) {
        if ($USE_RRD_FALLBACK) {
            return fetch_from_rrd($id);
        }
        return undef;
    }

    my %v;
    for (@raw) {
        if (/^([\w\-\+]+)=(.+)$/) {
            my ( $k, $val ) = ( $1, $2 );
            my $numeric_val = $val + 0;

            # Format the value with display string
            $v{$k} = format_metric( $numeric_val, $id );
        }
        elsif (/^value=(.+)$/) {
            my $numeric_val = $1 + 0;

            # Format the value with display string
            $v{value} = format_metric( $numeric_val, $id );
        }
    }

    if ( keys %v == 0 ) {
        if ($USE_RRD_FALLBACK) {
            return fetch_from_rrd($id);
        }
        return undef;
    }

    # Add metadata
    return {
        id        => $id,
        timestamp => $CURRENT_TIME,
        values    => \%v,
        source    => 'unixsock'
    };
}

# ---------- METRICS REGISTRY ----------
our %METRICS = (
    cpu => ["$HOST/cpu_avg-cpu-average/cpu"],

    memory => [
        "$HOST/memory/memory-active", "$HOST/memory/memory-inactive",
        "$HOST/memory/memory-free",
    ],

    load => ["$HOST/load/load"],

    swap => [ "$HOST/swap/swap-used", "$HOST/swap/swap-free", ],

    df => [
        "$HOST/df-root/df_complex-free", "$HOST/df-root/df_complex-reserved",
        "$HOST/df-root/df_complex-used",
    ],

    pf => {
        counters => [
            "$HOST/pf/pf_counters-bad-offset",
            "$HOST/pf/pf_counters-bad-timestamp",
            "$HOST/pf/pf_counters-congestion",
            "$HOST/pf/pf_counters-fragment",
            "$HOST/pf/pf_counters-ip-option",
            "$HOST/pf/pf_counters-match",
            "$HOST/pf/pf_counters-memory",
            "$HOST/pf/pf_counters-no-route",
            "$HOST/pf/pf_counters-normalize",
            "$HOST/pf/pf_counters-proto-cksum",
            "$HOST/pf/pf_counters-short",
            "$HOST/pf/pf_counters-src-limit",
            "$HOST/pf/pf_counters-state-insert",
            "$HOST/pf/pf_counters-state-limit",
            "$HOST/pf/pf_counters-state-mismatch",
            "$HOST/pf/pf_counters-synproxy",
            "$HOST/pf/pf_counters-translate",
        ],
        limits => [
            "$HOST/pf/pf_limits-max-src-conn",
            "$HOST/pf/pf_limits-max-src-conn-rate",
            "$HOST/pf/pf_limits-max-src-nodes",
            "$HOST/pf/pf_limits-max-src-states",
            "$HOST/pf/pf_limits-overload-flush-states",
            "$HOST/pf/pf_limits-overload-table-insertion",
            "$HOST/pf/pf_limits-syncookies-sent",
            "$HOST/pf/pf_limits-syncookies-validated",
            "$HOST/pf/pf_limits-synfloods-detected",
        ],
        source => [
            "$HOST/pf/pf_source-insert", "$HOST/pf/pf_source-removals",
            "$HOST/pf/pf_source-search",
        ],
        state => [
            "$HOST/pf/pf_state-insert", "$HOST/pf/pf_state-removals",
            "$HOST/pf/pf_state-search", "$HOST/pf/pf_states-current",
        ],
    },

    processes => {
        e2guardian => [
            map { "$HOST/processes-e2guardian/$_" }
              qw(ps_code ps_count ps_cputime ps_data ps_pagefaults ps_rss ps_stacksize ps_vm)
        ],
        clamd => [
            map { "$HOST/processes-clamd/$_" }
              qw(ps_code ps_count ps_cputime ps_data ps_pagefaults ps_rss ps_stacksize ps_vm)
        ],
        freshclam => [
            map { "$HOST/processes-freshclam/$_" }
              qw(ps_code ps_count ps_cputime ps_data ps_pagefaults ps_rss ps_stacksize ps_vm)
        ],
        ftpproxy => [
            map { "$HOST/processes-ftpproxy/$_" }
              qw(ps_code ps_count ps_cputime ps_data ps_pagefaults ps_rss ps_stacksize ps_vm)
        ],
        pflogd => [
            map { "$HOST/processes-pflogd/$_" }
              qw(ps_code ps_count ps_cputime ps_data ps_pagefaults ps_rss ps_stacksize ps_vm)
        ],
        pmacctd => [
            map { "$HOST/processes-pmacctd/$_" }
              qw(ps_code ps_count ps_cputime ps_data ps_pagefaults ps_rss ps_stacksize ps_vm)
        ],
        smtp_gated => [
            map { "$HOST/processes-smtp-gated/$_" }
              qw(ps_code ps_count ps_cputime ps_data ps_pagefaults ps_rss ps_stacksize ps_vm)
        ],
        smtpd => [
            map { "$HOST/processes-smtpd/$_" }
              qw(ps_code ps_count ps_cputime ps_data ps_pagefaults ps_rss ps_stacksize ps_vm)
        ],
        snort => [
            map { "$HOST/processes-snort/$_" }
              qw(ps_code ps_count ps_cputime ps_data ps_pagefaults ps_rss ps_stacksize ps_vm)
        ],
        snortsentry => [
            map { "$HOST/processes-snortsentry/$_" }
              qw(ps_code ps_count ps_cputime ps_data ps_pagefaults ps_rss ps_stacksize ps_vm)
        ],
        sockd => [
            map { "$HOST/processes-sockd/$_" }
              qw(ps_code ps_count ps_cputime ps_data ps_pagefaults ps_rss ps_stacksize ps_vm)
        ],
        sslproxy => [
            map { "$HOST/processes-sslproxy/$_" }
              qw(ps_code ps_count ps_cputime ps_data ps_pagefaults ps_rss ps_stacksize ps_vm)
        ],
        unbound => [
            map { "$HOST/processes-unbound/$_" }
              qw(ps_code ps_count ps_cputime ps_data ps_pagefaults ps_rss ps_stacksize ps_vm)
        ],
        httpd => [
            map { "$HOST/processes-httpd/$_" }
              qw(ps_code ps_count ps_cputime ps_data ps_pagefaults ps_rss ps_stacksize ps_vm)
        ],
        ntpd => [
            map { "$HOST/processes-ntpd/$_" }
              qw(ps_code ps_count ps_cputime ps_data ps_pagefaults ps_rss ps_stacksize ps_vm)
        ],
        cron => [
            map { "$HOST/processes-cron/$_" }
              qw(ps_code ps_count ps_cputime ps_data ps_pagefaults ps_rss ps_stacksize ps_vm)
        ],
        sshd => [
            map { "$HOST/processes-sshd/$_" }
              qw(ps_code ps_count ps_cputime ps_data ps_pagefaults ps_rss ps_stacksize ps_vm)
        ],
        p3scan => [
            map { "$HOST/processes-p3scan/$_" }
              qw(ps_code ps_count ps_cputime ps_data ps_pagefaults ps_rss ps_stacksize ps_vm)
        ],
        dhcpd => [
            map { "$HOST/processes-dhcpd/$_" }
              qw(ps_code ps_count ps_cputime ps_data ps_pagefaults ps_rss ps_stacksize ps_vm)
        ],
    },

    interfaces => {
        %%EXT_IF%% => [
            map { "$HOST/interface-%%EXT_IF%%/$_" } qw(if_octets if_packets if_errors)
        ],
        %%INT_IF%% => [
            map { "$HOST/interface-%%INT_IF%%/$_" }
              qw(if_octets if_packets if_errors)
        ],
    },

    disk => ["$HOST/disk-sd1/disk_octets"],

    ping => [
        "$HOST/ping/ping-1.1.1.1",          "$HOST/ping/ping-",
        "$HOST/ping/ping_droprate-1.1.1.1", "$HOST/ping/ping_droprate-",
        "$HOST/ping/ping_stddev-1.1.1.1",   "$HOST/ping/ping_stddev-",
    ],

    system => [ "$HOST/uptime/uptime", "$HOST/users/users", ],
);

# ---------- FETCH MODULE ----------

# Fetch metrics for a specific plugin or subcategory
sub fetch_module {
    my ( $plugin, $subcat ) = @_;
    my %data;

    if ( exists $METRICS{$plugin} ) {
        my $ref_type = ref( $METRICS{$plugin} );

        if ( $ref_type eq 'ARRAY' ) {

            # Simple array of metric IDs
            for my $id ( @{ $METRICS{$plugin} } ) {
                my $values = get_values($id);
                $data{$id} = $values if defined $values;
            }
        }
        elsif ( $ref_type eq 'HASH' ) {

            # Hash with subcategories (e.g., processes, pf)
            if ( defined $subcat && exists $METRICS{$plugin}{$subcat} ) {

                # Fetch specific subcategory
                for my $id ( @{ $METRICS{$plugin}{$subcat} } ) {
                    my $values = get_values($id);
                    $data{$id} = $values if defined $values;
                }
            }
            else {
                # Fetch all subcategories
                for my $sub ( keys %{ $METRICS{$plugin} } ) {
                    for my $id ( @{ $METRICS{$plugin}{$sub} } ) {
                        my $values = get_values($id);
                        $data{$id} = $values if defined $values;
                    }
                }
            }
        }
    }
    else {
        die "Unknown plugin: $plugin";
    }

    return {
        meta => {
            plugin       => $plugin,
            host         => $HOST,
            timestamp    => $CURRENT_TIME,
            metric_count => scalar( keys %data )
        },
        data => \%data,
    };
}

# Write JSON to file with proper directory creation
sub write_json_file {
    my ( $filepath, $data ) = @_;

    # Extract directory from filepath
    my ($dir) = $filepath =~ m{^(.*)/[^/]+$};

    # Create directory if it doesn't exist
    if ( $dir && !-d $dir ) {
        make_path( $dir, { mode => 0755 } )
          or die "Cannot create directory $dir: $!";
    }

    # Write JSON to file (truncates existing file)
    open( my $fh, '>', $filepath ) or die "Cannot write to $filepath: $!";
    print $fh JSON::XS->new->pretty->canonical->encode($data);
    close($fh);
}

# ---------- MAIN ----------

# Parse command-line or CGI arguments
my $cgi_action = $ENV{QUERY_STRING};

if ($cgi_action) {

    # CGI mode with query string
    $cgi_action =~ s/^action=//;
    $cgi_action = untaint($cgi_action);

    if ( exists $METRICS{$cgi_action} ) {
        my $result      = fetch_module($cgi_action);
        my $output_file = "$OUTPUT_BASE/$cgi_action/metrics";
        write_json_file( $output_file, $result );

        print "Content-Type: application/json\n\n";
        print JSON::XS->new->pretty->canonical->encode($result);
    }
    else {
        die "Unknown plugin: $cgi_action";
    }

}
elsif ( @ARGV > 1 ) {

    # Batch mode - multiple plugins specified
    # Process each plugin and write to its own endpoint file

    my $success_count = 0;
    my $fail_count    = 0;

    for my $plugin (@ARGV) {
        my $safe_plugin = untaint($plugin);

        unless ( exists $METRICS{$safe_plugin} ) {
            warn "Unknown plugin: $plugin (skipping)\n";
            log_msg("Unknown plugin: $plugin (skipping)");
            $fail_count++;
            next;
        }

        eval {
            my $result      = fetch_module($safe_plugin);
            my $output_file = "$OUTPUT_BASE/$safe_plugin/metrics";
            write_json_file( $output_file, $result );
            log_msg("Exported: $safe_plugin -> $output_file");
            $success_count++;
        };

        if ($@) {
            warn "Failed to export $safe_plugin: $@\n";
            log_msg("Failed to export $safe_plugin: $@");
            $fail_count++;
        }
    }

    log_msg(
        "Batch export completed: $success_count succeeded, $fail_count failed");

}
elsif ( @ARGV == 1 ) {

    # Single plugin mode
    my $plugin = untaint( $ARGV[0] );

    if ( exists $METRICS{$plugin} ) {
        my $result      = fetch_module($plugin);
        my $output_file = "$OUTPUT_BASE/$plugin/metrics";
        write_json_file( $output_file, $result );
        log_msg("Exported: $plugin -> $output_file");
    }
    else {
        die "Unknown plugin: $plugin";
    }
}
else {
    # Full aggregate mode - no arguments
    my $result = {
        meta => {
            host      => $HOST,
            timestamp => $CURRENT_TIME,
            plugins   => [ keys %METRICS ],
        },
        plugins => {}
    };

    # Fetch each plugin's data
    for my $plugin ( keys %METRICS ) {
        $result->{plugins}{$plugin} = fetch_module($plugin);
    }

    my $output_file = $AGGREGATE_FILE;
    write_json_file( $output_file, $result );
    log_msg("Full aggregate export completed");
}
