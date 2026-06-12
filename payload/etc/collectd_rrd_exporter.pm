#!/usr/bin/perl -T
# /etc/collectd_rrd_exporter.pm
# Taint-safe RRD fetcher for collectd_exporter.pl fallback
# Handles NaN gracefully, provides display-ready output, IEC conversion for all metrics

package collectd_rrd_exporter;

use strict;
use warnings;
use RRDs;
use Exporter 'import';
use Readonly;
use POSIX qw(isnan);

# Path to the boot-time reconciler override (written by collectd_reconciler.pm)
my $OVERRIDE_FILE = '/etc/collectd_rrd_map_override.pm';

# ----------------------------
# Constants and Configuration
# ----------------------------
Readonly our $RRD_BASE => '/var/www/htdocs/tn/data/rrd/collectd/tangent';

our @EXPORT_OK = qw(fetch_from_rrd);

# ----------------------------
# IEC Units for byte conversion
# ----------------------------
Readonly my %IEC_UNITS => (
    1024               => 'KiB',
    1024 * 1024        => 'MiB',
    1024 * 1024 * 1024 => 'GiB',
);

# ----------------------------
# Metric ID to RRD Path Mapping
# Maps collectd ID format to actual RRD file paths
# ----------------------------
Readonly my %ID_TO_RRD => (

    # CPU
    'tangent/cpu_avg-cpu-average/cpu' =>
      "$RRD_BASE/cpu_avg-cpu-average/cpu.rrd",

    # Memory
    'tangent/memory/memory-active'   => "$RRD_BASE/memory/memory-active.rrd",
    'tangent/memory/memory-inactive' => "$RRD_BASE/memory/memory-inactive.rrd",
    'tangent/memory/memory-free'     => "$RRD_BASE/memory/memory-free.rrd",

    # Load
    'tangent/load/load' => "$RRD_BASE/load/load.rrd",

    # Swap
    'tangent/swap/swap-used'          => "$RRD_BASE/swap/swap-used.rrd",
    'tangent/swap/swap-free'          => "$RRD_BASE/swap/swap-free.rrd",
    'tangent/swap-dev_sd1b/swap-used' =>
      "$RRD_BASE/swap-dev_sd1b/swap-used.rrd",
    'tangent/swap-dev_sd1b/swap-free' =>
      "$RRD_BASE/swap-dev_sd1b/swap-free.rrd",

    # Disk Filesystem
    'tangent/df-root/df_complex-free' =>
      "$RRD_BASE/df-root/df_complex-free.rrd",
    'tangent/df-root/df_complex-reserved' =>
      "$RRD_BASE/df-root/df_complex-reserved.rrd",
    'tangent/df-root/df_complex-used' =>
      "$RRD_BASE/df-root/df_complex-used.rrd",

    # Disk I/O
    'tangent/disk-sd1/disk_octets' => "$RRD_BASE/disk-sd1/disk_octets.rrd",

    # Network Interfaces
    'tangent/interface-%%EXT_IF%%/if_octets' =>
      "$RRD_BASE/interface-%%EXT_IF%%/if_octets.rrd",
    'tangent/interface-%%EXT_IF%%/if_packets' =>
      "$RRD_BASE/interface-%%EXT_IF%%/if_packets.rrd",
    'tangent/interface-%%EXT_IF%%/if_errors' =>
      "$RRD_BASE/interface-%%EXT_IF%%/if_errors.rrd",
    'tangent/interface-%%INT_IF%%/if_octets' =>
      "$RRD_BASE/interface-%%INT_IF%%/if_octets.rrd",
    'tangent/interface-%%INT_IF%%/if_packets' =>
      "$RRD_BASE/interface-%%INT_IF%%/if_packets.rrd",
    'tangent/interface-%%INT_IF%%/if_errors' =>
      "$RRD_BASE/interface-%%INT_IF%%/if_errors.rrd",
    'tangent/interface-lo0/if_octets' =>
      "$RRD_BASE/interface-lo0/if_octets.rrd",
    'tangent/interface-lo0/if_packets' =>
      "$RRD_BASE/interface-lo0/if_packets.rrd",
    'tangent/interface-lo0/if_errors' =>
      "$RRD_BASE/interface-lo0/if_errors.rrd",

    # Ping
    'tangent/ping/ping-1.1.1.1'          => "$RRD_BASE/ping/ping-1.1.1.1.rrd",
    'tangent/ping/ping-'                 => "$RRD_BASE/ping/ping-.rrd",
    'tangent/ping/ping_droprate-1.1.1.1' =>
      "$RRD_BASE/ping/ping_droprate-1.1.1.1.rrd",
    'tangent/ping/ping_droprate-'      => "$RRD_BASE/ping/ping_droprate-.rrd",
    'tangent/ping/ping_stddev-1.1.1.1' =>
      "$RRD_BASE/ping/ping_stddev-1.1.1.1.rrd",
    'tangent/ping/ping_stddev-' => "$RRD_BASE/ping/ping_stddev-.rrd",

    # System
    'tangent/uptime/uptime' => "$RRD_BASE/uptime/uptime.rrd",
    'tangent/users/users'   => "$RRD_BASE/users/users.rrd",
);

# Auto-generate PF metrics mapping
sub _generate_pf_mappings {
    my %mappings;

    # PF Counters (Standard hyphenated names)
    for my $counter (
        qw(bad-offset bad-timestamp congestion fragment ip-option match memory
        no-route normalize proto-cksum short src-limit state-insert state-limit
        state-mismatch synproxy translate)
      )
    {
        $mappings{"tangent/pf/pf_counters-$counter"} =
          "$RRD_BASE/pf/pf_counters-$counter.rrd";
    }

    # PF Limits - Handle literal spaces as seen on OpenBSD disk and LISTVAL
    my @pf_limits = (
        'max states per rule',
        'max-src-conn',
        'max-src-conn-rate',
        'max-src-nodes',
        'max-src-states',
        'overload flush states',
        'overload table insertion',
        'syncookies sent',
        'syncookies validated',
        'synfloods detected'
    );

    for my $limit (@pf_limits) {
        my $path = "$RRD_BASE/pf/pf_limits-$limit.rrd";

        # 1. Map the literal ID (with spaces) from LISTVAL
        $mappings{"tangent/pf/pf_limits-$limit"} = $path;

        # 2. Map the hyphenated alias used by the exporter script
        my $hyphenated = $limit;
        $hyphenated =~ s/ /-/g;
        $mappings{"tangent/pf/pf_limits-$hyphenated"} = $path
          if $hyphenated ne $limit;
    }

    # PF Source and State
    for my $src (qw(insert removals search)) {
        $mappings{"tangent/pf/pf_source-$src"} =
          "$RRD_BASE/pf/pf_source-$src.rrd";
        $mappings{"tangent/pf/pf_state-$src"} =
          "$RRD_BASE/pf/pf_state-$src.rrd";
    }
    $mappings{"tangent/pf/pf_states-current"} =
      "$RRD_BASE/pf/pf_states-current.rrd";

    return %mappings;
}

# Auto-generate process metrics mapping
sub _generate_process_mappings {
    my %mappings;
    my @processes =
      qw(e2guardian clamd freshclam ftpproxy pflogd pmacctd smtp-gated smtpd
      snort snortsentry sockd sslproxy unbound httpd ntpd cron sshd p3scan dhcpd);
    my @metrics =
      qw(ps_code ps_count ps_cputime ps_data ps_pagefaults ps_rss ps_stacksize ps_vm);

    for my $proc (@processes) {
        for my $metric (@metrics) {
            $mappings{"tangent/processes-$proc/$metric"} =
              "$RRD_BASE/processes-$proc/$metric.rrd";
        }
    }

    return %mappings;
}

# Build complete static ID to RRD mapping (baseline / fallback)
Readonly my %COMPLETE_ID_MAP =>
  ( %ID_TO_RRD, _generate_pf_mappings(), _generate_process_mappings() );

# ----------------------------
# Load override map from collectd_reconciler.pm (merged at module load time)
# The override is authoritative: its entries win over %COMPLETE_ID_MAP.
# This is intentional -- the reconciler has ground truth from the live RRD
# tree and tn-interfaces; the static map above is only a compile-time baseline.
# A load error in the override never crashes the exporter -- it warns and
# falls back to the static map cleanly.
# ----------------------------
my %_OVERRIDE_MAP;

{
    if ( -f $OVERRIDE_FILE ) {
        my $result = do $OVERRIDE_FILE;
        if ($@) {
            warn "collectd_rrd_exporter: override load error: $@\n";
        }
        elsif ( !defined $result ) {
            warn
"collectd_rrd_exporter: could not read override $OVERRIDE_FILE: $!\n";
        }
        elsif ( collectd_rrd_map_override->can('get_map') ) {
            %_OVERRIDE_MAP = %{ collectd_rrd_map_override::get_map() };
            warn "collectd_rrd_exporter: loaded "
              . scalar( keys %_OVERRIDE_MAP )
              . " override entries from $OVERRIDE_FILE\n"
              if $ENV{TN_DEBUG};
        }
        else {
            warn
"collectd_rrd_exporter: override loaded but get_map() missing -- ignoring\n";
        }
    }
    else {
        warn "collectd_rrd_exporter: no override file at $OVERRIDE_FILE"
          . " -- run collectd_reconciler.pm to generate it\n";
    }
}

# Merged map: override entries win, static map fills everything else
my %ACTIVE_ID_MAP = ( %COMPLETE_ID_MAP, %_OVERRIDE_MAP );

# ----------------------------
# Untaint helper
# ----------------------------
#sub untaint {
#    my ($value) = @_;
#    return undef unless defined $value;
#    $value =~ /^([\w.\-\/_]+)$/ or die "Tainted value rejected: $value";
#    return $1;
#}

sub untaint {
    my ($value) = @_;
    return undef unless defined $value;

    # Add \s to the allowed character set to support RRD filenames with spaces
    $value =~ /^([\w.\-\/_\s]+)$/ or die "Tainted value rejected: $value";
    return $1;
}

# ----------------------------
# Convert bytes to IEC units with display string
# ----------------------------
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

    foreach my $divisor ( sort { $b <=> $a } keys %IEC_UNITS ) {
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

# ----------------------------
# Format metric value based on type
# ----------------------------
sub format_metric {
    my ( $value, $id ) = @_;

    # Apply IEC conversion for memory, disk, swap, network octets
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

    # Page faults (just a count)
    if ( $id =~ /ps_pagefaults/ ) {
        return {
            display => sprintf( "%.0f", $value ),
            value   => int($value),
            status  => 'ok'
        };
    }

    # Load average
    #if ($id =~ /load/) {
    #    return {
    #        display => sprintf("%.2f", $value),
    #        value   => sprintf("%.2f", $value),
    #        status  => 'ok'
    #    };
    #}

    if ( $id =~ /\/load\// ) {
        return {
            display => sprintf( "%.2f", $value ),
            value   => sprintf( "%.2f", $value ),
            status  => 'ok'
        };
    }

    # Ping latency (milliseconds)
    if ( $id =~ /ping/ && $id !~ /droprate|stddev/ ) {
        return {
            display => sprintf( "%.2f ms", $value ),
            value   => sprintf( "%.2f",    $value ),
            unit    => 'ms',
            status  => 'ok'
        };
    }

    # Ping droprate (percentage)
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

    # Network packets/errors (counts)
    if ( $id =~ /if_packets|if_errors/ ) {
        return {
            display => sprintf( "%.0f", $value ),
            value   => int($value),
            status  => 'ok'
        };
    }

    # PF counters (counts)
    #if ($id =~ /pf_counters|pf_state|pf_source|pf_limits|pf_states/) {
    #    return {
    #        display => sprintf("%.0f", $value),
    #        value   => int($value),
    #        status  => 'ok'
    #    };
    #}

    if ( $id =~ /pf_(counters|state|source|limits|states)/ ) {
        return {
            display => sprintf( "%.0f", $value ),
            value   => int($value),
            status  => 'ok'
        };
    }

    # Users count
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

# ----------------------------
# Resolve NaN with smart defaults
# ----------------------------
sub resolve_nan {
    my ($id) = @_;

    # Process count: 0 means stopped
    if ( $id =~ /ps_count/ ) {
        return {
            display => "0 (stopped)",
            value   => 0,
            status  => 'stopped'
        };
    }

    # Process resources: unavailable
    if (
        $id =~ /processes.*ps_(rss|vm|data|code|stacksize|cputime|pagefaults)/ )
    {
        return {
            display => "—",
            value   => 0,
            status  => 'unavailable'
        };
    }

    # Memory/CPU/Load: should not happen, but handle gracefully
    #if ($id =~ /memory|^tangent\/cpu|load/) {
    #    return {
    #        display => "— (no data)",
    #        value   => 0,
    #        status  => 'unknown'
    #    };
    #}

    if ( $id =~ /memory|^tangent\/cpu|\/load\// ) {
        return {
            display => "— (no data)",
            value   => 0,
            status  => 'unknown'
        };
    }

  # Counters (PF, network): 0 is safe
  #if ($id =~ /pf_counters|pf_state|pf_source|pf_limits|if_packets|if_errors/) {
  #    return {
  #        display => "0",
  #        value   => 0,
  #        status  => 'ok'
  #    };
  #}

    if ( $id =~ /pf_(counters|state|source|limits|states)|if_(packets|errors)/ )
    {
        return {
            display => "0",
            value   => 0,
            status  => 'ok'
        };
    }

    # Network octets: 0 bytes
    if ( $id =~ /if_octets|disk_octets/ ) {
        return {
            display => "0 B",
            value   => 0,
            unit    => 'B',
            raw     => 0,
            status  => 'ok'
        };
    }

    # Ping: show as unavailable
    if ( $id =~ /ping/ ) {
        return {
            display => "—",
            value   => 0,
            status  => 'unavailable'
        };
    }

    # Default: no data
    return {
        display => "—",
        value   => 0,
        status  => 'unknown'
    };
}

# ----------------------------
# Fetch data from RRD file
# ----------------------------
sub fetch_from_rrd {
    my ($id) = @_;
    my $safe_id = untaint($id);

    # Look up RRD path -- override map takes precedence over static map
    my $rrd_path = $ACTIVE_ID_MAP{$safe_id};

    unless ( defined $rrd_path && -f $rrd_path ) {
        warn "No RRD file found for ID: $id (path: "
          . ( $rrd_path // 'undef' ) . ")";
        return {
            id        => $id,
            timestamp => time,
            values    => resolve_nan($id),
            source    => 'rrd'
        };
    }

    # Fetch last 5 minutes of data
    my ( $start, $step, $ds_names, $data ) =
      RRDs::fetch( $rrd_path, 'AVERAGE', '--start', time - 300, '--end', time );

    my $err = RRDs::error;
    if ($err) {
        warn "RRDs::fetch error for $id: $err";
        return {
            id        => $id,
            timestamp => time,
            values    => resolve_nan($id),
            source    => 'rrd'
        };
    }

    # Handle multi-DS metrics (like CPU with idle, system, user, etc.)
    if ( scalar(@$ds_names) > 1 ) {

        # Multi-DS metric: scan backwards for last non-NaN values for each DS
        my %ds_values;

        for my $ds_idx ( 0 .. $#$ds_names ) {
            my $ds_name     = $ds_names->[$ds_idx];
            my $found_value = undef;

            # Scan backwards through data
            for my $row ( reverse @$data ) {
                my $val = $row->[$ds_idx];
                if ( defined $val && !isnan($val) ) {
                    $found_value = $val;
                    last;
                }
            }

            if ( defined $found_value ) {
                $ds_values{$ds_name} = format_metric( $found_value, $id );
            }
            else {
                $ds_values{$ds_name} = resolve_nan($id);
            }
        }

        return {
            id        => $id,
            timestamp => time,
            values    => \%ds_values,
            source    => 'rrd'
        };
    }

    # Single-DS metric: scan backwards for last non-NaN value
    my $latest_value = undef;
    for my $row ( reverse @$data ) {
        my $val = $row->[0];
        if ( defined $val && !isnan($val) ) {
            $latest_value = $val;
            last;
        }
    }

    # Handle NaN or missing data
    if ( !defined $latest_value ) {
        return {
            id        => $id,
            timestamp => time,
            values    => { value => resolve_nan($id) },
            source    => 'rrd'
        };
    }

    # Format and return the value
    return {
        id        => $id,
        timestamp => time,
        values    => { value => format_metric( $latest_value, $id ) },
        source    => 'rrd'
    };
}

1;
