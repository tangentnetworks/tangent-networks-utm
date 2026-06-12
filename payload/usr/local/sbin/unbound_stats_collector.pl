#!/usr/bin/perl

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# /usr/local/bin/unbound_stats_collector.pl
# Collects Unbound statistics and writes to JSON file
# Run via /etc/crontab: */5 * * * * root /usr/local/bin/unbound_stats_collector.pl

use strict;
use warnings;
use JSON::PP;
use POSIX qw(strftime);

# Configuration
my $UNBOUND_CONTROL = '/usr/sbin/unbound-control';
my $STATS_FILE      = '/var/www/htdocs/tn/data/db/unbound/stats.json';
my $WEB_USER        = 'www';
my $WEB_GROUP       = 'www';

# Collect statistics
sub collect_stats {
    my %stats = ();

    # Get raw stats from unbound-control
    my $raw_stats = `$UNBOUND_CONTROL stats_noreset 2>/dev/null`;

    if ( $? != 0 ) {
        warn "Failed to get unbound stats: $!\n";
        return undef;
    }

    # Parse stats into hash
    my %raw = ();
    foreach my $line ( split /\n/, $raw_stats ) {
        if ( $line =~ /^(.+?)=(.+)$/ ) {
            $raw{$1} = $2;
        }
    }

    # Calculate derived metrics
    my $total_queries = $raw{'total.num.queries'}        || 0;
    my $cache_hits    = $raw{'total.num.cachehits'}      || 0;
    my $cache_miss    = $raw{'total.num.cachemiss'}      || 0;
    my $prefetch      = $raw{'total.num.prefetch'}       || 0;
    my $recursion     = $raw{'total.recursion.time.avg'} || 0;

    # Cache hit rate
    my $hit_rate = 0;
    if ( $total_queries > 0 ) {
        $hit_rate = sprintf( "%.1f", ( $cache_hits / $total_queries ) * 100 );
    }

    # Memory usage
    my $mem_cache =
      ( $raw{'mem.cache.rrset'} || 0 ) + ( $raw{'mem.cache.message'} || 0 );
    my $mem_cache_mb = sprintf( "%.1f", $mem_cache / ( 1024 * 1024 ) );

    # Format for display
    $stats{timestamp}           = time();
    $stats{timestamp_formatted} = strftime( "%Y-%m-%d %H:%M:%S", localtime() );
    $stats{queries_total}       = format_number($total_queries);
    $stats{queries_cached}      = format_number($cache_hits);
    $stats{cache_hit_rate}      = $hit_rate . '%';
    $stats{cache_size}          = $mem_cache_mb . ' MB';
    $stats{uptime}              = format_uptime( $raw{'time.up'} || 0 );
    $stats{num_queries_ip_ratelimited} =
      format_number( $raw{'total.num.queries_ip_ratelimited'} || 0 );
    $stats{total_recursion}   = format_number($cache_miss);
    $stats{avg_response_time} = sprintf( "%.1f", $recursion ) . 'ms';

    # Raw stats for advanced users
    $stats{raw} = {
        cache_miss => $cache_miss,
        prefetch   => $prefetch,
        zero_ttl   => $raw{'total.num.zero_ttl'} || 0,
        expired    => $raw{'total.num.expired'}  || 0,
    };

    return \%stats;
}

# Format large numbers with commas
sub format_number {
    my $num = shift || 0;
    $num =~ s/(\d)(?=(\d{3})+(?!\d))/$1,/g;
    return $num;
}

# Format uptime in human-readable format
sub format_uptime {
    my $seconds = shift || 0;

    my $days    = int( $seconds / 86400 );
    my $hours   = int( ( $seconds % 86400 ) / 3600 );
    my $minutes = int( ( $seconds % 3600 ) / 60 );

    if ( $days > 0 ) {
        return sprintf( "%dd %dh %dm", $days, $hours, $minutes );
    }
    elsif ( $hours > 0 ) {
        return sprintf( "%dh %dm", $hours, $minutes );
    }
    else {
        return sprintf( "%dm", $minutes );
    }
}

# Write stats to JSON file
sub write_stats {
    my $stats = shift;

    # Create directory if it doesn't exist
    my $dir = $STATS_FILE;
    $dir =~ s|/[^/]+$||;
    unless ( -d $dir ) {
        mkdir $dir, 0755 or die "Cannot create directory $dir: $!\n";
    }

    # Write JSON atomically (write to temp, then rename)
    my $temp_file = "$STATS_FILE.tmp.$$";

    open( my $fh, '>', $temp_file ) or die "Cannot open $temp_file: $!\n";
    print $fh JSON::PP->new->pretty->encode($stats);
    close($fh);

    # Set permissions and ownership
    chmod 0644, $temp_file or warn "Cannot chmod $temp_file: $!\n";

    # Get uid/gid for www user
    my $uid = getpwnam($WEB_USER);
    my $gid = getgrnam($WEB_GROUP);

    if ( defined $uid && defined $gid ) {
        chown $uid, $gid, $temp_file or warn "Cannot chown $temp_file: $!\n";
    }
    else {
        warn "Cannot find www user/group\n";
    }

    # Atomic rename
    rename $temp_file, $STATS_FILE
      or die "Cannot rename $temp_file to $STATS_FILE: $!\n";

    return 1;
}

# Main execution
sub main {
    my $stats = collect_stats();

    unless ($stats) {
        warn "Failed to collect stats\n";
        exit 1;
    }

    unless ( write_stats($stats) ) {
        warn "Failed to write stats\n";
        exit 1;
    }

    # Success - silent exit
    exit 0;
}

# Run
main();
