#!/usr/bin/perl -T

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

use strict;
use warnings;
use JSON::XS;
use POSIX qw(strftime);

# --- Security: Untaint PATH ---
$ENV{PATH} = '/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin';
delete @ENV{ 'IFS', 'CDPATH', 'ENV', 'BASH_ENV' };

my $output_file = '/var/www/htdocs/tn/data/stats/pf_stats.json';

my $stats = {
    TS      => strftime( "%Y-%m-%d %H:%M:%S", localtime ),
    ID      => "Firewall_Stats",
    pf      => {},                                        # PF status and uptime
    metrics => {},                                        # State table metrics
    rules   => [],                                        # Rule-level counters
};

# --- Helper: Convert bytes to IEC units ---
sub bytes_to_iec {
    my ($bytes)    = @_;
    my @units      = ( 'B', 'KiB', 'MiB', 'GiB', 'TiB' );
    my $unit_index = 0;
    while ( $bytes >= 1024 && $unit_index < $#units ) {
        $bytes /= 1024;
        $unit_index++;
    }
    return sprintf( "%.2f %s", $bytes, $units[$unit_index] );
}

# --- 1. PF Status and Uptime ---
my $systat_data = `systat -n pf 2>&1`;
foreach my $line ( split( /\n/, $systat_data ) ) {
    if ( $line =~ /pf Status\s+(\S+)/ ) {
        $stats->{pf}->{status} = $1;
    }
    elsif ( $line =~ /pf Since\s+(\S+)/ ) {
        $stats->{pf}->{since} = $1;
    }
}

# --- 2. State Table Metrics (pfctl -si) ---
open( my $fh, "-|", "pfctl -si" ) or die "Cannot run pfctl: $!";
while (<$fh>) {
    if (/current entries\s+(\d+)/) { $stats->{metrics}->{current}   = int($1); }
    if (/searches\s+(\d+)/)        { $stats->{metrics}->{searches}  = int($1); }
    if (/inserts\s+(\d+)/)         { $stats->{metrics}->{inserts}   = int($1); }
    if (/removals\s+(\d+)/)        { $stats->{metrics}->{removals}  = int($1); }
    if (/States\s+(\d+)/)          { $stats->{metrics}->{states}    = int($1); }
    if (/Src Nodes\s+(\d+)/)       { $stats->{metrics}->{src_nodes} = int($1); }
}
close($fh);

# --- 3. Rule-Level Counters (pfctl -vvsr) ---
open( $fh, "-|", "pfctl -vvsr" ) or die "Cannot run pfctl -vvsr: $!";
my $rule;
while (<$fh>) {
    if (/^@(\d+)/) {
        $rule =
          { id => $1, evaluations => 0, packets => 0, bytes => 0, states => 0 };
        push @{ $stats->{rules} }, $rule;
    }
    elsif ( $rule
        && /Evaluations:\s+(\d+)\s+Packets:\s+(\d+)\s+Bytes:\s+(\d+)\s+States:\s+(\d+)/
      )
    {
        my $evals   = int($1);
        my $packets = int($2);
        my $bytes   = int($3);
        my $states  = int($4);

        # Improved Efficiency Calculation
        my $ratio       = ( $packets > 0 ) ? ( $evals / $packets ) : 0;
        my $status_text = "Efficient";

        if ( $packets == 0 && $evals > 0 ) {
            $status_text = "Unused";
            $ratio =
              $evals;  # In this context, ratio shows how many evals were wasted
        }
        elsif ( $ratio > 20 ) {
            $status_text = "Optimize";
        }
        elsif ( $ratio > 5 ) {
            $status_text = "Review";
        }

        $rule->{evaluations} = $evals;
        $rule->{packets}     = $packets;
        $rule->{raw_bytes}   = $bytes;
        $rule->{bytes}       = bytes_to_iec($bytes);
        $rule->{states}      = $states;
        $rule->{ratio}       = $ratio;
        $rule->{status_text} = $status_text;
    }
}
close($fh);

# --- 4. Generate and Write JSON ---
my $json_out = JSON::XS->new->pretty->canonical->encode($stats);
open( my $out, ">", $output_file ) or die "Cannot open $output_file: $!";
print $out $json_out;
close($out);

# --- 5. Set Ownership and Permissions ---
my $uid = getpwnam('www');
my $gid = getgrnam('www');
if ( defined $uid && defined $gid ) {
    chown( $uid, $gid, $output_file );
}
chmod( 0644, $output_file );

# --- 6. Output JSON (with CGI header if applicable) ---
if ( exists $ENV{GATEWAY_INTERFACE} ) {
    print "Content-Type: application/json\n\n";
}
print $json_out;
