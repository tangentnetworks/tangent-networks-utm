#!/usr/bin/perl -T

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# /usr/local/sbin/get_geoip_data.pl
#
# Fetches GeoIP country data and ASN prefixes from RIPE
# Runs as root via cron (not a CGI)
#
# SECURITY:
# - Taint mode enabled
# - Safe command execution
# - Path validation
# - No user input (config is hardcoded)

use strict;
use warnings;
use File::Path qw(make_path);
use POSIX      qw(strftime);

# Clean environment for taint mode
$ENV{PATH} = '/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin';
delete @ENV{ 'IFS', 'CDPATH', 'ENV', 'BASH_ENV' };

# ============================================
# CONFIGURATION
# ============================================
my @TARGET_ASNS = qw( AS15169 AS13335 AS16509 );    # Google, Cloudflare, Amazon
my $BASE_DIR    = "/var/www/htdocs/tn/data/db/GeoIP";
my $RIPE_URL =
  "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-latest";
my $LOG_FILE = "/var/log/geoip_update.log";

# Subdirectories
my $V4_DIR  = "$BASE_DIR/ipv4";
my $V6_DIR  = "$BASE_DIR/ipv6";
my $ASN_DIR = "$BASE_DIR/ASN";

# ============================================
# LOGGING
# ============================================
sub log_msg {
    my ($msg) = @_;
    my $ts = strftime( '%Y-%m-%d %H:%M:%S', localtime );

    if ( open my $fh, '>>', $LOG_FILE ) {
        print $fh "[$ts] $msg\n";
        close $fh;
    }

    print "[$ts] $msg\n";
}

# ============================================
# SAFE PATH VALIDATION
# ============================================
sub validate_base_dir {
    my ($dir) = @_;

    # Must be under /var/www/htdocs
    if ( $dir =~ m{^(/var/www/htdocs/[a-zA-Z0-9/_.-]+)$} ) {
        return $1;
    }

    die "FATAL: Invalid base directory: $dir\n";
}

# ============================================
# PREPARE DIRECTORIES
# ============================================
$BASE_DIR = validate_base_dir($BASE_DIR);
$V4_DIR   = "$BASE_DIR/ipv4";
$V6_DIR   = "$BASE_DIR/ipv6";
$ASN_DIR  = "$BASE_DIR/ASN";

make_path( $V4_DIR, $V6_DIR, $ASN_DIR, { mode => 0755 } );

log_msg("GeoIP update started");
log_msg("Target directory: $BASE_DIR");

# ============================================
# CLEAN OLD DATA
# ============================================
log_msg("Cleaning old data...");

# Safe unlink with validated paths
opendir( my $dh_v4, $V4_DIR ) or die "Cannot open $V4_DIR: $!";
while ( my $file = readdir($dh_v4) ) {
    next unless $file =~ /^([A-Z]{2})\.txt$/;
    my $safe_file = $1;
    unlink "$V4_DIR/$safe_file.txt";
}
closedir($dh_v4);

opendir( my $dh_v6, $V6_DIR ) or die "Cannot open $V6_DIR: $!";
while ( my $file = readdir($dh_v6) ) {
    next unless $file =~ /^([A-Z]{2})\.txt$/;
    my $safe_file = $1;
    unlink "$V6_DIR/$safe_file.txt";
}
closedir($dh_v6);

opendir( my $dh_asn, $ASN_DIR ) or die "Cannot open $ASN_DIR: $!";
while ( my $file = readdir($dh_asn) ) {
    next unless $file =~ /^(AS\d+)\.txt$/;
    my $safe_file = $1;
    unlink "$ASN_DIR/$safe_file.txt";
}
closedir($dh_asn);

# ============================================
# PROCESS COUNTRIES
# Safe pipe with explicit command
# ============================================
log_msg("Fetching RIPE country data...");

# Untaint URL (hardcoded, but validate anyway)
my $safe_url = $RIPE_URL;
if ( $RIPE_URL =~ m{^(https://[a-zA-Z0-9./_-]+)$} ) {
    $safe_url = $1;
}
else {
    die "FATAL: Invalid RIPE URL\n";
}

# Safe open with list form (no shell injection)
open( my $pipe, '-|', 'ftp', '-o', '-', $safe_url )
  or die "FTP pipe failed: $!";

my $country_count = 0;

while ( my $line = <$pipe> ) {
    next if $line =~ /^#/;

    my @fields = split( /\|/, $line );

    # Validate country code
    next unless ( defined $fields[1] && $fields[1] =~ /^([A-Z]{2})$/ );
    my $country = $1;    # Untainted

    # Validate allocation status
    next
      unless ( defined $fields[6] && $fields[6] =~ /^(allocated|assigned)$/ );

    if ( defined $fields[2] && $fields[2] eq 'ipv4' ) {

        # Validate IP and count
        next unless ( $fields[3] =~ /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/ );
        my $ip = $1;
        next unless ( $fields[4] =~ /^(\d+)$/ );
        my $count = $1;

        # Calculate prefix length
        my $prefix_len = 32 - ( log($count) / log(2) );
        $prefix_len = int( $prefix_len + 0.5 );    # Round

        # Write to country file
        my $file = "$V4_DIR/$country.txt";
        if ( open my $fh, '>>', $file ) {
            print $fh "$ip/$prefix_len\n";
            close $fh;
        }
    }
    elsif ( defined $fields[2] && $fields[2] eq 'ipv6' ) {

        # Validate IPv6
        next unless ( $fields[3] =~ /^([0-9a-fA-F:]+)$/ );
        my $ipv6 = $1;
        next unless ( $fields[4] =~ /^(\d+)$/ );
        my $prefix = $1;

        # Write to country file
        my $file = "$V6_DIR/$country.txt";
        if ( open my $fh, '>>', $file ) {
            print $fh "$ipv6/$prefix\n";
            close $fh;
        }
    }

    $country_count++;
}

close($pipe);
log_msg("Processed $country_count country allocations");

# ============================================
# PROCESS ASNS
# ============================================
log_msg("Processing ASNs with curation...");

foreach my $asn (@TARGET_ASNS) {

    # Validate ASN format
    unless ( $asn =~ /^(AS\d{1,10})$/ ) {
        log_msg("WARNING: Invalid ASN format: $asn - skipping");
        next;
    }
    my $safe_asn = $1;

    log_msg("  Fetching $safe_asn...");

    my $url =
"https://stat.ripe.net/data/ris-prefixes/data.json?resource=$safe_asn&list_prefixes=true";

    # Safe pipe execution
    my $json_raw;
    {
        open( my $fh, '-|', 'ftp', '-o', '-', $url ) or do {
            log_msg("  WARNING: Failed to fetch $safe_asn");
            next;
        };
        local $/;
        $json_raw = <$fh>;
        close($fh);
    }

    unless ($json_raw) {
        log_msg("  WARNING: Empty response for $safe_asn");
        next;
    }

    # Extract IPv4 CIDRs
    my @v4_raw = ( $json_raw =~ m/"(\d{1,3}(?:\.\d{1,3}){3}\/\d+)"/g );

    unless (@v4_raw) {
        log_msg("  WARNING: No prefixes found for $safe_asn");
        next;
    }

    # Curate and merge
    my @curated = curate_ipv4(@v4_raw);

    # Write to file
    my $file = "$ASN_DIR/$safe_asn.txt";
    if ( open my $fh, '>', $file ) {
        print $fh join( "\n", @curated ) . "\n";
        close $fh;
        chmod 0644, $file;

        log_msg(
            sprintf(
                "  %s: %d -> %d prefixes (merged)",
                $safe_asn, scalar(@v4_raw), scalar(@curated)
            )
        );
    }
    else {
        log_msg("  WARNING: Failed to write $file: $!");
    }
}

log_msg("GeoIP update complete");
log_msg("Files written to: $BASE_DIR");

exit 0;

# ============================================
# HELPER: IPv4 CURATION LOGIC
# ============================================
sub curate_ipv4 {
    my @ranges;

    for my $cidr (@_) {

        # Parse CIDR
        my ( $ip, $mask ) = split( /\//, $cidr );
        next unless ( defined $ip && defined $mask );
        next unless ( $mask =~ /^\d+$/ && $mask >= 0 && $mask <= 32 );

        my @octets = split( /\./, $ip );
        next unless ( @octets == 4 );

        # Convert to integer range
        my $start =
          ( $octets[0] << 24 ) +
          ( $octets[1] << 16 ) +
          ( $octets[2] << 8 ) +
          $octets[3];
        my $end = $start + ( 2**( 32 - $mask ) ) - 1;

        push @ranges, { s => $start, e => $end };
    }

    return () unless @ranges;

    # Sort by start IP, then by end IP (descending)
    @ranges = sort { $a->{s} <=> $b->{s} || $b->{e} <=> $a->{e} } @ranges;

    # Merge overlapping ranges
    my @merged;
    my $current = shift @ranges;

    foreach my $next (@ranges) {
        if ( $next->{s} <= $current->{e} + 1 ) {

            # Overlapping or adjacent - merge
            $current->{e} = $next->{e} if $next->{e} > $current->{e};
        }
        else {
            # Gap - save current and start new
            push @merged, $current;
            $current = $next;
        }
    }
    push @merged, $current;

    # Convert back to CIDR notation
    return map { int_to_cidr( $_->{s}, $_->{e} ) } @merged;
}

sub int_to_cidr {
    my ( $start, $end ) = @_;
    my @result;

    while ( $end >= $start ) {
        my $maxsize = 32;

        while ( $maxsize > 0 ) {
            my $mask    = $maxsize - 1;
            my $masklen = 2**( 32 - $mask );

            last
              if ( ( $start % $masklen ) != 0
                || ( $start + $masklen - 1 ) > $end );
            $maxsize = $mask;
        }

        # Convert integer to dotted quad
        my $ip = join( '.',
            ( $start >> 24 ) & 255,
            ( $start >> 16 ) & 255,
            ( $start >> 8 ) & 255,
            $start & 255 );

        push @result, "$ip/$maxsize";
        $start += 2**( 32 - $maxsize );
    }

    return @result;
}

__END__

=head1 NAME

get_geoip_data.pl - Fetch GeoIP country and ASN prefix data

=head1 DESCRIPTION

Downloads and processes:
- Country IPv4/IPv6 allocations from RIPE
- ASN prefix lists from RIPE stat API

Output stored in /var/www/htdocs/tn/data/db/GeoIP/

=head1 USAGE

Run via /etc/crontab as root:
  30 12 * * *     root    /usr/local/sbin/get_geoip_data.pl

=head1 SECURITY

Runs in taint mode with validated paths and safe command execution.

=cut
