#!/usr/bin/perl -T

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# /usr/local/sbin/dhcpd_lease_watcher.pl
# Watches /var/db/dhcpd.leases for new lease assignments.
# Writes normalised log entries to data/logs/dhcpd/dhcpd.log.
# Called every 5 seconds by dhcpd_lease_watcher_runner.sh.

use strict;
use warnings;
use Fcntl       qw(:flock);
use POSIX       qw(strftime);
use Time::Local qw(timegm);

$ENV{PATH} = '/sbin:/usr/sbin:/bin:/usr/bin:/usr/local/sbin:/usr/local/bin';
delete @ENV{qw(IFS CDPATH ENV BASH_ENV)};

my $LEASE_FILE = '/var/db/dhcpd.leases';
my $LOG_FILE   = '/var/www/htdocs/tn/data/logs/dhcpd/dhcpd.log';
my $STATE_FILE = '/var/www/htdocs/tn/data/logs/dhcpd/dhcpd_watcher.state';
my $MTIME_FILE = '/var/www/htdocs/tn/data/logs/dhcpd/dhcpd_watcher.mtime';
my $LOG_DIR    = '/var/www/htdocs/tn/data/logs/dhcpd';
my $STATE_DAYS = 30;    # prune processed lease keys older than this

# Lease file must exist
exit 0 unless -f $LEASE_FILE;

# Get current mtime
my $current_mtime = ( stat($LEASE_FILE) )[9];
exit 0 unless defined $current_mtime;

# Read last known mtime
my $last_mtime = 0;
if ( -f $MTIME_FILE ) {
    open( my $fh, '<', $MTIME_FILE ) or exit 0;
    my $line = <$fh>;
    close $fh;
    if ( defined $line ) {
        chomp $line;
        ($last_mtime) = ( $line =~ /^(\d+)$/ ) ? ($1) : (0);
    }
}

# No change since last run
exit 0 if $current_mtime == $last_mtime;

# Load already-processed lease keys: epoch|ip|mac -> 1
# Prune entries older than STATE_DAYS on load
my %processed;
my $cutoff = time() - ( $STATE_DAYS * 86400 );
if ( -f $STATE_FILE ) {
    open( my $fh, '<', $STATE_FILE ) or exit 0;
    while ( my $line = <$fh> ) {
        chomp $line;

        # Format: epoch|ip|mac
        my ( $epoch, $ip, $mac ) = $line =~ /^(\d+)\|([\d.]+)\|([\da-f:]+)$/i;
        next unless defined $epoch && defined $ip && defined $mac;
        next if $epoch < $cutoff;    # prune old entries
        $processed{"$ip|$mac"} = $epoch;
    }
    close $fh;
}

# Parse lease file
my @new_leases;
{
    open( my $fh, '<', $LEASE_FILE ) or exit 0;
    local $/;
    my $raw = <$fh>;
    close $fh;

    # Untaint
    my ($content) = ( $raw =~ /^(.*)$/s );
    exit 0 unless defined $content;

    # Each lease block: lease IP { ... }
    while ( $content =~ /lease\s+([\d.]+)\s*\{([^}]+)\}/gs ) {
        my ( $ip, $block ) = ( $1, $2 );

        # Validate IP
        next unless $ip =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;

        my ($starts_raw) = $block =~ /starts\s+\d+\s+([\d\/]+\s+[\d:]+)/;
        my ($ends_raw)   = $block =~ /ends\s+\d+\s+([\d\/]+\s+[\d:]+)/;
        my ($mac)        = $block =~ /hardware\s+ethernet\s+([\da-f:]+)/i;
        my ($hostname)   = $block =~ /client-hostname\s+"([^"]{1,64})"/;

        next unless defined $starts_raw && defined $mac;

        # Validate and untaint fields
        ($starts_raw) =
          ( $starts_raw =~ /^(\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2})$/ )
          or next;
        ($mac) = ( $mac =~ /^([\da-f:]{17})$/i ) or next;
        $mac = lc $mac;
        $ends_raw =
          defined $ends_raw
          ? ( $ends_raw =~ /^(\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2})$/
            ? $1
            : undef )
          : undef;
        $hostname =
          defined $hostname
          ? ( $hostname =~ /^([\w._-]{1,64})$/ ? $1 : 'unknown' )
          : 'unknown';

# Convert starts (UTC in lease file) to epoch using timegm, format in local time
        my ( $y, $mo, $d, $h, $mi, $s ) =
          $starts_raw =~ /(\d{4})\/(\d{2})\/(\d{2}) (\d{2}):(\d{2}):(\d{2})/;
        my $starts_epoch =
          eval { timegm( $s, $mi, $h, $d, $mo - 1, $y - 1900 ) };
        next unless defined $starts_epoch && $starts_epoch > 0;

        # Dedup key: ip|mac
        my $dedup_key = "$ip|$mac";
        if ( exists $processed{$dedup_key} ) {
            next if $processed{$dedup_key} == $starts_epoch;
        }

        # Format timestamps in local time for log line
        my $starts_log =
          strftime( '%Y-%m-%d %H:%M:%S', localtime($starts_epoch) );

        my $ends_log = 'never';
        if ( defined $ends_raw ) {
            my ( $ey, $emo, $ed, $eh, $emi, $es ) =
              $ends_raw =~ /(\d{4})\/(\d{2})\/(\d{2}) (\d{2}):(\d{2}):(\d{2})/;
            my $ends_epoch =
              eval { timegm( $es, $emi, $eh, $ed, $emo - 1, $ey - 1900 ) };
            $ends_log =
              defined $ends_epoch
              ? strftime( '%Y-%m-%d %H:%M:%S', localtime($ends_epoch) )
              : 'unknown';
        }

        push @new_leases,
          {
            ip           => $ip,
            mac          => $mac,
            hostname     => $hostname,
            starts_log   => $starts_log,
            ends_log     => $ends_log,
            starts_epoch => $starts_epoch,
            dedup_key    => $dedup_key,
          };
    }
}

exit 0 unless @new_leases;

# Ensure log directory exists
unless ( -d $LOG_DIR ) {
    mkdir $LOG_DIR, 0755 or exit 0;
    chown 0, ( getgrnam('wheel') )[2], $LOG_DIR;
}

# Write new entries to log
open( my $log_fh, '>>', $LOG_FILE ) or exit 0;
flock( $log_fh, LOCK_EX )           or do { close $log_fh; exit 0; };

for my $lease ( sort { $a->{starts_epoch} <=> $b->{starts_epoch} } @new_leases )
{
    printf $log_fh "%s DHCPACK ip=%-15s mac=%-17s hostname=%-24s expires=%s\n",
      $lease->{starts_log},
      $lease->{ip},
      $lease->{mac},
      $lease->{hostname},
      $lease->{ends_log};

    $processed{ $lease->{dedup_key} } = $lease->{starts_epoch};
}

flock( $log_fh, LOCK_UN );
close $log_fh;

# Rewrite state file with current (pruned) processed set
open( my $state_fh, '>', $STATE_FILE ) or exit 0;
for my $key ( keys %processed ) {
    my ( $ip, $mac ) = split /\|/, $key;
    printf $state_fh "%d|%s|%s\n", $processed{$key}, $ip, $mac;
}
close $state_fh;

# Update mtime file
open( my $mtime_fh, '>', $MTIME_FILE ) or exit 0;
print $mtime_fh "$current_mtime\n";
close $mtime_fh;

exit 0;
