#!/usr/bin/perl -T

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# ---
# Description: Reverse JSON Lines Log Fetcher for pmacct
# Author: David Peter, Tangent Networks
# Path: ./cgi-bin/fetch_wan.pl
# ---

use strict;
use warnings;
use FindBin qw($RealBin);
use File::Spec;
use POSIX qw(strftime);
use Fcntl qw(:flock);

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

# Pre-load DBD::SQLite XS before pledge locks down dlopen()
use DBD::SQLite;

my $LOG_DATE = strftime( "%Y-%m-%d", localtime );
my $LOG_FILE = "/tmp/fetch_wan-${LOG_DATE}.log";

sub write_log {
    my ( $level, $msg ) = @_;
    my $ts = strftime( "%Y-%m-%d %H:%M:%S", localtime );
    if ( open( my $fh, '>>', $LOG_FILE ) ) {
        flock( $fh, LOCK_EX );
        print $fh "[$ts] [$level] $msg\n";
        close $fh;
    }
}

# Security check
my $session = security_check('standard');

use JSON::PP;
use CGI;

$ENV{'PATH'} = '/usr/bin:/bin';
delete @ENV{qw(IFS CDPATH ENV BASH_ENV)};

# Build log path from TNEnv -- chroot-safe, no dirname(__FILE__)
my $app_root = get_db_path();
$app_root =~ s{/data/db/?.*$}{};
$app_root =~ s{^/var/www}{};
my $PIPE_FILE = File::Spec->catfile( $app_root, 'data', 'pipes', 'pmacct',
    'ext_if_json.log' );

# Untaint -- path constructed from validated TNEnv root + literal segments
if ( $PIPE_FILE =~ m{^([-/\w.]+)$} ) {
    $PIPE_FILE = $1;
}
else {
    write_log( 'ERROR', "Unsafe pipe file path: $PIPE_FILE" );
    die "FATAL: Invalid pipe file path\n";
}

# Instantiate CGI and emit Content-Type before pledge so that a pledge failure
# cannot produce raw output ahead of the HTTP header.
my $cgi = CGI->new;
print $cgi->header(
    -type    => 'application/json',
    -charset => 'utf-8'
);

# =============================================
# OPENBSD PLEDGE + UNVEIL
# =============================================
{
    eval {
        if ( eval { require OpenBSD::Unveil; 1 } ) {
            my @to_unveil = (
                [ "$app_root/data/lib",          "r" ],
                [ "$app_root/data/config",       "r" ],
                [ "$app_root/data/db",           "rwc" ],
                [ "$app_root/data/pipes/pmacct", "r" ],
                [ "/tmp",                        "rwc" ],
                [ "/dev/urandom",                "r" ],
            );
            for my $entry (
                [ "$app_root/data/keys",      "r" ],
                [ "$app_root/data/logs",      "rwc" ],
                [ "/usr/lib/perl5",           "r" ],
                [ "/usr/libdata/perl5",       "r" ],
                [ "/usr/local/lib/perl5",     "r" ],
                [ "/usr/local/libdata/perl5", "r" ],
                [ "/usr/local/lib",           "r" ],
                [ "/usr/lib",                 "r" ],
              )
            {
                push @to_unveil, $entry if -d $entry->[0];
            }
            for my $entry (@to_unveil) {
                OpenBSD::Unveil::unveil( $entry->[0], $entry->[1] )
                  or die "unveil $entry->[0]: $!";
            }
            OpenBSD::Unveil::unveil() or die "unveil lock: $!";
        }
        if ( eval { require OpenBSD::Pledge; 1 } ) {
            OpenBSD::Pledge::pledge("stdio rpath wpath cpath flock")
              or die "pledge: $!";
        }
    };
    if ($@) {
        write_log( 'ERROR', "sandbox_init_failed: $@" );
        print '{"error":"Internal server error"}';
        exit 1;
    }
}

my $json_obj = JSON::PP->new->utf8->allow_nonref;

# Query Parameters
my $limit_raw  = $cgi->param('limit')  || 100;
my $offset_raw = $cgi->param('offset') || 0;

# Filter parameters (added to match fetch_lan.pl)
my $proto_raw     = $cgi->param('proto');
my $src_raw       = $cgi->param('src');
my $dst_raw       = $cgi->param('dst');
my $src_port_raw  = $cgi->param('src_port');
my $dst_port_raw  = $cgi->param('dst_port');
my $bytes_min_raw = $cgi->param('bytes_min');

# Wrap everything in eval to catch errors
eval {
    # Untaint and validate limit
    my $limit = 100;
    if ( $limit_raw =~ /^(\d+)$/ ) {
        $limit = $1;
        $limit = 500 if $limit > 500;    # Safety cap
    }

    # Untaint and validate offset
    my $offset = 0;
    if ( $offset_raw =~ /^(\d+)$/ ) {
        $offset = $1;
    }

    # Untaint filter parameters (added to match fetch_lan.pl)
    my ( $proto, $src, $dst, $src_port, $dst_port, $bytes_min );

    if ( $proto_raw && $proto_raw =~ /^([\w-]+)$/ ) {
        $proto = lc($1);
    }
    if ( $src_raw && $src_raw =~ /^([\w.:]+)$/ ) {
        $src = $1;
    }
    if ( $dst_raw && $dst_raw =~ /^([\w.:]+)$/ ) {
        $dst = $1;
    }
    if ( $src_port_raw && $src_port_raw =~ /^(\d+)$/ ) {
        $src_port = $1;
    }
    if ( $dst_port_raw && $dst_port_raw =~ /^(\d+)$/ ) {
        $dst_port = $1;
    }
    if ( $bytes_min_raw && $bytes_min_raw =~ /^(\d+)$/ ) {
        $bytes_min = $1;
    }

    # Check if log file exists
    if ( !-e $PIPE_FILE ) {
        print $json_obj->encode(
            {
                total  => 0,
                offset => int($offset),
                limit  => int($limit),
                data   => []
            }
        );
        exit 0;
    }

    # Check if log file is readable
    if ( !-r $PIPE_FILE ) {
        die "Log file not readable: $PIPE_FILE";
    }

    # Check if file is empty
    my $file_size = -s $PIPE_FILE;
    if ( $file_size == 0 ) {
        print $json_obj->encode(
            {
                total  => 0,
                offset => int($offset),
                limit  => int($limit),
                data   => []
            }
        );
        exit 0;
    }

    # Open file for binary reading
    open( my $fh, '<', $PIPE_FILE ) or die "Cannot open $PIPE_FILE: $!";

    my @entries;
    my $buffer_size = 4096;
    my $file_pos    = $file_size;
    my $leftover    = "";

    # Read backwards in chunks to find ALL JSON lines (not just limit)
    while ( $file_pos > 0 ) {
        my $read_size = ( $file_pos < $buffer_size ) ? $file_pos : $buffer_size;
        $file_pos -= $read_size;

        seek( $fh, $file_pos, 0 );
        read( $fh, my $chunk, $read_size );

        $chunk .= $leftover;
        my @lines = split( /\n/, $chunk );

        # The first element might be incomplete since we are reading chunks
        $leftover = ( $file_pos > 0 ) ? shift @lines : "";

        # Process lines in reverse order (newest first)
        foreach my $line ( reverse @lines ) {
            next unless $line =~ /^\s*\{.*\}\s*$/;    # Basic JSON check

            my $data;
            eval { $data = $json_obj->decode($line); };

            # Silently skip malformed JSON lines
            if ($@) {
                write_log( 'WARN', "Skipping malformed JSON line: $@" );
                next;
            }

            # Apply filters (added to match fetch_lan.pl)
            if ( $proto && lc( $data->{ip_proto} || '' ) ne $proto ) {
                next;
            }

            if ($src) {
                my $matches = 0;
                if ( $src =~ /^(\d+\.\d+\.)/ ) {
                    $matches = 1 if ( $data->{ip_src} || '' ) =~ /^\Q$src\E/;
                }
                elsif ( $src eq 'fe80::' ) {
                    $matches = 1 if ( $data->{ip_src} || '' ) =~ /^fe80:/;
                }
                else {
                    $matches = 1 if ( $data->{ip_src} || '' ) =~ /\Q$src\E/i;
                }
                next unless $matches;
            }

            if ($dst) {
                my $matches = 0;
                if ( $dst eq '224.' ) {
                    $matches = 1 if ( $data->{ip_dst} || '' ) =~ /^224\./;
                }
                elsif ( $dst eq 'ff' ) {
                    $matches = 1 if ( $data->{ip_dst} || '' ) =~ /^ff/;
                }
                else {
                    $matches = 1 if ( $data->{ip_dst} || '' ) =~ /\Q$dst\E/i;
                }
                next unless $matches;
            }

            if ( $src_port && ( $data->{port_src} || 0 ) != $src_port ) {
                next;
            }
            if ( $dst_port && ( $data->{port_dst} || 0 ) != $dst_port ) {
                next;
            }

            if ( $bytes_min && ( $data->{bytes} || 0 ) < $bytes_min ) {
                next;
            }

            # Add formatting and display class (optional enhancements)
            $data->{bytes_formatted} = format_bytes( $data->{bytes} );

            if (   ( $data->{ip_src} || '' ) =~ /:/
                || ( $data->{ip_dst} || '' ) =~ /:/ )
            {
                $data->{display_class} = 'ipv6';
            }
            elsif (( $data->{ip_dst} || '' ) =~ /^224\./
                || ( $data->{ip_dst} || '' ) =~ /^ff/ )
            {
                $data->{display_class} = 'multicast';
            }
            elsif (( $data->{port_src} || 0 ) == 53
                || ( $data->{port_dst} || 0 ) == 53 )
            {
                $data->{display_class} = 'dns';
            }
            else {
                $data->{display_class} = 'normal';
            }

            push @entries, $data;
        }
    }

    close($fh);

    # Count totals by category (added to match fetch_lan.pl with improved logic)
    my $total_filtered  = scalar @entries;
    my $ipv4_count      = 0;
    my $ipv6_count      = 0;
    my $multicast_count = 0;
    my $unicast_count   = 0;                 # Added u_count

    foreach my $entry (@entries) {
        my $dst = $entry->{ip_dst} || '';
        my $src = $entry->{ip_src} || '';

        # Check for multicast first (both IPv4 and IPv6)
        if ( $dst =~ /^224\./ || $dst =~ /^ff/ ) {
            $multicast_count++;
        }
        else {
            $unicast_count++;    # Count as unicast if not multicast
        }

        # Then check IP version
        if ( $src =~ /:/ || $dst =~ /:/ ) {
            $ipv6_count++;
        }
        else {
            $ipv4_count++;
        }
    }

    my @output = splice( @entries, $offset, $limit );

    print $json_obj->encode(
        {
            total     => int($total_filtered),
            ipv4      => int($ipv4_count),
            ipv6      => int($ipv6_count),
            multicast => int($multicast_count),
            u_count   => int($unicast_count),     # Added u_count
            offset    => int($offset),
            limit     => int($limit),
            data      => \@output
        }
    );
};

# Error handling
if ($@) {

    # Log error to stderr (will appear in httpd error log)
    write_log( 'ERROR', "fetch_wan.pl error: $@" );

    # Return error as JSON
    print $json_obj->encode(
        {
            error   => 'Internal server error',
            message => 'Failed to fetch data'
        }
    );
    exit 1;
}

exit 0;

# Helper function (added to match fetch_lan.pl)
sub format_bytes {
    my ($bytes) = @_;
    return '0 B' unless $bytes;
    return sprintf( '%.0f B',  $bytes )        if $bytes < 1024;
    return sprintf( '%.1f KB', $bytes / 1024 ) if $bytes < 1048576;
    return sprintf( '%.1f MB', $bytes / 1048576 );
}
