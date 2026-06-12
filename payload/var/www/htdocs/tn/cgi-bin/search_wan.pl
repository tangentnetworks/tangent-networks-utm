#!/usr/bin/perl -T

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# ---
# Description: Optimized Historical Search for pmacct
# Path: ./cgi-bin/search_wan.pl
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
my $LOG_FILE = "/tmp/search_wan-${LOG_DATE}.log";

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

my $cgi      = CGI->new;
my $json_obj = JSON::PP->new->utf8;

# Header emitted before pledge so that any pledge failure in the block below
# cannot produce output before Content-Type is sent.
print $cgi->header( -type => 'application/json', -charset => 'utf-8' );

# =============================================
# OPENBSD PLEDGE + UNVEIL
# =============================================
{
    my $app_root = get_db_path();
    $app_root =~ s{/data/db/?.*$}{};
    $app_root =~ s{^/var/www}{};

    eval {
        if ( eval { require OpenBSD::Unveil; 1 } ) {
            my @to_unveil = (
                [ "$app_root/data/lib",            "r" ],
                [ "$app_root/data/config",         "r" ],
                [ "$app_root/data/db",             "rwc" ],
                [ "$app_root/data/network/pmacct", "r" ],
                [ "/tmp",                          "rwc" ],
                [ "/dev/urandom",                  "r" ],
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
        print $json_obj->encode(
            { success => 0, error => 'Internal server error' } );
        exit 1;
    }
}

# Search Parameters
my $p_date   = $cgi->param('date');
my $p_hr     = $cgi->param('hr');
my $p_min    = $cgi->param('min');
my $p_src    = $cgi->param('src');
my $p_dst    = $cgi->param('dst');
my $p_port   = $cgi->param('port');
my $p_proto  = $cgi->param('proto');
my $p_limit  = $cgi->param('limit')  || 200;
my $p_offset = $cgi->param('offset') || 0;

if ( !$p_date ) {
    print $json_obj->encode( { error => "Date parameter required" } );
    exit;
}

# Validate and untaint date
my ( $y, $m, $d );
if ( $p_date =~ /^(\d{4})-(\d{2})-(\d{2})$/ ) {
    ( $y, $m, $d ) = ( $1, $2, $3 );
}
elsif ( $p_date =~ /^(\d{4})(\d{2})(\d{2})$/ ) {
    ( $y, $m, $d ) = ( $1, $2, $3 );
}
else {
    print $json_obj->encode(
        { error => "Invalid date format. Use YYYY-MM-DD or YYYYMMDD" } );
    exit;
}

my $compact_date = "$y$m$d";
my $display_date = "$y-$m-$d";

# Untaint and validate numeric params
my $limit = 200;
if ( defined $p_limit && $p_limit =~ /^(\d+)$/ ) {
    $limit = $1;
    $limit = 500 if $limit > 500;
}
my $offset = 0;
if ( defined $p_offset && $p_offset =~ /^(\d+)$/ ) {
    $offset = $1;
}

# Untaint filter params
my ( $f_src, $f_dst, $f_proto, $f_port, $f_hr, $f_min );
$f_src   = $1     if defined $p_src   && $p_src   =~ /^([\w.:]+)$/;
$f_dst   = $1     if defined $p_dst   && $p_dst   =~ /^([\w.:]+)$/;
$f_proto = lc($1) if defined $p_proto && $p_proto =~ /^([\w-]+)$/;
$f_port  = $1     if defined $p_port  && $p_port  =~ /^(\d+)$/;
$f_hr    = $1     if defined $p_hr    && $p_hr    =~ /^(\d{1,2})$/;
$f_min   = $1     if defined $p_min   && $p_min   =~ /^(\d{2})$/;

# Build base directory from TNEnv -- chroot-safe, no DOCUMENT_ROOT
my $app_root = get_db_path();
$app_root =~ s{/data/db/?.*$}{};
$app_root =~ s{^/var/www}{};
my $BASE_DIR =
  File::Spec->catdir( $app_root, 'data', 'network', 'pmacct', 'ext' );

# Collapse any .. segments
$BASE_DIR =~ s{/[^/]+/\.\.(/|$)}{$1}g;

unless ( -d $BASE_DIR ) {
    write_log( 'ERROR', "Data directory not found: $BASE_DIR" );
    print $json_obj->encode(
        { success => 0, error => "Data directory not found" } );
    exit;
}

opendir( my $dh, $BASE_DIR ) or do {
    write_log( 'ERROR', "Cannot open directory $BASE_DIR: $!" );
    print $json_obj->encode( { error => "Cannot access data directory" } );
    exit;
};
my @all_files = readdir($dh);
closedir $dh;

my @json_files  = grep { /\.json$/ } @all_files;
my @daily_files = grep { /^\Q$display_date\E\.json$/ } @json_files;
my @chunk_files = grep { /^ext_if-\Q$compact_date\E-\d{4}\.json$/ } @json_files;

my @files_to_scan;

if ( $f_hr && defined $f_min ) {
    my $hh         = sprintf( "%02d", $f_hr );
    my $chunk_file = "ext_if-$compact_date-$hh$f_min.json";
    if ( grep { $_ eq $chunk_file } @json_files ) {
        push @files_to_scan, File::Spec->catfile( $BASE_DIR, $chunk_file );
    }
    elsif (@daily_files) {
        push @files_to_scan, File::Spec->catfile( $BASE_DIR, $daily_files[0] );
    }
    else {
        print $json_obj->encode(
            {
                success => 0,
                error   => "No data found for $display_date at $hh:$f_min"
            }
        );
        exit;
    }
}
else {
    if (@daily_files) {
        push @files_to_scan, File::Spec->catfile( $BASE_DIR, $daily_files[0] );
    }
    elsif (@chunk_files) {
        push @files_to_scan,
          map { File::Spec->catfile( $BASE_DIR, $_ ) } @chunk_files;
    }
    else {
        print $json_obj->encode(
            {
                success         => 0,
                error           => "No data files found for $display_date",
                available_dates =>
                  [ grep { /^\d{4}-\d{2}-\d{2}\.json$/ } @json_files ]
            }
        );
        exit;
    }
}

my @results;
my $files_found = 0;
my $lines_read  = 0;

foreach my $target_file (@files_to_scan) {

    # Untaint each file path -- constructed from validated components
    next unless $target_file =~ m{^([-/\w.]+)$};
    $target_file = $1;
    next unless -e $target_file && -r $target_file;
    $files_found++;

    open( my $fh, '<', $target_file ) or do {
        write_log( 'WARN', "Could not open $target_file: $!" );
        next;
    };

    while ( my $line = <$fh> ) {
        next unless $line =~ /^\s*\{.*\}\s*$/;
        $lines_read++;

        eval {
            my $data = $json_obj->decode($line);

            if ( $f_src && $data->{ip_src} ) {
                next unless $data->{ip_src} =~ /\Q$f_src\E/i;
            }
            if ( $f_dst && $data->{ip_dst} ) {
                next unless $data->{ip_dst} =~ /\Q$f_dst\E/i;
            }
            if ( $f_proto && $data->{ip_proto} ) {
                next unless lc( $data->{ip_proto} ) eq $f_proto;
            }
            if ( $f_port && $data->{port_src} && $data->{port_dst} ) {
                next
                  unless $data->{port_src} == $f_port
                  || $data->{port_dst} == $f_port;
            }
            push @results, $data;
        };

        last if scalar(@results) >= ( $offset + $limit );
    }
    close($fh);
    last if scalar(@results) >= ( $offset + $limit );
}

my @paginated;
if ( $offset < scalar(@results) ) {
    my $end = $offset + $limit;
    $end       = scalar(@results) if $end > scalar(@results);
    @paginated = @results[ $offset .. ( $end - 1 ) ];
}

@paginated =
  sort { ( $b->{stamp_updated} // '' ) cmp( $a->{stamp_updated} // '' ) }
  @paginated;

print $json_obj->encode(
    {
        success  => scalar(@paginated) > 0 ? 1 : 0,
        metadata => {
            date_searched       => $display_date,
            hr_searched         => $f_hr,
            min_searched        => $f_min,
            total_files_scanned => $files_found,
            total_matches       => scalar(@results),
            returned_count      => scalar(@paginated),
        },
        data => \@paginated,
    }
);
