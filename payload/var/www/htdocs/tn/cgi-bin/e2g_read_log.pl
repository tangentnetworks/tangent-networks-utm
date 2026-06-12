#!/usr/bin/perl -T

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

use strict;
use warnings;
use FindBin qw($RealBin);
use File::Spec;
use File::Basename qw(dirname basename);

BEGIN {
    $ENV{PATH} = '/bin:/usr/bin:/usr/local/bin';
    delete @ENV{qw(IFS CDPATH ENV BASH_ENV)};

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

# Pre-read JSON POST body before TNSecurityCheck drains STDIN (STDIN-PREREAD-001)
    if (   $ENV{CONTENT_TYPE}
        && $ENV{CONTENT_TYPE} =~ /application\/json/
        && $ENV{CONTENT_LENGTH} )
    {
        read( STDIN, my $json_body, $ENV{CONTENT_LENGTH} );
        $ENV{POSTDATA} = $json_body;
    }
}

use TNEnv;
use TNSecurityCheck;

# Protected level -- requires valid session + CSRF
my $session = security_check('protected');

use CGI qw(:standard);
use JSON::PP;

my $script_dir = dirname(__FILE__);
if ( $script_dir =~ m{^([-/\w.]+)$} ) { $script_dir = $1 }
else                                  { die "FATAL: Invalid script_dir\n" }

# Pre-compute canonical paths before pledge (RELABS-001)
my $USER_LOG_DIR = File::Spec->rel2abs(
    File::Spec->catdir(
        $script_dir, '..',         'data', 'services',
        'queue',     'e2gfilters', 'outcome'
    )
);
my $CRON_LOG_DIR = File::Spec->rel2abs(
    File::Spec->catdir( $script_dir, '..', 'data', 'logs', 'cron' ) );

for my $ref ( \$USER_LOG_DIR, \$CRON_LOG_DIR ) {
    if ( $$ref =~ m{^([-/\w.]+)$} ) { $$ref = $1 }
    else                            { die "FATAL: Invalid path: $$ref\n" }
}

# =============================================
# RESPONSE HELPERS
# =============================================
sub send_json {
    my ($data) = @_;
    my $out = JSON::PP->new->utf8->encode($data);
    print "Status: 200 OK\r\n";
    print "Content-Type: application/json; charset=UTF-8\r\n";
    print "X-Frame-Options: DENY\r\n";
    print "X-Content-Type-Options: nosniff\r\n";
    print "Cache-Control: no-cache, no-store, must-revalidate, private\r\n";
    print "Connection: close\r\n";
    print "\r\n";
    print $out;
    exit 0;
}

sub send_error {
    my ( $code, $message ) = @_;
    my %st = (
        400 => 'Bad Request',
        403 => 'Forbidden',
        500 => 'Internal Server Error'
    );
    print "Status: $code " . ( $st{$code} || 'Error' ) . "\r\n";
    print "Content-Type: application/json\r\n";
    print "\r\n";
    print JSON::PP->new->utf8->encode( { success => 0, error => $message } );
    exit 0;
}

# =============================================
# OPENBSD PLEDGE + UNVEIL
# =============================================
{
    my $app_root = $script_dir;
    $app_root =~ s{/cgi-bin$}{};
    $app_root =~ s{^/var/www}{};
    eval {
        if ( eval { require OpenBSD::Unveil; 1 } ) {
            OpenBSD::Unveil::unveil( "$app_root/data/lib", "r" )
              or die "unveil lib: $!";
            OpenBSD::Unveil::unveil( "$app_root/data/config", "r" )
              or die "unveil config: $!";
            OpenBSD::Unveil::unveil( "$app_root/data/keys", "r" )
              or die "unveil keys: $!";
            OpenBSD::Unveil::unveil( "$app_root/data/db", "r" )
              or die "unveil db: $!";
            OpenBSD::Unveil::unveil( "$app_root/data/logs/cron", "r" )
              or die "unveil cron: $!";
            OpenBSD::Unveil::unveil(
                "$app_root/data/services/queue/e2gfilters/outcome", "r" )
              or die "unveil outcome: $!";
            OpenBSD::Unveil::unveil() or die "unveil lock: $!";
        }
        if ( eval { require OpenBSD::Pledge; 1 } ) {
            OpenBSD::Pledge::pledge("stdio rpath") or die "pledge: $!";
        }
    };
    if ($@) {
        send_error( 500, "Internal server error" );
    }
}

# =============================================
# MAIN
# =============================================
my $cgi       = CGI->new;
my $json_text = $ENV{POSTDATA} || $cgi->param('POSTDATA') || '';

unless ($json_text) {
    send_error( 400, "Empty request" );
}

my $data;
eval { $data = decode_json($json_text) };
if ($@) {
    send_error( 400, "Invalid JSON" );
}

my $action      = $data->{action}      || '';
my $filter_type = $data->{filter_type} || 'user';

# Untaint filter_type
if ( $filter_type =~ /^(user|childsafe|adult)$/ ) { $filter_type = $1 }
else { send_error( 400, "Invalid filter_type" ) }

if ( $action eq 'get_latest' ) {
    get_latest_log($filter_type);
}
elsif ( $action eq 'list' ) {
    list_logs($filter_type);
}
elsif ( $action eq 'get_specific' ) {
    my $filename = $data->{filename} || '';
    get_specific_log( $filter_type, $filename );
}
else {
    send_error( 400, "Unknown action: $action" );
}

# =============================================
# GET LATEST LOG
# =============================================
sub get_latest_log {
    my ($filter_type) = @_;
    my $log_dir       = get_log_dir($filter_type);
    my $pattern       = get_log_pattern($filter_type);

    unless ( -d $log_dir ) {
        send_json(
            {
                success     => 0,
                error       => "Log directory not found",
                filter_type => $filter_type
            }
        );
    }

    my $latest = find_latest_log( $log_dir, $pattern );
    unless ($latest) {
        send_json(
            {
                success     => 0,
                error       => "No logs found",
                filter_type => $filter_type
            }
        );
    }

    read_and_return_log( $latest, $filter_type );
}

# =============================================
# GET SPECIFIC LOG
# =============================================
sub get_specific_log {
    my ( $filter_type, $filename ) = @_;

    unless ( $filename =~ m{^(e2g[_a-z0-9\-]+\.log)$}i ) {
        send_error( 400, "Invalid filename" );
    }
    $filename = $1;

    my $log_dir  = get_log_dir($filter_type);
    my $log_path = File::Spec->catfile( $log_dir, $filename );

    unless ( $log_path =~ m{^([-/\w.]+)$} ) {
        send_error( 400, "Invalid log path" );
    }
    $log_path = $1;

    unless ( -f $log_path ) {
        send_json( { success => 0, error => "Log file not found: $filename" } );
    }

    read_and_return_log( $log_path, $filter_type );
}

# =============================================
# LIST LOGS
# =============================================
sub list_logs {
    my ($filter_type) = @_;
    my $log_dir       = get_log_dir($filter_type);
    my $pattern       = get_log_pattern($filter_type);

    unless ( -d $log_dir ) {
        send_json( { success => 1, logs => [], filter_type => $filter_type } );
    }

    my @logs;
    if ( opendir my $dh, $log_dir ) {
        while ( my $file = readdir $dh ) {
            next unless $file =~ /$pattern/;
            my $filepath = File::Spec->catfile( $log_dir, $file );
            my @stat     = stat($filepath);
            next unless @stat;
            push @logs,
              {
                filename    => $file,
                size        => $stat[7],
                mtime       => $stat[9],
                mtime_human => scalar( localtime( $stat[9] ) ),
              };
        }
        closedir $dh;
    }

    @logs = sort { $b->{mtime} <=> $a->{mtime} } @logs;
    send_json(
        {
            success     => 1,
            logs        => \@logs,
            count       => scalar(@logs),
            filter_type => $filter_type
        }
    );
}

# =============================================
# HELPERS
# =============================================
sub get_log_dir {
    my ($filter_type) = @_;
    return $filter_type eq 'user' ? $USER_LOG_DIR : $CRON_LOG_DIR;
}

sub get_log_pattern {
    my ($filter_type) = @_;
    if ( $filter_type eq 'user' ) {
        return qr/^e2g_user_filter-\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}\.log$/;
    }
    elsif ( $filter_type eq 'childsafe' ) {
        return
          qr/^e2guardian-childsafe-\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}\.log$/;
    }
    elsif ( $filter_type eq 'adult' ) {
        return qr/^e2guardian-adult-\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}\.log$/;
    }
    return qr/^e2g.*\.log$/;
}

sub find_latest_log {
    my ( $log_dir,     $pattern )      = @_;
    my ( $latest_file, $latest_mtime ) = ( undef, 0 );

    if ( opendir my $dh, $log_dir ) {
        while ( my $file = readdir $dh ) {
            next unless $file =~ /$pattern/;
            my $filepath = File::Spec->catfile( $log_dir, $file );
            my @stat     = stat($filepath);
            if ( @stat && $stat[9] > $latest_mtime ) {
                $latest_mtime = $stat[9];
                $latest_file  = $filepath;
            }
        }
        closedir $dh;
    }
    return $latest_file;
}

sub read_and_return_log {
    my ( $log_path, $filter_type ) = @_;

    open( my $fh, '<', $log_path )
      or send_json( { success => 0, error => "Failed to open log: $!" } );

    my @lines;
    my $byte_count = 0;
    while ( my $line = <$fh> ) {
        push @lines, $line;
        $byte_count += length($line);
    }
    close $fh;

    my @stat = stat($log_path);
    send_json(
        {
            success     => 1,
            content     => join( '', @lines ),
            filename    => basename($log_path),
            line_count  => scalar(@lines),
            size        => $byte_count,
            mtime       => $stat[9] || 0,
            mtime_human => scalar( localtime( $stat[9] || 0 ) ),
            filter_type => $filter_type,
        }
    );
}

exit 0;
