#!/usr/bin/perl -T

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# ---
# Description: e2guardian Log Info Fetcher (gets modification time)
# Path: ./cgi-bin/e2g_get_log_info.pl
# ---
use strict;
use warnings;
use FindBin qw($RealBin);
use File::Spec;
use File::Basename qw(dirname basename);
use Fcntl          qw(:flock);
use POSIX          qw(strftime);

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

    # STDIN-PREREAD-001: read POST body before security_check drains STDIN
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
use TNSecurity;

my $session = security_check('protected');

# Audit log -- access traceable to user and action
TNSecurity::log_security_event( 'info', 'E2G_E2G_GET_LOG_INFO_ACCESS',
        'User '
      . ( $session->{username} || 'unknown' )
      . ' accessed e2g_get_log_info' );

use CGI qw(:standard);
use JSON::PP;

my $script_dir = dirname(__FILE__);
if ( $script_dir =~ m{^([-/\w.]+)$} ) { $script_dir = $1 }
else                                  { die "FATAL: Invalid script_dir\n" }

# Pre-compute canonical paths before pledge (RELABS-001)
my $CRON_LOG_DIR = File::Spec->rel2abs(
    File::Spec->catdir( $script_dir, '..', 'data', 'logs', 'cron' ) );
my $USER_LOG_DIR = File::Spec->rel2abs(
    File::Spec->catdir(
        $script_dir, '..',         'data', 'services',
        'queue',     'e2gfilters', 'outcome'
    )
);

for my $ref ( \$CRON_LOG_DIR, \$USER_LOG_DIR ) {
    if ( $$ref =~ m{^([-/\w.]+)$} ) { $$ref = $1 }
    else                            { die "FATAL: Invalid path: $$ref\n" }
}

my $log_date  = strftime( "%Y-%m-%d", localtime );
my $DEBUG_LOG = "/tmp/e2g_get_log_info-${log_date}.log";

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
    print JSON::PP->new->utf8->encode( { success => 0, message => $message } );
    exit 0;
}

sub debug_log {
    my ($msg) = @_;
    my $ts = strftime( "%Y-%m-%d %H:%M:%S", localtime );
    if ( open( my $fh, '>>', $DEBUG_LOG ) ) {
        flock( $fh, LOCK_EX );
        print $fh "[$ts] $msg\n";
        close $fh;
    }
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
            OpenBSD::Unveil::unveil( "$app_root/data/db", "r" )
              or die "unveil db: $!";
            OpenBSD::Unveil::unveil( "$app_root/data/logs", "rwc" )
              or die "unveil logs: $!";
            OpenBSD::Unveil::unveil( "$app_root/data/keys", "r" )
              or die "unveil keys: $!";
            OpenBSD::Unveil::unveil( "$app_root/data/logs/cron", "r" )
              or die "unveil cron: $!";
            OpenBSD::Unveil::unveil(
                "$app_root/data/services/queue/e2gfilters/outcome", "r" )
              or die "unveil outcome: $!";
            OpenBSD::Unveil::unveil( "/tmp", "rwc" ) or die "unveil tmp: $!";
            OpenBSD::Unveil::unveil()                or die "unveil lock: $!";
        }
        if ( eval { require OpenBSD::Pledge; 1 } ) {
            OpenBSD::Pledge::pledge("stdio rpath wpath cpath flock")
              or die "pledge: $!";
        }
    };
    if ($@) {
        send_error( 500, "Internal server error" );
    }
}

# =============================================
# MAIN
# =============================================
# Use $ENV{POSTDATA} -- pre-read in BEGIN before security_check
my $postdata = $ENV{POSTDATA} || '';

debug_log("=== NEW LOG INFO REQUEST ===");

unless ($postdata) {
    debug_log("ERROR: Empty request");
    send_error( 400, "Empty request" );
}

my $data;
eval { $data = decode_json($postdata) };
if ($@) {
    debug_log("ERROR: Invalid JSON - $@");
    send_error( 400, "Invalid JSON" );
}

my $action  = $data->{action}  || '';
my $pattern = $data->{pattern} || '';

debug_log("Action: $action  Pattern: $pattern");

unless ( $action eq 'get_log_info' ) {
    debug_log("ERROR: Invalid action - $action");
    send_error( 400, "Invalid action" );
}

unless (
    $pattern =~ /^(e2guardian-adult-|e2guardian-childsafe-|e2g_user_filter-)$/ )
{
    debug_log("ERROR: Invalid pattern - $pattern");
    send_error( 400, "Invalid log pattern" );
}
$pattern = $1;

my $log_dir;
if ( $pattern =~ /^e2guardian-(adult|childsafe)-/ ) {
    $log_dir = $CRON_LOG_DIR;
}
elsif ( $pattern eq 'e2g_user_filter-' ) {
    $log_dir = $USER_LOG_DIR;
}
else {
    send_error( 400, "Unknown pattern" );
}

debug_log(
    "Log directory: $log_dir  Exists: " . ( -d $log_dir ? "YES" : "NO" ) );

unless ( -d $log_dir ) {
    debug_log("ERROR: Directory not found - $log_dir");
    send_json(
        {
            success       => 0,
            message       => "Log directory not found",
            last_modified => 0,
            log_file      => ''
        }
    );
}

my $latest_log = find_latest_log( $log_dir, $pattern );

if ($latest_log) {
    my $mtime    = ( stat($latest_log) )[9];
    my $filename = basename($latest_log);
    debug_log("Found: $filename  mtime: $mtime");
    send_json(
        {
            success       => 1,
            last_modified => $mtime,
            log_file      => $filename,
            message       => "Success"
        }
    );
}
else {
    debug_log("ERROR: No log files found for pattern $pattern");
    send_json(
        {
            success       => 0,
            message       => "No log files found",
            last_modified => 0,
            log_file      => ''
        }
    );
}

# =============================================
# FIND LATEST LOG FILE
# =============================================
sub find_latest_log {
    my ( $dir, $pattern ) = @_;

    opendir( my $dh, $dir ) or do {
        debug_log("ERROR: Cannot open directory $dir: $!");
        return undef;
    };

    my @log_files = grep { /^\Q$pattern\E/ && -f "$dir/$_" } readdir($dh);
    closedir($dh);

    return undef unless @log_files;

    my @sorted =
      sort { ( stat("$dir/$b") )[9] <=> ( stat("$dir/$a") )[9] } @log_files;

    my $latest = "$dir/$sorted[0]";
    if ( $latest =~ m{^([-/\w.:]+)$} ) { return $1 }
    debug_log("ERROR: Could not untaint path: $latest");
    return undef;
}
