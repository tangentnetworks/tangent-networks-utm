#!/usr/bin/perl -T

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

use strict;
use warnings;
use FindBin qw($RealBin);
use File::Spec;
use File::Basename qw(dirname);
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

my $session = security_check('restricted');

# Audit log -- access traceable to user and action
TNSecurity::log_security_event( 'info', 'E2G_E2G_MODE_SWITCH_ACCESS',
        'User '
      . ( $session->{username} || 'unknown' )
      . ' accessed e2g_mode_switch' );

use CGI qw(:standard);
use JSON::PP;

my $script_dir = dirname(__FILE__);
if ( $script_dir =~ m{^([-/\w.]+)$} ) { $script_dir = $1 }
else                                  { die "FATAL: Invalid script_dir\n" }

# Pre-compute canonical paths before pledge (RELABS-001)
my $REQ_DIR = File::Spec->rel2abs(
    File::Spec->catdir(
        $script_dir, '..',         'data', 'services',
        'queue',     'e2gfilters', 'request'
    )
);
my $OUT_DIR = File::Spec->rel2abs(
    File::Spec->catdir(
        $script_dir, '..',         'data', 'services',
        'queue',     'e2gfilters', 'outcome'
    )
);

for my $ref ( \$REQ_DIR, \$OUT_DIR ) {
    if ( $$ref =~ m{^([-/\w.]+)$} ) { $$ref = $1 }
    else                            { die "FATAL: Invalid path: $$ref\n" }
}

my $log_date  = strftime( "%Y-%m-%d", localtime );
my $DEBUG_LOG = "/tmp/e2g_mode_switch-${log_date}.log";

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
        print $fh "[$ts] [PERL] $msg\n";
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
            OpenBSD::Unveil::unveil( "$app_root/data/logs", "rwc" )
              or die "unveil logs: $!";
            OpenBSD::Unveil::unveil( "$app_root/data/keys", "r" )
              or die "unveil keys: $!";
            OpenBSD::Unveil::unveil(
                "$app_root/data/services/queue/e2gfilters/request", "rwc" )
              or die "unveil request: $!";
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

my $json_data = eval { decode_json($postdata) } if $postdata;
my $action =
  ( $json_data && $json_data->{action} ) ? $json_data->{action} : 'switch_mode';
my $mode =
  ( $json_data && $json_data->{mode} ) ? $json_data->{mode} : 'general';

# Untaint action and mode
if ( $action =~ /^(switch_mode)$/ ) { $action = $1 }
else                                { send_error( 400, "Invalid action" ) }

if ( $mode =~ /^(general|childsafe)$/ ) { $mode = $1 }
else                                    { send_error( 400, "Invalid mode" ) }

# Anti-spam lock -- check for pending jobs
opendir( my $dh, $REQ_DIR )
  or send_error( 500, "Cannot open request directory" );
my @pending = grep { /\.txt$/ } readdir($dh);
closedir($dh);

if (@pending) {
    debug_log("REJECTED: Job already in progress (@pending).");
    send_json(
        {
            success => 1,
            message => "Filter update is already running. Please wait...",
            data    => { status => "busy", job_id => $pending[0] }
        }
    );
}

# Generate unique job ID -- alphanumeric only, safe to untaint
my @chars  = ( 'a' .. 'z', '0' .. '9' );
my $job_id = join '', map { $chars[ rand @chars ] } 1 .. 12;

my $out_filename = "${job_id}.json";
my $out_path     = File::Spec->catfile( $OUT_DIR, $out_filename );
my $req_path     = File::Spec->catfile( $REQ_DIR, "${job_id}.txt" );

# Untaint constructed paths
if ( $out_path =~ m{^([-/\w.]+)$} ) { $out_path = $1 }
else                                { send_error( 500, "Invalid out path" ) }
if ( $req_path =~ m{^([-/\w.]+)$} ) { $req_path = $1 }
else                                { send_error( 500, "Invalid req path" ) }

debug_log("Starting new job $job_id for mode $mode");

if ( open( my $req_fh, '>', $req_path ) ) {
    flock( $req_fh, LOCK_EX );
    print $req_fh "$action|$mode|$out_filename\n";
    close($req_fh);
    chmod( 0640, $req_path );
}
else {
    debug_log("ERROR writing request: $!");
    send_error( 500, "Failed to queue job" );
}

# Respond immediately -- shell script runs for 15-20 min in background.
# JS heartbeat polls active_mode.json every 2s and updates UI when done.
debug_log("Job queued: $job_id for mode $mode -- responding immediately");

send_json(
    {
        success => 1,
        message => "Filter update queued -- running in background",
        data    => { job_id => $job_id, status => "processing", mode => $mode },
    }
);
