#!/usr/bin/perl -T

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# /var/www/htdocs/tn/cgi-bin/unbound_control.pl
# Unbound DNS management CGI interface
# Synchronous queue architecture - writes request, waits for outcome, returns to JS

use strict;
use warnings;
use FindBin qw($RealBin);
use File::Spec;

BEGIN {
    $ENV{PATH} = '/bin:/usr/bin:/sbin:/usr/sbin';
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
    # security_check('restricted') validates CSRF from $ENV{POSTDATA}
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

# Restricted level -- session + CSRF + admin role required.
# DNS cache manipulation and config reload are privileged operations:
#   flush_all    -- wipes cache for all LAN clients
#   flush_domain -- modifies resolver state
#   dump_cache   -- information disclosure (reveals LAN browsing state)
#   reload       -- reloads unbound config, could disrupt resolution
#   lookup       -- exposes internal resolver behaviour
# STDIN pre-read in BEGIN ensures CSRF token is available to security_check.
my $session = security_check('restricted');

# Audit log -- every DNS control action is traceable
TNSecurity::log_security_event( 'info', 'UNBOUND_CONTROL_ACCESS',
    "Admin ${\($session->{username} || 'unknown')} accessed unbound control" );

use JSON::PP;
use Time::HiRes qw(sleep time);
use File::Basename;
use POSIX qw(strftime);
use Fcntl qw(:flock);

# =============================================
# CONFIGURATION
# =============================================

my $script_dir = dirname(__FILE__);

# Untaint -- strict charset, rejects shell metacharacters
if ( $script_dir =~ m{^([-/\w.]+)$} ) { $script_dir = $1 }
else                                  { die "FATAL: Invalid script_dir\n" }

my $QUEUE_BASE =
  File::Spec->catdir( $script_dir, '..', 'data', 'services', 'queue',
    'unbound' );
my $REQUEST_DIR = File::Spec->catdir( $QUEUE_BASE, 'request' );
my $OUTCOME_DIR = File::Spec->catdir( $QUEUE_BASE, 'outcome' );

# Untaint queue paths -- constructed from clean script_dir + literal segments
for ( $QUEUE_BASE, $REQUEST_DIR, $OUTCOME_DIR ) {
    if (m{^([-/\w.]+)$}) { $_ = $1 }
    else                 { die "FATAL: Invalid queue path\n" }
}

my $WAIT_TIMEOUT  = 10;     # seconds
my $WAIT_INTERVAL = 0.2;    # seconds

# Dedicated error log -- date-stamped, one file per day
my $LOG_DATE = strftime( "%Y-%m-%d", localtime );
my $LOG_FILE = "/tmp/unbound-${LOG_DATE}.log";

# =============================================
# ERROR LOGGING
# =============================================

sub write_log {
    my ( $level, $msg ) = @_;
    my $timestamp = strftime( "%Y-%m-%d %H:%M:%S", localtime );
    if ( open( my $fh, '>>', $LOG_FILE ) ) {
        flock( $fh, LOCK_EX );
        print $fh "[$timestamp] [$level] $msg\n";
        close $fh;
    }
}

# =============================================
# RESPONSE STRUCTURE
# =============================================

# Print Content-Type header now -- before any output
# (replaces CGI->new / $q->header which drained STDIN)
print "Content-Type: application/json

";

my %response = (
    success => 0,
    error   => '',
    output  => ''
);

# =============================================
# OPENBSD PLEDGE + UNVEIL
# =============================================
# wpath/cpath: queue request dir (write job) + log file
# rpath:       queue outcome dir (poll), config, keys, db (session)
# flock:       safe log writes
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
            OpenBSD::Unveil::unveil( "$app_root/data/services/queue/unbound",
                "rwc" )
              or die "unveil queue: $!";
            OpenBSD::Unveil::unveil( "/tmp", "rwc" ) or die "unveil tmp: $!";
            OpenBSD::Unveil::unveil()                or die "unveil lock: $!";
        }
        if ( eval { require OpenBSD::Pledge; 1 } ) {
            OpenBSD::Pledge::pledge("stdio rpath wpath cpath flock")
              or die "pledge: $!";
        }
    };
    if ($@) {
        write_log( 'ERROR', "sandbox_init_failed: $@" );
        $response{error} = "Internal server error";
        print encode_json( \%response );
        exit;
    }
}

# =============================================
# HELPERS
# =============================================

sub ensure_directories {
    for my $dir ( $QUEUE_BASE, $REQUEST_DIR, $OUTCOME_DIR ) {
        unless ( -d $dir ) {
            mkdir $dir, 0750 or do {
                write_log( 'ERROR', "Cannot create directory $dir: $!" );
                die "Cannot create directory $dir: $!\n";
            };
        }
    }
}

sub generate_request_id {
    my $timestamp = time();
    my $random    = int( rand(99999) );
    return sprintf( "%d_%05d", $timestamp * 1000, $random );
}

sub write_request {
    my ( $request_id, $action, $params ) = @_;

    my $request_data = {
        request_id => $request_id,
        action     => $action,
        timestamp  => time(),
        %{ $params || {} }
    };

    my $request_file =
      File::Spec->catfile( $REQUEST_DIR, "${request_id}.json" );

# Untaint: REQUEST_DIR already clean, request_id is digits+underscore from generate_request_id
    if ( $request_file =~ m{^([-/\w.]+)$} ) { $request_file = $1 }
    else { die "FATAL: Invalid request file path\n" }

    open my $fh, '>', $request_file or die "Cannot write request file: $!\n";
    print $fh encode_json($request_data);
    close $fh;

    return $request_file;
}

sub wait_for_outcome {
    my ($request_id) = @_;

    my $outcome_file =
      File::Spec->catfile( $OUTCOME_DIR, "${request_id}.json" );

    # Untaint: OUTCOME_DIR already clean, request_id digits+underscore
    if ( $outcome_file =~ m{^([-/\w.]+)$} ) { $outcome_file = $1 }
    else {
        write_log( 'ERROR',
            "Invalid outcome file path for request_id: $request_id" );
        return { success => 0, error => "Internal path error" };
    }

    my $start_time = time();

    while (1) {
        if ( -f $outcome_file ) {
            open my $fh, '<', $outcome_file or do {
                write_log( 'ERROR',
                    "Cannot read outcome file $outcome_file: $!" );
                die "Cannot read outcome file: $!\n";
            };
            my $outcome_json = do { local $/; <$fh> };
            close $fh;

            my $outcome;
            eval { $outcome = decode_json($outcome_json) };
            if ($@) {
                write_log( 'ERROR',
                    "Failed to parse outcome JSON for $request_id: $@" );
                return {
                    success => 0,
                    error   => "Failed to parse outcome JSON",
                };
            }

            unlink $outcome_file;
            return $outcome;
        }

        if ( time() - $start_time > $WAIT_TIMEOUT ) {
            write_log( 'WARN', "Timeout waiting for outcome: $request_id" );
            return {
                success => 0,
                error   => "Operation timed out after ${WAIT_TIMEOUT}s",
                timeout => 1
            };
        }

        sleep $WAIT_INTERVAL;
    }
}

# =============================================
# MAIN
# =============================================

ensure_directories();

# Use $ENV{POSTDATA} -- pre-read in BEGIN block before security_check consumed STDIN
# $q->param('POSTDATA') returns empty after STDIN is already drained
my $postdata = $ENV{POSTDATA} || '';

unless ($postdata) {
    $response{error} = "No input data";
    print encode_json( \%response );
    exit;
}

my $request;
eval { $request = decode_json($postdata) };
if ($@) {
    $response{error} = "Invalid JSON";
    print encode_json( \%response );
    exit;
}

# Validate and untaint action -- whitelist only
my $raw_action      = $request->{action} || '';
my %allowed_actions = (
    flush_all    => 1,
    flush_domain => 1,
    dump_cache   => 1,
    reload       => 1,
    lookup       => 1,
);

unless ( $allowed_actions{$raw_action} ) {
    $response{error} = "Invalid action";
    print encode_json( \%response );
    exit;
}

# Untaint via whitelist capture
my $action;
if ( $raw_action =~ /^(flush_all|flush_domain|dump_cache|reload|lookup)$/ ) {
    $action = $1;
}

# Validate and untaint domain if required
my $domain;
if ( $action eq 'flush_domain' || $action eq 'lookup' ) {
    my $raw_domain = $request->{domain} || '';
    unless ($raw_domain) {
        $response{error} = "Domain required for $action";
        print encode_json( \%response );
        exit;
    }

    # Untaint: hostname chars only -- letters, digits, hyphen, dot
    if ( $raw_domain =~ /^([a-zA-Z0-9.-]+)$/ ) {
        $domain = $1;
    }
    else {
        $response{error} = "Invalid domain format";
        print encode_json( \%response );
        exit;
    }
}

my $request_id = generate_request_id();

my $params = {};
$params->{domain} = $domain if defined $domain;

TNSecurity::log_security_event( 'info', 'UNBOUND_ACTION_QUEUED',
        "${\($session->{username} || 'unknown')} queued unbound $action"
      . ( defined $domain ? " ($domain)" : '' )
      . " (id: $request_id)" );
eval { write_request( $request_id, $action, $params ) };
if ($@) {
    write_log( 'ERROR', "Failed to write request for action '$action': $@" );
    $response{error} = "Failed to write request";
    print encode_json( \%response );
    exit;
}

my $outcome = wait_for_outcome($request_id);
print encode_json($outcome);
exit;
