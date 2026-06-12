#!/usr/bin/perl -T

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

use strict;
use warnings;

use FindBin qw($RealBin);
use File::Spec;
use Fcntl qw(:flock);

BEGIN {
    $ENV{PATH} = '/bin:/usr/bin:/usr/local/bin:/sbin:/usr/sbin';
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

    # Pre-read JSON POST body before TNSecurityCheck drains STDIN
    # TNSecurityCheck::_check_csrf reads $ENV{POSTDATA} via CGI->new internally
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

# Pre-load before pledge locks down dlopen()
use DBD::SQLite;

# Security check - RESTRICTED level (admin only)
my $session = security_check('restricted');

use CGI qw(:standard);
use JSON::PP;
use POSIX qw(strftime);
use File::Basename;

my $script_dir = dirname(__FILE__);
if ( $script_dir =~ m{^([-/\w.]+)$} ) { $script_dir = $1 }
else                                  { die "FATAL: Invalid script_dir\n" }

my $QUEUE_REQ_DIR =
  File::Spec->catdir( $script_dir, '..', 'data', 'queue', 'integrity',
    'request' );
my $QUEUE_OUT_DIR =
  File::Spec->catdir( $script_dir, '..', 'data', 'queue', 'integrity',
    'outcome' );

# Pre-compute canonical paths before pledge (RELABS-001)
my $CANONICAL_REQ = File::Spec->rel2abs($QUEUE_REQ_DIR);
my $CANONICAL_OUT = File::Spec->rel2abs($QUEUE_OUT_DIR);
my $CONF_PATH     = File::Spec->rel2abs(
    File::Spec->catfile(
        $script_dir, '..', 'data', 'config', 'integrity_checks.conf'
    )
);

for my $ref ( \$CANONICAL_REQ, \$CANONICAL_OUT, \$CONF_PATH ) {
    if ( $$ref =~ m{^([-/\w.]+)$} ) { $$ref = $1 }
    else                            { die "FATAL: Invalid path: $$ref\n" }
}

my $log_date      = strftime( "%Y-%m-%d", localtime );
my $INTEGRITY_LOG = "/tmp/integrity_request-$log_date.log";

# =============================================
# RESPONSE HELPERS (power_mgmt.pl pattern)
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
    my %status_text = (
        400 => 'Bad Request',
        401 => 'Unauthorized',
        403 => 'Forbidden',
        500 => 'Internal Server Error'
    );
    my $status = $status_text{$code} || 'Error';
    print "Status: $code $status\r\n";
    print "Content-Type: application/json\r\n";
    print "\r\n";
    print JSON::PP->new->utf8->encode( { success => 0, message => $message } );
    exit 0;
}

# =============================================
# LOGGING
# =============================================
sub write_log {
    my ( $level, $msg ) = @_;
    my $timestamp = strftime( "%Y-%m-%d %H:%M:%S", localtime );
    my $username  = $session->{username} || 'unknown';
    if ( open( my $fh, '>>', $INTEGRITY_LOG ) ) {
        flock( $fh, LOCK_EX );
        print $fh "[$timestamp] USER:$username [$level] $msg\n";
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
            OpenBSD::Unveil::unveil( "$app_root/data/keys", "r" )
              or die "unveil keys: $!";
            OpenBSD::Unveil::unveil( "$app_root/data/db", "rwc" )
              or die "unveil db: $!";
            OpenBSD::Unveil::unveil( $CANONICAL_REQ, "rwc" )
              or die "unveil req: $!";
            OpenBSD::Unveil::unveil( $CANONICAL_OUT, "rwc" )
              or die "unveil out: $!";
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
        send_error( 500, "Internal server error" );
    }
}

# CGI object after pledge -- STDIN already consumed in BEGIN
my $q = CGI->new;

# =============================================
# MAIN
# =============================================

my $postdata = $ENV{POSTDATA} || $q->param('POSTDATA') || '';

unless ($postdata) {
    write_log( 'ERROR', "Empty request body" );
    send_error( 400, "Empty request body" );
}

my $json_data;
eval { $json_data = decode_json($postdata) };
if ($@) {
    write_log( 'ERROR', "Invalid JSON: $@" );
    send_error( 400, "Invalid JSON" );
}

my $check        = $json_data->{check}        || '';
my $action       = $json_data->{action}       || '';
my $request_time = $json_data->{request_time} || '';

if ( $check =~ /^([a-zA-Z0-9_-]+)$/ ) { $check = $1 }
else {
    write_log( 'ERROR', "Invalid check type: $check" );
    send_error( 400, "Invalid check type" );
}

if ( $action =~ /^(verify|update)$/ ) { $action = $1 }
else {
    write_log( 'ERROR', "Invalid action: $action" );
    send_error( 400, "Invalid action" );
}

if ( $request_time =~ /^(\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2})$/ ) {
    $request_time = $1;
}
else {
    write_log( 'ERROR', "Invalid request_time: $request_time" );
    send_error( 400, "Invalid request time format" );
}

# Validate check type against conf-derived whitelist
my %valid_checks = ( 'all' => 1 );
if ( open( my $cfg_fh, '<', $CONF_PATH ) ) {
    while ( my $line = <$cfg_fh> ) {
        next if $line =~ /^\s*#/;
        next if $line =~ /^\s*$/;
        my @f = split /\|/, $line;
        if ( @f >= 2 ) {
            my $cn = $f[1];
            $cn =~ s/^\s+|\s+$//g;
            $valid_checks{$cn} = 1 if $cn;
        }
    }
    close($cfg_fh);
}

unless ( $valid_checks{$check} ) {
    write_log( 'ERROR', "Invalid check type: $check" );
    send_error( 400, "Invalid check type: $check" );
}

my $req_file = "$CANONICAL_REQ/request-$request_time";
if ( $req_file =~ m{^([-/\w.]+)$} ) { $req_file = $1 }
else {
    write_log( 'ERROR', "Invalid request file path" );
    send_error( 500, "Invalid request file path" );
}

if ( open( my $req_fh, '>', $req_file ) ) {
    flock( $req_fh, LOCK_EX );
    print $req_fh "$action $check\n";
    close($req_fh);
    chmod( 0644, $req_file );
}
else {
    write_log( 'ERROR', "Failed to queue request: $!" );
    send_error( 500, "Failed to queue request" );
}

write_log( 'INFO', "Queued: $action on '$check' (request: $request_time)" );

my $outcome_file = "$CANONICAL_OUT/out-$request_time";
if ( $outcome_file =~ m{^([-/\w.]+)$} ) { $outcome_file = $1 }
else {
    write_log( 'ERROR', "Invalid outcome file path" );
    send_error( 500, "Invalid outcome file path" );
}

# Flush HTTP headers immediately before entering the blocking poll loop.
# OpenBSD httpd has a hardcoded FastCGI idle timer that fires when no
# bytes flow between httpd and slowcgi. Sending headers now resets the
# timer; the JSON body follows when the daemon writes the outcome file.
$| = 1;
print "Status: 200 OK\r\n";
print "Content-Type: application/json; charset=UTF-8\r\n";
print "X-Frame-Options: DENY\r\n";
print "X-Content-Type-Options: nosniff\r\n";
print "Cache-Control: no-cache, no-store, must-revalidate, private\r\n";
print "Connection: close\r\n";
print "\r\n";

my $max_wait       = 540;
my $poll_interval  = 0.5;
my $elapsed        = 0;
my $last_heartbeat = 0;

while ( $elapsed < $max_wait ) {
    if ( -f $outcome_file ) {
        if ( open( my $out_fh, '<', $outcome_file ) ) {
            local $/;
            my $outcome_json = <$out_fh>;
            close($out_fh);
            unlink($outcome_file);
            write_log( 'INFO', "Completed: $action on '$check' (${elapsed}s)" );
            print $outcome_json;
            exit 0;
        }
    }

    # Send a whitespace heartbeat every 20 seconds.
    # JSON parsers ignore leading whitespace so this does not
    # corrupt the response. It resets slowcgi and httpd idle timers
    # so long-running checks (etc, usr_local_lib) survive.
    if ( $elapsed - $last_heartbeat >= 20 ) {
        print " ";
        $last_heartbeat = $elapsed;
    }

    select( undef, undef, undef, $poll_interval );
    $elapsed += $poll_interval;
}

write_log( 'ERROR', "Timeout: $action on '$check' after ${max_wait}s" );
print JSON::PP->new->utf8->encode(
    { success => 0, message => "Verification timeout after ${max_wait}s" } );
exit 0;

__END__

=head1 SECURITY

Requires 'restricted' level access (admin only).
OpenBSD pledge/unveil hardened. BEGIN STDIN pre-read pattern (power_mgmt.pl).

=cut
