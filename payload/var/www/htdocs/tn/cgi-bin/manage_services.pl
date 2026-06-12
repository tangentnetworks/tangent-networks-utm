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
use Time::HiRes    qw(sleep time);

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
use TNSecurity;

# Restricted level -- requires valid session + CSRF + admin role
# Service start/stop/restart are privileged operations on a UTM appliance.
# security_check() exits with 403 before we get here if:
#   - No valid session cookie
#   - CSRF token missing or invalid
#   - Role is not 'admin'
my $session = security_check('restricted');

# Explicit audit log -- every service action is traceable to a user
# Follows pf_write_rules.pl / integrity_status.pl pattern
TNSecurity::log_security_event( 'info', 'MANAGE_SERVICES_ACCESS',
    "Admin ${\($session->{username} || 'unknown')} accessed service manager" );

use CGI qw(:standard);
use JSON::PP;

# ============================================================================
# CONFIGURATION
# ============================================================================
my $script_dir = dirname(__FILE__);
if ( $script_dir =~ m{^([-/\w.]+)$} ) { $script_dir = $1 }
else                                  { die "FATAL: Invalid script_dir\n" }

# Pre-compute canonical paths before pledge (RELABS-001)
my $QUEUE_REQ_DIR = File::Spec->rel2abs(
    File::Spec->catdir(
        $script_dir, '..', 'data', 'services', 'queue', 'request'
    )
);
my $QUEUE_OUT_DIR = File::Spec->rel2abs(
    File::Spec->catdir(
        $script_dir, '..', 'data', 'services', 'queue', 'outcome'
    )
);
my $LOG_DIR = File::Spec->rel2abs(
    File::Spec->catdir( $script_dir, '..', 'data', 'logs', 'bootlog' ) );

for my $ref ( \$QUEUE_REQ_DIR, \$QUEUE_OUT_DIR, \$LOG_DIR ) {
    if ( $$ref =~ m{^([-/\w.]+)$} ) { $$ref = $1 }
    else                            { die "FATAL: Invalid path: $$ref\n" }
}

my $log_date    = strftime( "%Y-%m-%d", localtime );
my $MANAGER_LOG = "$LOG_DIR/manager_${log_date}.log";
my $DEBUG_LOG   = "/tmp/manage_services-${log_date}.log";

# Service-specific timeouts (seconds)
my %SERVICE_TIMEOUTS = (
    'cron'        => 15,
    'dhcpd'       => 15,
    'ftpproxy'    => 15,
    'ftpproxy6'   => 15,
    'httpd'       => 20,
    'ntpd'        => 15,
    'rad'         => 15,
    'slaacd'      => 15,
    'slowcgi'     => 15,
    'smtpd'       => 20,
    'syslogd'     => 15,
    'unbound'     => 20,
    'snort'       => 45,
    'snortinline' => 45,
    'pmacct'      => 30,
    'clamd'       => 120,
    'freshclam'   => 60,
    'snortsentry' => 30,
    'e2guardian'  => 30,
    'collectd'    => 30,
    'p3scan'      => 30,
    'sockd'       => 20,
    'spamd'       => 30,
    'smtp-gated'  => 20,
    'sslproxy'    => 20,
    'imspector'   => 20,
    'tcpdump'     => 20,
    'default'     => 30,
);

my %ASYNC_SERVICES = map { $_ => 1 } qw(
  snort snortinline clamd freshclam pmacct e2guardian
);

my $POLL_INTERVAL = 0.5;

# Valid services whitelist
my %VALID_SERVICES = map { $_ => 1 } qw(
  snort snortinline snortsentry e2guardian collectd p3scan
  clamd freshclam pmacct sockd spamd smtp-gated sslproxy
  imspector tcpdump cron dhcpd ftpproxy ftpproxy6 httpd
  ntpd rad slaacd slowcgi smtpd syslogd unbound
);

# ============================================================================
# RESPONSE HELPERS
# ============================================================================
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
    print JSON::PP->new->utf8->encode(
        { success => 0, message => $message, data => {} } );
    exit 0;
}

sub write_log {
    my ( $level, $msg ) = @_;
    my $timestamp = strftime( "%Y-%m-%d %H:%M:%S", localtime );
    my $username  = $session->{username} || 'unknown';
    if ( open( my $fh, '>>', $MANAGER_LOG ) ) {
        flock( $fh, LOCK_EX );
        print $fh "[$timestamp] USER:$username [$level] $msg\n";
        close $fh;
    }
}

sub debug_log {
    my ($msg)    = @_;
    my $ts       = strftime( "%Y-%m-%d %H:%M:%S", localtime );
    my $username = $session->{username} || 'unknown';
    if ( open( my $fh, '>>', $DEBUG_LOG ) ) {
        flock( $fh, LOCK_EX );
        print $fh "[$ts] USER:$username PID:$$ $msg\n";
        close $fh;
    }
}

# ============================================================================
# ENSURE QUEUE DIRECTORIES EXIST BEFORE PLEDGE
# ============================================================================
for my $dir ( $LOG_DIR, $QUEUE_REQ_DIR, $QUEUE_OUT_DIR ) {
    unless ( -d $dir ) {
        mkdir( $dir, 0755 ) or die "FATAL: Cannot create directory $dir: $!\n";
    }
}

# ============================================================================
# OPENBSD PLEDGE + UNVEIL
# ============================================================================
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
            OpenBSD::Unveil::unveil( "$app_root/data/services/queue", "rwc" )
              or die "unveil queue: $!";
            OpenBSD::Unveil::unveil( "$app_root/data/logs/bootlog", "rwc" )
              or die "unveil bootlog: $!";
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

# ============================================================================
# MAIN
# ============================================================================
my $q        = CGI->new;
my $postdata = $ENV{POSTDATA} || $q->param('POSTDATA') || '';

debug_log( "=== NEW REQUEST === METHOD:" . ( $ENV{REQUEST_METHOD} || 'NONE' ) );

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

my $action  = $json_data->{action}  || '';
my $service = $json_data->{service} || '';

debug_log("Action: $action  Service: $service");

# Untaint action
if ( $action =~ /^(start|stop|restart|status|list)$/ ) { $action = $1 }
else {
    write_log( 'ERROR', "Invalid action: $action" );
    send_error( 400, "Invalid action" );
}

# Untaint service
if ( $service && $service =~ /^([a-zA-Z0-9_-]+)$/ ) { $service = $1 }

# Validate service (not required for list)
if ( $action ne 'list' && !$VALID_SERVICES{$service} ) {
    write_log( 'ERROR', "Invalid service: $service" );
    send_error( 400, "Invalid service: $service" );
}

my $MAX_WAIT = $SERVICE_TIMEOUTS{$service} || $SERVICE_TIMEOUTS{default};
debug_log("Timeout: ${MAX_WAIT}s for $service");

# Generate unique job ID -- service_action_timestamp
my $job_id = sprintf( "%s_%s_%d", $service || 'list', $action, int( time() ) );
if ( $job_id =~ m{^([-\w.]+)$} ) { $job_id = $1 }
else                             { send_error( 500, "Invalid job ID" ) }

debug_log("Job ID: $job_id");

# Write request to queue
my $req_file = "$QUEUE_REQ_DIR/${job_id}.txt";
if ( $req_file =~ m{^([-/\w.]+)$} ) { $req_file = $1 }
else { send_error( 500, "Invalid request file path" ) }

if ( open( my $req_fh, '>', $req_file ) ) {
    flock( $req_fh, LOCK_EX );
    print $req_fh "$action $service\n";
    close($req_fh);
    chmod( 0644, $req_file );
    debug_log("Request queued: $req_file");
}
else {
    write_log( 'ERROR', "Failed to queue request: $!" );
    send_error( 500, "Failed to queue request" );
}

write_log( 'INFO',
    "Queued: $action on '$service' (job: $job_id, timeout: ${MAX_WAIT}s)" );
TNSecurity::log_security_event( 'info', 'SERVICE_ACTION_QUEUED',
"${\($session->{username} || 'unknown')} queued $action on $service (job: $job_id)"
);

# Async path -- return immediately for background-dispatched services
if ( $ASYNC_SERVICES{$service}
    && ( $action eq 'start' || $action eq 'restart' ) )
{
    debug_log("Async dispatch: $action $service (job: $job_id)");
    write_log( 'INFO',
        "Async: $action on '$service' dispatched (job: $job_id)" );
    send_json(
        {
            success => 1,
            message =>
              "Command dispatched -- service is starting in the background",
            data => {
                queued    => \1,
                job_id    => $job_id,
                action    => $action,
                service   => $service,
                queued_at => time(),
            },
        }
    );
}

# Synchronous path -- stop / fast services / rcctl services
my $outcome_data;
eval { $outcome_data = wait_for_outcome( $job_id, $MAX_WAIT ) };

if ($@) {
    debug_log("ERROR in wait_for_outcome: $@");
    write_log( 'ERROR', "Exception in wait_for_outcome: $@" );
    send_error( 500, "Internal error waiting for result" );
}

if ($outcome_data) {
    debug_log("Outcome received");
    write_log( 'INFO',
        "Completed: $action on '$service' - "
          . ( $outcome_data->{success} ? "SUCCESS" : "FAILED" ) );
    send_json(
        {
            success => 1,
            message => "Command completed",
            data    => $outcome_data,
        }
    );
}
else {
    debug_log("Timeout after ${MAX_WAIT}s");
    write_log( 'WARN',
        "Timeout: $action on '$service' (job: $job_id, waited ${MAX_WAIT}s)" );
    send_json(
        {
            success => 0,
            message =>
"Command queued but timed out waiting for result (${MAX_WAIT}s). Check queue processor.",
            data => {
                job_id    => $job_id,
                action    => $action,
                service   => $service,
                queued_at => time(),
                timeout   => $MAX_WAIT,
            },
        }
    );
}

# ============================================================================
# WAIT FOR OUTCOME FILE
# ============================================================================
sub wait_for_outcome {
    my ( $job_id, $max_wait ) = @_;
    my $start_time  = time();
    my $check_count = 0;
    my $outcome_dir = $QUEUE_OUT_DIR;

    debug_log(
        "Waiting for outcome: ${job_id}-*.json in $outcome_dir (no timeout)");

    if ( opendir( my $req_dh, $QUEUE_REQ_DIR ) ) {
        my @req_files = grep { $_ ne '.' && $_ ne '..' } readdir($req_dh);
        closedir($req_dh);
        debug_log( "Request queue has "
              . scalar(@req_files)
              . " files: "
              . join( ", ", @req_files ) );
    }

    while (1) {
        $check_count++;

        unless ( opendir( my $dh, $outcome_dir ) ) {
            debug_log("ERROR: Cannot open $outcome_dir: $!");
            sleep($POLL_INTERVAL);
            next;
        }
        else {
            my @all_files = readdir($dh);
            closedir($dh);

            debug_log( "Files in outcome dir: " . scalar(@all_files) )
              if $check_count == 1;

            my @matched = grep { /^\Q${job_id}\E-.*\.json$/ } @all_files;

            if (@matched) {
                my $outcome_file = "$outcome_dir/$matched[0]";
                if ( $outcome_file =~ m{^([-/\w.:]+)$} ) { $outcome_file = $1 }
                else {
                    debug_log("ERROR: Cannot untaint: $outcome_file");
                    sleep($POLL_INTERVAL);
                    next;
                }

                debug_log("Found outcome: $outcome_file (check #$check_count)");

                open( my $fh, '<', $outcome_file ) or do {
                    debug_log("ERROR: Cannot open $outcome_file: $!");
                    sleep($POLL_INTERVAL);
                    next;
                };

                local $/;
                my $json_content = <$fh>;
                close($fh);

                my $outcome;
                eval { $outcome = decode_json($json_content) };
                if ($@) {
                    debug_log("ERROR parsing JSON: $@");
                    sleep($POLL_INTERVAL);
                    next;
                }

                unlink($outcome_file)
                  ? debug_log("Cleaned up: $outcome_file")
                  : debug_log("WARNING: Could not delete: $outcome_file");

                return $outcome;
            }
        }

        if ( $check_count % 10 == 0 ) {
            debug_log( "Still waiting... (check #${check_count}, "
                  . int( time() - $start_time )
                  . "s elapsed)" );
        }

        sleep($POLL_INTERVAL);
    }
}
