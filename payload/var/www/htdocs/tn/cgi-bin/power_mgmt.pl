#!/usr/bin/perl -T

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

use strict;
use warnings;
use FindBin qw($RealBin);
use File::Spec;

# =============================================
# BOOTSTRAP
# =============================================
BEGIN {
    # Clean environment for taint mode
    $ENV{PATH} = '/bin:/usr/bin:/usr/local/bin:/sbin:/usr/sbin';
    delete @ENV{qw(IFS CDPATH ENV BASH_ENV)};

    my $lib_path =
      File::Spec->catdir( $RealBin, File::Spec->updir, 'data', 'lib' );

    unless ( File::Spec->file_name_is_absolute($lib_path) ) {
        $lib_path = File::Spec->rel2abs($lib_path);
    }

    if ( $lib_path =~ m{^([-/\w.]+)$} ) {
        $lib_path = $1;
    }
    else {
        die "FATAL: Unsafe characters in lib path\n";
    }

    unless ( -d $lib_path ) {
        die "FATAL: Library directory not found: $lib_path\n";
    }

    unshift @INC, $lib_path;

    # Read raw JSON POST body for TNSecurityCheck
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

# Security check - RESTRICTED level (admin only, POST + CSRF + Session)
my $session = security_check('restricted');

# Now load other modules
use CGI;
use JSON::PP;
use POSIX qw(strftime);
use File::Basename;
use Time::HiRes qw(sleep time);
use Fcntl       qw(:flock);

# =============================================
# CONFIGURATION
# =============================================
my $script_dir = dirname(__FILE__);

my $QUEUE_REQ_DIR =
  File::Spec->catdir( $script_dir, '..', 'data', 'queue', 'powerstate',
    'request' );
my $QUEUE_OUT_DIR =
  File::Spec->catdir( $script_dir, '..', 'data', 'queue', 'powerstate',
    'outcome' );

my $LOG_FILE = '/tmp/pwmgmt.log';    # errors only

my $POLL_INTERVAL = 0.5;             # seconds
my $MAX_WAIT      = 30;              # seconds

# =============================================
# HELPERS
# =============================================

# Errors and warnings only -- all entries go to /tmp/pwmgmt.log
sub write_log {
    my ( $level, $msg ) = @_;
    return unless $level =~ /^(ERROR|WARN|INFO)$/;
    my $timestamp = strftime( "%Y-%m-%d %H:%M:%S", localtime );
    my $username  = $session->{username} || 'unknown';
    if ( open( my $fh, '>>', $LOG_FILE ) ) {
        flock( $fh, LOCK_EX );
        print $fh "[$timestamp] USER:$username [$level] $msg\n";
        close $fh;
    }
}

sub send_json {
    my ($data) = @_;
    my $json_output = JSON::PP->new->utf8->encode($data);

    print "Status: 200 OK\n";
    print "Content-Type: application/json; charset=UTF-8\n";
    print "Content-Length: " . length($json_output) . "\n";
    print "X-Frame-Options: DENY\n";
    print "X-Content-Type-Options: nosniff\n";
    print "Cache-Control: no-cache, no-store, must-revalidate, private\n";
    print "Connection: close\n";
    print "\n";
    print $json_output;
    exit 0;
}

sub send_error {
    my ( $code, $message ) = @_;

    my %status_text = (
        400 => 'Bad Request',
        401 => 'Unauthorized',
        403 => 'Forbidden',
        404 => 'Not Found',
        405 => 'Method Not Allowed',
        500 => 'Internal Server Error',
    );

    my $status = $status_text{$code} || 'Error';

    print "Status: $code $status\n";
    print "Content-Type: application/json\n";
    print "\n";
    print JSON::PP->new->utf8->encode(
        {
            success => 0,
            error   => $message,
            code    => $code,
        }
    );

    write_log( 'ERROR', "HTTP $code: $message" );
    exit 0;
}

# =============================================
# REQUEST VALIDATION
# =============================================

my $method = $ENV{REQUEST_METHOD} || '';
if ( $method =~ /^(POST)$/ ) {
    $method = $1;
}
else {
    send_error( 405, 'Method not allowed' );
}

# =============================================
# PARSE JSON BODY
# =============================================

my $postdata = $ENV{POSTDATA} || '';

unless ($postdata) {
    send_error( 400, 'Empty request body' );
}

my $json_data;
eval { $json_data = JSON::PP->new->utf8->decode($postdata); };
if ($@) {
    send_error( 400, 'Invalid JSON' );
}

# =============================================
# VALIDATE ACTION
# =============================================

my $action = $json_data->{action} || '';

# Strict whitelist - only restart and shutdown
if ( $action =~ /^(restart|shutdown)$/ ) {
    $action = $1;
}
else {
    write_log( 'WARN', "Invalid action attempted: $action" );
    send_error( 400, 'Invalid action. Must be restart or shutdown' );
}

# Map action to shell command
my %COMMANDS = (
    'restart'  => 'shutdown -r now',
    'shutdown' => 'shutdown -hp now',
);

my $command = $COMMANDS{$action};

# =============================================
# OPENBSD PLEDGE + UNVEIL
# =============================================
# wpath/cpath: queue request dir (write job file) + /tmp (log)
# rpath:       queue outcome dir (poll), config, keys, db (session already done)
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
            OpenBSD::Unveil::unveil( "$app_root/data/queue/powerstate", "rwc" )
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
        send_error( 500, 'Internal server error' );
    }
}

# =============================================
# ENSURE QUEUE DIRECTORIES EXIST
# =============================================

for my $dir ( $QUEUE_REQ_DIR, $QUEUE_OUT_DIR ) {
    unless ( -d $dir ) {

        # Untaint dir
        if ( $dir =~ m{^([-/\w.]+)$} ) {
            mkdir $1, 0750 or do {
                write_log( 'ERROR', "Cannot create directory: $dir" );
                send_error( 500, 'Queue directory error' );
            };
        }
    }
}

# =============================================
# WRITE REQUEST TO QUEUE
# =============================================

my $job_id   = sprintf( "power_%s_%d", $action, time() );
my $req_file = File::Spec->catfile( $QUEUE_REQ_DIR, "${job_id}.txt" );

# Untaint request file path
if ( $req_file =~ m{^([-/\w.]+)$} ) {
    $req_file = $1;
}
else {
    send_error( 500, 'Invalid queue path' );
}

if ( open( my $fh, '>', $req_file ) ) {
    print $fh "$command\n";
    close $fh;
    chmod( 0640, $req_file );
}
else {
    write_log( 'ERROR', "Failed to write queue file: $!" );
    send_error( 500, 'Failed to queue request' );
}

write_log( 'INFO', "Queued action '$action' (job: $job_id) command: $command" );

# =============================================
# POLL FOR OUTCOME
# =============================================

my $outcome = wait_for_outcome( $job_id, $MAX_WAIT );

if ($outcome) {
    write_log( 'INFO',
        "Action '$action' completed - "
          . ( $outcome->{success} ? 'SUCCESS' : 'FAILED' ) );
    send_json(
        {
            success => $outcome->{success} ? 1 : 0,
            message => $outcome->{message} || 'Action completed',
            action  => $action,
            job_id  => $job_id,
        }
    );
}
else {
    # For shutdown/restart this is actually OK - system may have gone down
    # before writing the outcome. We treat timeout as likely success.
    write_log( 'INFO',
"Action '$action' - no outcome received (system may have executed command)"
    );
    send_json(
        {
            success => 1,
            message =>
              'Command queued and likely executing. Connection may be lost.',
            action => $action,
            job_id => $job_id,
        }
    );
}

# =============================================
# WAIT FOR OUTCOME FILE
# =============================================

sub wait_for_outcome {
    my ( $job_id, $max_wait ) = @_;
    my $start = time();

    # Untaint outcome dir
    my $out_dir = $QUEUE_OUT_DIR;
    if ( $out_dir =~ m{^([-/\w.]+)$} ) {
        $out_dir = $1;
    }
    else {
        write_log( 'ERROR', "Invalid outcome dir path" );
        return undef;
    }

    while ( ( time() - $start ) < $max_wait ) {

        unless ( opendir( my $dh, $out_dir ) ) {
            sleep($POLL_INTERVAL);
            next;
        }
        else {
            my @files = readdir($dh);
            closedir($dh);

            foreach my $file (@files) {
                next if $file eq '.' || $file eq '..';
                next unless $file =~ /^\Q${job_id}\E.*\.json$/;

                my $outcome_file = File::Spec->catfile( $out_dir, $file );

                # Untaint
                if ( $outcome_file =~ m{^([-/\w.]+)$} ) {
                    $outcome_file = $1;
                }
                else {
                    next;
                }

                open( my $fh, '<', $outcome_file ) or next;
                local $/;
                my $content = <$fh>;
                close $fh;

                my $data;
                eval { $data = JSON::PP->new->utf8->decode($content) };
                next if $@;

                unlink $outcome_file;
                return $data;
            }
        }

        sleep($POLL_INTERVAL);
    }

    write_log( 'WARN', "Timeout waiting for outcome: $job_id" );
    return undef;
}
