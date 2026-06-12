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

# Standard level -- no CSRF required
my $session = security_check('restricted');

# Audit log -- access traceable to user and action
TNSecurity::log_security_event( 'info', 'E2G_E2G_WRITE_INPUT_ACCESS',
        'User '
      . ( $session->{username} || 'unknown' )
      . ' accessed e2g_write_input' );

use CGI qw(:standard);
use JSON::PP;

my $script_dir = dirname(__FILE__);
if ( $script_dir =~ m{^([-/\w.]+)$} ) { $script_dir = $1 }
else                                  { die "FATAL: Invalid script_dir\n" }

# Pre-compute canonical paths before pledge (RELABS-001)
my $USERFEEDS = File::Spec->rel2abs(
    File::Spec->catfile(
        $script_dir, '..',         'data',     'services',
        'queue',     'e2gfilters', 'userlist', 'userfeeds.txt'
    )
);

if ( $USERFEEDS =~ m{^([-/\w.]+)$} ) { $USERFEEDS = $1 }
else                                 { die "FATAL: Invalid userfeeds path\n" }

my $log_date  = strftime( "%Y-%m-%d", localtime );
my $DEBUG_LOG = "/tmp/e2g_write-${log_date}.log";

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

sub debug_log {
    my ($msg) = @_;
    my $ts = strftime( "%Y-%m-%d %H:%M:%S", localtime );
    if ( open( my $fh, '>>', $DEBUG_LOG ) ) {
        flock( $fh, LOCK_EX );
        print $fh "[$ts] [E2G_WRITE] $msg\n";
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
            OpenBSD::Unveil::unveil(
                "$app_root/data/services/queue/e2gfilters/userlist", "rwc" )
              or die "unveil userlist: $!";
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

# Read POST body from ENV{POSTDATA} -- pre-read in BEGIN before security_check
my $json_input = $ENV{POSTDATA} || '';

unless ($json_input) {
    send_error( 400, "Empty request" );
}

my $data;
eval { $data = decode_json($json_input) };
if ($@) {
    debug_log("JSON parse error: $@");
    send_error( 400, "Invalid JSON" );
}

my $action = $data->{action} // '';

if ( $action eq 'add' ) {
    send_json( add_feed($data) );
}
elsif ( $action eq 'remove' ) {
    send_json( remove_feed($data) );
}
else {
    debug_log("Invalid action: $action");
    send_error( 400, "Invalid action" );
}

# =============================================
# SUBS
# =============================================
sub add_feed {
    my ($params) = @_;
    my $cat      = untaint_category( $params->{category} );
    my $url      = untaint_url( $params->{url} );

    unless ( $cat && $url ) {
        debug_log( "Untaint failed for URL: " . ( $params->{url} // 'empty' ) );
        return {
            success => 0,
            error   => 'Validation failed: Invalid category or URL format'
        };
    }

    if ( open( my $fh, '>>', $USERFEEDS ) ) {
        flock( $fh, LOCK_EX );
        print $fh "$cat: $url\n";
        close($fh);
        debug_log("Added: $cat: $url");
        return { success => 1, message => "Feed added successfully" };
    }
    return { success => 0, error => "File write error: $!" };
}

sub remove_feed {
    my ($params) = @_;
    my $url = untaint_url( $params->{url} );
    return { success => 0, error => 'Invalid URL' } unless $url;

    if ( -f $USERFEEDS ) {
        open( my $fh, '<', $USERFEEDS )
          or return { success => 0, error => "Cannot read file: $!" };
        my @lines = <$fh>;
        close($fh);

        my @updated = grep { $_ !~ /\Q$url\E/ } @lines;

        open( my $wh, '>', $USERFEEDS )
          or return { success => 0, error => "Cannot write file: $!" };
        flock( $wh, LOCK_EX );
        print $wh @updated;
        close($wh);

        debug_log("Removed: $url");
        return { success => 1, message => 'Feed removed' };
    }
    return { success => 0, error => 'Feed file not found' };
}

sub untaint_category {
    my $c = shift // '';
    return ( $c =~ /^(HOSTFILE|DOMAIN|PORN|MIXED|ADVERTISER|CAPITOLE)$/i )
      ? uc($1)
      : undef;
}

sub untaint_url {
    my $u = shift // '';
    if ( $u =~ m|^(https?://[a-zA-Z0-9\-\._~:/?#\[\]\@\!\$&'\(\)\*\+,;=%]+)$|x )
    {
        return $1;
    }
    return undef;
}
