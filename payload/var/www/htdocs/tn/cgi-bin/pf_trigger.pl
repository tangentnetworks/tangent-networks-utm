#!/usr/bin/perl -T

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# /var/www/htdocs/tn/cgi-bin/pf_trigger.pl

BEGIN {
    if ( $ENV{GATEWAY_INTERFACE} ) {
        open( STDERR, '>>', '/tmp/pf_trigger_stderr.log' )
          or warn "Cannot redirect STDERR\n";
        STDERR->autoflush(1);
    }
}

use strict;
use warnings;

use FindBin qw($RealBin);
use File::Spec;

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
use JSON::XS;

# Now load other modules
use CGI        qw(:standard);
use JSON::PP   ();
use POSIX      qw(strftime);
use File::Path qw(make_path);

# Clean environment for taint mode
$ENV{PATH} = '/bin:/usr/bin';
delete @ENV{ 'IFS', 'CDPATH', 'ENV', 'BASH_ENV' };

# ============================================
# CONFIGURATION
# ============================================
my $_app_root = get_db_path();
$_app_root =~ s{/data/db/?.*$}{};

my $TRIGGERS_DIR =
  File::Spec->catdir( $_app_root, 'data', 'services', 'queue', 'pf-rules',
    'triggers' );

my $log_date = strftime( "%Y-%m-%d", localtime );
my $PF_LOG   = "/tmp/pf_trigger-" . strftime( "%Y-%m-%d", localtime ) . ".log";

# Security check before header -- _error_response() in TNSecurityCheck
# emits its own Status + Content-Type if auth fails, so the header must
# not be printed until we know the request is authenticated.
my $session = security_check('restricted');

# Auth passed -- now safe to emit the response header.
my $cgi = CGI->new;
print $cgi->header(
    -type    => 'application/json',
    -charset => 'utf-8',
    -status  => '200 OK'
);

# ============================================
# OPENBSD PLEDGE + UNVEIL
# ============================================
# Ensure triggers directory exists before pledge locks the filesystem
{
    use File::Path qw(make_path);
    my $_qdir =
      File::Spec->catdir( $_app_root, 'data', 'services', 'queue', 'pf-rules',
        'triggers' );
    make_path( $_qdir, { mode => 0755 } ) unless -d $_qdir;
}

{
    my $app_root = $_app_root;
    eval {
        if ( eval { require OpenBSD::Unveil; 1 } ) {
            my @to_unveil = (
                [ "$app_root/data/lib",                              "r" ],
                [ "$app_root/data/config",                           "r" ],
                [ "$app_root/data/db",                               "rwc" ],
                [ "/tmp",                                            "rwc" ],
                [ "/dev/urandom",                                    "r" ],
                [ "$app_root/data/services/queue/pf-rules/triggers", "rwc" ],
            );
            for my $entry (
                [ "$app_root/data/keys",      "r" ],
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
        my $err = $@;
        chomp $err;
        my $d = strftime( '%Y-%m-%d', localtime );
        if ( open( my $lf, '>>', "/tmp/pf_trigger-${d}.log" ) ) {
            print $lf "[FATAL] sandbox_init_failed: $err\n";
            close $lf;
        }
        print encode_json( { success => 0, error => "Internal server error" } );
        exit 1;
    }
}

# ============================================
# AUDIT LOGGING
# ============================================
sub write_log {
    my ( $level, $msg ) = @_;
    my $timestamp = strftime( "%Y-%m-%d %H:%M:%S", localtime );
    my $username  = $session->{username} || 'unknown';
    if ( open( my $log_fh, '>>', $PF_LOG ) ) {
        print $log_fh "[$timestamp] USER:$username [$level] $msg\n";
        close($log_fh);
    }
}

# ============================================
# UNTAINT ACTION
# ============================================
sub untaint_action {
    my ($action) = @_;

    if ( $action =~ /^(validate|apply|reset)$/ ) {
        return $1;
    }

    return undef;
}

# ============================================
# PARSE INPUT
# ============================================
my $json_text = $cgi->param('POSTDATA') || '';

unless ($json_text) {
    write_log( 'ERROR', "Empty request body" );
    print encode_json( { success => 0, error => "Empty request body" } );
    exit 1;
}

# Parse JSON
my $data;
eval { $data = decode_json($json_text); };

if ($@) {
    write_log( 'ERROR', "Invalid JSON: $@" );
    print encode_json( { success => 0, error => "Invalid JSON" } );
    exit 1;
}

unless ( $data->{action} ) {
    write_log( 'ERROR', "Missing action field" );
    print encode_json( { success => 0, error => "Missing action" } );
    exit 1;
}

# Untaint action
my $action = untaint_action( $data->{action} );
unless ($action) {
    write_log( 'ERROR', "Invalid action: " . ( $data->{action} || '' ) );
    print encode_json( { success => 0, error => "Invalid action" } );
    exit 1;
}

# ============================================
# ENSURE TRIGGERS DIRECTORY EXISTS
# ============================================
unless ( -d $TRIGGERS_DIR ) {
    make_path( $TRIGGERS_DIR, { mode => 0755 } ) or do {
        write_log( 'ERROR', "Failed to create triggers directory: $!" );
        print encode_json(
            { success => 0, error => "Failed to create directory" } );
        exit 1;
    };
}

# ============================================
# TOUCH TRIGGER FILE
# ============================================
my $trigger_file = File::Spec->catfile( $TRIGGERS_DIR, "${action}-requested" );

# Untaint: $action is already clean (from untaint_action capture);
# $TRIGGERS_DIR derives from get_db_path() and is tainted by Perl.
# Pattern confirms the full path contains only safe characters.
unless ( $trigger_file =~ m{^([-/\w.]+)$} ) {
    write_log( 'ERROR', "Invalid trigger file path: $trigger_file" );
    print encode_json( { success => 0, error => "Invalid trigger path" } );
    exit 1;
}
$trigger_file = $1;

# Safe open (no shell execution)
if ( open my $fh, '>', $trigger_file ) {
    print $fh time() . "\n";
    close $fh;

    write_log( 'INFO', "Trigger created: $action" );
    print encode_json( { success => 1 } );
}
else {
    write_log( 'ERROR',
        "Failed to create trigger file for action=$action: $!" );
    print encode_json( { success => 0, error => "Failed to create trigger" } );
}

exit 0;
