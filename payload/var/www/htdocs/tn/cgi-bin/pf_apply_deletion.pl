#!/usr/bin/perl -T

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# /var/www/htdocs/tn/cgi-bin/pf_apply_deletion.pl
#
# Called after the operator confirms the diff preview.
# Verifies the staged deletion conf exists, then drops
# apply-deletion-requested trigger for pf_monitor.sh.
# pf_monitor.sh copies the conf to /etc/pf/pf-addons.conf,
# reloads the anchor, calls pf_anchor_sync.sh, writes outcome.
#
# SECURITY:
#   - Taint mode (-T)
#   - RESTRICTED level (admin only)
#   - STDIN pre-read in BEGIN before security_check (STDIN-PREREAD-001)
#   - CSRF validated by security_check, not manually here
#   - Canonical path checks before every file operation
#   - No pfctl, no shell execution

use strict;
use warnings;
use FindBin qw($RealBin);
use File::Spec;

our $RAW_POST;

BEGIN {
    $ENV{PATH} = '/bin:/usr/bin';
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

    # STDIN-PREREAD-001
    if (   $ENV{CONTENT_TYPE}
        && $ENV{CONTENT_TYPE} =~ /application\/json/
        && $ENV{CONTENT_LENGTH} )
    {
        read( STDIN, $RAW_POST, $ENV{CONTENT_LENGTH} );
        $ENV{POSTDATA} = $RAW_POST;
    }
}

use TNEnv;
use TNSecurityCheck;

# Pre-load XS modules before pledge locks dlopen()
use DBD::SQLite;
use JSON::XS;

# security_check validates session + CSRF from $ENV{POSTDATA}
my $session = security_check('restricted');

use CGI   qw(:standard);
use POSIX qw(strftime);

# Print HTTP header immediately -- before any path construction or die
# can reach slowcgi as a raw 500 with no body.
{
    my $_cgi = CGI->new;
    print $_cgi->header(
        -type    => 'application/json',
        -charset => 'utf-8',
        -status  => '200 OK',
    );
}

# ============================================================
# RESPONSE HELPERS
# Header already sent -- just print body.
# ============================================================
sub send_json {
    my ($data) = @_;
    print encode_json($data);
    exit 0;
}

sub send_error {
    my ( $code, $message ) = @_;
    print encode_json( { success => 0, error => $message } );
    exit 0;
}

# ============================================================
# LOGGING
# ============================================================
my $LOG_DATE = strftime( '%Y-%m-%d', localtime );
my $LOG_FILE = "/tmp/pf_apply_deletion-${LOG_DATE}.log";

sub write_log {
    my ( $level, $msg ) = @_;
    my $ts   = strftime( '%Y-%m-%d %H:%M:%S', localtime );
    my $user = $session->{username} || 'unknown';
    if ( open my $fh, '>>', $LOG_FILE ) {
        print $fh "[$ts] USER:$user [$level] $msg\n";
        close $fh;
    }
}

# ============================================================
# PATHS -- all rel2abs before pledge (RELABS-001)
# ============================================================
my $script_dir = $RealBin;
if ( $script_dir =~ m{^([-/\w.]+)$} ) { $script_dir = $1 }
else {
    print encode_json( { success => 0, error => 'Invalid script path' } );
    exit 1;
}

my $app_root = $script_dir;
$app_root =~ s{/cgi-bin$}{};
$app_root =~ s{^/var/www}{};

my $QUEUE_BASE =
  File::Spec->catdir( $app_root, 'data', 'services', 'queue', 'pf-rules' );
my $STAGING       = File::Spec->catdir( $QUEUE_BASE, 'staging' );
my $TRIGGERS      = File::Spec->catdir( $QUEUE_BASE, 'triggers' );
my $DELETION_CONF = File::Spec->catfile( $STAGING, 'pf-addons-deletion.conf' );
my $APPLY_TRIGGER =
  File::Spec->catfile( $TRIGGERS, 'apply-deletion-requested' );

# Canonical base for path-traversal guard
my $CANONICAL_QUEUE    = File::Spec->rel2abs($QUEUE_BASE);
my $CANONICAL_STAGING  = File::Spec->rel2abs($STAGING);
my $CANONICAL_TRIGGERS = File::Spec->rel2abs($TRIGGERS);

# Untaint derived file paths
for my $ref ( \$DELETION_CONF, \$APPLY_TRIGGER ) {
    my $abs = File::Spec->rel2abs($$ref);
    if ( $abs =~ m{^([-/\w.]+)$} ) { $$ref = $1 }
    else {
        print encode_json( { success => 0, error => 'Invalid internal path' } );
        exit 1;
    }
}

# ============================================================
# OPENBSD PLEDGE + UNVEIL
# ============================================================
{
    eval {
        if ( eval { require OpenBSD::Unveil; 1 } ) {
            my @to_unveil = (
                [ "$app_root/data/lib",    'r' ],
                [ "$app_root/data/config", 'r' ],
                [ "$app_root/data/db",     'r' ],
                [ $CANONICAL_QUEUE,        'rwc' ],
                [ '/tmp',                  'rwc' ],
                [ '/dev/urandom',          'r' ],
            );
            for my $entry (
                [ "$app_root/data/keys",      'r' ],
                [ '/usr/lib/perl5',           'r' ],
                [ '/usr/libdata/perl5',       'r' ],
                [ '/usr/local/lib/perl5',     'r' ],
                [ '/usr/local/libdata/perl5', 'r' ],
                [ '/usr/local/lib',           'r' ],
                [ '/usr/lib',                 'r' ],
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
            OpenBSD::Pledge::pledge('stdio rpath wpath cpath flock')
              or die "pledge: $!";
        }
    };
    if ($@) {
        my $err = $@;
        chomp $err;
        if ( open my $lf, '>>', $LOG_FILE ) {
            print $lf "[FATAL] sandbox_init_failed: $err\n";
            close $lf;
        }
        print encode_json( { success => 0, error => 'Internal server error' } );
        exit 1;
    }
}

write_log( 'DEBUG', "pledge/unveil passed CANONICAL_QUEUE=$CANONICAL_QUEUE" );

# ============================================================
# PARSE REQUEST
# CSRF already validated by security_check via $ENV{POSTDATA}
# ============================================================
my $json_text = $RAW_POST || '';

unless ( $json_text && $json_text =~ /\S/ ) {
    write_log( 'ERROR', 'Empty request body' );
    send_error( 400, 'Empty request body' );
}

my $req;
eval { $req = decode_json($json_text) };
if ( $@ || !ref $req ) {
    write_log( 'ERROR', "JSON parse error: $@" );
    send_error( 400, 'Invalid JSON' );
}

# confirm field must be present and true
# JS sends { confirm: true, csrf_token: "..." } after user clicks Confirm
unless ( $req->{confirm} ) {
    write_log( 'WARN', 'apply-deletion called without confirm field' );
    send_error( 400, 'confirm field required' );
}

# ============================================================
# VERIFY STAGED CONF EXISTS
# pf_write_rules.pl must have run first.
# If the file is absent, the test step never happened.
# ============================================================

# Path-traversal guard before -f check
unless ( index( $DELETION_CONF, $CANONICAL_STAGING ) == 0 ) {
    write_log( 'ERROR',
        "DELETION_CONF outside canonical staging: $DELETION_CONF" );
    send_error( 500, 'Internal path error' );
}

unless ( -f $DELETION_CONF && -s $DELETION_CONF ) {
    write_log( 'ERROR',
        "Staged deletion conf missing or empty: $DELETION_CONF" );
    send_error( 400,
        'No staged deletion conf found -- re-run the preview step first' );
}

# ============================================================
# ENSURE TRIGGERS DIR EXISTS
# ============================================================
unless ( -d $TRIGGERS ) {
    unless ( $TRIGGERS =~ m{^([-/\w.]+)$} ) {
        write_log( 'ERROR', "Triggers dir path failed untaint: $TRIGGERS" );
        send_error( 500, 'Internal path error' );
    }
    mkdir $1, 0755 or do {
        write_log( 'ERROR', "Cannot create triggers dir: $!" );
        send_error( 500, 'Cannot create triggers directory' );
    };
}

# ============================================================
# DROP APPLY-DELETION-REQUESTED TRIGGER
# pf_monitor.sh polls every 2s, then:
#   1. Pre-flight pfctl -nf on staged conf
#   2. pfctl -a addons -f staged conf (live load)
#   3. cp staged conf -> /etc/pf/pf-addons.conf (persistence)
#   4. pf_anchor_sync.sh (rebuild active-addons.json + parsed-rules.json)
#   5. Write staging/apply-deletion-outcome.json
# ============================================================

# Path-traversal guard
unless ( index( $APPLY_TRIGGER, $CANONICAL_TRIGGERS ) == 0 ) {
    write_log( 'ERROR',
        "APPLY_TRIGGER outside canonical triggers: $APPLY_TRIGGER" );
    send_error( 500, 'Internal path error' );
}

{
    open my $fh, '>', $APPLY_TRIGGER or do {
        write_log( 'ERROR', "Cannot write apply trigger: $!" );
        send_error( 500, 'Cannot drop apply trigger' );
    };
    print $fh strftime( '%Y-%m-%d %H:%M:%S', localtime ) . "\n";
    close $fh;
}

write_log( 'INFO', 'apply-deletion-requested trigger written' );

# ============================================================
# RESPOND
# JS polls /data/services/queue/pf-rules/staging/apply-deletion-outcome.json
# ============================================================
send_json(
    {
        success      => \1,
        message      => 'Deletion queued -- firewall updating',
        outcome_path =>
          '/data/services/queue/pf-rules/staging/apply-deletion-outcome.json',
    }
);
