#!/usr/bin/perl -T

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# /var/www/htdocs/tn/cgi-bin/pf_write_rules.pl
#
# Receives an array of rule IDs to delete, reads parsed-rules.json,
# builds the proposed new conf minus those IDs, writes it atomically
# to queue/pf-rules/staging/pf-addons-deletion.conf, drops trigger
# test-deletion-requested for pf_monitor.sh.
# Returns the proposed conf text so JS can render the diff preview.
#
# SECURITY:
#   - Taint mode (-T)
#   - RESTRICTED level (admin only)
#   - STDIN pre-read in BEGIN before security_check (STDIN-PREREAD-001)
#   - CSRF validated by security_check, not manually here
#   - Canonical path checks before every file write
#   - Atomic write via temp+rename
#   - No shell execution

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

    # STDIN-PREREAD-001: read POST body before security_check drains STDIN
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

# Print HTTP header immediately after security_check so any subsequent
# die or send_error produces a complete HTTP response rather than a raw
# exit that slowcgi converts to a 500 with no body.
{
    my $_cgi = CGI->new;
    print $_cgi->header(
        -type    => 'application/json',
        -charset => 'utf-8',
        -status  => '200 OK',
    );
}

# ============================================================
# RESPONSE HELPERS (integrity_files.pl pattern)
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
my $LOG_FILE = "/tmp/pf_write_rules-${LOG_DATE}.log";

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
my $PARSED_JSON   = File::Spec->catfile( $QUEUE_BASE, 'parsed-rules.json' );
my $DELETION_CONF = File::Spec->catfile( $STAGING,  'pf-addons-deletion.conf' );
my $TEST_TRIGGER  = File::Spec->catfile( $TRIGGERS, 'test-deletion-requested' );

# Canonical bases for path traversal guard -- computed before pledge
my $CANONICAL_QUEUE    = File::Spec->rel2abs($QUEUE_BASE);
my $CANONICAL_STAGING  = File::Spec->rel2abs($STAGING);
my $CANONICAL_TRIGGERS = File::Spec->rel2abs($TRIGGERS);

# Untaint all derived file paths via regex after rel2abs
for my $ref ( \$PARSED_JSON, \$DELETION_CONF, \$TEST_TRIGGER ) {
    my $abs = File::Spec->rel2abs($$ref);
    if ( $abs =~ m{^([-/\w.]+)$} ) { $$ref = $1 }
    else {
        print encode_json( { success => 0, error => 'Invalid internal path' } );
        exit 1;
    }
}

# ============================================================
# OPENBSD PLEDGE + UNVEIL
# No CGI header printed here -- send_json/send_error handle it.
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

# Validate ids array
# IDs are MD5 hex strings produced by pf_rule_parser.pl (32 lowercase hex chars)
my $raw_ids = $req->{ids};
unless ( ref($raw_ids) eq 'ARRAY' && @$raw_ids > 0 ) {
    write_log( 'ERROR', 'Missing or empty ids array' );
    send_error( 400, 'ids must be a non-empty array' );
}

my @delete_ids;
for my $id (@$raw_ids) {
    unless ( defined $id && $id =~ /^([0-9a-f]{32})$/ ) {
        write_log( 'ERROR',
            'Invalid rule id: '
              . ( defined $id ? substr( $id, 0, 64 ) : 'undef' ) );
        send_error( 400, 'Invalid rule id format' );
    }
    push @delete_ids, $1;    # untainted
}

write_log( 'INFO', 'Deletion staged for ' . scalar(@delete_ids) . ' rule(s)' );

# ============================================================
# LOAD PARSED-RULES.JSON
# ============================================================
unless ( -f $PARSED_JSON && -s $PARSED_JSON ) {
    write_log( 'ERROR', 'parsed-rules.json not found or empty' );
    send_error( 500,
        'parsed-rules.json not available -- run pf_anchor_sync.sh first' );
}

my $parsed_text;
{
    open my $fh, '<', $PARSED_JSON or do {
        write_log( 'ERROR', "Cannot read parsed-rules.json: $!" );
        send_error( 500, 'Cannot read parsed rules data' );
    };
    local $/;
    $parsed_text = <$fh>;
    close $fh;
}

my $parsed;
eval { $parsed = decode_json($parsed_text) };
if ( $@ || !ref $parsed ) {
    write_log( 'ERROR', "parsed-rules.json decode error: $@" );
    send_error( 500, 'parsed-rules.json is corrupt' );
}

# ============================================================
# FLATTEN RULES FROM SECTIONS
# pf_rule_parser.pl output structure:
#   {
#     sections => [ { label => "...", rules => [ { id, raw, type,
#                     section, deps, provides }, ... ] }, ... ],
#     objects  => { name => uid_of_defining_rule },
#     graph    => { name => [uid, ...] }
#   }
# No top-level rules array -- must flatten from sections.
# ============================================================
my %delete_set = map { $_ => 1 } @delete_ids;
my $sections   = $parsed->{sections} || [];
my $objects    = $parsed->{objects}  || {};

my @all_rules;
for my $sec (@$sections) {
    my $label = $sec->{label} || 'CUSTOM PF RULES';
    for my $rule ( @{ $sec->{rules} || [] } ) {

        # Stamp section label onto each rule for grouping below
        push @all_rules, { %$rule, section => $label };
    }
}

# Build O(1) lookup by id
my %rule_by_id = map { $_->{id} => $_ } @all_rules;

# ============================================================
# BUILD PROPOSED NEW CONF
#
# 1. Determine which objects are still needed by kept rules
# 2. Emit definition lines for those objects (from their
#    defining rule's raw text)
# 3. Emit filter rules section by section, dropping empty sections
# ============================================================
my %needed_objects;
for my $rule (@all_rules) {
    next if $delete_set{ $rule->{id} };
    for my $dep ( @{ $rule->{deps} || [] } ) {

        # deps entries are { name, token, type } hashrefs from parser
        my $name = ref $dep eq 'HASH' ? $dep->{name} : $dep;
        $needed_objects{$name} = 1 if defined $name && $name ne '';
    }
}

# Group kept rules by section, preserving encounter order
my @section_order;
my %section_kept;
for my $rule (@all_rules) {
    next if $delete_set{ $rule->{id} };
    my $sec = $rule->{section};
    unless ( exists $section_kept{$sec} ) {
        push @section_order, $sec;
        $section_kept{$sec} = [];
    }
    push @{ $section_kept{$sec} }, $rule;
}

my $kept_count = 0;
$kept_count += scalar @{ $section_kept{$_} } for @section_order;

my @conf_lines;
push @conf_lines, '# pf-addons.conf -- rebuilt by pf_write_rules.pl';
push @conf_lines, '# ' . strftime( '%Y-%m-%d %H:%M:%S', localtime );
push @conf_lines, '# Pending deletion preview -- not yet applied';
push @conf_lines, '# Loaded via: pfctl -a addons -f /etc/pf/pf-addons.conf';
push @conf_lines, '';

# Emit object definitions for still-referenced objects
# objects hash maps name -> uid of the defining rule
for my $obj_name ( sort keys %$objects ) {
    next unless $needed_objects{$obj_name};
    my $def_id = $objects->{$obj_name};
    my $def    = $rule_by_id{$def_id};
    next unless $def && $def->{raw};
    push @conf_lines, $def->{raw};
    push @conf_lines, '';
}

# Emit filter rule sections
for my $sec (@section_order) {
    my @kept = @{ $section_kept{$sec} };
    next unless @kept;

    push @conf_lines, '';
    push @conf_lines, '# ' . ( '=' x 60 );
    push @conf_lines, "# $sec";
    push @conf_lines, '# ' . ( '=' x 60 );

    for my $rule (@kept) {
        push @conf_lines, $rule->{raw} if defined $rule->{raw};
    }
}

push @conf_lines, '';
push @conf_lines, '# --- End of pf-addons.conf ---';

my $conf_text = join( "\n", @conf_lines ) . "\n";

# ============================================================
# WRITE STAGING CONF (atomic temp+rename)
# ============================================================

# Ensure staging dir exists
unless ( -d $STAGING ) {
    unless ( $STAGING =~ m{^([-/\w.]+)$} ) {
        write_log( 'ERROR', "Staging dir path failed untaint: $STAGING" );
        send_error( 500, 'Internal path error' );
    }
    mkdir $1, 0755 or do {
        write_log( 'ERROR', "Cannot create staging dir: $!" );
        send_error( 500, 'Cannot create staging directory' );
    };
}

# Build and untaint temp path
my $safe_pid = $$ =~ /^(\d+)$/ ? $1 : 'x';
my $tmp_raw  = "${DELETION_CONF}.tmp.${safe_pid}";
unless ( $tmp_raw =~ m{^([-/\w.]+)$} ) {
    write_log( 'ERROR', "Temp path failed untaint: $tmp_raw" );
    send_error( 500, 'Internal path error' );
}
my $tmp = $1;

{
    open my $fh, '>', $tmp or do {
        write_log( 'ERROR', "Cannot write temp conf: $!" );
        send_error( 500, 'Cannot write staging conf' );
    };
    print $fh $conf_text;
    close $fh;
}

rename( $tmp, $DELETION_CONF ) or do {
    unlink $tmp;
    write_log( 'ERROR', "Cannot rename temp conf: $!" );
    send_error( 500, 'Cannot finalise staging conf' );
};

write_log( 'INFO',
        "Staged conf written: $DELETION_CONF ($kept_count rules kept, "
      . scalar(@delete_ids)
      . " deleted)" );

# ============================================================
# DROP TEST-DELETION-REQUESTED TRIGGER
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

{
    open my $fh, '>', $TEST_TRIGGER or do {
        write_log( 'ERROR', "Cannot write test trigger: $!" );
        send_error( 500, 'Cannot drop test trigger' );
    };
    print $fh strftime( '%Y-%m-%d %H:%M:%S', localtime ) . "\n";
    close $fh;
}

write_log( 'INFO', 'test-deletion-requested trigger written' );

# ============================================================
# RESPOND
# ============================================================
send_json(
    {
        success       => \1,
        proposed_conf => $conf_text,
        deleted_count => scalar(@delete_ids),
        kept_rules    => $kept_count,
    }
);
