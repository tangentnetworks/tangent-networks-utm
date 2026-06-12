#!/usr/bin/perl -T

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# /var/www/htdocs/tn/cgi-bin/pf_active_rules.pl
#
# PURPOSE:
#   POST {action:"read"}   -- Returns active-addons.json (currently loaded anchor blocks)
#   POST {action:"delete"} -- Accepts a block deletion request, writes to delete-requests queue
#
# SECURITY:
#   - Taint mode enabled (-T)
#   - RESTRICTED level (admin only, session + CSRF)
#   - POST body pre-read into $ENV{POSTDATA} before security_check (STDIN-PREREAD-001)
#   - All file writes use canonical path check
#   - No shell execution

use strict;
use warnings;

use FindBin qw($RealBin);
use File::Spec;

our $RAW_POST;

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

# Pre-read JSON POST body before TNSecurityCheck drains STDIN (STDIN-PREREAD-001)
# Also save to $RAW_POST -- security_check may clear $ENV{POSTDATA} internally
# after reading it for CSRF validation, leaving nothing for our code to read.
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

# Pre-load XS before pledge locks down dlopen()
use DBD::SQLite;
use JSON::XS;

# Security check - RESTRICTED level (admin only)
my $session = security_check('restricted');

use CGI      qw(:standard);
use JSON::PP ();
use POSIX    qw(strftime);

$ENV{PATH} = '/bin:/usr/bin';
delete @ENV{ 'IFS', 'CDPATH', 'ENV', 'BASH_ENV' };

# ============================================
# CONFIGURATION
# ============================================
my $_app_root = get_db_path();
$_app_root =~ s{/data/db/?.*$}{};

my $QUEUE_BASE =
  File::Spec->catdir( $_app_root, 'data', 'services', 'queue', 'pf-rules' );
my $ACTIVE_JSON = File::Spec->catfile( $QUEUE_BASE, 'active-addons.json' );
my $PARSED_JSON = File::Spec->catfile( $QUEUE_BASE, 'parsed-rules.json' );
my $DELETE_DIR  = File::Spec->catdir( $QUEUE_BASE, 'delete-requests' );
my $OUTCOME_DIR = File::Spec->catdir( $QUEUE_BASE, 'delete-outcome' );

# Pre-compute canonical bases before pledge
my $CANONICAL_QUEUE   = File::Spec->rel2abs($QUEUE_BASE);
my $CANONICAL_DELETE  = File::Spec->rel2abs($DELETE_DIR);
my $CANONICAL_OUTCOME = File::Spec->rel2abs($OUTCOME_DIR);

my $LOG_DATE = strftime( "%Y-%m-%d", localtime );
my $LOG_FILE = "/tmp/pf_active_rules-${LOG_DATE}.log";

my $cgi = CGI->new;
print $cgi->header(
    -type    => 'application/json',
    -charset => 'utf-8',
    -status  => '200 OK'
);

{
    my $app_root = $_app_root;
    eval {
        if ( eval { require OpenBSD::Unveil; 1 } ) {
            my @to_unveil = (
                [ "$app_root/data/lib",    "r" ],
                [ "$app_root/data/config", "r" ],
                [ "$app_root/data/db",     "rwc" ],
                [ "/tmp",                  "rwc" ],
                [ "/dev/urandom",          "r" ],
                [ $CANONICAL_QUEUE,        "rwc" ],
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
        print encode_json( { success => 0, error => "Internal server error" } );
        exit 1;
    }
}

# ============================================
# LOGGING
# ============================================
sub write_log {
    my ( $level, $msg ) = @_;
    my $ts   = strftime( "%Y-%m-%d %H:%M:%S", localtime );
    my $user = $session->{username} || 'unknown';
    if ( open my $fh, '>>', $LOG_FILE ) {
        print $fh "[$ts] USER:$user [$level] $msg\n";
        close $fh;
    }
}

write_log( 'DEBUG',
"pledge/unveil passed -- CANONICAL_QUEUE=$CANONICAL_QUEUE ACTIVE_JSON=$ACTIVE_JSON"
);

# ============================================
# ROUTE BY METHOD
# ============================================
my $json_text = $RAW_POST || '';

unless ($json_text) {
    write_log( 'ERROR', "Empty POST body" );
    print encode_json( { success => 0, error => "Empty request body" } );
    exit 0;
}

my $data;
eval { $data = decode_json($json_text) };
if ( $@ || !$data ) {
    write_log( 'ERROR', "Invalid JSON: $@" );
    print encode_json( { success => 0, error => "Invalid JSON" } );
    exit 0;
}

my $action = $data->{action} || '';
unless ( $action =~
/^(read|delete|parse|check|get_test_result|get_outcome|delete_entry|get_delete_outcome|get_intel)$/
  )
{
    write_log( 'ERROR', "Invalid action: $action" );
    print encode_json( { success => 0, error => "Invalid action" } );
    exit 0;
}
$action = $1;

# ============================================
# ACTION: READ -- serve active-addons.json
# ============================================
if ( $action eq 'read' ) {
    unless ( -f $ACTIVE_JSON ) {
        print encode_json(
            {
                success       => 1,
                anchor_loaded => 0,
                load_error    =>
'active-addons.json not found -- pf_anchor_sync.sh may not be running',
                blocks => [],
            }
        );
        exit 0;
    }

    open my $fh, '<', $ACTIVE_JSON or do {
        print encode_json(
            { success => 0, error => "Cannot read active-addons.json: $!" } );
        exit 0;
    };
    local $/;
    my $raw = <$fh>;
    close $fh;

    # Validate it parses before forwarding -- catch malformed file
    eval { decode_json($raw) };
    if ($@) {
        print encode_json(
            { success => 0, error => "Malformed active-addons.json" } );
        exit 0;
    }

    # Print raw -- avoids Perl boolean round-trip issues on re-encode
    print $raw;
    exit 0;
}

# ============================================
# ACTION: PARSE -- serve parsed-rules.json
# ============================================
if ( $action eq 'parse' ) {
    unless ( -f $PARSED_JSON ) {
        print encode_json(
            {
                success => 0,
                error   =>
'parsed-rules.json not found -- pf_anchor_sync.sh may not have run yet',
                sections => [],
                objects  => {},
                graph    => {},
            }
        );
        exit 0;
    }

    open my $fh, '<', $PARSED_JSON or do {
        print encode_json(
            { success => 0, error => "Cannot read parsed-rules.json: $!" } );
        exit 0;
    };
    local $/;
    my $raw = <$fh>;
    close $fh;

    eval { decode_json($raw) };
    if ($@) {
        print encode_json(
            { success => 0, error => "Malformed parsed-rules.json" } );
        exit 0;
    }

    print $raw;
    exit 0;
}

# ============================================
# ACTION: CHECK -- cascade dependency analysis
#
# POST { action:"check", target_name:"geoip_vn" }
# Returns which rules would become dangling if
# the named object (table/macro/queue) is deleted.
# ============================================
if ( $action eq 'check' ) {
    my $target = $data->{target_name} || '';
    unless ( $target =~ /^([\w_:]+)$/ ) {
        print encode_json( { success => 0, error => "Invalid target name" } );
        exit 0;
    }
    $target = $1;

    unless ( -f $PARSED_JSON ) {
        print encode_json(
            { success => 0, error => "parsed-rules.json not available" } );
        exit 0;
    }

    open my $fh, '<', $PARSED_JSON or do {
        print encode_json(
            { success => 0, error => "Cannot read parsed-rules.json: $!" } );
        exit 0;
    };
    local $/;
    my $raw = <$fh>;
    close $fh;

    my $dag = eval { decode_json($raw) };
    if ( $@ || !$dag ) {
        print encode_json(
            { success => 0, error => "Malformed parsed-rules.json" } );
        exit 0;
    }

    # Build O(1) lookup
    my %rule_by_id;
    for my $section ( @{ $dag->{sections} || [] } ) {
        for my $rule ( @{ $section->{rules} || [] } ) {
            $rule_by_id{ $rule->{id} } = $rule;
        }
    }

    # Iterative BFS cascade -- same algorithm as pf_rule_parser.pl
    my %visited;
    my %reasons;
    my @bfs_queue = ($target);

    while (@bfs_queue) {
        my $name = shift @bfs_queue;
        next unless exists $dag->{graph}{$name};

        for my $child_id ( @{ $dag->{graph}{$name} } ) {
            next if $visited{$child_id}++;

            my $child = $rule_by_id{$child_id};
            next unless $child;

            # Find which token(s) caused this dependency
            my @triggering =
              grep { $_->{name} eq $name } @{ $child->{deps} || [] };
            my $token_list =
              join( ', ', map { $_->{token} } @triggering ) || $name;

            $reasons{$child_id} = {
                rule_raw => $child->{raw},
                reason   => "Depends on '$name' via $token_list",
                section  => $child->{section} || '',
                type     => $child->{type}    || 'filter',
            };

            # If child is itself a provider, cascade further
            if ( $child->{provides} ) {
                push @bfs_queue, $child->{provides};
            }
        }
    }

    my $cascade_count = scalar keys %reasons;
    write_log( 'INFO', "check: target=$target cascade=$cascade_count" );

    print encode_json(
        {
            success       => 1,
            target        => $target,
            cascade_count => $cascade_count,
            affected      => \%reasons,
            safe          => ( $cascade_count == 0 ? \1 : \0 ),
        }
    );
    exit 0;
}

# ============================================
# ACTION: GET_DELETE_OUTCOME -- serve delete-outcome result JSON
# Replaces direct fetch of /data/services/queue/pf-rules/delete-outcome/
# which is blocked by router.pl (WAF). CGI layer bypasses it.
# Returns {"success":false,"not_ready":true} if file absent.
# ============================================
if ( $action eq 'get_delete_outcome' ) {
    my $request_id = $data->{request_id} || '';
    unless ( $request_id =~ /^(\d{10,11})$/ ) {
        print encode_json( { success => 0, error => 'Invalid request_id' } );
        exit 0;
    }
    $request_id = $1;

    my $outcome_file = File::Spec->catfile( $QUEUE_BASE, 'delete-outcome',
        "${request_id}.result.json" );
    unless ( $outcome_file =~ m{^([-/\w.]+)$} ) {
        print encode_json( { success => 0, error => 'Invalid path' } );
        exit 0;
    }
    $outcome_file = $1;

    unless ( -f $outcome_file ) {
        print encode_json( { success => 0, not_ready => \1 } );
        exit 0;
    }

    open my $fh, '<', $outcome_file or do {
        print encode_json(
            { success => 0, error => "Cannot read outcome: $!" } );
        exit 0;
    };
    local $/;
    my $raw = <$fh>;
    close $fh;

    eval { decode_json($raw) };
    if ($@) {
        print encode_json( { success => 0, error => 'Malformed outcome' } );
        exit 0;
    }

    print $raw;
    exit 0;
}

# ============================================
# ACTION: GET_TEST_RESULT -- serve deletion-test-result.json
# Written by pf_monitor.sh do_test_deletion after pfctl -nf
# ============================================
if ( $action eq 'get_test_result' ) {
    my $result_file = File::Spec->catfile( $QUEUE_BASE, 'staging',
        'deletion-test-result.json' );
    unless ( $result_file =~ m{^([-/\w.]+)$} ) {
        print encode_json( { success => 0, error => 'Invalid path' } );
        exit 0;
    }
    $result_file = $1;

    unless ( -f $result_file ) {
        print encode_json( { success => 0, not_ready => \1 } );
        exit 0;
    }

    open my $fh, '<', $result_file or do {
        print encode_json(
            { success => 0, error => "Cannot read test result: $!" } );
        exit 0;
    };
    local $/;
    my $raw = <$fh>;
    close $fh;

    eval { decode_json($raw) };
    if ($@) {
        print encode_json( { success => 0, error => 'Malformed test result' } );
        exit 0;
    }

    print $raw;
    exit 0;
}

# ============================================
# ACTION: GET_OUTCOME -- serve apply-deletion-outcome.json
# Written by pf_monitor.sh do_apply_deletion after anchor reload
# ============================================
if ( $action eq 'get_outcome' ) {
    my $outcome_file = File::Spec->catfile( $QUEUE_BASE, 'staging',
        'apply-deletion-outcome.json' );
    unless ( $outcome_file =~ m{^([-/\w.]+)$} ) {
        print encode_json( { success => 0, error => 'Invalid path' } );
        exit 0;
    }
    $outcome_file = $1;

    unless ( -f $outcome_file ) {
        print encode_json( { success => 0, not_ready => \1 } );
        exit 0;
    }

    open my $fh, '<', $outcome_file or do {
        print encode_json(
            { success => 0, error => "Cannot read outcome: $!" } );
        exit 0;
    };
    local $/;
    my $raw = <$fh>;
    close $fh;

    eval { decode_json($raw) };
    if ($@) {
        print encode_json( { success => 0, error => 'Malformed outcome' } );
        exit 0;
    }

    print $raw;
    exit 0;
}

# ============================================
# ACTION: DELETE_ENTRY -- remove specific IPs/CIDRs from a table
#
# POST {
#   action: "delete_entry",
#   table:   "user_block_ips",    (the PF table name)
#   type:    "ip_block",          (block type for queue routing)
#   entries: ["1.2.3.4", "5.6.7.0/24"]
# }
#
# Writes a delete-requests/<timestamp>.json with type=entry_delete.
# pf_delete_block.sh handles it: removes entries from conf, validates,
# applies. JS polls delete-outcome via action:get_delete_outcome.
# ============================================
if ( $action eq 'delete_entry' ) {
    my $table   = $data->{table}   || '';
    my $type    = $data->{type}    || '';
    my $entries = $data->{entries} || [];

    # Validate table name -- alphanumeric and underscore only
    unless ( $table =~ /^([a-zA-Z_][a-zA-Z0-9_]{0,63})$/ ) {
        write_log( 'ERROR', "delete_entry: invalid table name: $table" );
        print encode_json( { success => 0, error => 'Invalid table name' } );
        exit 0;
    }
    $table = $1;

    # Validate type -- must be a known block type
    unless ( $type =~ /^(ip_block|ip_pass|asn_block|geoip|feed)$/ ) {
        write_log( 'ERROR', "delete_entry: invalid type: $type" );
        print encode_json( { success => 0, error => 'Invalid type' } );
        exit 0;
    }
    $type = $1;

    # Validate entries array
    unless ( ref($entries) eq 'ARRAY' && @$entries > 0 ) {
        write_log( 'ERROR', 'delete_entry: empty entries array' );
        print encode_json(
            { success => 0, error => 'entries must be a non-empty array' } );
        exit 0;
    }

    if ( @$entries > 500 ) {
        write_log( 'ERROR',
            'delete_entry: too many entries in single request' );
        print encode_json(
            { success => 0, error => 'Maximum 500 entries per request' } );
        exit 0;
    }

# Validate each entry as an IP/CIDR or IPv6 -- same regex family as pf_write_input.pl
    my @clean_entries;
    for my $e (@$entries) {
        unless (
            defined $e
            && $e =~ m{
            ^(
                # IPv4
                (?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}
                (?:25[0-5]|2[0-4]\d|[01]?\d\d?)
                (?:/(?:[0-9]|[12]\d|3[0-2]))?
            |
                # IPv6 (simplified -- covers most forms)
                [0-9a-fA-F:]{2,39}(?:/(?:[0-9]|[1-9]\d|1[01]\d|12[0-8]))?
            )$
        }x
          )
        {
            write_log( 'ERROR',
                "delete_entry: invalid entry: " . substr( $e // '', 0, 64 ) );
            print encode_json(
                { success => 0, error => "Invalid entry format: $e" } );
            exit 0;
        }
        push @clean_entries, $1;
    }

    # Write delete request to queue -- same directory pf_monitor.sh watches
    my $timestamp = time();
    my $req_file  = File::Spec->catfile( $DELETE_DIR, "${timestamp}.json" );

    unless ( index( File::Spec->rel2abs($req_file), $CANONICAL_DELETE ) == 0 ) {
        print encode_json( { success => 0, error => 'Path error' } );
        exit 0;
    }
    unless ( $req_file =~ m{^([-/\w.]+)$} ) {
        print encode_json(
            { success => 0, error => 'Invalid request file path' } );
        exit 0;
    }
    $req_file = $1;

    my $req_obj = {
        type       => 'entry_delete',
        block_type => $type,
        table      => $table,
        entries    => \@clean_entries,
        requested  => $timestamp,
    };

    open my $fh, '>', $req_file or do {
        write_log( 'ERROR', "delete_entry: cannot write request: $!" );
        print encode_json(
            { success => 0, error => 'Failed to queue delete request' } );
        exit 0;
    };
    print $fh encode_json($req_obj);
    close $fh;

    write_log( 'INFO',
        "delete_entry queued: table=$table entries=" . scalar(@clean_entries) );

    print encode_json(
        {
            success    => \1,
            message    => 'Entry deletion queued',
            request_id => $timestamp,
        }
    );
    exit 0;
}

# ============================================
# ACTION: GET_INTEL -- serve /data/db/pf/intel.txt
# Direct fetch is blocked by httpd location "/data/db/pf/*".
# This action serves it through the CGI layer as plain text.
# ============================================
if ( $action eq 'get_intel' ) {
    my $intel_file =
      File::Spec->catfile( $_app_root, 'data', 'db', 'pf', 'intel.txt' );
    unless ( $intel_file =~ m{^([-/\w.]+)$} ) {
        print encode_json( { success => 0, error => 'Invalid intel path' } );
        exit 0;
    }
    $intel_file = $1;
    unless ( -f $intel_file && -r $intel_file ) {
        print encode_json( { success => 0, error => 'intel.txt not found' } );
        exit 0;
    }
    open my $fh, '<', $intel_file or do {
        print encode_json(
            { success => 0, error => "Cannot read intel.txt: $!" } );
        exit 0;
    };
    local $/;
    my $content = <$fh>;
    close $fh;
    my @lines = grep { /\S/ } split /\n/, $content;
    print encode_json( { success => \1, lines => \@lines } );
    exit 0;
}

# ============================================
# ACTION: DELETE -- validate and queue request
# ============================================

# VALIDATE DELETE REQUEST FIELDS
my $type = $data->{type} || '';
unless ( $type =~ /^(ip_block|ip_pass|asn_block|geoip|feed|custom)$/ ) {
    write_log( 'ERROR', "Invalid type: $type" );
    print encode_json( { success => 0, error => "Invalid deletion type" } );
    exit 0;
}
$type = $1;

# Type-specific validation
my $country  = '';
my $feed_idx = 0;
my $rule     = '';

if ( $type eq 'geoip' ) {
    my $raw_cc = $data->{country} || '';
    unless ( $raw_cc =~ /^([A-Z]{2})$/ ) {
        print encode_json( { success => 0, error => "Invalid country code" } );
        exit 0;
    }
    $country = $1;
}

if ( $type eq 'feed' ) {
    my $raw_idx = $data->{feed_index};
    unless ( defined $raw_idx && $raw_idx =~ /^(\d{1,4})$/ ) {
        print encode_json( { success => 0, error => "Invalid feed index" } );
        exit 0;
    }
    $feed_idx = int($1);
}

if ( $type eq 'custom' ) {
    my $raw_rule = $data->{rule} || '';

# Custom rules: alphanumeric, spaces, common PF symbols -- no shell metacharacters
    unless ( $raw_rule =~ /^([a-zA-Z0-9\s\-_.,:\/\(\)\[\]\{\}"']+)$/ ) {
        print encode_json(
            { success => 0, error => "Invalid rule characters" } );
        exit 0;
    }
    my $clean = $1;
    if ( $clean =~ /[;&|`\$<>]/ ) {
        print encode_json(
            { success => 0, error => "Dangerous characters in rule" } );
        exit 0;
    }
    unless ( $clean =~ /^(pass|block|match)\s/ ) {
        print encode_json(
            { success => 0, error => "Rule must start with pass/block/match" }
        );
        exit 0;
    }
    $rule = $clean;
}

# ============================================
# WRITE DELETE REQUEST FILE
# ============================================
my $timestamp = time();
my $req_file  = File::Spec->catfile( $DELETE_DIR, "${timestamp}.json" );

# Canonical path check
unless ( index( File::Spec->rel2abs($req_file), $CANONICAL_DELETE ) == 0 ) {
    print encode_json( { success => 0, error => "Path error" } );
    exit 0;
}

# Untaint
unless ( $req_file =~ m{^([-/\w.]+)$} ) {
    print encode_json( { success => 0, error => "Invalid request file path" } );
    exit 0;
}
$req_file = $1;

my $req_obj = {
    type      => $type,
    requested => $timestamp,
};
$req_obj->{country}    = $country  if $country;
$req_obj->{feed_index} = $feed_idx if $feed_idx;
$req_obj->{rule}       = $rule     if $rule;

open my $fh, '>', $req_file or do {
    write_log( 'ERROR', "Cannot write delete request: $!" );
    print encode_json(
        { success => 0, error => "Failed to queue delete request" } );
    exit 0;
};
print $fh encode_json($req_obj);
close $fh;

write_log( 'INFO',
    "Delete request queued: type=$type country=$country feed=$feed_idx" );

print encode_json(
    {
        success    => 1,
        message    => "Delete request queued",
        request_id => $timestamp,
    }
);
exit 0;
