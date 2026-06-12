#!/usr/bin/perl -T

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# /var/www/htdocs/tn/cgi-bin/pf_delete_input.pl
#
# Removes a single entry from a user-input queue file.
# Reads the file, filters out the exact matching line, rewrites.
#
# POST body (JSON):
#   { "type": "ip|asn|feed", "action": "block|pass", "value": "..." }
#
# SECURITY:
# - Taint mode enabled (-T)
# - RESTRICTED level (admin only, full audit trail)
# - All input untainted with strict validation (same validators as pf_write_input.pl)
# - Path canonicalisation check before any file operation
# - Atomic rewrite: write to temp, rename over original

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

# Security check - RESTRICTED level (admin only)
my $session = security_check('restricted');

use CGI      qw(:standard);
use JSON::PP ();
use POSIX    qw(strftime);

# Clean environment for taint mode
$ENV{PATH} = '/bin:/usr/bin';
delete @ENV{ 'IFS', 'CDPATH', 'ENV', 'BASH_ENV' };

# App root from TNEnv
my $_app_root = get_db_path();
$_app_root =~ s{/data/db/?.*$}{};

# ============================================
# CONFIGURATION
# ============================================
my $USER_INPUT =
  File::Spec->catdir( $_app_root, 'data', 'services', 'queue', 'pf-rules',
    'user-input' );
my $CANONICAL_INPUT = File::Spec->rel2abs($USER_INPUT);    # pre-pledge

my $log_date = strftime( "%Y-%m-%d", localtime );
my $PF_LOG =
  "/tmp/pf_delete_input-" . strftime( "%Y-%m-%d", localtime ) . ".log";

# Pre-computed paths for path-traversal checks -- must be done before unveil
# locks down the filesystem. File::Spec->rel2abs() calls getcwd() which needs
# rpath; computing here ensures it works regardless of pledge ordering.

# Instantiate CGI and emit Content-Type before pledge so that a pledge failure
# cannot produce raw output ahead of the HTTP header.
my $cgi = CGI->new;
print $cgi->header(
    -type    => 'application/json',
    -charset => 'utf-8',
    -status  => '200 OK'
);

# =============================================
# OPENBSD PLEDGE + UNVEIL
# =============================================
{
    my $app_root = $_app_root;
    eval {
        if ( eval { require OpenBSD::Unveil; 1 } ) {
            my @to_unveil = (
                [ "$app_root/data/lib",                                "r" ],
                [ "$app_root/data/config",                             "r" ],
                [ "$app_root/data/db",                                 "rwc" ],
                [ "/tmp",                                              "rwc" ],
                [ "/dev/urandom",                                      "r" ],
                [ "$app_root/data/services/queue/pf-rules/user-input", "rwc" ],
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
        if (
            open(
                my $lf,
                '>>',
                do {
                    my $d = strftime( '%Y-%m-%d', localtime );
                    "/tmp/pf_delete--${d}.log";
                }
            )
          )
        {
            print $lf "[FATAL] sandbox_init_failed: $err\n";
            close $lf;
        }
        print '{"success":0,"error":"Internal server error"}';
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
# ONLY ALLOW POST
# ============================================
my $method = $ENV{REQUEST_METHOD} || '';
unless ( $method eq 'POST' ) {
    write_log( 'ERROR', "Invalid method: $method" );
    print encode_json( { success => 0, error => "POST only" } );
    exit 1;
}

# ============================================
# UNTAINT HELPERS
# Copied verbatim from pf_write_input.pl to stay consistent.
# ============================================

sub untaint_ip {
    my ($ip) = @_;

    if ( $ip =~
/^((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))$/
      )
    {
        return $1;
    }
    if ( $ip =~
/^((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(?:[0-9]|[1-2][0-9]|3[0-2]))$/
      )
    {
        return $1;
    }
    if ( $ip =~ /^((?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4})$/ ) {
        return $1;
    }
    if ( $ip =~
/^((?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\/(?:[0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8]))$/
      )
    {
        return $1;
    }
    if ( $ip =~ /^((?:[0-9a-fA-F]{0,4}:){2,7}:?[0-9a-fA-F]{0,4})$/ ) {
        return $1;
    }
    return undef;
}

sub untaint_asn {
    my ($asn) = @_;
    if ( $asn =~ /^(AS\d{1,10})$/i ) {
        return uc($1);
    }
    return undef;
}

sub untaint_url {
    my ($url) = @_;
    if ( $url =~ /^(https?:\/\/[a-zA-Z0-9\-._~:\/?#\[\]@!$&'()*+,;=%]+)$/ ) {
        my $clean_url = $1;
        return undef if $clean_url =~ /^(file|ftp|data|javascript):/i;
        return $clean_url;
    }
    return undef;
}

sub untaint_action {
    my ($action) = @_;
    if ( $action =~ /^(block|pass)$/ ) {
        return $1;
    }
    return undef;
}

# ============================================
# SAFE DELETE - read, filter, atomic rewrite
# ============================================
sub safe_delete_line {
    my ( $filename, $target_line ) = @_;

    # Validate filename
    unless ( $filename =~ /^([a-z0-9_-]+\.(?:txt|json))$/i ) {
        return ( 0, "Invalid filename" );
    }

    my $safe_filename = $1;
    my $full_path     = File::Spec->catfile( $USER_INPUT, $safe_filename );

    # Use pre-computed canonical base (rel2abs unsafe after unveil)
    unless ( index( $full_path, $CANONICAL_INPUT ) == 0 ) {
        return ( 0, "Path traversal detected" );
    }

    # Untaint: path confirmed safe by index() check above.
    if ( $full_path =~ m{^([-/\w.]+)$} ) {
        $full_path = $1;
    }
    else {
        return ( 0, "Invalid path characters" );
    }

    unless ( -f $full_path ) {
        return ( 0, "File not found" );
    }

    # Read all lines
    my @lines;
    if ( open my $fh, '<', $full_path ) {
        while ( my $line = <$fh> ) {
            chomp $line;
            push @lines, $line if $line =~ /\S/;
        }
        close $fh;
    }
    else {
        return ( 0, "Cannot read file: $!" );
    }

    # Filter out exact match
    my $original_count = scalar @lines;
    @lines = grep { $_ ne $target_line } @lines;
    my $removed = $original_count - scalar(@lines);

    if ( $removed == 0 ) {
        return ( 0, "Entry not found in queue" );
    }

    # Atomic rewrite: write to temp file, rename over original
    my $tmp_path = $full_path . '.tmp';

    if ( open my $fh, '>', $tmp_path ) {
        for my $line (@lines) {
            print $fh $line . "\n";
        }
        close $fh;
    }
    else {
        return ( 0, "Cannot write temp file: $!" );
    }

    unless ( rename( $tmp_path, $full_path ) ) {
        unlink $tmp_path;
        return ( 0, "Cannot rename temp file: $!" );
    }

    return ( 1, $removed );
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

my $data;
eval { $data = decode_json($json_text); };

if ($@) {
    write_log( 'ERROR', "Invalid JSON: $@" );
    print encode_json( { success => 0, error => "Invalid JSON" } );
    exit 1;
}

# Validate type
my $type = $data->{type} || '';
unless ( $type =~ /^(ip|asn|feed)$/ ) {
    write_log( 'ERROR', "Invalid type: $type" );
    print encode_json( { success => 0, error => "Invalid type" } );
    exit 1;
}
$type = $1;

# ============================================
# ROUTE TO HANDLER
# ============================================
if ( $type eq 'ip' ) {
    handle_delete_ip($data);
}
elsif ( $type eq 'asn' ) {
    handle_delete_asn($data);
}
elsif ( $type eq 'feed' ) {
    handle_delete_feed($data);
}

# ============================================
# HANDLER: IP / CIDR
# ============================================
sub handle_delete_ip {
    my ($data) = @_;

    my $action = untaint_action( $data->{action} || '' );
    unless ($action) {
        write_log( 'ERROR',
            "Invalid action for ip delete: " . ( $data->{action} || '' ) );
        print encode_json( { success => 0, error => "Invalid action" } );
        exit 1;
    }

    my $ip = untaint_ip( $data->{value} || '' );
    unless ($ip) {
        write_log( 'ERROR',
            "Invalid IP/CIDR for delete: " . ( $data->{value} || '' ) );
        print encode_json(
            { success => 0, error => "Invalid IP/CIDR format" } );
        exit 1;
    }

    my $filename = "ip-$action.txt";
    my ( $ok, $detail ) = safe_delete_line( $filename, $ip );

    if ($ok) {
        write_log( 'INFO', "IP deleted from queue: $action $ip" );
        print encode_json( { success => 1 } );
    }
    else {
        write_log( 'ERROR', "IP delete failed: $action $ip - $detail" );
        print encode_json( { success => 0, error => $detail } );
    }
}

# ============================================
# HANDLER: ASN
# ============================================
sub handle_delete_asn {
    my ($data) = @_;

    my $action = untaint_action( $data->{action} || '' );
    unless ($action) {
        write_log( 'ERROR',
            "Invalid action for asn delete: " . ( $data->{action} || '' ) );
        print encode_json( { success => 0, error => "Invalid action" } );
        exit 1;
    }

    my $asn = untaint_asn( $data->{value} || '' );
    unless ($asn) {
        write_log( 'ERROR',
            "Invalid ASN for delete: " . ( $data->{value} || '' ) );
        print encode_json( { success => 0, error => "Invalid ASN format" } );
        exit 1;
    }

    my $filename = "asn-$action.txt";
    my ( $ok, $detail ) = safe_delete_line( $filename, $asn );

    if ($ok) {
        write_log( 'INFO', "ASN deleted from queue: $action $asn" );
        print encode_json( { success => 1 } );
    }
    else {
        write_log( 'ERROR', "ASN delete failed: $action $asn - $detail" );
        print encode_json( { success => 0, error => $detail } );
    }
}

# ============================================
# HANDLER: Feed URL
# Feed lines are stored as "action:url" so we
# reconstruct that format before matching.
# ============================================
sub handle_delete_feed {
    my ($data) = @_;

    my $action = untaint_action( $data->{action} || '' );
    unless ($action) {
        write_log( 'ERROR',
            "Invalid action for feed delete: " . ( $data->{action} || '' ) );
        print encode_json( { success => 0, error => "Invalid action" } );
        exit 1;
    }

    my $url = untaint_url( $data->{value} || '' );
    unless ($url) {
        write_log( 'ERROR',
            "Invalid feed URL for delete: " . ( $data->{value} || '' ) );
        print encode_json( { success => 0, error => "Invalid URL format" } );
        exit 1;
    }

    # Reconstruct the exact line as written by pf_write_input.pl
    my $target_line = "$action:$url";

    my ( $ok, $detail ) = safe_delete_line( 'feed-urls.txt', $target_line );

    if ($ok) {
        write_log( 'INFO', "Feed deleted from queue: $action $url" );
        print encode_json( { success => 1 } );
    }
    else {
        write_log( 'ERROR', "Feed delete failed: $action $url - $detail" );
        print encode_json( { success => 0, error => $detail } );
    }
}

exit 0;
