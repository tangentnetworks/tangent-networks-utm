#!/usr/bin/perl -T

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# /var/www/htdocs/tn/cgi-bin/pf_read_input.pl
#
# Returns current contents of the user-input queue files as JSON.
# Called by the WebUI on PF tab activation to populate the recent
# entry lists with persisted data from previous sessions.
#
# SECURITY:
# - Taint mode enabled (-T)
# - RESTRICTED level (admin only, full audit trail)
# - No external input processed beyond session cookie
# - Read-only: no file writes

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

# Pre-read JSON POST body before TNSecurityCheck drains STDIN (STDIN-PREREAD-001)
# TNSecurityCheck::_check_csrf() reads $ENV{POSTDATA} via CGI->new internally.
# Without this, $ENV{POSTDATA} is empty at security_check() time and the CSRF
# check fails even though the token was sent correctly by the client.
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

# ============================================
# CONFIGURATION
# ============================================
my $_app_root = get_db_path();
$_app_root =~ s{/data/db/?.*$}{};

my $USER_INPUT =
  File::Spec->catdir( $_app_root, 'data', 'services', 'queue', 'pf-rules',
    'user-input' );

# Pre-compute canonical base BEFORE pledge -- rel2abs/getcwd unsafe after unveil
my $CANONICAL_INPUT = File::Spec->rel2abs($USER_INPUT);

my $log_date = strftime( "%Y-%m-%d", localtime );
my $PF_LOG = "/tmp/pf_read_input-" . strftime( "%Y-%m-%d", localtime ) . ".log";

my $cgi = CGI->new;
print $cgi->header(
    -type    => 'application/json',
    -charset => 'utf-8',
    -status  => '200 OK'
);
$| = 1; # autoflush -- ensure header reaches browser before anything can kill us
print STDERR "[pf_read_input] CP1: header sent\n";

# ============================================
# OPENBSD PLEDGE + UNVEIL
# ============================================
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
            );
            for my $entry (
                [ "$app_root/data/services/queue/pf-rules/user-input", "r" ],
                [ "$app_root/data/keys",                               "r" ],
                [ "/usr/lib/perl5",                                    "r" ],
                [ "/usr/libdata/perl5",                                "r" ],
                [ "/usr/local/lib/perl5",                              "r" ],
                [ "/usr/local/libdata/perl5",                          "r" ],
                [ "/usr/local/lib",                                    "r" ],
                [ "/usr/lib",                                          "r" ],
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
        if ( open( my $lf, '>>', "/tmp/pf_read_input-${d}.log" ) ) {
            print $lf "[FATAL] sandbox_init_failed: $err\n";
            close $lf;
        }
        print encode_json( { success => 0, error => "Internal server error" } );
        exit 1;
    }
}
print STDERR "[pf_read_input] CP2: pledge block done\n";

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
# (security_check enforces POST internally;
#  GET would be rejected before reaching here)
# ============================================
my $method = $ENV{REQUEST_METHOD} || '';
print STDERR "[pf_read_input] CP3: method=$method\n";
unless ( $method eq 'POST' ) {
    write_log( 'ERROR', "Invalid method: $method" );
    print encode_json( { success => 0, error => "POST only" } );
    exit 1;
}

# ============================================
# SAFE FILE READ
# Returns arrayref of non-empty lines, or empty arrayref if file absent.
# ============================================
sub safe_read_lines {
    my ($filename) = @_;

    # Validate filename
    unless ( $filename =~ /^([a-z0-9_-]+\.(?:txt|json))$/i ) {
        return [];
    }

    my $safe_filename = $1;
    my $full_path     = File::Spec->catfile( $USER_INPUT, $safe_filename );

    # Use pre-computed canonical base (rel2abs unsafe after unveil)
    unless ( index( $full_path, $CANONICAL_INPUT ) == 0 ) {
        return [];
    }

    return [] unless -f $full_path;

    my @lines;
    if ( open my $fh, '<', $full_path ) {
        while ( my $line = <$fh> ) {
            chomp $line;
            push @lines, $line if $line =~ /\S/;
        }
        close $fh;
    }

    return \@lines;
}

# ============================================
# BUILD RESPONSE
#
# Queue file layout (mirrors pf_write_input.pl):
#   ip-block.txt    one IPv4/IPv6/CIDR per line
#   ip-pass.txt     one IPv4/IPv6/CIDR per line
#   asn-block.txt   one ASN per line  (AS12345)
#   asn-pass.txt    one ASN per line
#   feed-urls.txt   one entry per line (action:url)
# ============================================
my %result = (
    success => 1,
    ip      => { block => [], pass => [] },
    asn     => { block => [], pass => [] },
    feeds   => [],
);

# IP
$result{ip}{block} = safe_read_lines('ip-block.txt');
$result{ip}{pass}  = safe_read_lines('ip-pass.txt');

# ASN
$result{asn}{block} = safe_read_lines('asn-block.txt');
$result{asn}{pass}  = safe_read_lines('asn-pass.txt');

# Feeds - parse "action:url" format
my $raw_feeds = safe_read_lines('feed-urls.txt');
for my $line (@$raw_feeds) {
    if ( $line =~ /^(block|pass):(.+)$/ ) {
        push @{ $result{feeds} }, { action => $1, url => $2 };
    }
}

write_log(
    'INFO',
    sprintf(
        "Read queue: ip-block=%d ip-pass=%d asn-block=%d asn-pass=%d feeds=%d",
        scalar( @{ $result{ip}{block} } ),
        scalar( @{ $result{ip}{pass} } ),
        scalar( @{ $result{asn}{block} } ),
        scalar( @{ $result{asn}{pass} } ),
        scalar( @{ $result{feeds} } )
    )
);

print STDERR "[pf_read_input] CP4: about to encode_json\n";
print encode_json( \%result );
exit 0;
