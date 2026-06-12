#!/usr/bin/perl -T

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# /var/www/htdocs/tn/cgi-bin/pf_write_input.pl

BEGIN {
    if ( $ENV{GATEWAY_INTERFACE} ) {
        open( STDERR, '>>', '/tmp/pf_write_stderr.log' )
          or warn "Cannot redirect STDERR\n";
        STDERR->autoflush(1);
    }
}
#
# Receives user inputs from WebUI and writes to queue files
# Handles: IP, ASN, GeoIP, Feeds, Custom Rules
#
# SECURITY:
# - Taint mode enabled (-T)
# - RESTRICTED level (admin only, full audit trail)
# - All external input untainted with strict validation
# - No shell command execution
# - Chroot-safe paths only

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

my $USER_INPUT =
  File::Spec->catdir( $_app_root, 'data', 'services', 'queue', 'pf-rules',
    'user-input' );
my $CANONICAL_INPUT = File::Spec->rel2abs($USER_INPUT);    # pre-pledge

my $log_date = strftime( "%Y-%m-%d", localtime );
my $PF_LOG =
  "/tmp/pf_write_input-" . strftime( "%Y-%m-%d", localtime ) . ".log";

my $cgi = CGI->new;
print $cgi->header(
    -type    => 'application/json',
    -charset => 'utf-8',
    -status  => '200 OK'
);

# ============================================
# OPENBSD PLEDGE + UNVEIL
# ============================================
# Ensure queue directory exists before pledge locks the filesystem
{
    use File::Path qw(make_path);
    my $_qdir =
      File::Spec->catdir( $_app_root, 'data', 'services', 'queue', 'pf-rules',
        'user-input' );
    make_path( $_qdir, { mode => 0755 } ) unless -d $_qdir;
}

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
        my $d = strftime( '%Y-%m-%d', localtime );
        if ( open( my $lf, '>>', "/tmp/pf_write_input-${d}.log" ) ) {
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
# UNTAINT HELPERS
# ============================================

# Untaint IP/CIDR (IPv4 and IPv6)
sub untaint_ip {
    my ($ip) = @_;

    # IPv4 address
    if ( $ip =~
/^((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))$/
      )
    {
        return $1;
    }

    # IPv4 CIDR
    if ( $ip =~
/^((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(?:[0-9]|[1-2][0-9]|3[0-2]))$/
      )
    {
        return $1;
    }

    # IPv6 address (simplified - matches common formats)
    if ( $ip =~ /^((?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4})$/ ) {
        return $1;
    }

    # IPv6 CIDR
    if ( $ip =~
/^((?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\/(?:[0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8]))$/
      )
    {
        return $1;
    }

    # IPv6 compressed format
    if ( $ip =~ /^((?:[0-9a-fA-F]{0,4}:){2,7}:?[0-9a-fA-F]{0,4})$/ ) {
        return $1;
    }

    return undef;
}

# Untaint ASN
sub untaint_asn {
    my ($asn) = @_;

    if ( $asn =~ /^(AS\d{1,10})$/i ) {
        return uc($1);    # Return uppercase
    }

    return undef;
}

# Untaint country code
sub untaint_country_code {
    my ($code) = @_;

    if ( $code =~ /^([A-Z]{2})$/ ) {
        return $1;
    }

    return undef;
}

# Untaint URL
sub untaint_url {
    my ($url) = @_;

    # Only http:// and https://
    # Square brackets escaped with backslash inside character class
    if ( $url =~ /^(https?:\/\/[a-zA-Z0-9\-._~:\/?#\[\]@!$&'()*+,;=%]+)$/ ) {
        my $clean_url = $1;

        # Additional check - no dangerous schemes
        return undef if $clean_url =~ /^(file|ftp|data|javascript):/i;

        return $clean_url;
    }

    return undef;
}

# Untaint PF rule
sub untaint_pf_rule {
    my ($rule) = @_;

    # Allow all characters PF rules can contain including:
    #   $ -- macro references ($ext_if, $gateway)
    #   <> -- table references (<user_block_ips>)
    #   = -- not produced by builder but harmless
    #   ! -- negation (!<table>)
    if ( $rule =~ /^([a-zA-Z0-9\s\-_.,:\/\(\)\[\]\{\}"'\$<>=!@]+)$/ ) {
        my $clean_rule = $1;

        # No shell metacharacters
        return undef if $clean_rule =~ /[;&|`\\]/;

        # Must start with valid action
        return undef unless $clean_rule =~ /^(pass|block|match)\s/;

        return $clean_rule;
    }

    return undef;
}

# Untaint action
sub untaint_action {
    my ($action) = @_;

    if ( $action =~ /^(block|pass)$/ ) {
        return $1;
    }

    return undef;
}

# ============================================
# ENSURE DIRECTORY EXISTS (SAFE)
# ============================================
sub ensure_user_input_dir {
    unless ( -d $USER_INPUT ) {
        make_path( $USER_INPUT, { mode => 0755 } ) or do {
            write_log( 'ERROR', "Failed to create user-input directory: $!" );
            print encode_json(
                { success => 0, error => "Failed to create directory" } );
            exit 1;
        };
    }
}

# ============================================
# SAFE FILE WRITE
# ============================================
sub safe_append {
    my ( $filename, $content ) = @_;

    # Validate filename contains only safe characters
    unless ( $filename =~ /^([a-z0-9_-]+\.(?:txt|json))$/i ) {
        return 0;
    }

    my $safe_filename = $1;
    my $full_path     = File::Spec->catfile( $USER_INPUT, $safe_filename );

    # Use pre-computed canonical base (rel2abs unsafe after unveil)
    unless ( index( $full_path, $CANONICAL_INPUT ) == 0 ) {
        return 0;
    }

    # Untaint: path confirmed safe by index() check above;
    # pattern allows only the characters present in a valid queue path.
    if ( $full_path =~ m{^([-/\w.]+)$} ) {
        $full_path = $1;
    }
    else {
        return 0;
    }

    # Open file safely (no shell execution)
    if ( open my $fh, '>>', $full_path ) {
        print $fh $content . "\n";
        close $fh;
        return 1;
    }

    return 0;
}

sub safe_write {
    my ( $filename, $content ) = @_;

    # Validate filename contains only safe characters
    unless ( $filename =~ /^([a-z0-9_-]+\.(?:txt|json))$/i ) {
        return 0;
    }

    my $safe_filename = $1;
    my $full_path     = File::Spec->catfile( $USER_INPUT, $safe_filename );

    # Use pre-computed canonical base (rel2abs unsafe after unveil)
    unless ( index( $full_path, $CANONICAL_INPUT ) == 0 ) {
        return 0;
    }

    # Untaint: path confirmed safe by index() check above;
    # pattern allows only the characters present in a valid queue path.
    if ( $full_path =~ m{^([-/\w.]+)$} ) {
        $full_path = $1;
    }
    else {
        return 0;
    }

    # Open file safely (no shell execution)
    if ( open my $fh, '>', $full_path ) {
        print $fh $content;
        close $fh;
        return 1;
    }

    return 0;
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

# Validate required fields
unless ( $data->{type} ) {
    write_log( 'ERROR', "Missing 'type' field" );
    print encode_json( { success => 0, error => "Missing 'type' field" } );
    exit 1;
}

# Untaint type
my $type = $data->{type};
unless ( $type =~ /^(ip|asn|geoip|feed|custom_rule)$/ ) {
    write_log( 'ERROR', "Invalid type: $type" );
    print encode_json( { success => 0, error => "Invalid type" } );
    exit 1;
}
$type = $1;    # Now untainted

# ============================================
# ROUTE TO HANDLER
# ============================================
ensure_user_input_dir();

write_log( 'INFO', "Request received: type=$type" );

if ( $type eq 'ip' ) {
    handle_ip($data);
}
elsif ( $type eq 'asn' ) {
    handle_asn($data);
}
elsif ( $type eq 'geoip' ) {
    handle_geoip($data);
}
elsif ( $type eq 'feed' ) {
    handle_feed($data);
}
elsif ( $type eq 'custom_rule' ) {
    handle_custom_rule($data);
}

# ============================================
# HANDLER: IP/CIDR
# ============================================
sub handle_ip {
    my ($data) = @_;

    # Untaint action
    my $action = untaint_action( $data->{action} || 'block' );
    unless ($action) {
        write_log( 'ERROR',
            "Invalid action for ip: " . ( $data->{action} || '' ) );
        print encode_json( { success => 0, error => "Invalid action" } );
        exit 1;
    }

    # Untaint IP/CIDR
    my $ip = untaint_ip( $data->{value} || '' );
    unless ($ip) {
        write_log( 'ERROR', "Invalid IP/CIDR: " . ( $data->{value} || '' ) );
        print encode_json(
            { success => 0, error => "Invalid IP/CIDR format" } );
        exit 1;
    }

    # Write to file
    my $filename = "ip-$action.txt";

    if ( safe_append( $filename, $ip ) ) {
        write_log( 'INFO', "IP queued: $action $ip" );
        print encode_json( { success => 1 } );
    }
    else {
        write_log( 'ERROR', "Failed to write IP: $action $ip" );
        print encode_json( { success => 0, error => "Failed to write" } );
    }
}

# ============================================
# HANDLER: ASN
# ============================================
sub handle_asn {
    my ($data) = @_;

    # Untaint action
    my $action = untaint_action( $data->{action} || 'block' );
    unless ($action) {
        write_log( 'ERROR',
            "Invalid action for asn: " . ( $data->{action} || '' ) );
        print encode_json( { success => 0, error => "Invalid action" } );
        exit 1;
    }

    # Get ASN value
    my $value = $data->{value} || '';

    # Normalize format (accept "15169" or "AS15169")
    if ( $value =~ /^(\d{1,10})$/ ) {
        $value = "AS$1";
    }

    # Untaint ASN
    my $asn = untaint_asn($value);
    unless ($asn) {
        write_log( 'ERROR', "Invalid ASN: " . ( $data->{value} || '' ) );
        print encode_json( { success => 0, error => "Invalid ASN format" } );
        exit 1;
    }

    # Write to file
    my $filename = "asn-$action.txt";

    if ( safe_append( $filename, $asn ) ) {
        write_log( 'INFO', "ASN queued: $action $asn" );
        print encode_json( { success => 1 } );
    }
    else {
        write_log( 'ERROR', "Failed to write ASN: $action $asn" );
        print encode_json( { success => 0, error => "Failed to write" } );
    }
}

# ============================================
# HANDLER: GeoIP
# ============================================
sub handle_geoip {
    my ($data) = @_;

    # Untaint action
    my $action = untaint_action( $data->{action} || 'block' );
    unless ($action) {
        write_log( 'ERROR',
            "Invalid action for geoip: " . ( $data->{action} || '' ) );
        print encode_json( { success => 0, error => "Invalid action" } );
        exit 1;
    }

    # Validate countries array
    my $countries = $data->{countries} || [];
    unless ( ref($countries) eq 'ARRAY' && @$countries > 0 ) {
        write_log( 'ERROR', "No countries selected for geoip" );
        print encode_json( { success => 0, error => "No countries selected" } );
        exit 1;
    }

    # Untaint all country codes
    my @clean_countries;
    for my $country (@$countries) {
        my $clean = untaint_country_code($country);
        push @clean_countries, $clean if $clean;
    }

    unless (@clean_countries) {
        write_log( 'ERROR', "No valid country codes in geoip request" );
        print encode_json(
            { success => 0, error => "No valid country codes" } );
        exit 1;
    }

    # Build JSON
    my $policy = {
        action    => $action,
        countries => \@clean_countries,
        timestamp => time()
    };

    my $json_output = encode_json($policy);

    if ( safe_write( 'geoip-policy.json', $json_output ) ) {
        write_log( 'INFO',
                "GeoIP policy queued: $action "
              . scalar(@clean_countries)
              . " countries ("
              . join( ',', @clean_countries )
              . ")" );
        print encode_json( { success => 1 } );
    }
    else {
        write_log( 'ERROR', "Failed to write geoip policy" );
        print encode_json( { success => 0, error => "Failed to write" } );
    }
}

# ============================================
# HANDLER: Feed URL
# ============================================
sub handle_feed {
    my ($data) = @_;

    # Untaint action
    my $action = untaint_action( $data->{action} || 'block' );
    unless ($action) {
        write_log( 'ERROR',
            "Invalid action for feed: " . ( $data->{action} || '' ) );
        print encode_json( { success => 0, error => "Invalid action" } );
        exit 1;
    }

    # Untaint URL
    my $url = untaint_url( $data->{value} || '' );
    unless ($url) {
        write_log( 'ERROR', "Invalid feed URL: " . ( $data->{value} || '' ) );
        print encode_json( { success => 0, error => "Invalid URL format" } );
        exit 1;
    }

    # Write to file (format: action:URL)
    my $line = "$action:$url";

    if ( safe_append( 'feed-urls.txt', $line ) ) {
        write_log( 'INFO', "Feed URL queued: $action $url" );
        print encode_json( { success => 1 } );
    }
    else {
        write_log( 'ERROR', "Failed to write feed URL: $url" );
        print encode_json( { success => 0, error => "Failed to write" } );
    }
}

# ============================================
# HANDLER: Custom PF Rule
# JS sends all staged rules joined by \n as one value.
# Split, validate each line individually, write all or none.
# ============================================
sub handle_custom_rule {
    my ($data) = @_;

    my $raw_value = $data->{value} || '';
    unless ($raw_value) {
        write_log( 'ERROR', "Empty custom rule value" );
        print encode_json( { success => 0, error => "Empty rule value" } );
        exit 1;
    }

    # Split on newlines -- each line is one rule
    my @lines = split /\n/, $raw_value;
    my @clean_rules;

    for my $line (@lines) {
        $line =~ s/^\s+|\s+$//g;
        next unless $line =~ /\S/;             # skip blank lines

        my $clean = untaint_pf_rule($line);
        unless ($clean) {
            write_log( 'ERROR', "Invalid custom rule rejected: $line" );
            print encode_json(
                {
                    success => 0,
                    error   => "Invalid rule syntax: $line"
                }
            );
            exit 1;
        }
        push @clean_rules, $clean;
    }

    unless (@clean_rules) {
        write_log( 'ERROR', "No valid rules in submission" );
        print encode_json( { success => 0, error => "No valid rules" } );
        exit 1;
    }

    # Write all rules -- one per line
    my $written = 0;
    for my $rule (@clean_rules) {
        if ( safe_append( 'custom-rules.txt', $rule ) ) {
            write_log( 'INFO', "Custom rule queued: $rule" );
            $written++;
        }
        else {
            write_log( 'ERROR', "Failed to write custom rule: $rule" );
            print encode_json(
                { success => 0, error => "Failed to write rule" } );
            exit 1;
        }
    }

    print encode_json( { success => 1, count => $written } );
}

exit 0;
