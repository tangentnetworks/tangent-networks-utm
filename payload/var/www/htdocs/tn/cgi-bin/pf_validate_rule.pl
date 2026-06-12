#!/usr/bin/perl -T

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# /var/www/htdocs/tn/cgi-bin/pf_validate_rule.pl

BEGIN {
    if ( $ENV{GATEWAY_INTERFACE} ) {
        open( STDERR, '>>', '/tmp/pf_validate_rule_stderr.log' )
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

my $log_date = strftime( "%Y-%m-%d", localtime );
my $PF_LOG =
  "/tmp/pf_validate_rule-" . strftime( "%Y-%m-%d", localtime ) . ".log";

# Emit header before security_check so any rejection produces
# a complete HTTP response rather than raw headers from _error_response.
my $cgi = CGI->new;
print $cgi->header(
    -type    => 'application/json',
    -charset => 'utf-8',
    -status  => '200 OK'
);

# Security check - RESTRICTED level (admin only)
my $session = security_check('restricted');

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
        if ( open( my $lf, '>>', "/tmp/pf_validate_rule-${d}.log" ) ) {
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
# PARSE INPUT
# ============================================
my $json_text = $cgi->param('POSTDATA') || '';

unless ($json_text) {
    write_log( 'ERROR', "Empty request body" );
    print encode_json( { valid => 0, error => "Empty request body" } );
    exit 0;
}

sub untaint_pf_rule {
    my ($rule) = @_;

    # PF rules: alphanumeric, spaces, common PF symbols
    # No shell metacharacters
    if ( $rule =~ /^([a-zA-Z0-9\s\-_.,:\/\(\)\[\]\{\}"']+)$/ ) {
        my $clean = $1;

        # No shell metacharacters
        return undef if $clean =~ /[;&|`\$<>]/;

        # Must start with action
        return undef unless $clean =~ /^(pass|block|match)\s/;

        return $clean;
    }

    return undef;
}

# ============================================
# UNTAINT PF RULE
# ============================================

# Parse JSON
my $data;
eval { $data = decode_json($json_text); };

if ($@) {
    write_log( 'ERROR', "Invalid JSON: $@" );
    print encode_json( { valid => 0, error => "Invalid JSON" } );
    exit 0;
}

unless ( $data->{rule} ) {
    write_log( 'ERROR', "Missing rule field" );
    print encode_json( { valid => 0, error => "Missing rule" } );
    exit 0;
}

# ============================================
# VALIDATE RULE
# ============================================
my $rule = untaint_pf_rule( $data->{rule} );

unless ($rule) {
    write_log( 'WARN',
        "Rule rejected - invalid syntax or dangerous characters" );
    print encode_json(
        {
            valid => 0,
            error => "Invalid rule syntax or dangerous characters detected"
        }
    );
    exit 0;
}

# Additional checks
unless ( $rule =~ /\bfrom\b/ && $rule =~ /\bto\b/ ) {
    write_log( 'WARN', "Rule rejected - missing from/to keywords: $rule" );
    print encode_json(
        {
            valid => 0,
            error => "Rule must contain 'from' and 'to' keywords"
        }
    );
    exit 0;
}

if ( $rule =~ /\s{2,}/ ) {
    write_log( 'WARN', "Rule rejected - extra whitespace: $rule" );
    print encode_json(
        {
            valid => 0,
            error => "Remove extra spaces from rule"
        }
    );
    exit 0;
}

# Basic checks passed
write_log( 'INFO', "Rule passed basic validation: $rule" );
print encode_json(
    {
        valid => 1,
        note  =>
"Basic syntax OK - full pfctl validation when you click 'Validate Rules'"
    }
);

exit 0;
